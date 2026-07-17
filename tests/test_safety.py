from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from chirp.testing import TestClient
from conftest import space_config

from chirp_space.config import SpaceConfig
from chirp_space.content import LocalObjectStorage, PublishingService
from chirp_space.delivery import DeliveryService
from chirp_space.federation import ACTIVITY_JSON, FederationError, FederationService
from chirp_space.safety import FederationSafety, SafetyLimitError
from chirp_space.services import SpaceService
from chirp_space.store import SQLiteStore
from chirp_space.web import create_app

pytestmark = pytest.mark.issue(799)


def ready_store(path: str | Path = ":memory:") -> tuple[SQLiteStore, SpaceConfig]:
    config = replace(
        space_config(), canonical_origin="https://owner.example", federation_enabled=True
    )
    store = SQLiteStore(path)
    store.migrate()
    if store.state() is None:
        SpaceService(store, config).setup(
            claim_token=config.claim_token,
            canonical_origin=config.canonical_origin,
            handle="owner",
            display_name="Space Owner",
            bio="A resilient personal site.",
            password="correct horse battery staple",
        )
    return store, config


def test_database_rate_and_concurrency_limits_survive_restart(tmp_path: Path) -> None:
    database = tmp_path / "space.db"
    now = datetime(2026, 7, 17, 20, tzinfo=UTC)
    first, _config = ready_store(database)
    second = SQLiteStore(database)
    second.migrate()

    for index in range(20):
        store = first if index % 2 == 0 else second
        assert store.consume_rate_bucket(
            "inbound:ip:shared", capacity=20, refill_per_second=1, now=now
        ) == (True, 0)
    allowed, retry = second.consume_rate_bucket(
        "inbound:ip:shared", capacity=20, refill_per_second=1, now=now
    )
    assert not allowed
    assert retry >= 1

    assert first.acquire_federation_lease(
        "first", (("inbound-actor", "same", 1),), now=now, ttl=timedelta(seconds=30)
    )
    assert not second.acquire_federation_lease(
        "second", (("inbound-actor", "same", 1),), now=now, ttl=timedelta(seconds=30)
    )
    first.close()
    assert second.acquire_federation_lease(
        "recovered",
        (("inbound-actor", "same", 1),),
        now=now + timedelta(seconds=31),
        ttl=timedelta(seconds=30),
    )


def test_pause_contains_federation_while_local_publishing_remains_available(
    tmp_path: Path,
) -> None:
    store, config = ready_store()
    clock = [datetime(2026, 7, 17, 20, tzinfo=UTC)]
    safety = FederationSafety(store, config.secret_key, now=lambda: clock[0])
    control = safety.update_control(
        expected_revision=1,
        inbound_paused=True,
        outbound_paused=True,
        reason="peer abuse investigation",
    )
    assert control.inbound_paused
    assert control.outbound_paused
    with pytest.raises(SafetyLimitError, match="inbox is temporarily paused"):
        safety.begin_inbound(client_key="203.0.113.8", actor="https://peer.example/ap/actor")

    federation = FederationService(store, config, now=lambda: clock[0])
    delivery = DeliveryService(store, federation, now=lambda: clock[0])
    with pytest.raises(RuntimeError, match="delivery is paused"):
        delivery.enqueue(
            {
                "id": "https://owner.example/ap/activities/paused",
                "type": "Create",
                "actor": "https://owner.example/ap/actor",
                "object": "https://owner.example/posts/paused",
            },
            inbox_urls=["https://peer.example/ap/inbox"],
        )

    publishing = PublishingService(
        store, config, LocalObjectStorage(tmp_path / "media"), now=lambda: clock[0]
    )
    local = publishing.create(
        kind="short", state="public", title="", source="Still independently online"
    )
    assert publishing.get(local.id) == local


def test_invalid_signature_diagnostics_are_bounded_and_pseudonymous() -> None:
    store, config = ready_store()
    federation = FederationService(store, config)
    actor = "https://hostile.example/ap/actor/private-path"
    body = json.dumps(
        {
            "id": "https://hostile.example/activities/invalid",
            "type": "Create",
            "actor": actor,
            "object": "https://hostile.example/objects/1",
        }
    ).encode()
    with pytest.raises(FederationError, match="Signature header"):
        federation.receive_inbox(
            method="POST",
            target="/ap/inbox",
            headers={"Content-Type": ACTIVITY_JSON, "Signature": "not-valid"},
            body=body,
            client_key="198.51.100.44",
        )

    events = store.security_events()
    assert events[-1].decision == "denied-signature-header"
    assert events[-1].domain == "hostile.example"
    serialized = json.dumps(events[-1].detail) + events[-1].principal_token
    assert "198.51.100.44" not in serialized
    assert "private-path" not in (events[-1].actor_token or "")


@pytest.mark.asyncio
async def test_owner_can_pause_resume_and_export_evidence_without_shell() -> None:
    store = SQLiteStore()
    config = space_config()
    app = create_app(store=store, space_config=config)
    async with TestClient(app) as client:
        setup = await client.get("/setup")
        csrf = setup.text.split('name="csrf-token" content="', 1)[1].split('"', 1)[0]
        session = next(
            value.split(";", 1)[0]
            for name, value in setup.headers
            if name.lower() == "set-cookie" and value.startswith("chirp_session=")
        )
        claimed = await client.post(
            "/setup",
            data={
                "_csrf_token": csrf,
                "claim_token": config.claim_token,
                "canonical_origin": config.canonical_origin,
                "handle": "owner",
                "display_name": "Space Owner",
                "bio": "Independent",
                "password": "correct horse battery staple",
            },
            headers={"Cookie": session},
        )
        cookies = "; ".join(
            value.split(";", 1)[0]
            for name, value in claimed.headers
            if name.lower() == "set-cookie"
        )
        page = await client.get("/owner/connections", headers={"Cookie": cookies})
        assert "Federation safety and recovery" in page.text
        csrf = page.text.split('name="csrf-token" content="', 1)[1].split('"', 1)[0]
        paused = await client.post(
            "/owner/connections",
            data={
                "_csrf_token": csrf,
                "action": "pause-all",
                "revision": "1",
                "reason": "operator test",
            },
            headers={"Cookie": cookies},
        )
        assert paused.status == 302
        assert store.federation_control().inbound_paused
        exported = await client.get("/owner/federation/events", headers={"Cookie": cookies})
        assert exported.status == 200
        assert exported.header("content-disposition") == (
            'attachment; filename="federation-events.json"'
        )
        assert "pause-updated" in exported.text
