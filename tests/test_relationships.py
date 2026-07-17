from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from chirp.testing import TestClient
from conftest import space_config

from chirp_space.delivery import DeliveryResponse, DeliveryService, DeliveryWorker
from chirp_space.federation import FederationError, FederationService
from chirp_space.relationships import RelationshipService
from chirp_space.services import SpaceService
from chirp_space.store import SQLiteStore
from chirp_space.web import create_app

pytestmark = pytest.mark.issue(796)

TOKEN_RE = re.compile(r'<meta name="csrf-token" content="([^"]+)"')


class MappingFetcher:
    def __init__(self) -> None:
        self.documents: dict[str, dict[str, object]] = {}
        self.calls: list[str] = []

    def fetch_json(self, url: str):
        self.calls.append(url)
        try:
            return self.documents[url]
        except KeyError as exc:
            raise FederationError("missing", "Remote document missing.", status=502) from exc


class CaptureTransport:
    def __init__(self) -> None:
        self.bodies: list[bytes] = []

    def send(self, inbox_url: str, *, headers: Mapping[str, str], body: bytes) -> DeliveryResponse:
        assert inbox_url.startswith("https://")
        assert "Signature" in headers
        self.bodies.append(body)
        return DeliveryResponse(202, {})


def _node(origin: str, clock: list[datetime]):
    config = replace(space_config(), canonical_origin=origin, federation_enabled=True)
    store = SQLiteStore()
    store.migrate()
    host = origin.split("//", 1)[1].split(".", 1)[0]
    SpaceService(store, config).setup(
        claim_token=config.claim_token,
        canonical_origin=origin,
        handle=host,
        display_name=f"Owner at {origin}",
        bio="A relationship test node.",
        password="correct horse battery staple",
    )
    fetcher = MappingFetcher()
    federation = FederationService(store, config, fetcher=fetcher, now=lambda: clock[0])
    delivery = DeliveryService(store, federation, now=lambda: clock[0])
    relationships = RelationshipService(store, delivery, fetcher, now=lambda: clock[0])
    return store, federation, delivery, relationships, fetcher


def _deliver_one(
    store: SQLiteStore,
    federation: FederationService,
    clock: list[datetime],
) -> dict[str, object]:
    transport = CaptureTransport()
    outcomes = DeliveryWorker(store, federation, transport, now=lambda: clock[0]).run_once()
    assert len(outcomes) == 1
    assert outcomes[0].status == "delivered"
    return json.loads(transport.bodies[0])


def _connect_fetchers(
    alice_federation: FederationService,
    alice_fetcher: MappingFetcher,
    bob_federation: FederationService,
    bob_fetcher: MappingFetcher,
) -> tuple[dict[str, object], dict[str, object]]:
    alice_actor = alice_federation.actor_document()
    bob_actor = bob_federation.actor_document()
    alice_fetcher.documents.update(
        {
            str(bob_actor["id"]): bob_actor,
            "https://bob.example/.well-known/webfinger?resource=acct%3Abob%40bob.example": {
                "subject": "acct:bob@bob.example",
                "links": [
                    {
                        "rel": "self",
                        "type": "application/activity+json",
                        "href": bob_actor["id"],
                    }
                ],
            },
        }
    )
    bob_fetcher.documents[str(alice_actor["id"])] = alice_actor
    return alice_actor, bob_actor


def test_mutual_follow_state_circle_preferences_and_audience_preview() -> None:
    clock = [datetime(2026, 7, 17, 19, 0, tzinfo=UTC)]
    alice_store, alice_federation, alice_delivery, alice, alice_fetcher = _node(
        "https://alice.example", clock
    )
    bob_store, bob_federation, _bob_delivery, bob, bob_fetcher = _node("https://bob.example", clock)
    alice_actor, bob_actor = _connect_fetchers(
        alice_federation, alice_fetcher, bob_federation, bob_fetcher
    )

    discovered = alice.discover("@bob@bob.example")
    assert discovered.actor.id == bob_actor["id"]
    assert discovered.outbound_state == "none"
    assert alice.send_follow(discovered.actor.id).outbound_state == "pending"
    follow = _deliver_one(alice_store, alice_federation, clock)
    assert bob.receive(follow) == "pending-follow"
    bob_inbound = bob_store.relationship(str(alice_actor["id"]))
    assert bob_inbound is not None
    assert bob_inbound.inbound_state == "pending"

    bob.accept_follower(str(alice_actor["id"]))
    accepted = _deliver_one(bob_store, bob_federation, clock)
    assert alice.receive(accepted) == "following"
    alice_outbound = alice_store.relationship(str(bob_actor["id"]))
    assert alice_outbound is not None
    assert alice_outbound.outbound_state == "following"

    bob.send_follow(str(alice_actor["id"]))
    reverse_follow = _deliver_one(bob_store, bob_federation, clock)
    assert alice.receive(reverse_follow) == "pending-follow"
    alice.accept_follower(str(bob_actor["id"]))
    reverse_accept = _deliver_one(alice_store, alice_federation, clock)
    assert bob.receive(reverse_accept) == "following"
    alice_relationship = alice_store.relationship(str(bob_actor["id"]))
    assert alice_relationship is not None
    assert alice_relationship.friend
    assert alice_federation.collection("followers")["totalItems"] == 1
    assert alice_federation.collection("following")["totalItems"] == 1

    alice.set_preference(alice_relationship.actor.id, preference="pinned", enabled=True)
    alice.set_preference(alice_relationship.actor.id, preference="muted", enabled=True)
    alice.set_preference(
        alice_relationship.actor.id,
        preference="note",
        enabled=True,
        note="Met through the open web.",
    )
    circle = alice.create_circle("Close friends")
    circle = alice.set_circle_members(circle.id, [alice_relationship.actor.id])
    assert circle.member_actor_ids == (alice_relationship.actor.id,)
    preview = alice.audience_preview("circle", circle_id=circle.id)
    assert preview.recipient_actor_ids == (alice_relationship.actor.id,)
    assert "cannot be revoked" in preview.disclosure

    alice_delivery.enqueue(
        {
            "id": "https://alice.example/ap/activities/pending-like",
            "type": "Like",
            "actor": "https://alice.example/ap/actor",
            "object": "https://bob.example/objects/1",
        },
        inbox_urls=["https://bob.example/ap/inbox"],
    )
    blocked = alice.block_actor(alice_relationship.actor.id)
    assert blocked.blocked
    assert blocked.outbound_state == "removed"
    assert blocked.inbound_state == "removed"
    assert alice_store.circles()[0].member_actor_ids == ()
    assert alice_delivery.health().discarded == 1
    unblocked = alice.unblock_actor(alice_relationship.actor.id)
    assert not unblocked.blocked
    assert unblocked.outbound_state == "removed"
    assert unblocked.inbound_state == "removed"


def test_stale_reordered_events_unavailable_delete_and_domain_block() -> None:
    clock = [datetime(2026, 7, 17, 19, 0, tzinfo=UTC)]
    alice_store, alice_federation, _delivery, alice, alice_fetcher = _node(
        "https://alice.example", clock
    )
    _bob_store, bob_federation, _bob_delivery, _bob, bob_fetcher = _node(
        "https://bob.example", clock
    )
    _alice_actor, bob_actor = _connect_fetchers(
        alice_federation, alice_fetcher, bob_federation, bob_fetcher
    )
    relationship = alice.discover(str(bob_actor["id"]))
    pending = alice.send_follow(relationship.actor.id)
    assert pending.outbound_follow_id is not None
    alice.unfollow(relationship.actor.id)
    stale_accept = {
        "id": "https://bob.example/ap/activities/stale-accept",
        "type": "Accept",
        "actor": relationship.actor.id,
        "object": pending.outbound_follow_id,
    }
    assert alice.receive(stale_accept) == "stale-response"
    removed = alice_store.relationship(relationship.actor.id)
    assert removed is not None
    assert removed.outbound_state == "removed"

    unavailable = alice.mark_unavailable(relationship.actor.id)
    assert unavailable.unavailable
    assert unavailable.outbound_state == "removed"
    deleted = {
        "id": "https://bob.example/ap/activities/delete-account",
        "type": "Delete",
        "actor": relationship.actor.id,
        "object": relationship.actor.id,
    }
    assert alice.receive(deleted) == "remote-deleted"
    remote_deleted = alice_store.relationship(relationship.actor.id)
    assert remote_deleted is not None
    assert remote_deleted.outbound_state == "remote-deleted"
    assert remote_deleted.actor.deleted_at == clock[0]

    alice.block_domain("bob.example")
    calls_before = len(alice_fetcher.calls)
    with pytest.raises(PermissionError, match="blocked"):
        alice.discover("@bob@bob.example")
    assert len(alice_fetcher.calls) == calls_before
    alice.unblock_domain("bob.example")
    restored = alice_store.relationship(relationship.actor.id)
    assert restored is not None
    assert restored.outbound_state == "removed"


def test_circle_rejects_nonfriends_and_restricted_empty_audiences() -> None:
    clock = [datetime(2026, 7, 17, 19, 0, tzinfo=UTC)]
    _store, alice_federation, _delivery, alice, alice_fetcher = _node(
        "https://alice.example", clock
    )
    _bob_store, bob_federation, _bob_delivery, _bob, bob_fetcher = _node(
        "https://bob.example", clock
    )
    _alice_actor, bob_actor = _connect_fetchers(
        alice_federation, alice_fetcher, bob_federation, bob_fetcher
    )
    relationship = alice.discover(str(bob_actor["id"]))
    circle = alice.create_circle("Family")
    with pytest.raises(ValueError, match="friends"):
        alice.set_circle_members(circle.id, [relationship.actor.id])
    for visibility in ("followers", "friends", "circle"):
        with pytest.raises(ValueError, match="no eligible"):
            alice.audience_preview(
                visibility, circle_id=circle.id if visibility == "circle" else None
            )
    assert alice.audience_preview("local").recipient_actor_ids == ()


def test_discovery_rejects_identity_confusion_and_remote_markup() -> None:
    clock = [datetime(2026, 7, 17, 19, 0, tzinfo=UTC)]
    _store, _federation, _delivery, alice, fetcher = _node("https://alice.example", clock)
    fetcher.documents["https://evil.example/ap/actor"] = {
        "id": "https://other.example/ap/actor",
        "type": "Person",
        "preferredUsername": "evil",
        "name": "Evil",
        "inbox": "https://evil.example/ap/inbox",
    }
    with pytest.raises(FederationError, match="does not match"):
        alice.discover("https://evil.example/ap/actor")

    fetcher.documents["https://evil.example/ap/actor"] = {
        "id": "https://evil.example/ap/actor",
        "type": "Person",
        "preferredUsername": "evil",
        "name": "<img src=x onerror=alert(1)>",
        "inbox": "https://evil.example/ap/inbox",
    }
    with pytest.raises(FederationError, match="plain text"):
        alice.discover("https://evil.example/ap/actor")


def _csrf(response) -> str:
    match = TOKEN_RE.search(response.text)
    assert match is not None
    return match.group(1)


def _cookie(response, name: str) -> str | None:
    for header, value in response.headers:
        if header.lower() == "set-cookie" and value.startswith(f"{name}="):
            return value.split(";", 1)[0]
    return None


async def test_plain_and_htmx_connection_flows_share_accessible_page() -> None:
    config = replace(space_config(), federation_enabled=True)
    store = SQLiteStore()
    store.migrate()
    SpaceService(store, config).setup(
        claim_token=config.claim_token,
        canonical_origin=config.canonical_origin,
        handle="owner",
        display_name="Space Owner",
        bio="A home on the open web.",
        password="correct horse battery staple",
    )
    fetcher = MappingFetcher()
    fetcher.documents["https://bob.example/ap/actor"] = {
        "id": "https://bob.example/ap/actor",
        "type": "Person",
        "preferredUsername": "bob",
        "name": "Bob Example",
        "inbox": "https://bob.example/ap/inbox",
    }
    app = create_app(store=store, space_config=config, federation_fetcher=fetcher)
    async with TestClient(app) as client:
        assert (await client.get("/owner/connections")).status == 302
        login = await client.get("/login")
        chirp_cookie = _cookie(login, "chirp_session")
        assert chirp_cookie is not None
        signed_in = await client.post(
            "/login",
            data={
                "_csrf_token": _csrf(login),
                "handle": "owner",
                "password": "correct horse battery staple",
            },
            headers={"Cookie": chirp_cookie},
        )
        owner_cookie = _cookie(signed_in, "space_owner_session")
        chirp_cookie = _cookie(signed_in, "chirp_session") or chirp_cookie
        assert owner_cookie is not None
        cookies = f"{chirp_cookie}; {owner_cookie}"
        page = await client.get("/owner/connections", headers={"Cookie": cookies})
        assert page.status == 200
        assert "Following and followers are asymmetric" in page.text
        discovered = await client.post(
            "/owner/connections",
            data={
                "_csrf_token": _csrf(page),
                "action": "discover",
                "reference": "https://bob.example/ap/actor",
            },
            headers={"Cookie": cookies},
        )
        assert discovered.status == 302
        page = await client.get("/owner/connections", headers={"Cookie": cookies})
        assert "Bob Example" in page.text
        preview = await client.post(
            "/owner/connections",
            data={
                "_csrf_token": _csrf(page),
                "action": "audience-preview",
                "visibility": "local",
            },
            headers={"Cookie": cookies, "HX-Request": "true"},
        )
        assert preview.status == 200
        assert preview.header("x-chirp-render-intent") == "fragment"
        assert "never federated" in preview.text
