from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from conftest import space_config

from chirp_space.cli import main
from chirp_space.delivery import (
    DeliveryResponse,
    DeliveryService,
    DeliveryWorker,
    HTTPSDeliveryTransport,
)
from chirp_space.federation import FederationError, FederationService, FetchResponse
from chirp_space.services import SpaceService
from chirp_space.store import SQLiteStore

pytestmark = pytest.mark.issue(794)


class MappingFetcher:
    def __init__(self, documents: dict[str, dict[str, object]]) -> None:
        self.documents = documents

    def fetch_json(self, url: str):
        return self.documents[url]


class ScriptedTransport:
    def __init__(self, *responses: DeliveryResponse | FederationError) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, Mapping[str, str], bytes]] = []

    def send(self, inbox_url: str, *, headers: Mapping[str, str], body: bytes) -> DeliveryResponse:
        self.calls.append((inbox_url, headers, body))
        response = self.responses.pop(0)
        if isinstance(response, FederationError):
            raise response
        return response


class NodeTransport:
    def __init__(self, nodes: dict[str, FederationService]) -> None:
        self.nodes = nodes
        self.calls = 0

    def send(self, inbox_url: str, *, headers: Mapping[str, str], body: bytes) -> DeliveryResponse:
        self.calls += 1
        node = self.nodes[inbox_url]
        receipt = node.receive_inbox(
            method="POST", target=urlsplit(inbox_url).path, headers=headers, body=body
        )
        assert receipt.status in {"accepted", "duplicate"}
        return DeliveryResponse(202, {})


def _node(
    origin: str,
    *,
    now: list[datetime],
    path: str | Path = ":memory:",
    max_active_deliveries: int = 10_000,
) -> tuple[SQLiteStore, FederationService, DeliveryService]:
    config = replace(space_config(), canonical_origin=origin, federation_enabled=True)
    store = SQLiteStore(path, max_active_deliveries=max_active_deliveries)
    store.migrate()
    if store.state() is None:
        host = urlsplit(origin).hostname
        if host is None:
            raise ValueError("Test node origin requires a host.")
        SpaceService(store, config).setup(
            claim_token=config.claim_token,
            canonical_origin=origin,
            handle=host.split(".", 1)[0],
            display_name=f"Owner at {origin}",
            bio="A durable federation test node.",
            password="correct horse battery staple",
        )
    federation = FederationService(store, config, now=lambda: now[0])
    return store, federation, DeliveryService(store, federation, now=lambda: now[0])


def _activity(origin: str, suffix: str, activity_type: str = "Create") -> dict[str, object]:
    return {
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": f"{origin}/ap/activities/{suffix}",
        "type": activity_type,
        "actor": f"{origin}/ap/actor",
        "object": {
            "id": f"{origin}/objects/{suffix}",
            "type": "Note",
            "content": f"Post {suffix}",
        },
    }


def test_delivery_survives_restart_and_preserves_per_inbox_order(tmp_path: Path) -> None:
    clock = [datetime(2026, 7, 17, 18, 0, tzinfo=UTC)]
    database = tmp_path / "space.db"
    store, federation, delivery = _node("https://alice.example", now=clock, path=database)
    first = delivery.enqueue(
        _activity("https://alice.example", "first"),
        inbox_urls=["https://bob.example/ap/inbox"],
    )[0]
    clock[0] += timedelta(seconds=1)
    second = delivery.enqueue(
        _activity("https://alice.example", "second"),
        inbox_urls=["https://bob.example/ap/inbox"],
    )[0]
    transport = ScriptedTransport(DeliveryResponse(503, {}))
    worker = DeliveryWorker(store, federation, transport, now=lambda: clock[0])

    outcome = worker.run_once()
    assert [item.id for item in outcome] == [first.id]
    assert outcome[0].status == "retrying"
    assert outcome[0].next_attempt_at == clock[0] + timedelta(minutes=1)
    stored_second = store.delivery(second.id)
    assert stored_second is not None
    assert stored_second.status == "pending"
    store.close()

    restarted, federation, delivery = _node("https://alice.example", now=clock, path=database)
    assert delivery.health().retrying == 1
    assert delivery.health().pending == 1
    assert (
        DeliveryWorker(
            restarted,
            federation,
            ScriptedTransport(DeliveryResponse(202, {})),
            now=lambda: clock[0],
        ).run_once()
        == ()
    )

    clock[0] += timedelta(minutes=1)
    transport = ScriptedTransport(DeliveryResponse(202, {}), DeliveryResponse(202, {}))
    worker = DeliveryWorker(restarted, federation, transport, now=lambda: clock[0])
    assert worker.run_once()[0].id == first.id
    assert worker.run_once()[0].id == second.id
    assert delivery.health().delivered == 2


def test_due_delivery_claim_prevents_concurrent_worker_ownership(tmp_path: Path) -> None:
    clock = [datetime(2026, 7, 17, 18, 0, tzinfo=UTC)]
    database = tmp_path / "lease.db"
    first_store, _federation, delivery = _node("https://alice.example", now=clock, path=database)
    delivery.enqueue(
        _activity("https://alice.example", "lease"),
        inbox_urls=["https://bob.example/ap/inbox"],
    )
    second_store = SQLiteStore(database)
    second_store.migrate()

    assert len(first_store.due_delivery_jobs(now=clock[0], limit=16)) == 1
    assert second_store.due_delivery_jobs(now=clock[0], limit=16) == ()
    first_store.close()
    second_store.close()


def test_retry_schedule_circuit_retry_after_and_dead_letter_controls() -> None:
    clock = [datetime(2026, 7, 17, 18, 0, tzinfo=UTC)]
    store, federation, delivery = _node("https://alice.example", now=clock)
    queued = delivery.enqueue(
        _activity("https://alice.example", "retry"),
        inbox_urls=["https://bob.example/ap/inbox"],
    )[0]
    transport = ScriptedTransport(
        DeliveryResponse(500, {}),
        DeliveryResponse(429, {}),
        DeliveryResponse(503, {"retry-after": "999999"}),
    )
    worker = DeliveryWorker(store, federation, transport, now=lambda: clock[0])

    first = worker.run_once()[0]
    assert first.next_attempt_at - clock[0] == timedelta(minutes=1)
    clock[0] = first.next_attempt_at
    second = worker.run_once()[0]
    assert second.next_attempt_at - clock[0] == timedelta(minutes=5)
    clock[0] = second.next_attempt_at
    third = worker.run_once()[0]
    assert third.next_attempt_at - clock[0] == timedelta(days=1)
    assert delivery.health().open_circuits == 1

    dead = replace(
        third,
        status="dead",
        next_attempt_at=clock[0],
        last_error="HTTP 400",
        updated_at=clock[0],
    )
    store.update_delivery(dead)
    delivery.retry_dead_letter(queued.id)
    retried_delivery = store.delivery(queued.id)
    assert retried_delivery is not None
    assert retried_delivery.status == "pending"
    delivery.discard(queued.id)
    assert delivery.health().discarded == 1


def test_terminal_block_network_failure_and_fanout_bounds() -> None:
    clock = [datetime(2026, 7, 17, 18, 0, tzinfo=UTC)]
    store, federation, delivery = _node("https://alice.example", now=clock)
    blocked = delivery.enqueue(
        _activity("https://alice.example", "blocked"),
        inbox_urls=["https://blocked.example/ap/inbox"],
    )[0]
    untouched = ScriptedTransport(DeliveryResponse(202, {}))
    result = DeliveryWorker(
        store,
        federation,
        untouched,
        now=lambda: clock[0],
        is_blocked=lambda inbox: "blocked.example" in inbox,
    ).run_once()[0]
    assert result.id == blocked.id
    assert result.status == "dead"
    assert untouched.calls == []

    with pytest.raises(ValueError, match="500"):
        delivery.enqueue(
            _activity("https://alice.example", "fanout"),
            inbox_urls=[f"https://peer{index}.example/ap/inbox" for index in range(501)],
        )

    network = delivery.enqueue(
        _activity("https://alice.example", "network"),
        inbox_urls=["https://offline.example/ap/inbox"],
    )[0]
    transport = ScriptedTransport(
        FederationError("delivery-network", "Federation delivery failed.", status=502)
    )
    retried = DeliveryWorker(store, federation, transport, now=lambda: clock[0]).run_once()[0]
    assert retried.id == network.id
    assert retried.status == "retrying"

    bounded_store, _bounded_federation, bounded_delivery = _node(
        "https://carol.example", now=clock, max_active_deliveries=1
    )
    bounded_delivery.enqueue(
        _activity("https://carol.example", "one"),
        inbox_urls=["https://one.example/ap/inbox"],
    )
    with pytest.raises(RuntimeError, match="queue is full"):
        bounded_delivery.enqueue(
            _activity("https://carol.example", "two"),
            inbox_urls=["https://two.example/ap/inbox"],
        )
    assert bounded_store.queue_health(now=clock[0]).pending == 1


def test_activity_content_is_immutable_and_duplicate_destination_is_idempotent() -> None:
    clock = [datetime(2026, 7, 17, 18, 0, tzinfo=UTC)]
    _store, _federation, delivery = _node("https://alice.example", now=clock)
    activity = _activity("https://alice.example", "immutable")
    queued = delivery.enqueue(
        activity,
        inbox_urls=[
            "https://bob.example/ap/inbox",
            "https://bob.example/ap/inbox",
        ],
    )
    assert len(queued) == 1
    assert delivery.enqueue(activity, inbox_urls=["https://bob.example/ap/inbox"]) == queued
    with pytest.raises(RuntimeError, match="different content"):
        delivery.enqueue(
            activity | {"object": "https://alice.example/objects/changed"},
            inbox_urls=["https://bob.example/ap/inbox"],
        )


def test_two_nodes_exchange_supported_matrix_and_converge_duplicates() -> None:
    clock = [datetime(2026, 7, 17, 18, 0, tzinfo=UTC)]
    alice_store, alice_federation, alice_delivery = _node("https://alice.example", now=clock)
    bob_store, bob_federation, _bob_delivery = _node("https://bob.example", now=clock)
    alice_key = alice_federation.actor_document()["publicKey"]
    bob_federation.fetcher = MappingFetcher({str(alice_key["id"]): dict(alice_key)})
    transport = NodeTransport({"https://bob.example/ap/inbox": bob_federation})
    worker = DeliveryWorker(alice_store, alice_federation, transport, now=lambda: clock[0])
    types = ("Follow", "Accept", "Reject", "Create", "Update", "Delete", "Like", "Announce", "Undo")
    for index, activity_type in enumerate(types):
        alice_delivery.enqueue(
            _activity("https://alice.example", str(index), activity_type),
            inbox_urls=["https://bob.example/ap/inbox"],
        )
        clock[0] += timedelta(seconds=1)
    for _ in types:
        assert worker.run_once()[0].status == "delivered"
    assert transport.calls == len(types)
    receipts = bob_store.inbox_receipts()
    assert len(receipts) == len(types)
    assert {receipt.activity_type for receipt in receipts} == set(types)

    body = json.dumps(
        _activity("https://alice.example", "duplicate"), separators=(",", ":")
    ).encode()
    headers = alice_federation.sign_request("POST", "https://bob.example/ap/inbox", body)
    first = bob_federation.receive_inbox(
        method="POST", target="/ap/inbox", headers=headers, body=body
    )
    assert first.status == "accepted"
    clock[0] += timedelta(seconds=1)
    equivalent_body = json.dumps(json.loads(body), indent=2, sort_keys=True).encode()
    fresh_headers = alice_federation.sign_request(
        "POST", "https://bob.example/ap/inbox", equivalent_body
    )
    duplicate = bob_federation.receive_inbox(
        method="POST", target="/ap/inbox", headers=fresh_headers, body=equivalent_body
    )
    assert duplicate.status == "duplicate"

    changed = json.loads(body) | {"object": "https://alice.example/objects/changed"}
    changed_body = json.dumps(changed, separators=(",", ":")).encode()
    clock[0] += timedelta(seconds=1)
    changed_headers = alice_federation.sign_request(
        "POST", "https://bob.example/ap/inbox", changed_body
    )
    with pytest.raises(FederationError, match="different content"):
        bob_federation.receive_inbox(
            method="POST", target="/ap/inbox", headers=changed_headers, body=changed_body
        )


def test_https_transport_rejects_mixed_private_dns_before_post() -> None:
    called = False

    def requester(
        _url: str,
        _address: str,
        _port: int,
        _headers: Mapping[str, str],
        _body: bytes,
        _timeout: float,
    ) -> FetchResponse:
        nonlocal called
        called = True
        return FetchResponse(202, {}, b"")

    transport = HTTPSDeliveryTransport(
        resolver=lambda _host, _port: ["93.184.216.34", "127.0.0.1"],
        requester=requester,
    )
    with pytest.raises(FederationError, match="globally routable"):
        transport.send("https://bob.example/ap/inbox", headers={}, body=b"{}")
    assert called is False


def test_queue_cli_reports_health_without_database_surgery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'cli.db'}")
    monkeypatch.setattr(sys, "argv", ["chirp-space", "queue"])
    main()
    assert capsys.readouterr().out == "processed=0 pending=0 retrying=0 dead=0\n"
