from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from chirp.testing import TestClient
from conftest import space_config
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from chirp_space.federation import (
    ACTIVITY_JSON,
    FederationError,
    FederationService,
    FetchResponse,
    SafeFetcher,
    parse_json_object,
    validate_public_address,
    validate_remote_url,
)
from chirp_space.services import SpaceService
from chirp_space.store import SQLiteStore
from chirp_space.web import create_app

pytestmark = pytest.mark.issue(793)


class MappingFetcher:
    def __init__(self, documents: dict[str, dict[str, object]]) -> None:
        self.documents = documents

    def fetch_json(self, url: str):
        try:
            return self.documents[url]
        except KeyError as exc:
            raise FederationError(
                "missing", "Test remote document is missing.", status=502
            ) from exc


def _node(origin: str, *, now: datetime | None = None):
    config = replace(space_config(), canonical_origin=origin)
    store = SQLiteStore()
    store.migrate()
    SpaceService(store, config).setup(
        claim_token=config.claim_token,
        canonical_origin=origin,
        handle=origin.split("//", 1)[1].split(".", 1)[0],
        display_name=f"Owner at {origin}",
        bio="A federated test node.",
        password="correct horse battery staple",
    )
    clock = (lambda: now) if now is not None else None
    federation = FederationService(store, config, fetcher=MappingFetcher({}), now=clock)
    return config, store, federation


def _rfc9421_headers(
    federation: FederationService,
    *,
    key_id: str,
    body: bytes,
    now: datetime,
) -> dict[str, str]:
    content_digest = f"sha-256=:{base64.b64encode(hashlib.sha256(body).digest()).decode()}:"
    parameters = (
        '("@method" "@target-uri" "content-digest" "content-type")'
        f';created={int(now.timestamp())};keyid="{key_id}";alg="rsa-v1_5-sha256"'
    )
    signature_base = "\n".join(
        (
            '"@method": POST',
            '"@target-uri": https://alice.example/ap/inbox',
            f'"content-digest": {content_digest}',
            f'"content-type": {ACTIVITY_JSON}',
            f'"@signature-params": {parameters}',
        )
    )
    key = federation.ensure_key()
    signature = federation._private_key(key).sign(
        signature_base.encode(), padding.PKCS1v15(), hashes.SHA256()
    )
    return {
        "Content-Type": ACTIVITY_JSON,
        "Content-Digest": content_digest,
        "Signature-Input": f"sig1={parameters}",
        "Signature": f"sig1=:{base64.b64encode(signature).decode()}:",
    }


def test_actor_webfinger_collections_and_encrypted_key() -> None:
    _config, store, federation = _node("https://alice.example")
    actor = federation.actor_document()
    assert actor["id"] == "https://alice.example/ap/actor"
    assert actor["preferredUsername"] == "alice"
    assert actor["url"] == "https://alice.example/@alice"
    public_key = actor["publicKey"]
    assert public_key["owner"] == actor["id"]

    stored = store.active_federation_key()
    assert stored is not None
    assert b"BEGIN ENCRYPTED PRIVATE KEY" in stored.encrypted_private_pem
    assert stored.public_pem.encode() not in stored.encrypted_private_pem
    key_id = str(public_key["id"]).rsplit("/", 1)[1]
    assert federation.key_document(key_id)["publicKeyPem"] == stored.public_pem

    jrd = federation.webfinger("acct:alice@alice.example")
    assert jrd["links"][0]["type"] == ACTIVITY_JSON
    with pytest.raises(FederationError, match="not found"):
        federation.webfinger("acct:mallory@alice.example")
    assert federation.collection("outbox")["orderedItems"] == []
    assert federation.collection("followers")["totalItems"] == 0


def test_key_rotation_retains_public_overlap_and_tombstones() -> None:
    now = datetime(2026, 7, 17, 18, 0, tzinfo=UTC)
    config, store, original_service = _node("https://alice.example", now=now)
    original = original_service.ensure_key()
    clock = [now]
    federation = FederationService(store, config, now=lambda: clock[0])
    replacement = federation.rotate_key()

    assert replacement.id != original.id
    assert federation.actor_document()["publicKey"]["id"].endswith(replacement.id)
    assert federation.key_document(original.id)["publicKeyPem"] == original.public_pem
    tombstone = federation.tombstone_document(
        "https://alice.example/objects/1", former_type="Article", deleted_at=now
    )
    assert tombstone == {
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": "https://alice.example/objects/1",
        "type": "Tombstone",
        "formerType": "Article",
        "deleted": "2026-07-17T18:00:00Z",
    }

    clock[0] += timedelta(days=31)
    with pytest.raises(FederationError, match="not found"):
        federation.key_document(original.id)


def test_two_nodes_sign_verify_deduplicate_and_ignore_unknown_activity() -> None:
    now = datetime(2026, 7, 17, 18, 0, tzinfo=UTC)
    _alice_config, alice_store, alice = _node("https://alice.example", now=now)
    _bob_config, _bob_store, bob = _node("https://bob.example", now=now)
    bob_actor = bob.actor_document()
    bob_key = bob_actor["publicKey"]
    alice.fetcher = MappingFetcher({str(bob_key["id"]): dict(bob_key)})

    activity = {
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": "https://bob.example/activities/1",
        "type": "Follow",
        "actor": "https://bob.example/ap/actor",
        "object": "https://alice.example/ap/actor",
    }
    body = json.dumps(activity, separators=(",", ":")).encode()
    headers = bob.sign_request("POST", "https://alice.example/ap/inbox", body)
    receipt = alice.receive_inbox(method="POST", target="/ap/inbox", headers=headers, body=body)
    assert receipt.status == "accepted"
    assert receipt.activity_type == "Follow"
    assert alice_store.inbox_receipts() == (receipt,)
    with pytest.raises(FederationError, match="already processed"):
        alice.receive_inbox(method="POST", target="/ap/inbox", headers=headers, body=body)

    unknown = activity | {"id": "https://bob.example/activities/2", "type": "Teleport"}
    unknown_body = json.dumps(unknown, separators=(",", ":")).encode()
    unknown_headers = bob.sign_request("POST", "https://alice.example/ap/inbox", unknown_body)
    ignored = alice.receive_inbox(
        method="POST", target="/ap/inbox", headers=unknown_headers, body=unknown_body
    )
    assert ignored.status == "unsupported"
    assert ignored.diagnostic == "activity type ignored"


def test_rfc9421_signature_profile_and_target_integrity() -> None:
    now = datetime(2026, 7, 17, 18, 0, tzinfo=UTC)
    _alice_config, _alice_store, alice = _node("https://alice.example", now=now)
    _bob_config, _bob_store, bob = _node("https://bob.example", now=now)
    bob_key = bob.ensure_key()
    key_id = f"https://bob.example/ap/keys/{bob_key.id}"
    alice.fetcher = MappingFetcher({key_id: bob.key_document(bob_key.id)})
    activity = {
        "id": "https://bob.example/activities/rfc9421-1",
        "type": "Follow",
        "actor": "https://bob.example/ap/actor",
        "object": "https://alice.example/ap/actor",
    }
    body = json.dumps(activity, separators=(",", ":")).encode()
    headers = _rfc9421_headers(bob, key_id=key_id, body=body, now=now)

    receipt = alice.receive_inbox(method="POST", target="/ap/inbox", headers=headers, body=body)
    assert receipt.status == "accepted"

    changed_activity = activity | {"id": "https://bob.example/activities/rfc9421-2"}
    changed_body = json.dumps(changed_activity, separators=(",", ":")).encode()
    changed_headers = _rfc9421_headers(bob, key_id=key_id, body=changed_body, now=now)
    with pytest.raises(FederationError, match="verification failed"):
        alice.receive_inbox(
            method="POST", target="/ap/other-inbox", headers=changed_headers, body=changed_body
        )


def test_signature_rejects_tamper_key_mismatch_and_clock_skew() -> None:
    now = datetime(2026, 7, 17, 18, 0, tzinfo=UTC)
    _alice_config, _alice_store, alice = _node("https://alice.example", now=now)
    _bob_config, _bob_store, bob = _node("https://bob.example", now=now)
    bob_key = bob.actor_document()["publicKey"]
    alice.fetcher = MappingFetcher({str(bob_key["id"]): dict(bob_key)})
    activity = {
        "id": "https://bob.example/activities/3",
        "type": "Create",
        "actor": "https://bob.example/ap/actor",
        "object": {"id": "https://bob.example/objects/3", "type": "Note"},
    }
    body = json.dumps(activity, separators=(",", ":")).encode()
    headers = bob.sign_request("POST", "https://alice.example/ap/inbox", body)

    with pytest.raises(FederationError, match="digest"):
        alice.receive_inbox(method="POST", target="/ap/inbox", headers=headers, body=body + b" ")
    wrong_host = bob.sign_request("POST", "https://evil.example/ap/inbox", body)
    with pytest.raises(FederationError, match="does not match"):
        alice.receive_inbox(method="POST", target="/ap/inbox", headers=wrong_host, body=body)
    mismatched = MappingFetcher(
        {str(bob_key["id"]): dict(bob_key) | {"owner": "https://mallory.example/ap/actor"}}
    )
    alice.fetcher = mismatched
    with pytest.raises(FederationError, match="does not belong"):
        alice.receive_inbox(method="POST", target="/ap/inbox", headers=headers, body=body)

    alice.fetcher = MappingFetcher({str(bob_key["id"]): dict(bob_key)})
    late_alice = FederationService(
        alice.store,
        alice.config,
        fetcher=alice.fetcher,
        now=lambda: now + timedelta(minutes=11),
    )
    with pytest.raises(FederationError, match="outside the replay window"):
        late_alice.receive_inbox(method="POST", target="/ap/inbox", headers=headers, body=body)


def test_json_and_ssrf_boundaries_fail_before_remote_io() -> None:
    with pytest.raises(FederationError, match="duplicate key"):
        parse_json_object(b'{"id":"one","id":"two"}')
    with pytest.raises(FederationError, match="JSON object"):
        parse_json_object(b"[]")
    nested: object = "leaf"
    for _ in range(33):
        nested = [nested]
    with pytest.raises(FederationError, match="nesting"):
        parse_json_object(json.dumps({"value": nested}).encode())
    with pytest.raises(FederationError, match="too many values"):
        parse_json_object(json.dumps({str(index): index for index in range(10_001)}).encode())
    with pytest.raises(FederationError, match="256 KiB"):
        parse_json_object(json.dumps({"value": "x" * (256 * 1024 + 1)}).encode())
    for address in ("127.0.0.1", "::1", "10.0.0.1", "169.254.169.254", "2001:db8::1"):
        with pytest.raises(FederationError, match="globally routable"):
            validate_public_address(address)
    with pytest.raises(FederationError, match="port 443"):
        validate_remote_url("https://example.com:8443/actor")
    with pytest.raises(FederationError, match="without credentials"):
        validate_remote_url("https://user:secret@example.com/actor")

    called = False

    def requester(*_args):
        nonlocal called
        called = True
        return FetchResponse(200, {"content-type": ACTIVITY_JSON}, b"{}")

    private = SafeFetcher(resolver=lambda _host, _port: ["127.0.0.1"], requester=requester)
    with pytest.raises(FederationError, match="globally routable"):
        private.fetch_json("https://2130706433/actor")
    assert not called

    mixed = SafeFetcher(
        resolver=lambda _host, _port: ["93.184.216.34", "10.0.0.1"], requester=requester
    )
    with pytest.raises(FederationError, match="globally routable"):
        mixed.fetch_json("https://example.com/actor")
    assert not called


def test_safe_fetcher_revalidates_redirects_and_caches_bounded_json() -> None:
    requests: list[str] = []

    def resolver(host: str, _port: int):
        return ["93.184.216.34"] if host == "example.com" else ["127.0.0.1"]

    def redirecting(url: str, *_args):
        requests.append(url)
        return FetchResponse(302, {"location": "https://internal.example/actor"}, b"")

    fetcher = SafeFetcher(resolver=resolver, requester=redirecting)
    with pytest.raises(FederationError, match="globally routable"):
        fetcher.fetch_json("https://example.com/actor")
    assert requests == ["https://example.com/actor"]

    calls = 0

    def successful(_url: str, *_args):
        nonlocal calls
        calls += 1
        return FetchResponse(
            200,
            {"content-type": ACTIVITY_JSON},
            b'{"id":"https://example.com/actor","type":"Person"}',
        )

    cached = SafeFetcher(resolver=lambda _host, _port: ["93.184.216.34"], requester=successful)
    assert cached.fetch_json("https://example.com/actor")["type"] == "Person"
    assert cached.fetch_json("https://example.com/actor")["type"] == "Person"
    assert calls == 1


@pytest.mark.asyncio
async def test_protocol_routes_are_narrow_and_content_negotiated() -> None:
    store = SQLiteStore()
    config = replace(space_config(), canonical_origin="https://alice.example")
    app = create_app(store=store, space_config=config)
    service = SpaceService(store, config)
    service.setup(
        claim_token=config.claim_token,
        canonical_origin=config.canonical_origin,
        handle="alice",
        display_name="Alice",
        bio="A federated profile.",
        password="correct horse battery staple",
    )
    async with TestClient(app) as client:
        actor = await client.get("/ap/actor", headers={"Accept": ACTIVITY_JSON})
        assert actor.status == 200
        assert actor.content_type == ACTIVITY_JSON
        assert actor.json["id"] == "https://alice.example/ap/actor"
        rejected = await client.get("/ap/actor", headers={"Accept": "text/html"})
        assert rejected.status == 406
        webfinger = await client.get("/.well-known/webfinger?resource=acct:alice@alice.example")
        assert webfinger.status == 200
        assert webfinger.content_type == "application/jrd+json"
        outbox = await client.get("/ap/outbox", headers={"Accept": ACTIVITY_JSON})
        assert outbox.json["type"] == "OrderedCollection"


@pytest.mark.asyncio
async def test_federation_endpoints_stay_dark_without_enablement() -> None:
    config = replace(space_config(), federation_enabled=False)
    app = create_app(store=SQLiteStore(), space_config=config)
    async with TestClient(app) as client:
        assert (await client.get("/ap/actor", headers={"Accept": ACTIVITY_JSON})).status == 404
        assert (
            await client.get("/.well-known/webfinger?resource=acct:owner@localhost")
        ).status == 404
