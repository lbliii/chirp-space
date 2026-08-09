"""Acceptance coverage for chronological feed, interactions, and notifications (#797)."""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from chirp.testing import TestClient
from conftest import space_config

from chirp_space.content import LocalObjectStorage, PublishingService
from chirp_space.delivery import DeliveryService
from chirp_space.federation import FederationError, FederationService
from chirp_space.feed import FeedService
from chirp_space.media import PillowImageNormalizer
from chirp_space.models import RemoteActor
from chirp_space.relationships import RelationshipService
from chirp_space.services import SpaceService
from chirp_space.store import SQLiteStore
from chirp_space.web import create_app

pytestmark = pytest.mark.issue(797)

TOKEN_RE = re.compile(r'<meta name="csrf-token" content="([^"]+)"')


class MappingFetcher:
    def __init__(self) -> None:
        self.documents: dict[str, dict[str, object]] = {}

    def fetch_json(self, url: str):
        try:
            return self.documents[url]
        except KeyError as exc:
            raise FederationError("missing", "Remote document missing.", status=502) from exc


def _cookie(response, name: str) -> str | None:
    for header, value in response.headers:
        if header.lower() == "set-cookie" and value.startswith(f"{name}="):
            return value.split(";", 1)[0]
    return None


def _csrf(response) -> str:
    match = TOKEN_RE.search(response.text)
    assert match is not None
    return match.group(1)


async def _claim(client: TestClient) -> str:
    page = await client.get("/setup")
    chirp_cookie = _cookie(page, "chirp_session")
    assert chirp_cookie is not None
    created = await client.post(
        "/setup",
        data={
            "_csrf_token": _csrf(page),
            "claim_token": "owner-claim-token-for-tests",
            "canonical_origin": "http://localhost:8000",
            "handle": "owner",
            "display_name": "Space Owner",
            "bio": "A home on the open web.",
            "password": "correct horse battery staple",
        },
        headers={"Cookie": chirp_cookie},
    )
    owner_cookie = _cookie(created, "space_owner_session")
    assert owner_cookie is not None
    return f"{_cookie(created, 'chirp_session') or chirp_cookie}; {owner_cookie}"


def _services(clock: list[datetime], tmp_path=None):
    config = replace(space_config(), federation_enabled=True)
    store = SQLiteStore()
    store.migrate()
    SpaceService(store, config).setup(
        claim_token=config.claim_token,
        canonical_origin=config.canonical_origin,
        handle="owner",
        display_name="Space Owner",
        bio="Feed proof node.",
        password="correct horse battery staple",
    )
    fetcher = MappingFetcher()
    federation = FederationService(store, config, fetcher=fetcher, now=lambda: clock[0])
    delivery = DeliveryService(store, federation, now=lambda: clock[0])
    relationships = RelationshipService(store, delivery, fetcher, now=lambda: clock[0])
    feed = FeedService(store, config, delivery, now=lambda: clock[0])
    if tmp_path is None:
        raise AssertionError("tmp_path is required for publishing media root")
    root = tmp_path / "media"
    publishing = PublishingService(
        store, config, LocalObjectStorage(root), PillowImageNormalizer(), now=lambda: clock[0]
    )
    return store, relationships, feed, publishing, config


def _follow_bob(store: SQLiteStore, relationships: RelationshipService, clock: list[datetime]):
    actor = RemoteActor(
        id="https://bob.example/ap/actor",
        inbox_url="https://bob.example/ap/inbox",
        preferred_username="bob",
        display_name="Bob",
        domain="bob.example",
        last_contact_at=clock[0],
    )
    store.upsert_remote_actor(actor)
    relationship = store.relationship(actor.id)
    assert relationship is not None
    store.save_relationship(
        replace(
            relationship,
            outbound_state="following",
            outbound_follow_id="https://localhost/ap/activities/follow-bob",
            updated_at=clock[0],
        )
    )
    return actor


def test_mixed_local_remote_ordering_update_delete_block_and_pagination(
    tmp_path: Path,
) -> None:
    clock = [datetime(2026, 7, 17, 12, 0, tzinfo=UTC)]
    store, relationships, feed, publishing, _config = _services(clock, tmp_path)
    bob = _follow_bob(store, relationships, clock)
    owner = store.state()
    assert owner is not None

    local = publishing.create(
        kind="short",
        state="public",
        title="",
        source="Local note in the feed",
        tags=("space",),
    )
    assert local.published_at is not None

    older = clock[0] - timedelta(hours=2)
    newer = clock[0] - timedelta(hours=1)
    feed.receive(
        {
            "id": "https://bob.example/ap/activities/create-1",
            "type": "Create",
            "actor": bob.id,
            "object": {
                "id": "https://bob.example/notes/1",
                "type": "Note",
                "content": "Remote older note",
                "published": older.isoformat().replace("+00:00", "Z"),
            },
        }
    )
    feed.receive(
        {
            "id": "https://bob.example/ap/activities/create-2",
            "type": "Create",
            "actor": bob.id,
            "object": {
                "id": "https://bob.example/notes/2",
                "type": "Note",
                "content": "Remote newer note",
                "published": newer.isoformat().replace("+00:00", "Z"),
            },
        }
    )
    duplicate = feed.receive(
        {
            "id": "https://bob.example/ap/activities/create-2-dup",
            "type": "Create",
            "actor": bob.id,
            "object": {
                "id": "https://bob.example/notes/2",
                "type": "Note",
                "content": "Should not replace",
                "published": newer.isoformat().replace("+00:00", "Z"),
            },
        }
    )
    assert duplicate == "duplicate"

    page, cursor = feed.home_feed(limit=2)
    assert len(page) == 2
    assert page[0].object_id.endswith(local.id)
    assert page[1].object_id == "https://bob.example/notes/2"
    assert cursor is not None
    older_page, _ = feed.home_feed(cursor=cursor, limit=2)
    assert [item.object_id for item in older_page] == ["https://bob.example/notes/1"]

    updated = feed.receive(
        {
            "id": "https://bob.example/ap/activities/update-2",
            "type": "Update",
            "actor": bob.id,
            "object": {
                "id": "https://bob.example/notes/2",
                "type": "Note",
                "content": "Remote newer note (edited)",
                "published": newer.isoformat().replace("+00:00", "Z"),
            },
        }
    )
    assert updated == "updated"
    after_update, _ = feed.home_feed(limit=10)
    edited = next(item for item in after_update if item.object_id.endswith("/notes/2"))
    assert edited.content_text == "Remote newer note (edited)"
    assert edited.status == "updated"
    assert edited.sort_at == newer

    deleted = feed.receive(
        {
            "id": "https://bob.example/ap/activities/delete-1",
            "type": "Delete",
            "actor": bob.id,
            "object": "https://bob.example/notes/1",
        }
    )
    assert deleted == "tombstone"
    after_delete, _ = feed.home_feed(limit=10)
    tombstone = next(item for item in after_delete if item.object_id.endswith("/notes/1"))
    assert tombstone.status == "tombstone"
    assert tombstone.content_text == ""

    relationships.block_actor(bob.id)
    blocked_feed, _ = feed.home_feed(limit=10)
    assert all(item.actor_id != bob.id for item in blocked_feed)

    unavailable_actor = RemoteActor(
        id="https://cara.example/ap/actor",
        inbox_url="https://cara.example/ap/inbox",
        preferred_username="cara",
        display_name="Cara",
        domain="cara.example",
        last_contact_at=clock[0],
    )
    store.upsert_remote_actor(unavailable_actor)
    relationship = store.relationship(unavailable_actor.id)
    assert relationship is not None
    store.save_relationship(
        replace(
            relationship,
            outbound_state="following",
            unavailable=True,
            updated_at=clock[0],
        )
    )
    feed.receive(
        {
            "id": "https://cara.example/ap/activities/create-1",
            "type": "Create",
            "actor": unavailable_actor.id,
            "object": {
                "id": "https://cara.example/notes/1",
                "type": "Note",
                "content": "Stale cached note",
                "published": (clock[0] - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            },
        }
    )
    feed.mark_unavailable("https://cara.example/notes/1")
    stale_feed, _ = feed.home_feed(limit=20)
    stale = next(item for item in stale_feed if item.object_id.endswith("cara.example/notes/1"))
    assert stale.status == "unavailable"


def test_likes_reposts_bookmarks_replies_mentions_and_notifications(tmp_path: Path) -> None:
    clock = [datetime(2026, 7, 17, 15, 0, tzinfo=UTC)]
    store, _relationships, feed, publishing, config = _services(clock, tmp_path)
    bob = _follow_bob(store, _relationships, clock)
    owner = store.state()
    assert owner is not None
    local = publishing.create(
        kind="short",
        state="public",
        title="",
        source="Please reply here",
        tags=(),
    )
    object_id = f"{config.canonical_origin}/posts/{local.id}"

    like = feed.like(object_id)
    assert feed.like(object_id).id == like.id
    feed.repost(object_id)
    feed.bookmark(object_id)
    assert len(feed.bookmarks()) == 1
    reply = feed.reply(object_id, source="A calm reply", visibility="public")
    assert reply.in_reply_to == object_id

    feed.receive(
        {
            "id": "https://bob.example/ap/activities/like-local",
            "type": "Like",
            "actor": bob.id,
            "object": object_id,
        }
    )
    feed.receive(
        {
            "id": "https://bob.example/ap/activities/mention-1",
            "type": "Create",
            "actor": bob.id,
            "object": {
                "id": "https://bob.example/notes/mention",
                "type": "Note",
                "content": "Hello there",
                "published": clock[0].isoformat().replace("+00:00", "Z"),
                "tag": [
                    {
                        "type": "Mention",
                        "href": f"{config.canonical_origin}/ap/actor",
                    }
                ],
            },
        }
    )
    malformed = None
    try:
        feed.receive(
            {
                "id": "https://bob.example/ap/activities/bad",
                "type": "Create",
                "actor": bob.id,
                "object": "https://bob.example/notes/missing-embed",
            }
        )
    except ValueError as exc:
        malformed = str(exc)
    assert malformed is not None

    notes = feed.notifications(limit=20)
    kinds = {item.kind for item in notes}
    assert "like" in kinds
    assert "mention" in kinds
    assert feed.unread_notification_count() >= 2
    feed.mark_all_notifications_read()
    assert feed.unread_notification_count() == 0

    feed.unlike(object_id)
    feed.unrepost(object_id)
    feed.unbookmark(object_id)
    assert feed.bookmarks() == ()


def test_muted_actors_excluded_and_clock_skew_clamped(tmp_path: Path) -> None:
    clock = [datetime(2026, 7, 17, 18, 0, tzinfo=UTC)]
    store, relationships, feed, _publishing, _config = _services(clock, tmp_path)
    bob = _follow_bob(store, relationships, clock)
    relationships.set_preference(bob.id, preference="muted", enabled=True)
    far_future = clock[0] + timedelta(days=30)
    feed.receive(
        {
            "id": "https://bob.example/ap/activities/create-skew",
            "type": "Create",
            "actor": bob.id,
            "object": {
                "id": "https://bob.example/notes/skew",
                "type": "Note",
                "content": "Skewed timestamp",
                "published": far_future.isoformat().replace("+00:00", "Z"),
            },
        }
    )
    muted_feed, _ = feed.home_feed(limit=10)
    assert all(item.actor_id != bob.id for item in muted_feed)
    with_muted, _ = feed.home_feed(limit=10, include_muted=True)
    skewed = next(item for item in with_muted if item.object_id.endswith("/notes/skew"))
    assert skewed.sort_at == clock[0]


@pytest.mark.asyncio
async def test_plain_and_htmx_feed_paths_remain_usable() -> None:
    store = SQLiteStore()
    app = create_app(store=store, space_config=space_config())
    async with TestClient(app) as client:
        cookies = await _claim(client)
        home = await client.get("/home", headers={"Cookie": cookies})
        assert home.status == 200
        assert "Chronological friend feed" in home.text
        assert "No ranking" in home.text

        published = await client.post(
            "/owner/content/new",
            data={
                "_csrf_token": _csrf(home),
                "kind": "short",
                "state": "public",
                "title": "",
                "source": "Owner note for interactions",
                "external_url": "",
                "alt_text": "",
                "tags": "",
                "intent": "save",
                "revision": "0",
            },
            headers={"Cookie": cookies},
        )
        assert published.status in {200, 302, 303}
        feed_page = await client.get("/home", headers={"Cookie": cookies})
        assert "Owner note for interactions" in feed_page.text
        object_match = re.search(
            r'name="object_id" value="(http[^"]+/posts/[^"]+)"', feed_page.text
        )
        assert object_match is not None
        object_id = object_match.group(1)
        liked = await client.post(
            "/home",
            data={
                "_csrf_token": _csrf(feed_page),
                "action": "like",
                "object_id": object_id,
            },
            headers={"Cookie": cookies},
        )
        assert liked.status in {200, 302, 303}
        htmx = await client.post(
            "/home",
            data={
                "_csrf_token": _csrf(feed_page),
                "action": "bookmark",
                "object_id": object_id,
            },
            headers={"Cookie": cookies, "HX-Request": "true"},
        )
        assert htmx.status == 200
        assert "Bookmarked privately" in htmx.text or "bookmark" in htmx.text.lower()
        notes = await client.get("/notifications", headers={"Cookie": cookies})
        assert notes.status == 200
        bookmarks = await client.get("/bookmarks", headers={"Cookie": cookies})
        assert bookmarks.status == 200
        assert object_id in bookmarks.text
