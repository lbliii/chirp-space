from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import space_config

from chirp_space.content import (
    GuestbookService,
    LocalObjectStorage,
    NormalizedImage,
    NormalizedVariant,
    PublishingService,
    RecoverableMediaError,
    render_markdown,
)
from chirp_space.services import SpaceService
from chirp_space.store import SQLiteStore

pytestmark = pytest.mark.issue(791)


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 17, 12, tzinfo=UTC)

    def __call__(self) -> datetime:
        value = self.value
        self.value += timedelta(minutes=1)
        return value


class StubNormalizer:
    def normalize(self, data: bytes) -> NormalizedImage:
        if data == b"malformed":
            raise ValueError("Photo could not be safely decoded.")
        return NormalizedImage(
            b"normalized:" + data,
            "image/webp",
            "webp",
            640,
            480,
            (NormalizedVariant("small", b"small:" + data, "image/webp", "webp", 320, 240),),
        )


class PutFailureStorage:
    def put(self, key: str, data: bytes, *, content_type: str) -> None:
        raise OSError("object store unavailable")

    def get(self, key: str) -> bytes:
        raise FileNotFoundError(key)

    def delete(self, key: str) -> None:
        return None


class FlakyDeleteStorage(LocalObjectStorage):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.failures_remaining = 1

    def delete(self, key: str) -> None:
        if self.failures_remaining:
            self.failures_remaining -= 1
            raise OSError("temporary delete failure")
        super().delete(key)


def ready_store() -> SQLiteStore:
    store = SQLiteStore()
    store.migrate()
    config = space_config()
    SpaceService(store, config).setup(
        claim_token=config.claim_token,
        canonical_origin=config.canonical_origin,
        handle="owner",
        display_name="Space Owner",
        bio="A personal site.",
        password="correct horse battery staple",
    )
    return store


def test_content_lifecycle_pagination_archive_search_and_tombstone(tmp_path: Path) -> None:
    store = ready_store()
    service = PublishingService(
        store,
        space_config(),
        LocalObjectStorage(tmp_path / "media"),
        now=Clock(),
    )
    first = service.create(
        kind="short",
        state="public",
        title="",
        source="First bounded note",
        tags="chirp, notes",
    )
    draft = service.create(
        kind="journal",
        state="draft",
        title="A journal entry",
        source="# Heading\n\nA [safe link](https://example.com).",
        tags="notes",
    )
    service.create(
        kind="link",
        state="public",
        title="An external link",
        source="Worth reading",
        external_url="https://example.com/article",
        tags="reading",
    )

    page, cursor = service.list_public(limit=1)
    assert len(page) == 1
    assert cursor is not None
    older, _ = service.list_public(cursor=cursor, limit=1)
    assert older
    assert older[0].id != page[0].id
    assert service.list_public(query="bounded")[0] == (first,)
    assert service.list_public(tag="chirp")[0] == (first,)
    assert service.archive() == ((2026, 7, 2),)
    assert dict(service.tag_counts()) == {"notes": 1, "chirp": 1, "reading": 1}

    published = service.update(
        draft.id,
        expected_revision=1,
        state="public",
        title=draft.title,
        source=draft.source,
        tags=draft.tags,
    )
    assert published.revision == 2
    assert published.published_at is not None
    with pytest.raises(RuntimeError, match="another session"):
        service.update(
            draft.id,
            expected_revision=1,
            state="draft",
            title=draft.title,
            source=draft.source,
            tags=draft.tags,
        )

    tombstone = service.delete(first.id, expected_revision=1)
    assert tombstone.state == "deleted"
    assert service.get(first.id) == tombstone
    assert first not in service.list_public()[0]

    blocks = render_markdown("# <script>alert(1)</script>\n\n- safe\n- [link](https://example.com)")
    assert blocks[0].lines[0][0].text == "<script>alert(1)</script>"
    assert blocks[1].lines[1][0].href == "https://example.com"


def test_media_contract_missing_object_cleanup_and_recoverable_draft(tmp_path: Path) -> None:
    store = ready_store()
    storage = LocalObjectStorage(tmp_path / "media")
    service = PublishingService(store, space_config(), storage, StubNormalizer(), now=Clock())
    photo = service.create(
        kind="photo",
        state="public",
        title="",
        source="A caption",
        image_bytes=b"source-image-with-metadata",
        alt_text="A green hill under a blue sky",
    )
    assert photo.media is not None
    assert service.media_bytes(photo.media) == b"normalized:source-image-with-metadata"
    assert photo.media.media_type == "image/webp"
    assert photo.media.width == 640
    assert photo.media.variants[0].name == "small"
    assert service.media_bytes(photo.media, variant="small") == (
        b"small:source-image-with-metadata"
    )

    storage.delete(photo.media.object_key)
    with pytest.raises(FileNotFoundError, match="missing"):
        service.media_bytes(photo.media)
    missing = store.media(photo.media.id)
    assert missing is not None
    assert missing.status == "missing"

    failure_store = ready_store()
    failing = PublishingService(
        failure_store, space_config(), PutFailureStorage(), StubNormalizer(), now=Clock()
    )
    with pytest.raises(RecoverableMediaError) as captured:
        failing.create(
            kind="photo",
            state="public",
            title="",
            source="Recover me",
            image_bytes=b"valid",
            alt_text="A descriptive alternative",
        )
    assert captured.value.draft.state == "draft"
    assert failure_store.content_item(captured.value.draft.id) == captured.value.draft


def test_media_delete_and_replacement_are_observable(tmp_path: Path) -> None:
    store = ready_store()
    storage = LocalObjectStorage(tmp_path / "media")
    service = PublishingService(store, space_config(), storage, StubNormalizer(), now=Clock())
    photo = service.create(
        kind="photo",
        state="draft",
        title="",
        source="Before",
        image_bytes=b"first",
        alt_text="First image",
    )
    assert photo.media is not None
    old_media = photo.media
    replaced = service.update(
        photo.id,
        expected_revision=1,
        state="public",
        title="",
        source="After",
        tags=(),
        alt_text="Replacement image",
        image_bytes=b"second",
    )
    assert replaced.media is not None
    assert replaced.media.id != old_media.id
    stored_old_media = store.media(old_media.id)
    assert stored_old_media is not None
    assert stored_old_media.status == "deleted"
    service.delete(replaced.id, expected_revision=2)
    stored_replacement = store.media(replaced.media.id)
    assert stored_replacement is not None
    assert stored_replacement.status == "deleted"

    retry_store = ready_store()
    flaky_storage = FlakyDeleteStorage(tmp_path / "flaky-media")
    retrying = PublishingService(
        retry_store, space_config(), flaky_storage, StubNormalizer(), now=Clock()
    )
    retry_photo = retrying.create(
        kind="photo",
        state="public",
        title="",
        source="Cleanup retry",
        image_bytes=b"retry",
        alt_text="An image awaiting cleanup",
    )
    assert retry_photo.media is not None
    retrying.delete(retry_photo.id, expected_revision=1)
    pending = retry_store.media(retry_photo.media.id)
    assert pending is not None
    assert pending.status == "cleanup-pending"
    assert retrying.retry_media_cleanup() == (1, 0)
    cleaned = retry_store.media(retry_photo.media.id)
    assert cleaned is not None
    assert cleaned.status == "deleted"


def test_guestbook_duplicate_rate_limit_and_moderation() -> None:
    store = ready_store()
    guestbook = GuestbookService(store, space_config(), now=Clock())
    first = guestbook.submit(
        display_name="Visitor",
        message="A thoughtful note",
        website_url="https://example.com",
        client_key="198.51.100.10",
    )
    with pytest.raises(ValueError, match="already received"):
        guestbook.submit(
            display_name="Visitor",
            message="A thoughtful note",
            website_url="https://example.com",
            client_key="198.51.100.10",
        )
    for number in (2, 3):
        guestbook.submit(
            display_name="Visitor",
            message=f"Unique note {number}",
            website_url=None,
            client_key="198.51.100.10",
        )
    with pytest.raises(PermissionError, match="limit reached"):
        guestbook.submit(
            display_name="Visitor",
            message="A fourth unique note",
            website_url=None,
            client_key="198.51.100.10",
        )
    approved = guestbook.moderate(first.id, "approved")
    assert approved.status == "approved"
    assert store.guestbook_entries(public_only=True) == (approved,)


def test_local_storage_rejects_path_escape(tmp_path: Path) -> None:
    storage = LocalObjectStorage(tmp_path / "media")
    with pytest.raises(ValueError, match="escapes"):
        storage.put("../outside", b"data", content_type="image/webp")
