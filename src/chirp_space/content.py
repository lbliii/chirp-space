"""Local-first publishing, normalized media, and moderated guestbook services."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from chirp_space.config import SpaceConfig
from chirp_space.models import ContentItem, GuestbookEntry, MediaAsset, MediaVariant, Owner
from chirp_space.store import Store

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_IMAGE_DIMENSION = 4096
ALLOWED_KINDS = frozenset({"short", "journal", "photo", "link"})
ALLOWED_STATES = frozenset({"draft", "local_only", "public"})
TAG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")
LINK_RE = re.compile(r"\[([^\]\n]{1,120})\]\((https://[^\s)]+)\)")


class ObjectStorage(Protocol):
    def put(self, key: str, data: bytes, *, content_type: str) -> None: ...
    def get(self, key: str) -> bytes: ...
    def delete(self, key: str) -> None: ...


@dataclass(frozen=True, slots=True)
class NormalizedVariant:
    name: str
    data: bytes
    media_type: str
    extension: str
    width: int
    height: int


@dataclass(frozen=True, slots=True)
class NormalizedImage:
    """A metadata-free image produced by the separately approved media adapter."""

    data: bytes
    media_type: str
    extension: str
    width: int
    height: int
    variants: tuple[NormalizedVariant, ...] = ()


@dataclass(frozen=True, slots=True)
class MarkdownInline:
    text: str
    href: str | None = None


@dataclass(frozen=True, slots=True)
class MarkdownBlock:
    kind: str
    lines: tuple[tuple[MarkdownInline, ...], ...]


@dataclass(frozen=True, slots=True)
class ContentPresentation:
    item: ContentItem
    path: str
    blocks: tuple[MarkdownBlock, ...]


class ImageNormalizer(Protocol):
    """Decode and re-encode untrusted uploads without leaking library types."""

    def normalize(self, data: bytes) -> NormalizedImage: ...


class LocalObjectStorage:
    """Filesystem adapter for local development and deterministic contract tests."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()

    def put(self, key: str, data: bytes, *, content_type: str) -> None:
        _ = content_type
        target = self._target(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(f"{target.suffix}.tmp-{uuid.uuid4().hex}")
        temporary.write_bytes(data)
        temporary.replace(target)

    def get(self, key: str) -> bytes:
        try:
            return self._target(key).read_bytes()
        except FileNotFoundError as exc:
            raise FileNotFoundError("Media object is missing from storage.") from exc

    def delete(self, key: str) -> None:
        self._target(key).unlink(missing_ok=True)

    def _target(self, key: str) -> Path:
        candidate = (self.root / key).resolve()
        if self.root not in candidate.parents or key.startswith(("/", "\\")):
            raise ValueError("Media object key escapes the storage root.")
        return candidate


class RecoverableMediaError(RuntimeError):
    def __init__(self, message: str, *, draft: ContentItem) -> None:
        super().__init__(message)
        self.draft = draft


class PublishingService:
    def __init__(
        self,
        store: Store,
        config: SpaceConfig,
        storage: ObjectStorage,
        image_normalizer: ImageNormalizer | None = None,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.config = config
        self.storage = storage
        self.image_normalizer = image_normalizer
        self._now = now or (lambda: datetime.now(UTC))

    def create(
        self,
        *,
        kind: str,
        state: str,
        title: str,
        source: str,
        tags: str | Sequence[str] = (),
        external_url: str | None = None,
        image_bytes: bytes | None = None,
        alt_text: str = "",
    ) -> ContentItem:
        owner = self._owner()
        normalized = self._validated_fields(
            kind=kind,
            state=state,
            title=title,
            source=source,
            tags=tags,
            external_url=external_url,
            media_present=image_bytes is not None,
            alt_text=alt_text,
        )
        now = self._now()
        item_id = str(uuid.uuid7())
        media: MediaAsset | None = None
        if image_bytes is not None:
            try:
                media = self._save_image(image_bytes, alt_text=normalized[4])
            except (OSError, RuntimeError, ValueError) as exc:
                draft = ContentItem(
                    item_id,
                    owner.id,
                    kind,
                    "draft",
                    normalized[0],
                    normalized[1],
                    normalized[2],
                    None,
                    normalized[3],
                    1,
                    now,
                    now,
                    None,
                    None,
                )
                self.store.create_content(draft)
                raise RecoverableMediaError(
                    f"Photo upload failed; recoverable draft {draft.id} was saved.", draft=draft
                ) from exc
        published_at = now if state == "public" else None
        item = ContentItem(
            item_id,
            owner.id,
            kind,
            state,
            normalized[0],
            normalized[1],
            normalized[2],
            media,
            normalized[3],
            1,
            now,
            now,
            published_at,
            None,
        )
        try:
            return self.store.create_content(item)
        except OSError, RuntimeError, ValueError:
            if media is not None:
                try:
                    self.store.update_media_status(media.id, "cleanup-pending")
                    self.storage.delete(media.object_key)
                    self.store.update_media_status(media.id, "deleted")
                except (OSError, RuntimeError) as cleanup_error:
                    raise RuntimeError(
                        "Content save failed and uploaded media cleanup also failed."
                    ) from cleanup_error
            raise

    def preview(
        self,
        *,
        kind: str,
        state: str,
        title: str,
        source: str,
        tags: str | Sequence[str] = (),
        external_url: str | None = None,
        image_bytes: bytes | None = None,
        alt_text: str = "",
    ) -> ContentItem:
        """Validate an owner preview without writing content or objects."""
        owner = self._owner()
        normalized = self._validated_fields(
            kind=kind,
            state=state,
            title=title,
            source=source,
            tags=tags,
            external_url=external_url,
            media_present=image_bytes is not None,
            alt_text=alt_text,
        )
        now = self._now()
        media = None
        if image_bytes is not None:
            image = self._normalize_image(image_bytes)
            media = MediaAsset(
                str(uuid.uuid7()),
                "",
                image.media_type,
                image.width,
                image.height,
                len(image.data),
                hashlib.sha256(image.data).hexdigest(),
                normalized[4],
                "ready",
                now,
                tuple(
                    MediaVariant(
                        variant.name,
                        "",
                        variant.media_type,
                        variant.width,
                        variant.height,
                        len(variant.data),
                        hashlib.sha256(variant.data).hexdigest(),
                    )
                    for variant in image.variants
                ),
            )
        return ContentItem(
            str(uuid.uuid7()),
            owner.id,
            kind,
            state,
            normalized[0],
            normalized[1],
            normalized[2],
            media,
            normalized[3],
            1,
            now,
            now,
            now if state == "public" else None,
            None,
        )

    def update(
        self,
        item_id: str,
        *,
        expected_revision: int,
        state: str,
        title: str,
        source: str,
        tags: str | Sequence[str],
        external_url: str | None = None,
        alt_text: str = "",
        image_bytes: bytes | None = None,
    ) -> ContentItem:
        current = self._required(item_id)
        media = current.media
        if image_bytes is not None:
            media = self._save_image(image_bytes, alt_text=alt_text)
        normalized = self._validated_fields(
            kind=current.kind,
            state=state,
            title=title,
            source=source,
            tags=tags,
            external_url=external_url,
            media_present=media is not None,
            alt_text=alt_text,
        )
        now = self._now()
        published_at = current.published_at
        if state == "public" and published_at is None:
            published_at = now
        updated = replace(
            current,
            state=state,
            title=normalized[0],
            source=normalized[1],
            external_url=normalized[2],
            tags=normalized[3],
            revision=expected_revision + 1,
            updated_at=now,
            published_at=published_at,
            media=(replace(media, alt_text=normalized[4]) if media else None),
        )
        try:
            result = self.store.update_content(updated, expected_revision=expected_revision)
        except OSError, RuntimeError, ValueError:
            if media is not None and media is not current.media:
                self._discard_media(media)
            raise
        if current.media is not None and media is not current.media:
            self._discard_media(current.media)
        return result

    def delete(self, item_id: str, *, expected_revision: int) -> ContentItem:
        current = self._required(item_id)
        now = self._now()
        tombstone = replace(
            current,
            state="deleted",
            title="",
            source="",
            external_url=None,
            tags=(),
            revision=expected_revision + 1,
            updated_at=now,
            deleted_at=now,
        )
        result = self.store.update_content(tombstone, expected_revision=expected_revision)
        if current.media is not None:
            try:
                self._discard_media(current.media)
            except OSError:
                return result
        return result

    def get(self, item_id: str, *, owner: bool = False) -> ContentItem | None:
        item = self.store.content_item(item_id)
        if item is None or (not owner and item.state not in {"public", "deleted"}):
            return None
        return item

    def list_public(
        self,
        *,
        cursor: str | None = None,
        kind: str | None = None,
        tag: str | None = None,
        year: int | None = None,
        month: int | None = None,
        query: str | None = None,
        limit: int = 20,
    ) -> tuple[tuple[ContentItem, ...], str | None]:
        if kind is not None and kind not in ALLOWED_KINDS:
            raise ValueError("Content kind filter is invalid.")
        if year is not None and not 2000 <= year <= 9999:
            raise ValueError("Archive year is invalid.")
        if month is not None and not 1 <= month <= 12:
            raise ValueError("Archive month is invalid.")
        if not 1 <= limit <= 50:
            raise ValueError("Page size must be between 1 and 50.")
        before = self._decode_cursor(cursor) if cursor else None
        normalized_query = _plain(query or "", "Search", 100, required=False) or None
        items = self.store.content_items(
            public_only=True,
            limit=limit + 1,
            before=before,
            kind=kind,
            tag=_tag(tag) if tag else None,
            year=year,
            month=month,
            query=normalized_query,
        )
        page = items[:limit]
        next_cursor = self._encode_cursor(page[-1]) if len(items) > limit and page else None
        return page, next_cursor

    def owner_items(self) -> tuple[ContentItem, ...]:
        return self.store.content_items(public_only=False, limit=100)

    def archive(self) -> tuple[tuple[int, int, int], ...]:
        return self.store.content_archive()

    def tag_counts(self) -> tuple[tuple[str, int], ...]:
        return self.store.tag_counts()

    def media_bytes(self, asset: MediaAsset, *, variant: str | None = None) -> bytes:
        if asset.status != "ready":
            raise FileNotFoundError("Media asset is not ready.")
        selected = next((item for item in asset.variants if item.name == variant), None)
        if variant is not None and selected is None:
            raise FileNotFoundError("Media variant does not exist.")
        object_key = selected.object_key if selected else asset.object_key
        checksum = selected.checksum if selected else asset.checksum
        try:
            data = self.storage.get(object_key)
        except FileNotFoundError:
            self.store.update_media_status(asset.id, "missing")
            raise
        if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), checksum):
            self.store.update_media_status(asset.id, "missing")
            raise FileNotFoundError("Media asset checksum does not match storage.")
        return data

    def retry_media_cleanup(self, *, limit: int = 100) -> tuple[int, int]:
        """Retry bounded object deletion and return (deleted, failed)."""
        deleted = 0
        failed = 0
        for media in self.store.media_by_status("cleanup-pending", limit=limit):
            try:
                self._delete_untracked_objects(
                    [media.object_key, *(variant.object_key for variant in media.variants)]
                )
            except OSError:
                failed += 1
                continue
            self.store.update_media_status(media.id, "deleted")
            deleted += 1
        return deleted, failed

    def _save_image(self, data: bytes, *, alt_text: str) -> MediaAsset:
        result = self._normalize_image(data)
        asset_id = str(uuid.uuid7())
        object_root = f"media/{uuid.uuid4().hex}/{asset_id}"
        object_key = f"{object_root}-full.{result.extension}"
        planned = (
            (object_key, result.data, result.media_type),
            *(
                (
                    f"{object_root}-{variant.name}.{variant.extension}",
                    variant.data,
                    variant.media_type,
                )
                for variant in result.variants
            ),
        )
        written: list[str] = []
        try:
            for key, output, media_type in planned:
                self.storage.put(key, output, content_type=media_type)
                written.append(key)
        except OSError:
            self._delete_untracked_objects(written)
            raise
        variants = tuple(
            MediaVariant(
                variant.name,
                key,
                variant.media_type,
                variant.width,
                variant.height,
                len(variant.data),
                hashlib.sha256(variant.data).hexdigest(),
            )
            for variant, (key, _output, _media_type) in zip(
                result.variants, planned[1:], strict=True
            )
        )
        asset = MediaAsset(
            asset_id,
            object_key,
            result.media_type,
            result.width,
            result.height,
            len(result.data),
            hashlib.sha256(result.data).hexdigest(),
            alt_text,
            "ready",
            self._now(),
            variants,
        )
        try:
            self.store.save_media(asset)
        except OSError, RuntimeError, ValueError:
            try:
                self._delete_untracked_objects([key for key, _data, _type in planned])
            except OSError as cleanup_error:
                raise RuntimeError(
                    "Media metadata failed and temporary object cleanup also failed."
                ) from cleanup_error
            raise
        return asset

    def _normalize_image(self, data: bytes) -> NormalizedImage:
        if not data or len(data) > MAX_UPLOAD_BYTES:
            raise ValueError("Photo must be between 1 byte and 10 MiB.")
        if self.image_normalizer is None:
            raise RuntimeError("Photo processing is unavailable in this deployment.")
        result = self.image_normalizer.normalize(data)
        if result.media_type not in {"image/jpeg", "image/png", "image/webp"}:
            raise ValueError("Photo must be JPEG, PNG, or WebP.")
        if result.extension not in {"jpg", "png", "webp"}:
            raise ValueError("Photo processor returned an unsupported file extension.")
        if not (1 <= result.width <= MAX_IMAGE_DIMENSION) or not (
            1 <= result.height <= MAX_IMAGE_DIMENSION
        ):
            raise ValueError("Photo dimensions cannot exceed 4096 x 4096.")
        if not result.data or len(result.data) > MAX_UPLOAD_BYTES:
            raise ValueError("Normalized photo exceeds 10 MiB.")
        names = tuple(variant.name for variant in result.variants)
        if len(names) != len(set(names)) or any(name not in {"small", "medium"} for name in names):
            raise ValueError("Photo processor returned invalid responsive variant names.")
        for variant in result.variants:
            if variant.media_type not in {"image/jpeg", "image/png", "image/webp"}:
                raise ValueError("Photo variant has an unsupported media type.")
            if variant.extension not in {"jpg", "png", "webp"}:
                raise ValueError("Photo variant has an unsupported file extension.")
            if not variant.data or len(variant.data) > MAX_UPLOAD_BYTES:
                raise ValueError("Photo variant exceeds 10 MiB.")
            if not (1 <= variant.width <= result.width) or not (
                1 <= variant.height <= result.height
            ):
                raise ValueError("Photo variant dimensions exceed the full image.")
        return result

    def _discard_media(self, media: MediaAsset) -> None:
        self.store.update_media_status(media.id, "cleanup-pending")
        self._delete_untracked_objects(
            [media.object_key, *(variant.object_key for variant in media.variants)]
        )
        self.store.update_media_status(media.id, "deleted")

    def _delete_untracked_objects(self, keys: Sequence[str]) -> None:
        failures = 0
        for key in keys:
            try:
                self.storage.delete(key)
            except OSError:
                failures += 1
        if failures:
            raise OSError(f"Media object cleanup failed for {failures} object(s).")

    def _validated_fields(
        self,
        *,
        kind: str,
        state: str,
        title: str,
        source: str,
        tags: str | Sequence[str],
        external_url: str | None,
        media_present: bool,
        alt_text: str,
    ) -> tuple[str, str, str | None, tuple[str, ...], str]:
        if kind not in ALLOWED_KINDS or state not in ALLOWED_STATES:
            raise ValueError("Content kind or lifecycle state is invalid.")
        normalized_title = _plain(title, "Title", 200, required=kind in {"journal", "link"})
        maximum = 100_000 if kind == "journal" else 2_000 if kind == "photo" else 1_000
        normalized_source = _plain(source, "Content", maximum, required=kind != "photo")
        if kind == "photo" and not media_present:
            raise ValueError("Photo content requires a normalized image.")
        if kind != "photo" and media_present:
            raise ValueError("Only photo content may include an image upload.")
        normalized_alt = _plain(alt_text, "Photo alt text", 500, required=kind == "photo")
        normalized_url = _https_url(external_url, "Link URL") if kind == "link" else None
        normalized_tags = _tags(tags)
        return (
            normalized_title,
            normalized_source,
            normalized_url,
            normalized_tags,
            normalized_alt,
        )

    def _owner(self) -> Owner:
        state = self.store.state()
        if state is None:
            raise RuntimeError("Space setup is incomplete.")
        return state.owner

    def _required(self, item_id: str) -> ContentItem:
        item = self.store.content_item(item_id)
        if item is None or item.state == "deleted":
            raise ValueError("Content item was not found or is deleted.")
        return item

    def _encode_cursor(self, item: ContentItem) -> str:
        timestamp = item.published_at or item.updated_at
        payload = f"{timestamp.isoformat()}|{item.id}".encode()
        signature = hmac.new(self.config.secret_key.encode(), payload, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(payload + b"." + signature).decode().rstrip("=")

    def _decode_cursor(self, cursor: str) -> tuple[datetime, str]:
        try:
            padded = cursor + "=" * (-len(cursor) % 4)
            value = base64.urlsafe_b64decode(padded)
            payload, signature = value.rsplit(b".", 1)
            expected = hmac.new(self.config.secret_key.encode(), payload, hashlib.sha256).digest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError
            timestamp, item_id = payload.decode().split("|", 1)
            return datetime.fromisoformat(timestamp).astimezone(UTC), str(uuid.UUID(item_id))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("Archive cursor is invalid or expired.") from exc


class GuestbookService:
    def __init__(
        self,
        store: Store,
        config: SpaceConfig,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.config = config
        self._now = now or (lambda: datetime.now(UTC))

    def submit(
        self,
        *,
        display_name: str,
        message: str,
        website_url: str | None,
        client_key: str,
        honeypot: str = "",
    ) -> GuestbookEntry:
        if honeypot:
            raise ValueError("Guestbook submission was rejected.")
        name = _plain(display_name, "Display name", 80, required=True)
        body = _plain(message, "Guestbook message", 2_000, required=True)
        website = _https_url(website_url, "Guestbook website") if website_url else None
        now = self._now()
        abuse_token = hmac.new(
            self.config.secret_key.encode(), client_key.encode(), hashlib.sha256
        ).hexdigest()[:32]
        submission_hash = hmac.new(
            self.config.secret_key.encode(),
            "\x1f".join((client_key, name, body, website or "")).encode(),
            hashlib.sha256,
        ).hexdigest()
        entry = GuestbookEntry(
            str(uuid.uuid7()),
            name,
            body,
            website,
            "pending",
            abuse_token,
            submission_hash,
            now,
            None,
        )
        result = self.store.create_guestbook_entry(entry, since=now - timedelta(hours=1), limit=3)
        if result == "duplicate":
            raise ValueError("This guestbook submission was already received.")
        if result == "limited":
            raise PermissionError("Guestbook submission limit reached. Try again later.")
        return entry

    def moderate(self, entry_id: str, action: str) -> GuestbookEntry:
        if action not in {"approved", "rejected", "deleted"}:
            raise ValueError("Guestbook moderation action is invalid.")
        return self.store.moderate_guestbook(entry_id, status=action, moderated_at=self._now())


def render_markdown(source: str) -> tuple[MarkdownBlock, ...]:
    """Parse a tiny Markdown subset into template-safe structured values."""
    blocks: list[MarkdownBlock] = []
    for raw_block in re.split(r"\n\s*\n", source.strip()):
        lines = raw_block.splitlines()
        if not lines:
            continue
        if all(line.startswith("- ") for line in lines):
            blocks.append(MarkdownBlock("list", tuple(_inline(line[2:]) for line in lines)))
        elif lines[0].startswith("# "):
            blocks.append(MarkdownBlock("heading", (_inline(lines[0][2:]),)))
            if len(lines) > 1:
                blocks.append(
                    MarkdownBlock("paragraph", tuple(_inline(line) for line in lines[1:]))
                )
        else:
            blocks.append(MarkdownBlock("paragraph", tuple(_inline(line) for line in lines)))
    return tuple(blocks)


def present_content(item: ContentItem) -> ContentPresentation:
    return ContentPresentation(item, content_path(item), render_markdown(item.source))


def content_path(item: ContentItem) -> str:
    prefix = {
        "short": "posts",
        "journal": "journal",
        "photo": "photos",
        "link": "links",
    }.get(item.kind)
    if prefix is None:
        raise ValueError("Content kind has no public permalink.")
    return f"/{prefix}/{item.id}"


def _inline(value: str) -> tuple[MarkdownInline, ...]:
    output: list[MarkdownInline] = []
    position = 0
    for match in LINK_RE.finditer(value):
        if match.start() > position:
            output.append(MarkdownInline(value[position : match.start()]))
        output.append(MarkdownInline(match.group(1), _https_url(match.group(2), "Markdown link")))
        position = match.end()
    if position < len(value) or not output:
        output.append(MarkdownInline(value[position:]))
    return tuple(output)


def _plain(value: str, field: str, limit: int, *, required: bool) -> str:
    normalized = value.strip()
    if required and not normalized:
        raise ValueError(f"{field} is required.")
    if len(normalized) > limit or any(
        ord(character) < 32 and character not in {"\n", "\t"} for character in normalized
    ):
        raise ValueError(f"{field} exceeds its safe text limit.")
    return normalized


def _https_url(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    candidate = value.strip()
    parsed = urlsplit(candidate)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or any(ord(character) < 32 for character in candidate)
        or len(candidate) > 2_048
    ):
        raise ValueError(f"{field} must be a bounded HTTPS URL without credentials.")
    return candidate


def _tags(value: str | Sequence[str]) -> tuple[str, ...]:
    raw = value.split(",") if isinstance(value, str) else value
    tags = tuple(dict.fromkeys(_tag(item) for item in raw if item.strip()))
    if len(tags) > 8:
        raise ValueError("Content supports at most eight tags.")
    return tags


def _tag(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().casefold()).strip("-")
    if not TAG_RE.fullmatch(normalized):
        raise ValueError("Tag must normalize to 1 to 40 letters, numbers, or hyphens.")
    return normalized
