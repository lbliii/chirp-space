"""Versioned Space export, restore, key rotation, domain migration, and deletion."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import secrets
import zipfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from chirp.security.passwords import verify_login

from chirp_space.config import SpaceConfig, normalize_origin
from chirp_space.content import ObjectStorage
from chirp_space.federation import FederationService
from chirp_space.models import (
    Circle,
    ContentItem,
    FederationKey,
    GuestbookEntry,
    MediaAsset,
    MediaVariant,
    Owner,
    ProfileModule,
    Relationship,
    RemoteActor,
    SiteSettings,
    SiteState,
    SpaceDataSnapshot,
    Theme,
)
from chirp_space.relationships import RelationshipService
from chirp_space.store import Store

ENVELOPE_FORMAT = "chirp-space-export"
ENVELOPE_VERSION = 1
SUPPORTED_ENVELOPE_VERSIONS = frozenset({1})
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_MANIFEST_BYTES = 1 * 1024 * 1024
MAX_SPACE_JSON_BYTES = 20 * 1024 * 1024
MAX_MEDIA_OBJECTS = 10_000
DELETE_CONFIRMATION = "DELETE THIS SPACE"
RESTORE_CONFIRMATION = "REPLACE LOCAL SPACE"
MIGRATE_CONFIRMATION = "MIGRATE CANONICAL ORIGIN"
ROTATE_CONFIRMATION = "ROTATE SIGNING KEY"
RETENTION_DISCLOSURE = (
    "Local deletion removes this deployment's database rows and media objects. "
    "Remote Delete delivery is best-effort for supported Undo/Follow cleanup only. "
    "Account-level Delete and Move are outside federation contract v1. "
    "Independent remote servers may retain copies, caches, and deliveries indefinitely."
)


class LifecycleError(ValueError):
    """Fail-closed lifecycle validation or safety error."""


@dataclass(frozen=True, slots=True)
class MediaObjectRef:
    object_key: str
    media_type: str
    byte_size: int
    checksum: str
    missing: bool = False


@dataclass(frozen=True, slots=True)
class ImportPreview:
    envelope_version: int
    site_id: str
    owner_id: str
    handle: str
    canonical_origin: str
    content_count: int
    media_count: int
    relationship_count: int
    guestbook_count: int
    media_missing: tuple[str, ...]
    conflicts: tuple[str, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DeletionReport:
    local_purged: bool
    remote_undos_enqueued: int
    remote_delivery_attempted: bool
    retention_disclosure: str
    notes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DomainMigrationResult:
    previous_origin: str
    new_origin: str
    federation_identity_broken: bool
    notes: tuple[str, ...]


class SpaceLifecycleService:
    """Owner lifecycle operations with explicit confirmations and fail-closed safety."""

    def __init__(
        self,
        store: Store,
        config: SpaceConfig,
        storage: ObjectStorage,
        *,
        federation: FederationService | None = None,
        relationships: RelationshipService | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.config = config
        self.storage = storage
        self.federation = federation
        self.relationships = relationships
        self._now = now or (lambda: datetime.now(UTC))

    def build_snapshot(self) -> SpaceDataSnapshot:
        state = self._require_state()
        return SpaceDataSnapshot(
            owner=state.owner,
            settings=state.settings,
            modules=state.modules,
            recovery_code_hashes=self.store.unused_recovery_code_hashes(state.owner.id),
            federation_keys=self.store.federation_keys(),
            relationships=self.store.relationships(),
            circles=self.store.circles(),
            blocked_domains=self.store.blocked_domains(),
            content_items=self.store.export_content_items(),
            media_assets=self.store.export_media_assets(),
            guestbook_entries=self.store.guestbook_entries(public_only=False),
        )

    def export_archive(self) -> bytes:
        snapshot = self.build_snapshot()
        media_refs, media_blobs = self._collect_media(snapshot.media_assets)
        payload = _snapshot_to_json(snapshot, media_refs)
        space_json = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode()
        if len(space_json) > MAX_SPACE_JSON_BYTES:
            raise LifecycleError("Export payload exceeds the bounded space.json size limit.")
        if len(media_blobs) > MAX_MEDIA_OBJECTS:
            raise LifecycleError("Export contains too many media objects.")
        manifest = {
            "format": ENVELOPE_FORMAT,
            "envelope_version": ENVELOPE_VERSION,
            "exported_at": self._now().astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "site_id": snapshot.settings.id,
            "owner_id": snapshot.owner.id,
            "canonical_origin": snapshot.settings.canonical_origin,
            "counts": {
                "content": len(snapshot.content_items),
                "media_assets": len(snapshot.media_assets),
                "media_objects": len(media_blobs),
                "relationships": len(snapshot.relationships),
                "guestbook": len(snapshot.guestbook_entries),
                "federation_keys": len(snapshot.federation_keys),
            },
            "space_sha256": hashlib.sha256(space_json).hexdigest(),
            "media": [
                {
                    "object_key": key,
                    "sha256": hashlib.sha256(blob).hexdigest(),
                    "byte_size": len(blob),
                }
                for key, blob in sorted(media_blobs.items())
            ],
            "security": {
                "contains_password_hash": True,
                "contains_recovery_code_hashes": True,
                "contains_encrypted_private_keys": any(
                    key.encrypted_private_pem for key in snapshot.federation_keys
                ),
                "plaintext_private_keys": False,
                "key_encryption_secret_required_for_restore": True,
            },
            "retention_disclosure": RETENTION_DISCLOSURE,
        }
        manifest_json = json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2).encode()
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", manifest_json)
            archive.writestr("space.json", space_json)
            for key, blob in sorted(media_blobs.items()):
                archive.writestr(f"media/{key}", blob)
        data = buffer.getvalue()
        if len(data) > MAX_ARCHIVE_BYTES:
            raise LifecycleError("Export archive exceeds the 100 MiB envelope limit.")
        return data

    def preview_import(self, archive: bytes) -> ImportPreview:
        snapshot, media_blobs, warnings = self._parse_archive(archive)
        conflicts: list[str] = []
        current = self.store.state()
        if current is not None:
            if current.settings.id != snapshot.settings.id:
                conflicts.append(
                    "Local site ID differs from the archive; restore will replace this Space."
                )
            if current.owner.id != snapshot.owner.id:
                conflicts.append(
                    "Local owner ID differs from the archive; restore will replace this owner."
                )
            if current.settings.canonical_origin != snapshot.settings.canonical_origin:
                conflicts.append(
                    "Canonical origin differs; after restore align SPACE_CANONICAL_ORIGIN "
                    "or run domain migration."
                )
        missing = tuple(
            ref.object_key
            for ref in _media_refs_from_snapshot_payload(_snapshot_to_json(snapshot, ()))
            if ref.object_key not in media_blobs and not ref.missing
        )
        # Prefer missing flags recorded in the archive payload.
        payload_missing = tuple(
            item["object_key"]
            for item in _snapshot_to_json(snapshot, ())["media_manifest"]
            if item.get("missing")
        )
        media_missing = tuple(sorted(set(missing) | set(payload_missing)))
        if media_missing:
            warnings = (
                *warnings,
                "Archive references media objects that are absent or marked missing.",
            )
        return ImportPreview(
            envelope_version=ENVELOPE_VERSION,
            site_id=snapshot.settings.id,
            owner_id=snapshot.owner.id,
            handle=snapshot.owner.handle,
            canonical_origin=snapshot.settings.canonical_origin,
            content_count=len(snapshot.content_items),
            media_count=len(snapshot.media_assets),
            relationship_count=len(snapshot.relationships),
            guestbook_count=len(snapshot.guestbook_entries),
            media_missing=media_missing,
            conflicts=tuple(conflicts),
            warnings=warnings,
        )

    def restore_archive(
        self,
        archive: bytes,
        *,
        confirmation: str,
        owner: Owner | None,
        password: str = "",
        claim_token: str = "",
    ) -> ImportPreview:
        if confirmation.strip() != RESTORE_CONFIRMATION:
            raise LifecycleError(f'Type "{RESTORE_CONFIRMATION}" to confirm restore.')
        current = self.store.state()
        if current is None:
            self._require_claim_token(claim_token)
        else:
            self._require_owner_password(owner, password)
        preview = self.preview_import(archive)
        snapshot, media_blobs, _warnings = self._parse_archive(archive)
        self._assert_keys_decryptable(snapshot.federation_keys)
        # Stage media to temporary keys only after validation; write after DB commit would
        # leave orphans on DB failure, so write media first then restore DB, rolling media
        # back on failure when possible.
        written: list[str] = []
        try:
            for key, blob in media_blobs.items():
                self.storage.put(key, blob, content_type="application/octet-stream")
                written.append(key)
            self.store.replace_lifecycle_snapshot(snapshot)
        except Exception:
            for key in written:
                with contextlib.suppress(Exception):
                    self.storage.delete(key)
            raise
        return preview

    def rotate_signing_key(
        self,
        *,
        confirmation: str,
        owner: Owner | None,
        password: str,
    ) -> FederationKey:
        if confirmation.strip() != ROTATE_CONFIRMATION:
            raise LifecycleError(f'Type "{ROTATE_CONFIRMATION}" to confirm key rotation.')
        self._require_owner_password(owner, password)
        if self.federation is None:
            raise LifecycleError("Federation service is required for signing-key rotation.")
        return self.federation.rotate_key()

    def migrate_canonical_origin(
        self,
        *,
        confirmation: str,
        owner: Owner | None,
        password: str,
        acknowledge_federation_break: bool,
    ) -> DomainMigrationResult:
        if confirmation.strip() != MIGRATE_CONFIRMATION:
            raise LifecycleError(f'Type "{MIGRATE_CONFIRMATION}" to confirm domain migration.')
        self._require_owner_password(owner, password)
        state = self._require_state()
        target = self.config.canonical_origin
        if state.settings.canonical_origin == target:
            raise LifecycleError(
                "site_settings.canonical_origin already matches SPACE_CANONICAL_ORIGIN."
            )
        notes: list[str] = []
        has_federation_state = bool(
            self.store.federation_keys()
            or self.store.relationships()
            or self.config.federation_enabled
        )
        federation_break = False
        if has_federation_state:
            if not acknowledge_federation_break:
                raise LifecycleError(
                    "Domain migration with federation state requires acknowledging that "
                    "Move is outside federation contract v1 and actor IDs at the previous "
                    "origin will not migrate."
                )
            federation_break = True
            notes.append(
                "Federation identity continuity is not preserved; Move is outside contract v1."
            )
            if self.federation is not None:
                control = self.store.federation_control()
                self.store.update_federation_control(
                    replace(
                        control,
                        inbound_paused=True,
                        outbound_paused=True,
                        reason="canonical-origin migration; Move unsupported in federation v1",
                        revision=control.revision + 1,
                        updated_at=self._now(),
                    ),
                    expected_revision=control.revision,
                )
                notes.append("Inbound and outbound federation paused for operator recovery.")
        previous = state.settings.canonical_origin
        updated = self.store.update_canonical_origin(
            target, expected_revision=state.settings.revision, now=self._now()
        )
        notes.append(
            "Local canonical origin updated. Keep SPACE_HOST_ALIASES pointing at the previous "
            "host only when you intentionally accept dual-host traffic."
        )
        return DomainMigrationResult(
            previous_origin=previous,
            new_origin=updated.canonical_origin,
            federation_identity_broken=federation_break,
            notes=tuple(notes),
        )

    def delete_space(
        self,
        *,
        confirmation: str,
        owner: Owner | None,
        password: str,
        attempt_remote: bool = True,
    ) -> DeletionReport:
        if confirmation.strip() != DELETE_CONFIRMATION:
            raise LifecycleError(f'Type "{DELETE_CONFIRMATION}" to confirm permanent deletion.')
        self._require_owner_password(owner, password)
        state = self._require_state()
        notes: list[str] = []
        remote_enqueued = 0
        remote_attempted = False
        notes.append(
            "No account-level Delete activity is sent; that surface is outside federation v1."
        )
        if attempt_remote and self.config.federation_enabled and self.relationships is not None:
            remote_attempted = True
            for relationship in self.store.relationships():
                if relationship.outbound_state in {"pending", "following"}:
                    try:
                        self.relationships.unfollow(relationship.actor.id)
                        remote_enqueued += 1
                    except Exception as exc:
                        notes.append(
                            f"Best-effort Undo Follow failed for {relationship.actor.id}: {exc}"
                        )
        elif attempt_remote and not self.config.federation_enabled:
            notes.append("Federation is disabled; no remote Delete/Undo delivery was attempted.")
        elif attempt_remote and self.relationships is None:
            notes.append(
                "Remote Undo delivery was skipped because relationship service wiring is absent."
            )

        media_keys = tuple(_media_keys(self.store.export_media_assets()))
        self.store.purge_lifecycle_data()
        for key in media_keys:
            try:
                self.storage.delete(key)
            except Exception as exc:
                notes.append(f"Media object cleanup failed for {key}: {exc}")
        if self.store.state() is not None:
            raise LifecycleError("Local purge did not clear owner state.")
        notes.append(f"Owner {state.owner.id} and site {state.settings.id} purged locally.")
        return DeletionReport(
            local_purged=True,
            remote_undos_enqueued=remote_enqueued,
            remote_delivery_attempted=remote_attempted,
            retention_disclosure=RETENTION_DISCLOSURE,
            notes=tuple(notes),
        )

    def _collect_media(
        self, assets: Sequence[MediaAsset]
    ) -> tuple[tuple[MediaObjectRef, ...], dict[str, bytes]]:
        refs: list[MediaObjectRef] = []
        blobs: dict[str, bytes] = {}
        for asset in assets:
            for key, media_type, byte_size, checksum in _asset_object_rows(asset):
                try:
                    data = self.storage.get(key)
                except FileNotFoundError:
                    refs.append(
                        MediaObjectRef(
                            object_key=key,
                            media_type=media_type,
                            byte_size=byte_size,
                            checksum=checksum,
                            missing=True,
                        )
                    )
                    continue
                digest = hashlib.sha256(data).hexdigest()
                if digest != checksum:
                    raise LifecycleError(f"Media object {key} checksum mismatch during export.")
                if len(data) != byte_size:
                    raise LifecycleError(f"Media object {key} size mismatch during export.")
                blobs[key] = data
                refs.append(
                    MediaObjectRef(
                        object_key=key,
                        media_type=media_type,
                        byte_size=byte_size,
                        checksum=checksum,
                        missing=False,
                    )
                )
        return tuple(refs), blobs

    def _parse_archive(
        self, archive: bytes
    ) -> tuple[SpaceDataSnapshot, dict[str, bytes], tuple[str, ...]]:
        if len(archive) > MAX_ARCHIVE_BYTES:
            raise LifecycleError("Archive exceeds the 100 MiB envelope limit.")
        if len(archive) < 4 or archive[:2] != b"PK":
            raise LifecycleError("Archive is not a valid Chirp Space export ZIP.")
        warnings: list[str] = []
        try:
            with zipfile.ZipFile(io.BytesIO(archive)) as zf:
                names = set(zf.namelist())
                if "manifest.json" not in names or "space.json" not in names:
                    raise LifecycleError("Archive is missing manifest.json or space.json.")
                for name in names:
                    if name.endswith("/") or name in {"manifest.json", "space.json"}:
                        continue
                    if not name.startswith("media/") or name == "media/":
                        raise LifecycleError(f"Archive contains unexpected member {name!r}.")
                    if ".." in name or name.startswith(("media/../", "/")):
                        raise LifecycleError("Archive media path escapes the media/ prefix.")
                manifest_raw = zf.read("manifest.json")
                space_raw = zf.read("space.json")
                if len(manifest_raw) > MAX_MANIFEST_BYTES:
                    raise LifecycleError("manifest.json exceeds the size bound.")
                if len(space_raw) > MAX_SPACE_JSON_BYTES:
                    raise LifecycleError("space.json exceeds the size bound.")
                try:
                    manifest = json.loads(manifest_raw.decode())
                    payload = json.loads(space_raw.decode())
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise LifecycleError("Archive JSON is corrupt or not UTF-8.") from exc
                if not isinstance(manifest, dict) or not isinstance(payload, dict):
                    raise LifecycleError("Archive JSON roots must be objects.")
                _validate_manifest(manifest, space_raw)
                snapshot = _snapshot_from_json(payload)
                media_blobs: dict[str, bytes] = {}
                media_entries = manifest.get("media")
                if not isinstance(media_entries, list):
                    raise LifecycleError("manifest.media must be a list.")
                if len(media_entries) > MAX_MEDIA_OBJECTS:
                    raise LifecycleError("Archive declares too many media objects.")
                for entry in media_entries:
                    if not isinstance(entry, dict):
                        raise LifecycleError("manifest.media entries must be objects.")
                    key = str(entry.get("object_key", ""))
                    expected = str(entry.get("sha256", ""))
                    size = int(entry.get("byte_size", -1))
                    member = f"media/{key}"
                    if member not in names:
                        raise LifecycleError(f"Missing media member for {key}.")
                    blob = zf.read(member)
                    if len(blob) != size or hashlib.sha256(blob).hexdigest() != expected:
                        raise LifecycleError(f"Media member {key} failed integrity checks.")
                    media_blobs[key] = blob
                for name in names:
                    if name.startswith("media/") and not name.endswith("/"):
                        key = name.removeprefix("media/")
                        if key and key not in media_blobs:
                            raise LifecycleError(f"Archive includes undeclared media member {key}.")
        except zipfile.BadZipFile as exc:
            raise LifecycleError("Archive is not a valid ZIP file.") from exc
        if snapshot.settings.canonical_origin != self.config.canonical_origin:
            warnings.append(
                "Archive canonical origin differs from this deployment's "
                "SPACE_CANONICAL_ORIGIN; migrate after restore if intentional."
            )
        return snapshot, media_blobs, tuple(warnings)

    def _assert_keys_decryptable(self, keys: Sequence[FederationKey]) -> None:
        if self.federation is None:
            if keys:
                raise LifecycleError(
                    "Encrypted federation keys cannot be validated without FederationService."
                )
            return
        for key in keys:
            try:
                self.federation._private_key(key)
            except Exception as exc:
                raise LifecycleError(
                    "Encrypted federation private keys do not decrypt with this deployment's "
                    "SPACE_KEY_ENCRYPTION_KEY. Restore refused."
                ) from exc

    def _require_state(self) -> SiteState:
        state = self.store.state()
        if state is None:
            raise LifecycleError("Space setup is incomplete.")
        return state

    def _require_owner_password(self, owner: Owner | None, password: str) -> Owner:
        state = self._require_state()
        if owner is None or owner.id != state.owner.id:
            raise PermissionError("Owner sign-in is required.")
        if not verify_login(password, state.owner.password_hash):
            raise PermissionError("Password confirmation failed.")
        return state.owner

    def _require_claim_token(self, claim_token: str) -> None:
        if not secrets.compare_digest(claim_token, self.config.claim_token):
            raise PermissionError("The owner claim token is not valid.")


def _validate_manifest(manifest: Mapping[str, Any], space_raw: bytes) -> None:
    if manifest.get("format") != ENVELOPE_FORMAT:
        raise LifecycleError("Archive format is not chirp-space-export.")
    version = manifest.get("envelope_version")
    if not isinstance(version, int) or version not in SUPPORTED_ENVELOPE_VERSIONS:
        raise LifecycleError("Unsupported or missing envelope_version.")
    digest = manifest.get("space_sha256")
    if not isinstance(digest, str) or hashlib.sha256(space_raw).hexdigest() != digest:
        raise LifecycleError("space.json failed manifest integrity check.")
    security = manifest.get("security")
    if not isinstance(security, dict):
        raise LifecycleError("manifest.security is required.")
    if security.get("plaintext_private_keys") is True:
        raise LifecycleError("Archives that claim plaintext private keys are rejected.")


def _snapshot_to_json(
    snapshot: SpaceDataSnapshot, media_refs: Sequence[MediaObjectRef]
) -> dict[str, Any]:
    refs = media_refs or tuple(
        MediaObjectRef(
            object_key=key,
            media_type=media_type,
            byte_size=byte_size,
            checksum=checksum,
            missing=False,
        )
        for asset in snapshot.media_assets
        for key, media_type, byte_size, checksum in _asset_object_rows(asset)
    )
    return {
        "envelope_version": ENVELOPE_VERSION,
        "owner": {
            "id": snapshot.owner.id,
            "handle": snapshot.owner.handle,
            "display_name": snapshot.owner.display_name,
            "bio": snapshot.owner.bio,
            "location": snapshot.owner.location,
            "website_url": snapshot.owner.website_url,
            "password_hash": snapshot.owner.password_hash,
            "claimed_at": _iso(snapshot.owner.claimed_at),
        },
        "settings": {
            "id": snapshot.settings.id,
            "canonical_origin": snapshot.settings.canonical_origin,
            "theme": {
                "palette": snapshot.settings.theme.palette,
                "font": snapshot.settings.theme.font,
                "scale": snapshot.settings.theme.scale,
                "density": snapshot.settings.theme.density,
                "radius": snapshot.settings.theme.radius,
                "layout_width": snapshot.settings.theme.layout_width,
            },
            "revision": snapshot.settings.revision,
            "updated_at": _iso(snapshot.settings.updated_at),
        },
        "modules": [
            {
                "kind": module.kind,
                "enabled": module.enabled,
                "position": module.position,
                "config": module.config,
            }
            for module in snapshot.modules
        ],
        "recovery_code_hashes": list(snapshot.recovery_code_hashes),
        "federation_keys": [
            {
                "id": key.id,
                "public_pem": key.public_pem,
                "encrypted_private_pem_b64": base64.b64encode(key.encrypted_private_pem).decode(),
                "created_at": _iso(key.created_at),
                "retired_at": _iso(key.retired_at) if key.retired_at else None,
            }
            for key in snapshot.federation_keys
        ],
        "relationships": [_relationship_to_json(item) for item in snapshot.relationships],
        "circles": [
            {
                "id": circle.id,
                "name": circle.name,
                "member_actor_ids": list(circle.member_actor_ids),
                "created_at": _iso(circle.created_at),
            }
            for circle in snapshot.circles
        ],
        "blocked_domains": list(snapshot.blocked_domains),
        "content_items": [_content_to_json(item) for item in snapshot.content_items],
        "media_assets": [_media_to_json(item) for item in snapshot.media_assets],
        "guestbook_entries": [_guestbook_to_json(item) for item in snapshot.guestbook_entries],
        "media_manifest": [
            {
                "object_key": ref.object_key,
                "media_type": ref.media_type,
                "byte_size": ref.byte_size,
                "checksum": ref.checksum,
                "missing": ref.missing,
            }
            for ref in refs
        ],
    }


def _snapshot_from_json(payload: Mapping[str, Any]) -> SpaceDataSnapshot:
    version = payload.get("envelope_version")
    if version not in SUPPORTED_ENVELOPE_VERSIONS:
        raise LifecycleError("space.json envelope_version is unsupported.")
    owner_raw = _object(payload, "owner")
    settings_raw = _object(payload, "settings")
    theme_raw = _object(settings_raw, "theme")
    owner = Owner(
        id=_uuid_text(owner_raw["id"], "owner.id"),
        handle=str(owner_raw["handle"]),
        display_name=str(owner_raw["display_name"]),
        bio=str(owner_raw["bio"]),
        location=str(owner_raw["location"]),
        website_url=str(owner_raw["website_url"]) if owner_raw.get("website_url") else None,
        password_hash=str(owner_raw["password_hash"]),
        claimed_at=_parse_dt(owner_raw["claimed_at"]),
    )
    settings = SiteSettings(
        id=_uuid_text(settings_raw["id"], "settings.id"),
        canonical_origin=normalize_origin(str(settings_raw["canonical_origin"]), production=False),
        theme=Theme(
            palette=str(theme_raw["palette"]),
            font=str(theme_raw["font"]),
            scale=str(theme_raw["scale"]),
            density=str(theme_raw["density"]),
            radius=str(theme_raw["radius"]),
            layout_width=str(theme_raw["layout_width"]),
        ),
        revision=int(settings_raw["revision"]),
        updated_at=_parse_dt(settings_raw["updated_at"]),
    )
    modules = tuple(
        ProfileModule(
            kind=str(item["kind"]),
            enabled=bool(item["enabled"]),
            position=int(item["position"]),
            config=dict(item["config"]) if isinstance(item.get("config"), dict) else {},
        )
        for item in _list(payload, "modules")
    )
    recovery = tuple(str(item) for item in _list(payload, "recovery_code_hashes"))
    keys = tuple(
        FederationKey(
            id=_uuid_text(item["id"], "federation_keys.id"),
            public_pem=str(item["public_pem"]),
            encrypted_private_pem=base64.b64decode(str(item["encrypted_private_pem_b64"])),
            created_at=_parse_dt(item["created_at"]),
            retired_at=_parse_dt(item["retired_at"]) if item.get("retired_at") else None,
        )
        for item in _list(payload, "federation_keys")
    )
    if any(
        b"PRIVATE KEY" in key.encrypted_private_pem
        and b"ENCRYPTED" not in key.encrypted_private_pem
        for key in keys
    ):
        raise LifecycleError("Plaintext private keys are forbidden in import envelopes.")
    relationships = tuple(_relationship_from_json(item) for item in _list(payload, "relationships"))
    circles = tuple(
        Circle(
            id=_uuid_text(item["id"], "circles.id"),
            name=str(item["name"]),
            member_actor_ids=tuple(str(value) for value in item.get("member_actor_ids", ())),
            created_at=_parse_dt(item["created_at"]),
        )
        for item in _list(payload, "circles")
    )
    blocked = tuple(str(item) for item in _list(payload, "blocked_domains"))
    media_assets = tuple(_media_from_json(item) for item in _list(payload, "media_assets"))
    media_by_id = {asset.id: asset for asset in media_assets}
    content_items = tuple(
        _content_from_json(item, media_by_id) for item in _list(payload, "content_items")
    )
    guestbook = tuple(_guestbook_from_json(item) for item in _list(payload, "guestbook_entries"))
    return SpaceDataSnapshot(
        owner=owner,
        settings=settings,
        modules=modules,
        recovery_code_hashes=recovery,
        federation_keys=keys,
        relationships=relationships,
        circles=circles,
        blocked_domains=blocked,
        content_items=content_items,
        media_assets=media_assets,
        guestbook_entries=guestbook,
    )


def _media_refs_from_snapshot_payload(payload: Mapping[str, Any]) -> tuple[MediaObjectRef, ...]:
    return tuple(
        MediaObjectRef(
            object_key=str(item["object_key"]),
            media_type=str(item["media_type"]),
            byte_size=int(item["byte_size"]),
            checksum=str(item["checksum"]),
            missing=bool(item.get("missing", False)),
        )
        for item in _list(payload, "media_manifest")
    )


def _relationship_to_json(relationship: Relationship) -> dict[str, Any]:
    actor = relationship.actor
    return {
        "actor": {
            "id": actor.id,
            "inbox_url": actor.inbox_url,
            "preferred_username": actor.preferred_username,
            "display_name": actor.display_name,
            "domain": actor.domain,
            "last_contact_at": _iso(actor.last_contact_at),
            "deleted_at": _iso(actor.deleted_at) if actor.deleted_at else None,
        },
        "outbound_state": relationship.outbound_state,
        "inbound_state": relationship.inbound_state,
        "outbound_follow_id": relationship.outbound_follow_id,
        "inbound_follow_id": relationship.inbound_follow_id,
        "pinned": relationship.pinned,
        "muted": relationship.muted,
        "blocked": relationship.blocked,
        "unavailable": relationship.unavailable,
        "note": relationship.note,
        "updated_at": _iso(relationship.updated_at),
    }


def _relationship_from_json(raw: Mapping[str, Any]) -> Relationship:
    actor_raw = _object(raw, "actor")
    actor = RemoteActor(
        id=str(actor_raw["id"]),
        inbox_url=str(actor_raw["inbox_url"]),
        preferred_username=str(actor_raw["preferred_username"]),
        display_name=str(actor_raw["display_name"]),
        domain=str(actor_raw["domain"]),
        last_contact_at=_parse_dt(actor_raw["last_contact_at"]),
        deleted_at=_parse_dt(actor_raw["deleted_at"]) if actor_raw.get("deleted_at") else None,
    )
    if urlsplit(actor.id).scheme != "https" or urlsplit(actor.inbox_url).scheme != "https":
        raise LifecycleError("Relationship actor URLs must be HTTPS.")
    return Relationship(
        actor=actor,
        outbound_state=str(raw["outbound_state"]),
        inbound_state=str(raw["inbound_state"]),
        outbound_follow_id=str(raw["outbound_follow_id"])
        if raw.get("outbound_follow_id")
        else None,
        inbound_follow_id=str(raw["inbound_follow_id"]) if raw.get("inbound_follow_id") else None,
        pinned=bool(raw["pinned"]),
        muted=bool(raw["muted"]),
        blocked=bool(raw["blocked"]),
        unavailable=bool(raw["unavailable"]),
        note=str(raw.get("note", "")),
        updated_at=_parse_dt(raw["updated_at"]),
    )


def _content_to_json(item: ContentItem) -> dict[str, Any]:
    return {
        "id": item.id,
        "owner_id": item.owner_id,
        "kind": item.kind,
        "state": item.state,
        "title": item.title,
        "source": item.source,
        "external_url": item.external_url,
        "media_id": item.media.id if item.media else None,
        "tags": list(item.tags),
        "revision": item.revision,
        "created_at": _iso(item.created_at),
        "updated_at": _iso(item.updated_at),
        "published_at": _iso(item.published_at) if item.published_at else None,
        "deleted_at": _iso(item.deleted_at) if item.deleted_at else None,
    }


def _content_from_json(
    raw: Mapping[str, Any], media_by_id: Mapping[str, MediaAsset]
) -> ContentItem:
    media_id = raw.get("media_id")
    media = media_by_id.get(str(media_id)) if media_id else None
    return ContentItem(
        id=_uuid_text(raw["id"], "content.id"),
        owner_id=_uuid_text(raw["owner_id"], "content.owner_id"),
        kind=str(raw["kind"]),
        state=str(raw["state"]),
        title=str(raw["title"]),
        source=str(raw["source"]),
        external_url=str(raw["external_url"]) if raw.get("external_url") else None,
        media=media,
        tags=tuple(str(tag) for tag in raw.get("tags", ())),
        revision=int(raw["revision"]),
        created_at=_parse_dt(raw["created_at"]),
        updated_at=_parse_dt(raw["updated_at"]),
        published_at=_parse_dt(raw["published_at"]) if raw.get("published_at") else None,
        deleted_at=_parse_dt(raw["deleted_at"]) if raw.get("deleted_at") else None,
    )


def _media_to_json(asset: MediaAsset) -> dict[str, Any]:
    return {
        "id": asset.id,
        "object_key": asset.object_key,
        "media_type": asset.media_type,
        "width": asset.width,
        "height": asset.height,
        "byte_size": asset.byte_size,
        "checksum": asset.checksum,
        "alt_text": asset.alt_text,
        "status": asset.status,
        "created_at": _iso(asset.created_at),
        "variants": [
            {
                "name": variant.name,
                "object_key": variant.object_key,
                "media_type": variant.media_type,
                "width": variant.width,
                "height": variant.height,
                "byte_size": variant.byte_size,
                "checksum": variant.checksum,
            }
            for variant in asset.variants
        ],
    }


def _media_from_json(raw: Mapping[str, Any]) -> MediaAsset:
    variants = tuple(
        MediaVariant(
            name=str(item["name"]),
            object_key=str(item["object_key"]),
            media_type=str(item["media_type"]),
            width=int(item["width"]),
            height=int(item["height"]),
            byte_size=int(item["byte_size"]),
            checksum=str(item["checksum"]),
        )
        for item in raw.get("variants", ())
    )
    return MediaAsset(
        id=_uuid_text(raw["id"], "media.id"),
        object_key=str(raw["object_key"]),
        media_type=str(raw["media_type"]),
        width=int(raw["width"]),
        height=int(raw["height"]),
        byte_size=int(raw["byte_size"]),
        checksum=str(raw["checksum"]),
        alt_text=str(raw["alt_text"]),
        status=str(raw["status"]),
        created_at=_parse_dt(raw["created_at"]),
        variants=variants,
    )


def _guestbook_to_json(entry: GuestbookEntry) -> dict[str, Any]:
    return {
        "id": entry.id,
        "display_name": entry.display_name,
        "message": entry.message,
        "website_url": entry.website_url,
        "status": entry.status,
        "abuse_token": entry.abuse_token,
        "submission_hash": entry.submission_hash,
        "created_at": _iso(entry.created_at),
        "moderated_at": _iso(entry.moderated_at) if entry.moderated_at else None,
    }


def _guestbook_from_json(raw: Mapping[str, Any]) -> GuestbookEntry:
    return GuestbookEntry(
        id=_uuid_text(raw["id"], "guestbook.id"),
        display_name=str(raw["display_name"]),
        message=str(raw["message"]),
        website_url=str(raw["website_url"]) if raw.get("website_url") else None,
        status=str(raw["status"]),
        abuse_token=str(raw["abuse_token"]),
        submission_hash=str(raw["submission_hash"]),
        created_at=_parse_dt(raw["created_at"]),
        moderated_at=_parse_dt(raw["moderated_at"]) if raw.get("moderated_at") else None,
    )


def _asset_object_rows(
    asset: MediaAsset,
) -> tuple[tuple[str, str, int, str], ...]:
    rows = [
        (asset.object_key, asset.media_type, asset.byte_size, asset.checksum),
        *[
            (variant.object_key, variant.media_type, variant.byte_size, variant.checksum)
            for variant in asset.variants
        ],
    ]
    return tuple(rows)


def _media_keys(assets: Sequence[MediaAsset]) -> tuple[str, ...]:
    keys: list[str] = []
    for asset in assets:
        for key, _media_type, _size, _checksum in _asset_object_rows(asset):
            keys.append(key)
    return tuple(keys)


def _object(payload: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise LifecycleError(f"{key} must be an object.")
    return value


def _list(payload: Mapping[str, Any], key: str) -> list[Any]:
    value = payload.get(key)
    if not isinstance(value, list):
        raise LifecycleError(f"{key} must be a list.")
    return value


def _uuid_text(value: object, field: str) -> str:
    text = str(value)
    try:
        import uuid

        uuid.UUID(text)
    except ValueError as exc:
        raise LifecycleError(f"{field} must be a UUID.") from exc
    return text


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_dt(value: object) -> datetime:
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
