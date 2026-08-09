from __future__ import annotations

import io
import json
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest
from chirp.testing import TestClient
from conftest import space_config

from chirp_space.content import LocalObjectStorage, PublishingService
from chirp_space.federation import FederationService
from chirp_space.lifecycle import (
    DELETE_CONFIRMATION,
    ENVELOPE_VERSION,
    MIGRATE_CONFIRMATION,
    RESTORE_CONFIRMATION,
    RETENTION_DISCLOSURE,
    ROTATE_CONFIRMATION,
    LifecycleError,
    SpaceLifecycleService,
)
from chirp_space.services import SpaceService
from chirp_space.store import SQLiteStore
from chirp_space.web import create_app

pytestmark = pytest.mark.issue(800)

OWNER_PASSWORD = "correct horse battery staple"


class FakeNormalizer:
    def normalize(self, data: bytes):
        from chirp_space.content import NormalizedImage, NormalizedVariant

        return NormalizedImage(
            data=b"normalized:" + data,
            media_type="image/webp",
            extension="webp",
            width=640,
            height=480,
            variants=(
                NormalizedVariant(
                    name="small",
                    data=b"small:" + data,
                    media_type="image/webp",
                    extension="webp",
                    width=320,
                    height=240,
                ),
            ),
        )


def _claimed(tmp_path: Path, *, origin: str = "http://localhost:8000"):
    config = replace(space_config(), canonical_origin=origin, federation_enabled=True)
    store = SQLiteStore()
    store.migrate()
    service = SpaceService(store, config)
    result = service.setup(
        claim_token=config.claim_token,
        canonical_origin=origin,
        handle="owner",
        display_name="Owner",
        bio="Portable Space",
        password=OWNER_PASSWORD,
    )
    storage = LocalObjectStorage(tmp_path / "media")
    publishing = PublishingService(store, config, storage, FakeNormalizer())
    federation = FederationService(store, config)
    federation.ensure_key()
    lifecycle = SpaceLifecycleService(store, config, storage, federation=federation)
    return config, store, service, storage, publishing, federation, lifecycle, result


def test_export_import_round_trip_across_fresh_store(tmp_path: Path) -> None:
    config, _store, _service, _storage, publishing, federation, lifecycle, _setup = _claimed(
        tmp_path
    )
    publishing.create(
        kind="short",
        state="public",
        title="",
        source="Hello portable world",
        tags=("alpha",),
    )
    publishing.create(
        kind="photo",
        state="public",
        title="Sky",
        source="A photo",
        alt_text="Blue sky",
        image_bytes=b"jpeg-source-with-metadata",
        tags=("photo",),
    )
    original_key = federation.ensure_key()
    archive = lifecycle.export_archive()

    fresh = SQLiteStore()
    fresh.migrate()
    fresh_storage = LocalObjectStorage(tmp_path / "fresh-media")
    fresh_federation = FederationService(fresh, config)
    fresh_lifecycle = SpaceLifecycleService(
        fresh, config, fresh_storage, federation=fresh_federation
    )
    preview = fresh_lifecycle.restore_archive(
        archive,
        confirmation=RESTORE_CONFIRMATION,
        owner=None,
        claim_token=config.claim_token,
    )
    assert preview.handle == "owner"
    assert preview.envelope_version == ENVELOPE_VERSION
    state = fresh.state()
    assert state is not None
    assert state.owner.display_name == "Owner"
    assert len(fresh.export_content_items()) == 2
    active = fresh.active_federation_key()
    assert active is not None
    assert active.id == original_key.id
    restored_photo = next(item for item in fresh.export_content_items() if item.kind == "photo")
    assert restored_photo.media is not None
    assert fresh_storage.get(restored_photo.media.object_key).startswith(b"normalized:")


def test_corrupt_wrong_version_oversized_and_partial_media(tmp_path: Path) -> None:
    _config, _store, _service, _storage, publishing, _federation, lifecycle, _setup = _claimed(
        tmp_path
    )
    publishing.create(
        kind="photo",
        state="public",
        title="Sky",
        source="A photo",
        alt_text="Blue sky",
        image_bytes=b"jpeg-source-with-metadata",
        tags=("photo",),
    )
    archive = lifecycle.export_archive()

    with pytest.raises(LifecycleError, match="not a valid"):
        lifecycle.preview_import(b"not-a-zip")

    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        space = zf.read("space.json")
    manifest["envelope_version"] = 99
    bad = io.BytesIO()
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("space.json", space)
    with pytest.raises(LifecycleError, match="Unsupported"):
        lifecycle.preview_import(bad.getvalue())

    oversized = b"PK" + b"0" * (100 * 1024 * 1024 + 1)
    with pytest.raises(LifecycleError, match="100 MiB"):
        lifecycle.preview_import(oversized)

    broken = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(archive)) as source, zipfile.ZipFile(broken, "w") as target:
        for info in source.infolist():
            if info.filename.startswith("media/"):
                continue
            target.writestr(info, source.read(info.filename))
    with pytest.raises(LifecycleError, match="Missing media"):
        lifecycle.preview_import(broken.getvalue())


def test_restore_rejects_wrong_encryption_key(tmp_path: Path) -> None:
    config, _store, _service, _storage, _publishing, _federation, lifecycle, _setup = _claimed(
        tmp_path
    )
    archive = lifecycle.export_archive()
    other = replace(config, key_encryption_key="totally-different-encryption-secret-value")
    fresh = SQLiteStore()
    fresh.migrate()
    fresh_lifecycle = SpaceLifecycleService(
        fresh,
        other,
        LocalObjectStorage(tmp_path / "other"),
        federation=FederationService(fresh, other),
    )
    with pytest.raises(LifecycleError, match="SPACE_KEY_ENCRYPTION_KEY"):
        fresh_lifecycle.restore_archive(
            archive,
            confirmation=RESTORE_CONFIRMATION,
            owner=None,
            claim_token=config.claim_token,
        )


def test_key_rotation_owner_confirmation_and_overlap(tmp_path: Path) -> None:
    _config, store, service, _storage, _publishing, federation, lifecycle, setup = _claimed(
        tmp_path
    )
    original = federation.ensure_key()
    with pytest.raises(LifecycleError, match="ROTATE SIGNING KEY"):
        lifecycle.rotate_signing_key(
            confirmation="nope", owner=setup.state.owner, password=OWNER_PASSWORD
        )
    replacement = lifecycle.rotate_signing_key(
        confirmation=ROTATE_CONFIRMATION, owner=setup.state.owner, password=OWNER_PASSWORD
    )
    assert replacement.id != original.id
    assert federation.key_document(original.id)["publicKeyPem"] == original.public_pem
    assert federation.actor_document()["publicKey"]["id"].endswith(replacement.id)
    # Hostile/stale: retired key remains available; offline peer just cannot fetch after TTL
    # (covered by federation suite). Confirm local session still authenticates.
    owner, _token = service.login("owner", OWNER_PASSWORD)
    assert owner.id == setup.state.owner.id
    active = store.active_federation_key()
    assert active is not None
    assert active.id == replacement.id


def test_domain_migration_fail_closed_without_federation_ack(tmp_path: Path) -> None:
    config, store, _service, _storage, _publishing, federation, lifecycle, setup = _claimed(
        tmp_path, origin="http://localhost:8000"
    )
    federation.ensure_key()
    migrated_config = replace(config, canonical_origin="https://new.example")
    lifecycle = SpaceLifecycleService(
        store,
        migrated_config,
        _storage,
        federation=FederationService(store, migrated_config),
    )
    with pytest.raises(LifecycleError, match="Move is outside"):
        lifecycle.migrate_canonical_origin(
            confirmation=MIGRATE_CONFIRMATION,
            owner=setup.state.owner,
            password=OWNER_PASSWORD,
            acknowledge_federation_break=False,
        )
    result = lifecycle.migrate_canonical_origin(
        confirmation=MIGRATE_CONFIRMATION,
        owner=setup.state.owner,
        password=OWNER_PASSWORD,
        acknowledge_federation_break=True,
    )
    assert result.previous_origin == "http://localhost:8000"
    assert result.new_origin == "https://new.example"
    assert result.federation_identity_broken is True
    control = store.federation_control()
    assert control.inbound_paused is True
    assert control.outbound_paused is True
    migrated = store.state()
    assert migrated is not None
    assert migrated.settings.canonical_origin == "https://new.example"


def test_deletion_requires_confirmation_and_discloses_retention(tmp_path: Path) -> None:
    _config, store, _service, _storage, publishing, _federation, lifecycle, setup = _claimed(
        tmp_path
    )
    publishing.create(kind="short", state="public", title="", source="bye", tags=())
    with pytest.raises(LifecycleError, match="DELETE THIS SPACE"):
        lifecycle.delete_space(
            confirmation="delete",
            owner=setup.state.owner,
            password=OWNER_PASSWORD,
            attempt_remote=False,
        )
    report = lifecycle.delete_space(
        confirmation=DELETE_CONFIRMATION,
        owner=setup.state.owner,
        password=OWNER_PASSWORD,
        attempt_remote=True,
    )
    assert report.local_purged is True
    assert report.retention_disclosure == RETENTION_DISCLOSURE
    assert store.state() is None
    assert "account-level Delete" in " ".join(report.notes)


async def test_owner_lifecycle_page_export_and_named_blocks(tmp_path: Path) -> None:
    config, store, _service, storage, publishing, _federation, _lifecycle, _setup = _claimed(
        tmp_path
    )
    publishing.create(kind="short", state="public", title="", source="page proof", tags=())
    app = create_app(
        debug=True,
        store=store,
        space_config=config,
        object_storage=storage,
        image_normalizer=FakeNormalizer(),
    )
    async with TestClient(app) as client:
        login_page = await client.get("/login")
        csrf = login_page.text.split('name="csrf-token" content="', 1)[1].split('"', 1)[0]
        session = next(
            value.split(";", 1)[0]
            for name, value in login_page.headers
            if name.lower() == "set-cookie" and value.startswith("chirp_session=")
        )
        logged_in = await client.post(
            "/login",
            data={
                "_csrf_token": csrf,
                "handle": "owner",
                "password": OWNER_PASSWORD,
            },
            headers={"Cookie": session},
        )
        assert logged_in.status in {302, 303}
        cookies = "; ".join(
            value.split(";", 1)[0]
            for name, value in logged_in.headers
            if name.lower() == "set-cookie"
        )
        if "chirp_session=" not in cookies:
            cookies = f"{session}; {cookies}"
        page = await client.get("/owner/lifecycle", headers={"Cookie": cookies})
        assert page.status == 200
        assert "Export backup" in page.text
        assert "Local deletion removes this deployment" in page.text
        assert "federation contract v1" in page.text
        exported = await client.get("/owner/lifecycle/export", headers={"Cookie": cookies})
        assert exported.status == 200
        assert exported.header("content-disposition") == (
            'attachment; filename="chirp-space-export.zip"'
        )
        assert exported.body[:2] == b"PK"
