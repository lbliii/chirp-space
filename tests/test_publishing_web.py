from __future__ import annotations

import re
from pathlib import Path

import pytest
from chirp.testing import TestClient
from conftest import space_config

from chirp_space.content import LocalObjectStorage, NormalizedImage, NormalizedVariant
from chirp_space.store import SQLiteStore
from chirp_space.web import create_app

pytestmark = [pytest.mark.issue(791), pytest.mark.asyncio]


class WebNormalizer:
    def normalize(self, data: bytes) -> NormalizedImage:
        if data == b"malformed":
            raise ValueError("Photo could not be safely decoded.")
        return NormalizedImage(
            b"web-normalized:" + data,
            "image/webp",
            "webp",
            800,
            600,
            (NormalizedVariant("small", b"web-small:" + data, "image/webp", "webp", 400, 300),),
        )


def _cookie(response, name: str) -> str | None:
    for header, value in response.headers:
        if header.lower() == "set-cookie" and value.startswith(f"{name}="):
            return value.split(";", 1)[0]
    return None


def _csrf(response) -> str:
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', response.text)
    assert match is not None
    return match.group(1)


def _refresh_chirp_cookie(cookies: str, response) -> str:
    latest = _cookie(response, "chirp_session")
    if latest is None:
        return cookies
    owner = next(part for part in cookies.split("; ") if part.startswith("space_owner_session="))
    return f"{latest}; {owner}"


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


def _content_form(csrf: str, **changes: str) -> dict[str, str]:
    values = {
        "_csrf_token": csrf,
        "kind": "short",
        "state": "public",
        "title": "",
        "source": "A first public note",
        "external_url": "",
        "alt_text": "",
        "tags": "chirp, launch",
        "intent": "save",
        "revision": "0",
    }
    values.update(changes)
    return values


def _multipart(fields: dict[str, str], image: bytes) -> tuple[bytes, str]:
    boundary = "CHIRP-SPACE-BOUNDARY"
    parts: list[bytes] = []
    for name, value in fields.items():
        parts.append(
            (
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'
            ).encode()
        )
    parts.append(
        (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="image"; filename="photo.jpg"\r\n'
            "Content-Type: image/jpeg\r\n\r\n"
        ).encode()
        + image
        + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


async def test_no_javascript_preview_publish_edit_archive_feed_and_delete(
    tmp_path: Path,
) -> None:
    store = SQLiteStore()
    app = create_app(
        store=store,
        space_config=space_config(),
        object_storage=LocalObjectStorage(tmp_path / "media"),
    )
    async with TestClient(app) as client:
        cookies = await _claim(client)
        form_page = await client.get("/owner/content/new", headers={"Cookie": cookies})
        cookies = _refresh_chirp_cookie(cookies, form_page)
        csrf = _csrf(form_page)

        preview = await client.post(
            "/owner/content/new",
            data=_content_form(csrf, intent="preview", source="Private preview text"),
            headers={
                "Cookie": cookies,
                "HX-Request": "true",
                "HX-Target": "main-content",
            },
        )
        assert preview.status == 200
        assert "<!doctype html>" not in preview.text
        assert "Private preview" in preview.text
        assert store.content_items(public_only=False) == ()

        created = await client.post(
            "/owner/content/new",
            data=_content_form(csrf),
            headers={"Cookie": cookies},
        )
        assert created.status == 302
        permalink = created.header("location")
        assert permalink is not None
        assert permalink.startswith("/posts/")
        item_id = permalink.rsplit("/", 1)[1]

        detail = await client.get(permalink)
        assert detail.status == 200
        assert "A first public note" in detail.text
        archive = await client.get("/archive", query={"q": "first public"})
        assert archive.status == 200
        assert permalink in archive.text
        tag = await client.get("/tags/chirp")
        assert permalink in tag.text
        feed = await client.get("/feed.xml")
        assert feed.status == 200
        assert permalink in feed.text
        assert feed.content_type == "application/rss+xml; charset=utf-8"

        edit = await client.get(f"/owner/content/{item_id}/edit", headers={"Cookie": cookies})
        cookies = _refresh_chirp_cookie(cookies, edit)
        updated = await client.post(
            f"/owner/content/{item_id}/edit",
            data=_content_form(
                _csrf(edit),
                state="local_only",
                source="Owner-only revision",
                revision="1",
            ),
            headers={"Cookie": cookies},
        )
        assert updated.status == 302
        assert updated.header("location") == "/owner/content"
        assert (await client.get(permalink)).status == 404

        stale = await client.post(
            f"/owner/content/{item_id}/edit",
            data=_content_form(
                _csrf(edit),
                state="public",
                source="Stale update",
                revision="1",
            ),
            headers={"Cookie": cookies},
        )
        assert stale.status == 200
        assert "another session" in stale.text

        latest = store.content_item(item_id)
        assert latest is not None
        delete_page = await client.get(
            f"/owner/content/{item_id}/edit", headers={"Cookie": cookies}
        )
        deleted = await client.post(
            f"/owner/content/{item_id}/delete",
            data={
                "_csrf_token": _csrf(delete_page),
                "revision": str(latest.revision),
                "confirm": "delete",
            },
            headers={"Cookie": cookies},
        )
        assert deleted.status == 302
        tombstone = await client.get(permalink)
        assert tombstone.status == 200
        assert "stable tombstone" in tombstone.text.lower()


async def test_guestbook_submission_duplicate_moderation_and_public_visibility(
    tmp_path: Path,
) -> None:
    store = SQLiteStore()
    app = create_app(
        store=store,
        space_config=space_config(),
        object_storage=LocalObjectStorage(tmp_path / "media"),
    )
    async with TestClient(app) as client:
        owner_cookies = await _claim(client)
        guestbook = await client.get("/guestbook")
        visitor_cookie = _cookie(guestbook, "chirp_session")
        assert visitor_cookie is not None
        submission = {
            "_csrf_token": _csrf(guestbook),
            "display_name": "A Visitor",
            "message": "Thank you for this thoughtful site.",
            "website_url": "https://example.com",
            "company": "",
        }
        pending = await client.post(
            "/guestbook", data=submission, headers={"Cookie": visitor_cookie}
        )
        assert pending.status == 302
        assert pending.header("location") == "/guestbook?submitted=1"
        assert "thoughtful site" not in (await client.get("/guestbook")).text

        duplicate = await client.post(
            "/guestbook", data=submission, headers={"Cookie": visitor_cookie}
        )
        assert duplicate.status == 200
        assert "already received" in duplicate.text

        moderation = await client.get("/owner/content", headers={"Cookie": owner_cookies})
        owner_cookies = _refresh_chirp_cookie(owner_cookies, moderation)
        entry = store.guestbook_entries(public_only=False)[0]
        approved = await client.post(
            f"/owner/guestbook/{entry.id}",
            data={"_csrf_token": _csrf(moderation), "action": "approved"},
            headers={"Cookie": owner_cookies},
        )
        assert approved.status == 302
        public = await client.get("/guestbook")
        assert "Thank you for this thoughtful site." in public.text
        assert "A Visitor" in public.text


async def test_plain_multipart_photo_upload_media_and_missing_object(tmp_path: Path) -> None:
    store = SQLiteStore()
    storage = LocalObjectStorage(tmp_path / "media")
    app = create_app(
        store=store,
        space_config=space_config(),
        object_storage=storage,
        image_normalizer=WebNormalizer(),
    )
    async with TestClient(app) as client:
        cookies = await _claim(client)
        page = await client.get("/owner/content/new", headers={"Cookie": cookies})
        cookies = _refresh_chirp_cookie(cookies, page)
        fields = _content_form(
            _csrf(page),
            kind="photo",
            source="A shoreline at dusk",
            alt_text="Dark rocks beside calm water at dusk",
        )
        body, content_type = _multipart(fields, b"jpeg-source-with-metadata")
        created = await client.post(
            "/owner/content/new",
            body=body,
            headers={"Cookie": cookies, "Content-Type": content_type},
        )
        assert created.status == 302
        permalink = created.header("location")
        assert permalink is not None
        assert permalink.startswith("/photos/")
        photo = store.content_items(public_only=True)[0]
        assert photo.media is not None

        detail = await client.get(permalink)
        assert "Dark rocks beside calm water at dusk" in detail.text
        assert f"/media/{photo.media.id}/small 400w" in detail.text
        media = await client.get(f"/media/{photo.media.id}")
        assert media.status == 200
        assert media.body == b"web-normalized:jpeg-source-with-metadata"
        assert media.content_type == "image/webp"
        small = await client.get(f"/media/{photo.media.id}/small")
        assert small.body == b"web-small:jpeg-source-with-metadata"

        storage.delete(photo.media.object_key)
        missing = await client.get(f"/media/{photo.media.id}")
        assert missing.status == 404
        missing_asset = store.media(photo.media.id)
        assert missing_asset is not None
        assert missing_asset.status == "missing"
        unavailable = await client.get(permalink)
        assert "Photo temporarily unavailable" in unavailable.text
        assert "Dark rocks beside calm water at dusk" in unavailable.text

        malformed_fields = _content_form(
            _csrf(page),
            kind="photo",
            state="public",
            source="Recoverable upload",
            alt_text="A useful description",
        )
        malformed_body, malformed_type = _multipart(malformed_fields, b"malformed")
        malformed = await client.post(
            "/owner/content/new",
            body=malformed_body,
            headers={"Cookie": cookies, "Content-Type": malformed_type},
        )
        assert malformed.status == 200
        assert "recoverable draft" in malformed.text
        drafts = store.content_items(public_only=False)
        assert any(item.state == "draft" and item.source == "Recoverable upload" for item in drafts)


async def test_malformed_plain_form_stays_recoverable(tmp_path: Path) -> None:
    store = SQLiteStore()
    app = create_app(
        store=store,
        space_config=space_config(),
        object_storage=LocalObjectStorage(tmp_path / "media"),
    )
    async with TestClient(app) as client:
        cookies = await _claim(client)
        page = await client.get("/owner/content/new", headers={"Cookie": cookies})
        cookies = _refresh_chirp_cookie(cookies, page)
        malformed = await client.post(
            "/owner/content/new",
            data=_content_form(
                _csrf(page),
                kind="link",
                title="Unsafe link",
                external_url="http://user:password@example.com",
            ),
            headers={"Cookie": cookies},
        )
        assert malformed.status == 200
        assert "bounded HTTPS URL without credentials" in malformed.text
        assert "http://user:password@example.com" in malformed.text
        assert store.content_items(public_only=False) == ()
