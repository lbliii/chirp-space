from __future__ import annotations

import re

import pytest
from chirp.testing import TestClient
from conftest import space_config

from chirp_space.models import MODULE_KINDS
from chirp_space.store import SQLiteStore
from chirp_space.web import create_app

pytestmark = [pytest.mark.issue(790), pytest.mark.asyncio]


def _cookie(response, name: str) -> str | None:
    for header, value in response.headers:
        if header.lower() == "set-cookie" and value.startswith(f"{name}="):
            return value.split(";", 1)[0]
    return None


def _csrf(response) -> str:
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', response.text)
    assert match is not None
    return match.group(1)


async def _claim(client: TestClient):
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
    latest_chirp = _cookie(created, "chirp_session") or chirp_cookie
    assert owner_cookie is not None
    return created, f"{latest_chirp}; {owner_cookie}"


async def test_plain_first_claim_profile_and_recovery_receipt() -> None:
    store = SQLiteStore()
    app = create_app(store=store, space_config=space_config())
    async with TestClient(app) as client:
        pending = await client.get("/")
        assert pending.status == 200
        assert "waiting for its owner" in pending.text
        assert "private information" in pending.text

        created, cookies = await _claim(client)
        assert created.status == 302
        assert created.header("location") == "/owner"
        owner = await client.get("/owner", headers={"Cookie": cookies})
        assert owner.status == 200
        assert owner.text.count("<code>") >= 10
        owner_chirp = _cookie(owner, "chirp_session")
        if owner_chirp:
            cookies = f"{owner_chirp}; {cookies.split('; ', 1)[1]}"

        second_read = await client.get("/owner", headers={"Cookie": cookies})
        assert "Save these recovery codes now" not in second_read.text
        profile = await client.get("/@owner")
        assert profile.status == 200
        assert "Space Owner" in profile.text
        assert "A home on the open web." in profile.text
        missing = await client.get("/@someone-else")
        assert missing.status == 404


async def test_htmx_preview_does_not_persist_and_save_is_atomic() -> None:
    store = SQLiteStore()
    app = create_app(store=store, space_config=space_config())
    async with TestClient(app) as client:
        _created, cookies = await _claim(client)
        page = await client.get("/owner/customize", headers={"Cookie": cookies})
        latest_chirp = _cookie(page, "chirp_session")
        if latest_chirp:
            cookies = f"{latest_chirp}; {cookies.split('; ', 1)[1]}"
        data = {
            "_csrf_token": _csrf(page),
            "revision": "1",
            "display_name": "A New Name",
            "tagline": "Small notes, carefully kept",
            "bio": "A revised profile.",
            "location": "The web",
            "website_url": "https://example.com",
            "links": "Writing | https://example.com/writing",
            "palette": "dark",
            "font": "serif",
            "scale": "generous",
            "density": "comfortable",
            "radius": "round",
            "layout_width": "wide",
            "module_order": ",".join(MODULE_KINDS),
            "enable_identity": "on",
            "enable_links": "on",
            "recent_limit": "5",
            "journal_limit": "5",
            "photo_columns": "3",
            "tag_limit": "12",
            "guestbook_prompt": "Say hello",
            "intent": "preview",
        }
        preview = await client.post(
            "/owner/customize",
            data=data,
            headers={"Cookie": cookies, "HX-Request": "true"},
        )
        assert preview.status == 200
        assert "Private preview" in preview.text
        assert "A New Name" in preview.text
        preview_state = store.state()
        assert preview_state is not None
        assert preview_state.owner.display_name == "Space Owner"

        data["intent"] = "save"
        saved = await client.post("/owner/customize", data=data, headers={"Cookie": cookies})
        assert saved.status == 302
        saved_state = store.state()
        assert saved_state is not None
        assert saved_state.owner.display_name == "A New Name"
        assert saved_state.settings.theme.palette == "dark"


async def test_malformed_theme_and_form_are_rendered_safely() -> None:
    store = SQLiteStore()
    app = create_app(store=store, space_config=space_config())
    async with TestClient(app) as client:
        _created, cookies = await _claim(client)
        page = await client.get("/owner/customize", headers={"Cookie": cookies})
        latest_chirp = _cookie(page, "chirp_session")
        if latest_chirp:
            cookies = f"{latest_chirp}; {cookies.split('; ', 1)[1]}"
        response = await client.post(
            "/owner/customize",
            data={
                "_csrf_token": _csrf(page),
                "revision": "1",
                "display_name": "Owner",
                "palette": "</style><script>alert(1)</script>",
                "font": "system",
                "scale": "standard",
                "density": "comfortable",
                "radius": "soft",
                "layout_width": "standard",
                "module_order": ",".join(MODULE_KINDS),
                "enable_identity": "on",
            },
            headers={"Cookie": cookies},
        )
        assert response.status == 200
        assert "Choose an approved palette value" in response.text
        assert "<script>alert(1)</script>" not in response.text
        current = store.state()
        assert current is not None
        assert current.settings.revision == 1


async def test_health_readiness_and_app_contract_check() -> None:
    app = create_app(store=SQLiteStore(), space_config=space_config())
    app.check(warnings_as_errors=True)
    async with TestClient(app) as client:
        assert (await client.get("/health")).status == 200
        assert (await client.get("/ready")).status == 200
