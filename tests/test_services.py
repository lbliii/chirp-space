from __future__ import annotations

import pytest
from conftest import space_config

from chirp_space.models import MODULE_KINDS
from chirp_space.services import SetupResult, SpaceService
from chirp_space.store import SQLiteStore

pytestmark = pytest.mark.issue(790)


def _claimed() -> tuple[SQLiteStore, SpaceService, SetupResult]:
    store = SQLiteStore()
    store.migrate()
    service = SpaceService(store, space_config())
    result = service.setup(
        claim_token="owner-claim-token-for-tests",
        canonical_origin="http://localhost:8000",
        handle="owner",
        display_name="Space Owner",
        bio="A local-first home.",
        password="correct horse battery staple",
    )
    return store, service, result


def _customization(service: SpaceService, owner, *, palette: str = "dark", revision: int = 1):
    return service.build_customization(
        owner,
        display_name="A New Name",
        bio="A revised biography.",
        location="The web",
        website_url="https://example.com",
        palette=palette,
        font="serif",
        scale="generous",
        density="comfortable",
        radius="round",
        layout_width="wide",
        module_order=",".join(MODULE_KINDS),
        enabled={kind: kind in {"identity", "links", "guestbook"} for kind in MODULE_KINDS},
        module_values={
            "tagline": "Notes from one corner of the web",
            "links": "Writing | https://example.com/writing",
            "recent_limit": 5,
            "journal_limit": 5,
            "photo_columns": 3,
            "tag_limit": 12,
            "guestbook_prompt": "Say hello",
        },
        expected_revision=revision,
    )


def test_claim_is_secret_guarded_and_generates_stable_identity() -> None:
    store = SQLiteStore()
    store.migrate()
    service = SpaceService(store, space_config())
    with pytest.raises(PermissionError, match="not valid"):
        service.setup(
            claim_token="wrong",
            canonical_origin="http://localhost:8000",
            handle="owner",
            display_name="Space Owner",
            bio="",
            password="correct horse battery staple",
        )
    with pytest.raises(ValueError, match="must match"):
        service.setup(
            claim_token="owner-claim-token-for-tests",
            canonical_origin="https://attacker.example",
            handle="owner",
            display_name="Space Owner",
            bio="",
            password="correct horse battery staple",
        )

    result = service.setup(
        claim_token="owner-claim-token-for-tests",
        canonical_origin="http://localhost:8000",
        handle="owner",
        display_name="Space Owner",
        bio="A local-first home.",
        password="correct horse battery staple",
    )
    assert len(result.recovery_codes) == 8
    assert result.state.owner.id != result.state.settings.id
    assert service.current_owner(result.session_token) == result.state.owner


def test_password_sessions_and_recovery_are_replay_safe() -> None:
    _store, service, setup = _claimed()
    with pytest.raises(PermissionError, match="incorrect"):
        service.login("owner", "wrong password")
    owner, old_session = service.login("OWNER", "correct horse battery staple")
    assert service.current_owner(old_session) == owner

    recovered, recovered_session = service.login_with_recovery_code(
        "owner", setup.recovery_codes[0].lower()
    )
    assert recovered == owner
    assert service.current_owner(old_session) is None
    assert service.current_owner(recovered_session) == owner
    with pytest.raises(PermissionError, match="incorrect"):
        service.login_with_recovery_code("owner", setup.recovery_codes[0])
    service.logout(recovered_session)
    assert service.current_owner(recovered_session) is None


def test_preview_validation_and_atomic_customization() -> None:
    store, service, setup = _claimed()
    customization = _customization(service, setup.state.owner)
    before = store.state()
    assert before is not None
    assert before.settings.revision == 1
    saved = service.save_customization(setup.state.owner, customization)
    assert saved.settings.revision == 2
    assert saved.settings.theme.palette == "dark"
    assert saved.owner.website_url == "https://example.com"
    assert saved.modules[-1].config == {"prompt": "Say hello"}

    with pytest.raises(RuntimeError, match="another session"):
        service.save_customization(setup.state.owner, customization)
    with pytest.raises(ValueError, match="approved palette"):
        _customization(
            service, saved.owner, palette="</style><script>alert(1)</script>", revision=2
        )


def test_modules_reject_unknown_order_code_and_unsafe_links() -> None:
    _store, service, setup = _claimed()
    with pytest.raises(ValueError, match="exactly once"):
        service.build_customization(
            setup.state.owner,
            display_name="Owner",
            bio="",
            location="",
            website_url="",
            palette="system",
            font="system",
            scale="standard",
            density="comfortable",
            radius="soft",
            layout_width="standard",
            module_order="identity,links",
            enabled={kind: kind == "identity" for kind in MODULE_KINDS},
            module_values={},
            expected_revision=1,
        )
    with pytest.raises(ValueError, match="HTTPS URL"):
        service.build_customization(
            setup.state.owner,
            display_name="Owner",
            bio="",
            location="",
            website_url="",
            palette="system",
            font="system",
            scale="standard",
            density="comfortable",
            radius="soft",
            layout_width="standard",
            module_order=",".join(MODULE_KINDS),
            enabled={kind: kind == "identity" for kind in MODULE_KINDS},
            module_values={"links": "Bad | javascript:alert(1)"},
            expected_revision=1,
        )
