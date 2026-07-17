from __future__ import annotations

import pytest
from conftest import space_config

from chirp_space.services import SpaceService
from chirp_space.store import SQLiteStore

pytestmark = pytest.mark.issue(790)


def test_sqlite_migration_and_identity_survive_restart(tmp_path) -> None:
    database_path = tmp_path / "space.db"
    first = SQLiteStore(database_path)
    first.migrate()
    setup = SpaceService(first, space_config()).setup(
        claim_token="owner-claim-token-for-tests",
        canonical_origin="http://localhost:8000",
        handle="owner",
        display_name="Space Owner",
        bio="A durable local-first home.",
        password="correct horse battery staple",
    )
    owner_id = setup.state.owner.id
    site_id = setup.state.settings.id
    first.close()

    second = SQLiteStore(database_path)
    second.migrate()
    restored = second.state()
    assert restored is not None
    assert restored.owner.id == owner_id
    assert restored.settings.id == site_id
    assert restored.settings.revision == 1
    assert [module.position for module in restored.modules] == list(range(8))
    second.close()


def test_repeated_setup_is_transactionally_rejected() -> None:
    store = SQLiteStore()
    store.migrate()
    service = SpaceService(store, space_config())
    service.setup(
        claim_token="owner-claim-token-for-tests",
        canonical_origin="http://localhost:8000",
        handle="owner",
        display_name="Space Owner",
        bio="",
        password="correct horse battery staple",
    )
    with pytest.raises(PermissionError, match="already complete"):
        service.setup(
            claim_token="owner-claim-token-for-tests",
            canonical_origin="http://localhost:8000",
            handle="second",
            display_name="Second Owner",
            bio="",
            password="another correct battery staple",
        )
