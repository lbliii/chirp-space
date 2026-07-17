from __future__ import annotations

import pytest

from chirp_space.config import SpaceConfig, normalize_origin

pytestmark = pytest.mark.issue(790)


def test_production_configuration_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPACE_ENV", "production")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("CHIRP_SECRET_KEY", raising=False)
    monkeypatch.delenv("SPACE_OWNER_CLAIM_TOKEN", raising=False)
    monkeypatch.delenv("SPACE_CANONICAL_ORIGIN", raising=False)
    monkeypatch.delenv("RAILWAY_PUBLIC_DOMAIN", raising=False)

    with pytest.raises(RuntimeError, match="PostgreSQL"):
        SpaceConfig.from_env(debug=False)


def test_origins_reject_paths_credentials_and_remote_plain_http() -> None:
    with pytest.raises(ValueError, match="without a path"):
        normalize_origin("https://example.com/private", production=True)
    with pytest.raises(ValueError, match="without a path"):
        normalize_origin("https://owner:secret@example.com", production=True)
    with pytest.raises(ValueError, match="local development"):
        normalize_origin("http://example.com", production=False)
    assert normalize_origin("http://localhost:8000/", production=False) == "http://localhost:8000"
