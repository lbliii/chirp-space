from __future__ import annotations

from chirp_space.config import SpaceConfig


def space_config() -> SpaceConfig:
    return SpaceConfig(
        env="development",
        debug=True,
        database_url="sqlite:///:memory:",
        secret_key="s" * 64,
        claim_token="owner-claim-token-for-tests",
        canonical_origin="http://localhost:8000",
    )
