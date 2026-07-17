"""Environment-backed Chirp Space configuration."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from urllib.parse import urlsplit

PRODUCTION_ENVS = frozenset({"production", "staging"})


def normalize_origin(value: str, *, production: bool) -> str:
    """Return a canonical HTTP origin or raise an actionable error."""
    candidate = value.strip().rstrip("/")
    parsed = urlsplit(candidate)
    allowed_schemes = {"https"} if production else {"http", "https"}
    if (
        parsed.scheme not in allowed_schemes
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        scheme = "an HTTPS" if production else "an HTTP or HTTPS"
        raise ValueError(f"SPACE_CANONICAL_ORIGIN must be {scheme} origin without a path.")
    if (
        not production
        and parsed.scheme == "http"
        and parsed.hostname
        not in {
            "localhost",
            "127.0.0.1",
            "::1",
        }
    ):
        raise ValueError("Plain HTTP is allowed only for local development origins.")
    return candidate


@dataclass(frozen=True, slots=True)
class SpaceConfig:
    env: str
    debug: bool
    database_url: str
    secret_key: str
    claim_token: str
    canonical_origin: str
    host_aliases: tuple[str, ...] = ()

    @property
    def production(self) -> bool:
        return self.env in PRODUCTION_ENVS

    @classmethod
    def from_env(cls, *, debug: bool = True) -> SpaceConfig:
        env = (os.environ.get("SPACE_ENV") or "development").strip().lower()
        if env == "prod":
            env = "production"
        production = env in PRODUCTION_ENVS
        database_url = (os.environ.get("DATABASE_URL") or "").strip()
        secret_key = (os.environ.get("CHIRP_SECRET_KEY") or "").strip()
        claim_token = (os.environ.get("SPACE_OWNER_CLAIM_TOKEN") or "").strip()
        canonical_origin = (os.environ.get("SPACE_CANONICAL_ORIGIN") or "").strip()
        railway_domain = (os.environ.get("RAILWAY_PUBLIC_DOMAIN") or "").strip()
        if not canonical_origin and railway_domain:
            canonical_origin = f"https://{railway_domain}"

        if production:
            if not database_url.startswith(("postgresql://", "postgres://")):
                raise RuntimeError("DATABASE_URL must use PostgreSQL in production.")
            if len(secret_key) < 32:
                raise RuntimeError("CHIRP_SECRET_KEY must be at least 32 characters.")
            if len(claim_token) < 24:
                raise RuntimeError("SPACE_OWNER_CLAIM_TOKEN must be at least 24 characters.")
            if not canonical_origin:
                raise RuntimeError("SPACE_CANONICAL_ORIGIN is required in production.")
        else:
            database_url = database_url or "sqlite:///:memory:"
            secret_key = secret_key or secrets.token_urlsafe(48)
            claim_token = claim_token or "development-owner-claim-token"
            canonical_origin = canonical_origin or "http://localhost:8000"

        aliases = tuple(
            item.strip().lower()
            for item in (os.environ.get("SPACE_HOST_ALIASES") or "").split(",")
            if item.strip()
        )
        return cls(
            env=env,
            debug=debug,
            database_url=database_url,
            secret_key=secret_key,
            claim_token=claim_token,
            canonical_origin=normalize_origin(canonical_origin, production=production),
            host_aliases=aliases,
        )
