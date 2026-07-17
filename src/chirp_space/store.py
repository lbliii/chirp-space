"""Application-owned persistence for identity, sessions, and customization."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Protocol

from chirp_space.models import (
    FederationKey,
    InboxReceipt,
    Owner,
    ProfileModule,
    SiteSettings,
    SiteState,
    Theme,
)

SQLITE_MIGRATION = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS owners (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    id TEXT NOT NULL UNIQUE,
    handle TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    bio TEXT NOT NULL,
    location TEXT NOT NULL,
    website_url TEXT,
    password_hash TEXT NOT NULL,
    claimed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS site_settings (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    id TEXT NOT NULL UNIQUE,
    canonical_origin TEXT NOT NULL,
    palette TEXT NOT NULL,
    font TEXT NOT NULL,
    scale TEXT NOT NULL,
    density TEXT NOT NULL,
    radius TEXT NOT NULL,
    layout_width TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS profile_modules (
    kind TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    position INTEGER NOT NULL UNIQUE CHECK (position >= 0),
    config_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery_codes (
    owner_id TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL UNIQUE,
    used_at TEXT,
    PRIMARY KEY (owner_id, code_hash)
);
CREATE TABLE IF NOT EXISTS owner_sessions (
    token_hash TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_owner_sessions_active
    ON owner_sessions(owner_id, expires_at, revoked_at);
CREATE TABLE IF NOT EXISTS federation_keys (
    id TEXT PRIMARY KEY,
    public_pem TEXT NOT NULL,
    encrypted_private_pem BLOB NOT NULL,
    created_at TEXT NOT NULL,
    retired_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_federation_key_active
    ON federation_keys((retired_at IS NULL)) WHERE retired_at IS NULL;
CREATE TABLE IF NOT EXISTS inbox_receipts (
    signature_hash TEXT PRIMARY KEY,
    activity_id TEXT NOT NULL UNIQUE,
    activity_type TEXT NOT NULL,
    status TEXT NOT NULL,
    diagnostic TEXT NOT NULL,
    received_at TEXT NOT NULL
);
"""

POSTGRES_MIGRATION = (
    """CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )""",
    """CREATE TABLE IF NOT EXISTS owners (
        singleton_id SMALLINT PRIMARY KEY CHECK (singleton_id = 1),
        id UUID NOT NULL UNIQUE,
        handle TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        bio TEXT NOT NULL,
        location TEXT NOT NULL,
        website_url TEXT,
        password_hash TEXT NOT NULL,
        claimed_at TIMESTAMPTZ NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS site_settings (
        singleton_id SMALLINT PRIMARY KEY CHECK (singleton_id = 1),
        id UUID NOT NULL UNIQUE,
        canonical_origin TEXT NOT NULL,
        palette TEXT NOT NULL,
        font TEXT NOT NULL,
        scale TEXT NOT NULL,
        density TEXT NOT NULL,
        radius TEXT NOT NULL,
        layout_width TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK (revision >= 1),
        updated_at TIMESTAMPTZ NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS profile_modules (
        kind TEXT PRIMARY KEY,
        enabled BOOLEAN NOT NULL,
        position INTEGER NOT NULL UNIQUE CHECK (position >= 0),
        config_json TEXT NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS recovery_codes (
        owner_id UUID NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
        code_hash TEXT NOT NULL UNIQUE,
        used_at TIMESTAMPTZ,
        PRIMARY KEY (owner_id, code_hash)
    )""",
    """CREATE TABLE IF NOT EXISTS owner_sessions (
        token_hash TEXT PRIMARY KEY,
        owner_id UUID NOT NULL REFERENCES owners(id) ON DELETE CASCADE,
        expires_at TIMESTAMPTZ NOT NULL,
        revoked_at TIMESTAMPTZ
    )""",
    """CREATE INDEX IF NOT EXISTS idx_owner_sessions_active
        ON owner_sessions(owner_id, expires_at, revoked_at)""",
    """CREATE TABLE IF NOT EXISTS federation_keys (
        id UUID PRIMARY KEY,
        public_pem TEXT NOT NULL,
        encrypted_private_pem BYTEA NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        retired_at TIMESTAMPTZ
    )""",
    """CREATE UNIQUE INDEX IF NOT EXISTS idx_federation_key_active
        ON federation_keys((retired_at IS NULL)) WHERE retired_at IS NULL""",
    """CREATE TABLE IF NOT EXISTS inbox_receipts (
        signature_hash TEXT PRIMARY KEY,
        activity_id TEXT NOT NULL UNIQUE,
        activity_type TEXT NOT NULL,
        status TEXT NOT NULL,
        diagnostic TEXT NOT NULL,
        received_at TIMESTAMPTZ NOT NULL
    )""",
)


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class Store(Protocol):
    def migrate(self) -> None: ...
    def close(self) -> None: ...
    def probe(self) -> bool: ...
    def state(self) -> SiteState | None: ...
    def bootstrap(
        self,
        *,
        owner: Owner,
        settings: SiteSettings,
        modules: Sequence[ProfileModule],
        recovery_code_hashes: Sequence[str],
    ) -> None: ...
    def create_session(self, owner_id: str, hashed_token: str, expires_at: datetime) -> None: ...
    def owner_for_session(self, hashed_token: str, now: datetime) -> Owner | None: ...
    def revoke_session(self, hashed_token: str) -> None: ...
    def revoke_all_sessions(self, owner_id: str) -> None: ...
    def consume_recovery_code(self, owner_id: str, hashed_code: str) -> bool: ...
    def update_customization(
        self,
        *,
        owner: Owner,
        settings: SiteSettings,
        modules: Sequence[ProfileModule],
        expected_revision: int,
    ) -> SiteState: ...
    def active_federation_key(self) -> FederationKey | None: ...
    def federation_key(self, key_id: str) -> FederationKey | None: ...
    def create_federation_key(self, key: FederationKey) -> None: ...
    def rotate_federation_key(self, key: FederationKey, *, retired_at: datetime) -> None: ...
    def record_inbox_receipt(self, receipt: InboxReceipt) -> bool: ...
    def inbox_receipts(self) -> tuple[InboxReceipt, ...]: ...


class SQLiteStore:
    """Persistent local adapter used for development and deterministic proof."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._connection = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.row_factory = sqlite3.Row
        self._lock = RLock()

    def migrate(self) -> None:
        with self._lock:
            self._connection.executescript(SQLITE_MIGRATION)
            self._connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, name, applied_at) VALUES (1, ?, ?)",
                ("local identity and customization foundation", _iso(datetime.now(UTC))),
            )
            self._connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, name, applied_at) VALUES (2, ?, ?)",
                ("federation identity and inbox receipts", _iso(datetime.now(UTC))),
            )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def probe(self) -> bool:
        with self._lock:
            return self._connection.execute("SELECT 1").fetchone() is not None

    def state(self) -> SiteState | None:
        with self._lock:
            owner_row = self._connection.execute(
                "SELECT * FROM owners WHERE singleton_id = 1"
            ).fetchone()
            if owner_row is None:
                return None
            settings_row = self._connection.execute(
                "SELECT * FROM site_settings WHERE singleton_id = 1"
            ).fetchone()
            module_rows = self._connection.execute(
                "SELECT * FROM profile_modules ORDER BY position"
            ).fetchall()
        if settings_row is None:
            raise RuntimeError("Space owner exists without site settings.")
        return _state_from_rows(owner_row, settings_row, module_rows)

    def bootstrap(
        self,
        *,
        owner: Owner,
        settings: SiteSettings,
        modules: Sequence[ProfileModule],
        recovery_code_hashes: Sequence[str],
    ) -> None:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                if self._connection.execute("SELECT 1 FROM owners").fetchone() is not None:
                    raise RuntimeError("Space setup is already complete.")
                self._connection.execute(
                    """INSERT INTO owners(
                        singleton_id, id, handle, display_name, bio, location, website_url,
                        password_hash, claimed_at
                    ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        owner.id,
                        owner.handle,
                        owner.display_name,
                        owner.bio,
                        owner.location,
                        owner.website_url,
                        owner.password_hash,
                        _iso(owner.claimed_at),
                    ),
                )
                self._insert_settings(settings)
                self._insert_modules(modules, settings.updated_at)
                self._connection.executemany(
                    "INSERT INTO recovery_codes(owner_id, code_hash) VALUES (?, ?)",
                    [(owner.id, value) for value in recovery_code_hashes],
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def create_session(self, owner_id: str, hashed_token: str, expires_at: datetime) -> None:
        with self._lock:
            self._connection.execute(
                "INSERT INTO owner_sessions(token_hash, owner_id, expires_at) VALUES (?, ?, ?)",
                (hashed_token, owner_id, _iso(expires_at)),
            )

    def owner_for_session(self, hashed_token: str, now: datetime) -> Owner | None:
        with self._lock:
            row = self._connection.execute(
                """SELECT owners.* FROM owner_sessions AS session
                JOIN owners ON owners.id = session.owner_id
                WHERE session.token_hash = ? AND session.revoked_at IS NULL
                  AND session.expires_at > ?""",
                (hashed_token, _iso(now)),
            ).fetchone()
        return _owner_from_row(row) if row is not None else None

    def revoke_session(self, hashed_token: str) -> None:
        with self._lock:
            self._connection.execute(
                "UPDATE owner_sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
                (_iso(datetime.now(UTC)), hashed_token),
            )

    def revoke_all_sessions(self, owner_id: str) -> None:
        with self._lock:
            self._connection.execute(
                "UPDATE owner_sessions SET revoked_at = ? WHERE owner_id = ? AND revoked_at IS NULL",
                (_iso(datetime.now(UTC)), owner_id),
            )

    def consume_recovery_code(self, owner_id: str, hashed_code: str) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                """UPDATE recovery_codes SET used_at = ?
                WHERE owner_id = ? AND code_hash = ? AND used_at IS NULL""",
                (_iso(datetime.now(UTC)), owner_id, hashed_code),
            )
            return cursor.rowcount == 1

    def update_customization(
        self,
        *,
        owner: Owner,
        settings: SiteSettings,
        modules: Sequence[ProfileModule],
        expected_revision: int,
    ) -> SiteState:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                cursor = self._connection.execute(
                    """UPDATE site_settings SET canonical_origin = ?, palette = ?, font = ?,
                    scale = ?, density = ?, radius = ?, layout_width = ?, revision = ?, updated_at = ?
                    WHERE singleton_id = 1 AND revision = ?""",
                    (
                        settings.canonical_origin,
                        settings.theme.palette,
                        settings.theme.font,
                        settings.theme.scale,
                        settings.theme.density,
                        settings.theme.radius,
                        settings.theme.layout_width,
                        settings.revision,
                        _iso(settings.updated_at),
                        expected_revision,
                    ),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError(
                        "Customization changed in another session. Reload and try again."
                    )
                self._connection.execute(
                    """UPDATE owners SET display_name = ?, bio = ?, location = ?, website_url = ?
                    WHERE singleton_id = 1""",
                    (owner.display_name, owner.bio, owner.location, owner.website_url),
                )
                self._connection.execute("DELETE FROM profile_modules")
                self._insert_modules(modules, settings.updated_at)
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        result = self.state()
        if result is None:
            raise RuntimeError("Customization update removed the Space owner state.")
        return result

    def _insert_settings(self, settings: SiteSettings) -> None:
        self._connection.execute(
            """INSERT INTO site_settings(
                singleton_id, id, canonical_origin, palette, font, scale, density, radius,
                layout_width, revision, updated_at
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                settings.id,
                settings.canonical_origin,
                settings.theme.palette,
                settings.theme.font,
                settings.theme.scale,
                settings.theme.density,
                settings.theme.radius,
                settings.theme.layout_width,
                settings.revision,
                _iso(settings.updated_at),
            ),
        )

    def _insert_modules(self, modules: Sequence[ProfileModule], now: datetime) -> None:
        self._connection.executemany(
            """INSERT INTO profile_modules(kind, enabled, position, config_json, updated_at)
            VALUES (?, ?, ?, ?, ?)""",
            [
                (
                    module.kind,
                    int(module.enabled),
                    module.position,
                    json.dumps(module.config),
                    _iso(now),
                )
                for module in modules
            ],
        )

    def active_federation_key(self) -> FederationKey | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM federation_keys WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return FederationKey(
            id=str(row["id"]),
            public_pem=str(row["public_pem"]),
            encrypted_private_pem=bytes(row["encrypted_private_pem"]),
            created_at=_datetime(row["created_at"]),
            retired_at=_datetime(row["retired_at"]) if row["retired_at"] else None,
        )

    def create_federation_key(self, key: FederationKey) -> None:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                if self._connection.execute(
                    "SELECT 1 FROM federation_keys WHERE retired_at IS NULL"
                ).fetchone():
                    raise RuntimeError("An active federation key already exists.")
                self._connection.execute(
                    """INSERT INTO federation_keys(
                        id, public_pem, encrypted_private_pem, created_at, retired_at
                    ) VALUES (?, ?, ?, ?, ?)""",
                    (
                        key.id,
                        key.public_pem,
                        key.encrypted_private_pem,
                        _iso(key.created_at),
                        _iso(key.retired_at) if key.retired_at else None,
                    ),
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def federation_key(self, key_id: str) -> FederationKey | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM federation_keys WHERE id = ?", (key_id,)
            ).fetchone()
        if row is None:
            return None
        return FederationKey(
            id=str(row["id"]),
            public_pem=str(row["public_pem"]),
            encrypted_private_pem=bytes(row["encrypted_private_pem"]),
            created_at=_datetime(row["created_at"]),
            retired_at=_datetime(row["retired_at"]) if row["retired_at"] else None,
        )

    def rotate_federation_key(self, key: FederationKey, *, retired_at: datetime) -> None:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                updated = self._connection.execute(
                    "UPDATE federation_keys SET retired_at = ? WHERE retired_at IS NULL",
                    (_iso(retired_at),),
                )
                if updated.rowcount != 1:
                    raise RuntimeError("Federation key rotation requires one active key.")
                self._connection.execute(
                    """INSERT INTO federation_keys(
                        id, public_pem, encrypted_private_pem, created_at, retired_at
                    ) VALUES (?, ?, ?, ?, NULL)""",
                    (key.id, key.public_pem, key.encrypted_private_pem, _iso(key.created_at)),
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def record_inbox_receipt(self, receipt: InboxReceipt) -> bool:
        with self._lock:
            try:
                self._connection.execute(
                    """INSERT INTO inbox_receipts(
                        signature_hash, activity_id, activity_type, status, diagnostic, received_at
                    ) VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        receipt.signature_hash,
                        receipt.activity_id,
                        receipt.activity_type,
                        receipt.status,
                        receipt.diagnostic,
                        _iso(receipt.received_at),
                    ),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def inbox_receipts(self) -> tuple[InboxReceipt, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM inbox_receipts ORDER BY received_at"
            ).fetchall()
        return tuple(
            InboxReceipt(
                signature_hash=str(row["signature_hash"]),
                activity_id=str(row["activity_id"]),
                activity_type=str(row["activity_type"]),
                status=str(row["status"]),
                diagnostic=str(row["diagnostic"]),
                received_at=_datetime(row["received_at"]),
            )
            for row in rows
        )


class PostgresStore:
    """Production PostgreSQL adapter with transactional single-owner setup."""

    def __init__(self, database_url: str) -> None:
        from psycopg_pool import ConnectionPool

        self._pool = ConnectionPool(database_url, min_size=1, max_size=5, open=True)

    def migrate(self) -> None:
        with self._pool.connection() as connection, connection.transaction():
            for statement in POSTGRES_MIGRATION:
                connection.execute(statement)
            connection.execute(
                """INSERT INTO schema_migrations(version, name) VALUES (1, %s)
                ON CONFLICT (version) DO NOTHING""",
                ("local identity and customization foundation",),
            )
            connection.execute(
                """INSERT INTO schema_migrations(version, name) VALUES (2, %s)
                ON CONFLICT (version) DO NOTHING""",
                ("federation identity and inbox receipts",),
            )

    def close(self) -> None:
        self._pool.close()

    def probe(self) -> bool:
        with self._pool.connection() as connection:
            return connection.execute("SELECT 1").fetchone() is not None

    def state(self) -> SiteState | None:
        with self._pool.connection() as connection:
            owner_row = connection.execute("SELECT * FROM owners WHERE singleton_id = 1").fetchone()
            if owner_row is None:
                return None
            settings_row = connection.execute(
                "SELECT * FROM site_settings WHERE singleton_id = 1"
            ).fetchone()
            module_rows = connection.execute(
                "SELECT * FROM profile_modules ORDER BY position"
            ).fetchall()
        if settings_row is None:
            raise RuntimeError("Space owner exists without site settings.")
        return _state_from_sequences(owner_row, settings_row, module_rows)

    def bootstrap(
        self,
        *,
        owner: Owner,
        settings: SiteSettings,
        modules: Sequence[ProfileModule],
        recovery_code_hashes: Sequence[str],
    ) -> None:
        with self._pool.connection() as connection, connection.transaction():
            connection.execute("SELECT pg_advisory_xact_lock(790)")
            if connection.execute("SELECT 1 FROM owners").fetchone() is not None:
                raise RuntimeError("Space setup is already complete.")
            connection.execute(
                """INSERT INTO owners(
                    singleton_id, id, handle, display_name, bio, location, website_url,
                    password_hash, claimed_at
                ) VALUES (1, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    owner.id,
                    owner.handle,
                    owner.display_name,
                    owner.bio,
                    owner.location,
                    owner.website_url,
                    owner.password_hash,
                    owner.claimed_at,
                ),
            )
            connection.execute(
                """INSERT INTO site_settings(
                    singleton_id, id, canonical_origin, palette, font, scale, density, radius,
                    layout_width, revision, updated_at
                ) VALUES (1, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                _settings_values(settings),
            )
            connection.cursor().executemany(
                """INSERT INTO profile_modules(kind, enabled, position, config_json, updated_at)
                VALUES (%s, %s, %s, %s, %s)""",
                _module_values(modules, settings.updated_at),
            )
            connection.cursor().executemany(
                "INSERT INTO recovery_codes(owner_id, code_hash) VALUES (%s, %s)",
                [(owner.id, value) for value in recovery_code_hashes],
            )

    def create_session(self, owner_id: str, hashed_token: str, expires_at: datetime) -> None:
        with self._pool.connection() as connection:
            connection.execute(
                "INSERT INTO owner_sessions(token_hash, owner_id, expires_at) VALUES (%s, %s, %s)",
                (hashed_token, owner_id, expires_at),
            )

    def owner_for_session(self, hashed_token: str, now: datetime) -> Owner | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                """SELECT owners.* FROM owner_sessions AS session
                JOIN owners ON owners.id = session.owner_id
                WHERE session.token_hash = %s AND session.revoked_at IS NULL
                  AND session.expires_at > %s""",
                (hashed_token, now),
            ).fetchone()
        return _owner_from_sequence(row) if row is not None else None

    def revoke_session(self, hashed_token: str) -> None:
        with self._pool.connection() as connection:
            connection.execute(
                "UPDATE owner_sessions SET revoked_at = now() WHERE token_hash = %s AND revoked_at IS NULL",
                (hashed_token,),
            )

    def revoke_all_sessions(self, owner_id: str) -> None:
        with self._pool.connection() as connection:
            connection.execute(
                "UPDATE owner_sessions SET revoked_at = now() WHERE owner_id = %s AND revoked_at IS NULL",
                (owner_id,),
            )

    def consume_recovery_code(self, owner_id: str, hashed_code: str) -> bool:
        with self._pool.connection() as connection:
            row = connection.execute(
                """UPDATE recovery_codes SET used_at = now()
                WHERE owner_id = %s AND code_hash = %s AND used_at IS NULL
                RETURNING code_hash""",
                (owner_id, hashed_code),
            ).fetchone()
        return row is not None

    def update_customization(
        self,
        *,
        owner: Owner,
        settings: SiteSettings,
        modules: Sequence[ProfileModule],
        expected_revision: int,
    ) -> SiteState:
        with self._pool.connection() as connection, connection.transaction():
            row = connection.execute(
                """UPDATE site_settings SET canonical_origin = %s, palette = %s, font = %s,
                scale = %s, density = %s, radius = %s, layout_width = %s,
                revision = %s, updated_at = %s
                WHERE singleton_id = 1 AND revision = %s RETURNING id""",
                (
                    settings.canonical_origin,
                    settings.theme.palette,
                    settings.theme.font,
                    settings.theme.scale,
                    settings.theme.density,
                    settings.theme.radius,
                    settings.theme.layout_width,
                    settings.revision,
                    settings.updated_at,
                    expected_revision,
                ),
            ).fetchone()
            if row is None:
                raise RuntimeError(
                    "Customization changed in another session. Reload and try again."
                )
            connection.execute(
                """UPDATE owners SET display_name = %s, bio = %s, location = %s, website_url = %s
                WHERE singleton_id = 1""",
                (owner.display_name, owner.bio, owner.location, owner.website_url),
            )
            connection.execute("DELETE FROM profile_modules")
            connection.cursor().executemany(
                """INSERT INTO profile_modules(kind, enabled, position, config_json, updated_at)
                VALUES (%s, %s, %s, %s, %s)""",
                _module_values(modules, settings.updated_at),
            )
        result = self.state()
        if result is None:
            raise RuntimeError("Customization update removed the Space owner state.")
        return result

    def active_federation_key(self) -> FederationKey | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT * FROM federation_keys WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return FederationKey(
            id=str(row[0]),
            public_pem=str(row[1]),
            encrypted_private_pem=bytes(row[2]),
            created_at=_datetime(row[3]),
            retired_at=_datetime(row[4]) if row[4] else None,
        )

    def create_federation_key(self, key: FederationKey) -> None:
        with self._pool.connection() as connection, connection.transaction():
            connection.execute("SELECT pg_advisory_xact_lock(793)")
            if connection.execute(
                "SELECT 1 FROM federation_keys WHERE retired_at IS NULL"
            ).fetchone():
                raise RuntimeError("An active federation key already exists.")
            connection.execute(
                """INSERT INTO federation_keys(
                    id, public_pem, encrypted_private_pem, created_at, retired_at
                ) VALUES (%s, %s, %s, %s, %s)""",
                (
                    key.id,
                    key.public_pem,
                    key.encrypted_private_pem,
                    key.created_at,
                    key.retired_at,
                ),
            )

    def federation_key(self, key_id: str) -> FederationKey | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                "SELECT * FROM federation_keys WHERE id = %s", (key_id,)
            ).fetchone()
        if row is None:
            return None
        return FederationKey(
            id=str(row[0]),
            public_pem=str(row[1]),
            encrypted_private_pem=bytes(row[2]),
            created_at=_datetime(row[3]),
            retired_at=_datetime(row[4]) if row[4] else None,
        )

    def rotate_federation_key(self, key: FederationKey, *, retired_at: datetime) -> None:
        with self._pool.connection() as connection, connection.transaction():
            connection.execute("SELECT pg_advisory_xact_lock(793)")
            retired = connection.execute(
                """UPDATE federation_keys SET retired_at = %s
                WHERE retired_at IS NULL RETURNING id""",
                (retired_at,),
            ).fetchone()
            if retired is None:
                raise RuntimeError("Federation key rotation requires one active key.")
            connection.execute(
                """INSERT INTO federation_keys(
                    id, public_pem, encrypted_private_pem, created_at, retired_at
                ) VALUES (%s, %s, %s, %s, NULL)""",
                (key.id, key.public_pem, key.encrypted_private_pem, key.created_at),
            )

    def record_inbox_receipt(self, receipt: InboxReceipt) -> bool:
        with self._pool.connection() as connection:
            row = connection.execute(
                """INSERT INTO inbox_receipts(
                    signature_hash, activity_id, activity_type, status, diagnostic, received_at
                ) VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING RETURNING signature_hash""",
                (
                    receipt.signature_hash,
                    receipt.activity_id,
                    receipt.activity_type,
                    receipt.status,
                    receipt.diagnostic,
                    receipt.received_at,
                ),
            ).fetchone()
        return row is not None

    def inbox_receipts(self) -> tuple[InboxReceipt, ...]:
        with self._pool.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM inbox_receipts ORDER BY received_at"
            ).fetchall()
        return tuple(_inbox_receipt_from_sequence(row) for row in rows)


def store_from_url(database_url: str) -> Store:
    if database_url.startswith("sqlite:///"):
        path = database_url.removeprefix("sqlite:///")
        return SQLiteStore(path or ":memory:")
    if database_url.startswith(("postgresql://", "postgres://")):
        return PostgresStore(database_url)
    raise RuntimeError("DATABASE_URL must use sqlite:/// locally or PostgreSQL in production.")


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _datetime(value: object) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(UTC)
    return datetime.fromisoformat(str(value)).astimezone(UTC)


def _owner_from_row(row: sqlite3.Row) -> Owner:
    return Owner(
        id=str(row["id"]),
        handle=str(row["handle"]),
        display_name=str(row["display_name"]),
        bio=str(row["bio"]),
        location=str(row["location"]),
        website_url=str(row["website_url"]) if row["website_url"] else None,
        password_hash=str(row["password_hash"]),
        claimed_at=_datetime(row["claimed_at"]),
    )


def _owner_from_sequence(row: Sequence[object]) -> Owner:
    return Owner(
        id=str(row[1]),
        handle=str(row[2]),
        display_name=str(row[3]),
        bio=str(row[4]),
        location=str(row[5]),
        website_url=str(row[6]) if row[6] else None,
        password_hash=str(row[7]),
        claimed_at=_datetime(row[8]),
    )


def _state_from_rows(
    owner_row: sqlite3.Row, settings_row: sqlite3.Row, module_rows: Sequence[sqlite3.Row]
) -> SiteState:
    owner = _owner_from_row(owner_row)
    settings = SiteSettings(
        id=str(settings_row["id"]),
        canonical_origin=str(settings_row["canonical_origin"]),
        theme=Theme(
            palette=str(settings_row["palette"]),
            font=str(settings_row["font"]),
            scale=str(settings_row["scale"]),
            density=str(settings_row["density"]),
            radius=str(settings_row["radius"]),
            layout_width=str(settings_row["layout_width"]),
        ),
        revision=int(settings_row["revision"]),
        updated_at=_datetime(settings_row["updated_at"]),
    )
    modules = tuple(
        ProfileModule(
            kind=str(row["kind"]),
            enabled=bool(row["enabled"]),
            position=int(row["position"]),
            config=json.loads(str(row["config_json"])),
        )
        for row in module_rows
    )
    return SiteState(owner, settings, modules)


def _state_from_sequences(
    owner_row: Sequence[object],
    settings_row: Sequence[object],
    module_rows: Sequence[Sequence[object]],
) -> SiteState:
    owner = _owner_from_sequence(owner_row)
    settings = SiteSettings(
        id=str(settings_row[1]),
        canonical_origin=str(settings_row[2]),
        theme=Theme(
            palette=str(settings_row[3]),
            font=str(settings_row[4]),
            scale=str(settings_row[5]),
            density=str(settings_row[6]),
            radius=str(settings_row[7]),
            layout_width=str(settings_row[8]),
        ),
        revision=int(str(settings_row[9])),
        updated_at=_datetime(settings_row[10]),
    )
    modules = tuple(
        ProfileModule(
            kind=str(row[0]),
            enabled=bool(row[1]),
            position=int(str(row[2])),
            config=json.loads(str(row[3])),
        )
        for row in module_rows
    )
    return SiteState(owner, settings, modules)


def _settings_values(settings: SiteSettings) -> tuple[object, ...]:
    return (
        settings.id,
        settings.canonical_origin,
        settings.theme.palette,
        settings.theme.font,
        settings.theme.scale,
        settings.theme.density,
        settings.theme.radius,
        settings.theme.layout_width,
        settings.revision,
        settings.updated_at,
    )


def _module_values(modules: Sequence[ProfileModule], now: datetime) -> list[tuple[object, ...]]:
    return [
        (module.kind, module.enabled, module.position, json.dumps(module.config), now)
        for module in modules
    ]


def _inbox_receipt_from_sequence(row: Sequence[object]) -> InboxReceipt:
    return InboxReceipt(
        signature_hash=str(row[0]),
        activity_id=str(row[1]),
        activity_type=str(row[2]),
        status=str(row[3]),
        diagnostic=str(row[4]),
        received_at=_datetime(row[5]),
    )
