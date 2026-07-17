"""Application-owned persistence for identity, sessions, and customization."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock
from typing import Protocol

from chirp_space.models import (
    Circle,
    Delivery,
    DeliveryJob,
    FederationKey,
    InboxReceipt,
    OutboundActivity,
    Owner,
    ProfileModule,
    QueueHealth,
    Relationship,
    RemoteActor,
    SiteSettings,
    SiteState,
    Theme,
)

MAX_ACTIVE_DELIVERIES = 10_000

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
    body_hash TEXT NOT NULL,
    activity_type TEXT NOT NULL,
    status TEXT NOT NULL,
    diagnostic TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS outbound_activities (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL,
    activity_type TEXT NOT NULL,
    object_id TEXT,
    body BLOB NOT NULL,
    body_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
    id TEXT PRIMARY KEY,
    activity_id TEXT NOT NULL REFERENCES outbound_activities(id) ON DELETE CASCADE,
    inbox_url TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'retrying', 'delivered', 'dead', 'discarded')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TEXT NOT NULL,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(activity_id, inbox_url)
);
CREATE INDEX IF NOT EXISTS idx_deliveries_due
    ON deliveries(status, next_attempt_at, inbox_url, created_at);
CREATE TABLE IF NOT EXISTS delivery_peers (
    inbox_url TEXT PRIMARY KEY,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    circuit_open_until TEXT,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS remote_actors (
    id TEXT PRIMARY KEY,
    inbox_url TEXT NOT NULL,
    preferred_username TEXT NOT NULL,
    display_name TEXT NOT NULL,
    domain TEXT NOT NULL,
    last_contact_at TEXT NOT NULL,
    deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS relationships (
    actor_id TEXT PRIMARY KEY REFERENCES remote_actors(id) ON DELETE CASCADE,
    outbound_state TEXT NOT NULL CHECK (
        outbound_state IN ('none', 'pending', 'following', 'rejected', 'removed', 'remote-deleted', 'unavailable')
    ),
    inbound_state TEXT NOT NULL CHECK (
        inbound_state IN ('none', 'pending', 'follower', 'rejected', 'removed')
    ),
    outbound_follow_id TEXT,
    inbound_follow_id TEXT,
    pinned INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
    muted INTEGER NOT NULL DEFAULT 0 CHECK (muted IN (0, 1)),
    blocked INTEGER NOT NULL DEFAULT 0 CHECK (blocked IN (0, 1)),
    unavailable INTEGER NOT NULL DEFAULT 0 CHECK (unavailable IN (0, 1)),
    note TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS circles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS circle_members (
    circle_id TEXT NOT NULL REFERENCES circles(id) ON DELETE CASCADE,
    actor_id TEXT NOT NULL REFERENCES relationships(actor_id) ON DELETE CASCADE,
    PRIMARY KEY(circle_id, actor_id)
);
CREATE TABLE IF NOT EXISTS domain_blocks (
    domain TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
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
        body_hash TEXT NOT NULL,
        activity_type TEXT NOT NULL,
        status TEXT NOT NULL,
        diagnostic TEXT NOT NULL,
        received_at TIMESTAMPTZ NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS outbound_activities (
        id TEXT PRIMARY KEY,
        actor_id TEXT NOT NULL,
        activity_type TEXT NOT NULL,
        object_id TEXT,
        body BYTEA NOT NULL,
        body_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS deliveries (
        id UUID PRIMARY KEY,
        activity_id TEXT NOT NULL REFERENCES outbound_activities(id) ON DELETE CASCADE,
        inbox_url TEXT NOT NULL,
        status TEXT NOT NULL CHECK (
            status IN ('pending', 'retrying', 'delivered', 'dead', 'discarded')
        ),
        attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
        next_attempt_at TIMESTAMPTZ NOT NULL,
        last_error TEXT,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        UNIQUE(activity_id, inbox_url)
    )""",
    """CREATE INDEX IF NOT EXISTS idx_deliveries_due
        ON deliveries(status, next_attempt_at, inbox_url, created_at)""",
    """CREATE TABLE IF NOT EXISTS delivery_peers (
        inbox_url TEXT PRIMARY KEY,
        consecutive_failures INTEGER NOT NULL DEFAULT 0,
        circuit_open_until TIMESTAMPTZ,
        updated_at TIMESTAMPTZ NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS remote_actors (
        id TEXT PRIMARY KEY,
        inbox_url TEXT NOT NULL,
        preferred_username TEXT NOT NULL,
        display_name TEXT NOT NULL,
        domain TEXT NOT NULL,
        last_contact_at TIMESTAMPTZ NOT NULL,
        deleted_at TIMESTAMPTZ
    )""",
    """CREATE TABLE IF NOT EXISTS relationships (
        actor_id TEXT PRIMARY KEY REFERENCES remote_actors(id) ON DELETE CASCADE,
        outbound_state TEXT NOT NULL CHECK (
            outbound_state IN (
                'none', 'pending', 'following', 'rejected', 'removed', 'remote-deleted', 'unavailable'
            )
        ),
        inbound_state TEXT NOT NULL CHECK (
            inbound_state IN ('none', 'pending', 'follower', 'rejected', 'removed')
        ),
        outbound_follow_id TEXT,
        inbound_follow_id TEXT,
        pinned BOOLEAN NOT NULL DEFAULT FALSE,
        muted BOOLEAN NOT NULL DEFAULT FALSE,
        blocked BOOLEAN NOT NULL DEFAULT FALSE,
        unavailable BOOLEAN NOT NULL DEFAULT FALSE,
        note TEXT NOT NULL DEFAULT '',
        updated_at TIMESTAMPTZ NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS circles (
        id UUID PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        created_at TIMESTAMPTZ NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS circle_members (
        circle_id UUID NOT NULL REFERENCES circles(id) ON DELETE CASCADE,
        actor_id TEXT NOT NULL REFERENCES relationships(actor_id) ON DELETE CASCADE,
        PRIMARY KEY(circle_id, actor_id)
    )""",
    """CREATE TABLE IF NOT EXISTS domain_blocks (
        domain TEXT PRIMARY KEY,
        created_at TIMESTAMPTZ NOT NULL
    )""",
)

RELATIONSHIP_SELECT = """SELECT
    a.id, a.inbox_url, a.preferred_username, a.display_name, a.domain,
    a.last_contact_at, a.deleted_at, r.outbound_state, r.inbound_state,
    r.outbound_follow_id, r.inbound_follow_id,
    r.pinned, r.muted,
    (r.blocked OR EXISTS(SELECT 1 FROM domain_blocks b WHERE b.domain = a.domain))
        AS effective_blocked,
    r.unavailable, r.note, r.updated_at
FROM relationships r JOIN remote_actors a ON a.id = r.actor_id"""


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
    def record_inbox_receipt(self, receipt: InboxReceipt) -> str: ...
    def inbox_receipts(self) -> tuple[InboxReceipt, ...]: ...
    def enqueue_activity(
        self, activity: OutboundActivity, inbox_urls: Sequence[str]
    ) -> tuple[Delivery, ...]: ...
    def due_delivery_jobs(self, *, now: datetime, limit: int) -> tuple[DeliveryJob, ...]: ...
    def update_delivery(
        self, delivery: Delivery, *, circuit_open_until: datetime | None = None
    ) -> None: ...
    def delivery(self, delivery_id: str) -> Delivery | None: ...
    def retry_delivery(self, delivery_id: str, *, now: datetime) -> bool: ...
    def discard_delivery(self, delivery_id: str, *, now: datetime) -> bool: ...
    def queue_health(self, *, now: datetime) -> QueueHealth: ...
    def upsert_remote_actor(self, actor: RemoteActor) -> Relationship: ...
    def relationship(self, actor_id: str) -> Relationship | None: ...
    def relationships(self) -> tuple[Relationship, ...]: ...
    def save_relationship(self, relationship: Relationship) -> Relationship: ...
    def create_circle(self, circle: Circle) -> Circle: ...
    def circles(self) -> tuple[Circle, ...]: ...
    def set_circle_members(self, circle_id: str, actor_ids: Sequence[str]) -> Circle: ...
    def block_actor(self, actor_id: str, *, now: datetime) -> Relationship: ...
    def unblock_actor(self, actor_id: str, *, now: datetime) -> Relationship: ...
    def block_domain(self, domain: str, *, now: datetime) -> None: ...
    def unblock_domain(self, domain: str) -> None: ...
    def blocked_domains(self) -> tuple[str, ...]: ...
    def is_blocked(self, actor_id: str | None = None, domain: str | None = None) -> bool: ...


class SQLiteStore:
    """Persistent local adapter used for development and deterministic proof."""

    def __init__(
        self,
        path: str | Path = ":memory:",
        *,
        max_active_deliveries: int = MAX_ACTIVE_DELIVERIES,
    ) -> None:
        self._connection = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.row_factory = sqlite3.Row
        self._lock = RLock()
        self._max_active_deliveries = max_active_deliveries

    def migrate(self) -> None:
        with self._lock:
            self._connection.executescript(SQLITE_MIGRATION)
            inbox_columns = {
                str(row[1]) for row in self._connection.execute("PRAGMA table_info(inbox_receipts)")
            }
            if "body_hash" not in inbox_columns:
                self._connection.execute(
                    "ALTER TABLE inbox_receipts ADD COLUMN body_hash TEXT NOT NULL DEFAULT ''"
                )
            self._connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, name, applied_at) VALUES (1, ?, ?)",
                ("local identity and customization foundation", _iso(datetime.now(UTC))),
            )
            self._connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, name, applied_at) VALUES (2, ?, ?)",
                ("federation identity and inbox receipts", _iso(datetime.now(UTC))),
            )
            self._connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, name, applied_at) VALUES (3, ?, ?)",
                ("durable federation activities and deliveries", _iso(datetime.now(UTC))),
            )
            self._connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, name, applied_at) VALUES (4, ?, ?)",
                ("asymmetric relationships and local circles", _iso(datetime.now(UTC))),
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

    def record_inbox_receipt(self, receipt: InboxReceipt) -> str:
        with self._lock:
            try:
                self._connection.execute(
                    """INSERT INTO inbox_receipts(
                        signature_hash, activity_id, body_hash, activity_type,
                        status, diagnostic, received_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        receipt.signature_hash,
                        receipt.activity_id,
                        receipt.body_hash,
                        receipt.activity_type,
                        receipt.status,
                        receipt.diagnostic,
                        _iso(receipt.received_at),
                    ),
                )
            except sqlite3.IntegrityError:
                replay = self._connection.execute(
                    "SELECT 1 FROM inbox_receipts WHERE signature_hash = ?",
                    (receipt.signature_hash,),
                ).fetchone()
                if replay is not None:
                    return "replay"
                existing = self._connection.execute(
                    "SELECT body_hash FROM inbox_receipts WHERE activity_id = ?",
                    (receipt.activity_id,),
                ).fetchone()
                if existing is not None:
                    return "duplicate" if existing[0] == receipt.body_hash else "conflict"
                return "replay"
        return "created"

    def inbox_receipts(self) -> tuple[InboxReceipt, ...]:
        with self._lock:
            rows = self._connection.execute(
                """SELECT signature_hash, activity_id, body_hash, activity_type,
                status, diagnostic, received_at FROM inbox_receipts ORDER BY received_at"""
            ).fetchall()
        return tuple(
            InboxReceipt(
                signature_hash=str(row["signature_hash"]),
                activity_id=str(row["activity_id"]),
                body_hash=str(row["body_hash"]),
                activity_type=str(row["activity_type"]),
                status=str(row["status"]),
                diagnostic=str(row["diagnostic"]),
                received_at=_datetime(row["received_at"]),
            )
            for row in rows
        )

    def enqueue_activity(
        self, activity: OutboundActivity, inbox_urls: Sequence[str]
    ) -> tuple[Delivery, ...]:
        if len(inbox_urls) > 500:
            raise ValueError("Federation fan-out cannot exceed 500 inboxes.")
        destinations = tuple(dict.fromkeys(inbox_urls))
        now = activity.created_at
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                existing = self._connection.execute(
                    "SELECT body FROM outbound_activities WHERE id = ?", (activity.id,)
                ).fetchone()
                if existing is None:
                    self._connection.execute(
                        """INSERT INTO outbound_activities(
                            id, actor_id, activity_type, object_id, body, body_hash, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (
                            activity.id,
                            activity.actor_id,
                            activity.activity_type,
                            activity.object_id,
                            activity.body,
                            hashlib.sha256(activity.body).hexdigest(),
                            _iso(activity.created_at),
                        ),
                    )
                elif bytes(existing[0]) != activity.body:
                    raise RuntimeError("Outbound activity ID already has different content.")
                existing_destinations = {
                    str(row[0])
                    for row in self._connection.execute(
                        "SELECT inbox_url FROM deliveries WHERE activity_id = ?", (activity.id,)
                    )
                }
                new_delivery_count = len(set(destinations) - existing_destinations)
                active_row = self._connection.execute(
                    """SELECT COUNT(*) FROM deliveries
                    WHERE status IN ('pending', 'retrying')"""
                ).fetchone()
                active_count = int(active_row[0]) if active_row is not None else 0
                if active_count + new_delivery_count > self._max_active_deliveries:
                    raise RuntimeError("Federation delivery queue is full.")
                for inbox_url in destinations:
                    self._connection.execute(
                        """INSERT OR IGNORE INTO deliveries(
                            id, activity_id, inbox_url, status, attempts, next_attempt_at,
                            last_error, created_at, updated_at
                        ) VALUES (?, ?, ?, 'pending', 0, ?, NULL, ?, ?)""",
                        (
                            str(uuid.uuid7()),
                            activity.id,
                            inbox_url,
                            _iso(now),
                            _iso(now),
                            _iso(now),
                        ),
                    )
                rows = self._connection.execute(
                    "SELECT * FROM deliveries WHERE activity_id = ? ORDER BY inbox_url",
                    (activity.id,),
                ).fetchall()
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return tuple(_delivery_from_mapping(row) for row in rows)

    def due_delivery_jobs(self, *, now: datetime, limit: int) -> tuple[DeliveryJob, ...]:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                rows = self._connection.execute(
                    """SELECT
                        d.id AS delivery_id, d.activity_id, d.inbox_url, d.status, d.attempts,
                        d.next_attempt_at, d.last_error, d.created_at AS delivery_created_at,
                        d.updated_at, a.actor_id, a.activity_type, a.object_id, a.body,
                        a.created_at AS activity_created_at
                    FROM deliveries d
                    JOIN outbound_activities a ON a.id = d.activity_id
                    LEFT JOIN delivery_peers p ON p.inbox_url = d.inbox_url
                    WHERE d.status IN ('pending', 'retrying')
                      AND d.next_attempt_at <= ?
                      AND (p.circuit_open_until IS NULL OR p.circuit_open_until <= ?)
                      AND NOT EXISTS (
                        SELECT 1 FROM deliveries earlier
                        WHERE earlier.inbox_url = d.inbox_url
                          AND earlier.status IN ('pending', 'retrying')
                          AND (earlier.created_at < d.created_at OR (
                            earlier.created_at = d.created_at AND earlier.id < d.id
                          ))
                      )
                    ORDER BY d.next_attempt_at, d.created_at, d.id
                    LIMIT ?""",
                    (_iso(now), _iso(now), max(0, limit)),
                ).fetchall()
                lease_until = _iso(now + timedelta(minutes=5))
                self._connection.executemany(
                    "UPDATE deliveries SET next_attempt_at = ? WHERE id = ?",
                    [(lease_until, str(row["delivery_id"])) for row in rows],
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return tuple(_delivery_job_from_mapping(row) for row in rows)

    def update_delivery(
        self, delivery: Delivery, *, circuit_open_until: datetime | None = None
    ) -> None:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                updated = self._connection.execute(
                    """UPDATE deliveries SET status = ?, attempts = ?, next_attempt_at = ?,
                    last_error = ?, updated_at = ? WHERE id = ?""",
                    (
                        delivery.status,
                        delivery.attempts,
                        _iso(delivery.next_attempt_at),
                        delivery.last_error,
                        _iso(delivery.updated_at),
                        delivery.id,
                    ),
                )
                if updated.rowcount != 1:
                    raise RuntimeError("Federation delivery no longer exists.")
                if delivery.status == "delivered":
                    self._connection.execute(
                        """INSERT INTO delivery_peers(
                            inbox_url, consecutive_failures, circuit_open_until, updated_at
                        ) VALUES (?, 0, NULL, ?)
                        ON CONFLICT(inbox_url) DO UPDATE SET
                            consecutive_failures = 0, circuit_open_until = NULL,
                            updated_at = excluded.updated_at""",
                        (delivery.inbox_url, _iso(delivery.updated_at)),
                    )
                elif delivery.status in {"retrying", "dead"}:
                    self._connection.execute(
                        """INSERT INTO delivery_peers(
                            inbox_url, consecutive_failures, circuit_open_until, updated_at
                        ) VALUES (?, 1, ?, ?)
                        ON CONFLICT(inbox_url) DO UPDATE SET
                            consecutive_failures = delivery_peers.consecutive_failures + 1,
                            circuit_open_until = COALESCE(
                                excluded.circuit_open_until, delivery_peers.circuit_open_until
                            ),
                            updated_at = excluded.updated_at""",
                        (
                            delivery.inbox_url,
                            _iso(circuit_open_until) if circuit_open_until else None,
                            _iso(delivery.updated_at),
                        ),
                    )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def delivery(self, delivery_id: str) -> Delivery | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM deliveries WHERE id = ?", (delivery_id,)
            ).fetchone()
        return _delivery_from_mapping(row) if row is not None else None

    def retry_delivery(self, delivery_id: str, *, now: datetime) -> bool:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._connection.execute(
                    "SELECT inbox_url FROM deliveries WHERE id = ? AND status = 'dead'",
                    (delivery_id,),
                ).fetchone()
                if row is None:
                    self._connection.execute("COMMIT")
                    return False
                self._connection.execute(
                    """UPDATE deliveries SET status = 'pending', attempts = 0,
                    next_attempt_at = ?, last_error = NULL, created_at = ?, updated_at = ?
                    WHERE id = ?""",
                    (_iso(now), _iso(now), _iso(now), delivery_id),
                )
                self._connection.execute(
                    """UPDATE delivery_peers SET consecutive_failures = 0,
                    circuit_open_until = NULL, updated_at = ? WHERE inbox_url = ?""",
                    (_iso(now), str(row[0])),
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return True

    def discard_delivery(self, delivery_id: str, *, now: datetime) -> bool:
        with self._lock:
            updated = self._connection.execute(
                """UPDATE deliveries SET status = 'discarded', updated_at = ?
                WHERE id = ? AND status IN ('pending', 'retrying', 'dead')""",
                (_iso(now), delivery_id),
            )
        return updated.rowcount == 1

    def queue_health(self, *, now: datetime) -> QueueHealth:
        with self._lock:
            counts = {
                str(row[0]): int(row[1])
                for row in self._connection.execute(
                    "SELECT status, COUNT(*) FROM deliveries GROUP BY status"
                )
            }
            circuits = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM delivery_peers WHERE circuit_open_until > ?",
                    (_iso(now),),
                ).fetchone()[0]
            )
        return _queue_health(counts, circuits)

    def upsert_remote_actor(self, actor: RemoteActor) -> Relationship:
        with self._lock:
            self._connection.execute(
                """INSERT INTO remote_actors(
                    id, inbox_url, preferred_username, display_name, domain,
                    last_contact_at, deleted_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    inbox_url = excluded.inbox_url,
                    preferred_username = excluded.preferred_username,
                    display_name = excluded.display_name,
                    domain = excluded.domain,
                    last_contact_at = excluded.last_contact_at,
                    deleted_at = excluded.deleted_at""",
                (
                    actor.id,
                    actor.inbox_url,
                    actor.preferred_username,
                    actor.display_name,
                    actor.domain,
                    _iso(actor.last_contact_at),
                    _iso(actor.deleted_at) if actor.deleted_at else None,
                ),
            )
            self._connection.execute(
                """INSERT OR IGNORE INTO relationships(
                    actor_id, outbound_state, inbound_state, updated_at
                ) VALUES (?, 'none', 'none', ?)""",
                (actor.id, _iso(actor.last_contact_at)),
            )
        result = self.relationship(actor.id)
        if result is None:
            raise RuntimeError("Remote actor persistence did not create a relationship.")
        return result

    def relationship(self, actor_id: str) -> Relationship | None:
        with self._lock:
            row = self._connection.execute(
                f"{RELATIONSHIP_SELECT} WHERE a.id = ?", (actor_id,)
            ).fetchone()
        return _relationship_from_mapping(row) if row is not None else None

    def relationships(self) -> tuple[Relationship, ...]:
        with self._lock:
            rows = self._connection.execute(
                f"{RELATIONSHIP_SELECT} ORDER BY r.pinned DESC, a.display_name, a.id"
            ).fetchall()
        return tuple(_relationship_from_mapping(row) for row in rows)

    def save_relationship(self, relationship: Relationship) -> Relationship:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                updated = self._connection.execute(
                    """UPDATE relationships SET outbound_state = ?, inbound_state = ?,
                    outbound_follow_id = ?, inbound_follow_id = ?, pinned = ?, muted = ?,
                    blocked = ?, unavailable = ?, note = ?, updated_at = ? WHERE actor_id = ?""",
                    (
                        relationship.outbound_state,
                        relationship.inbound_state,
                        relationship.outbound_follow_id,
                        relationship.inbound_follow_id,
                        relationship.pinned,
                        relationship.muted,
                        relationship.blocked,
                        relationship.unavailable,
                        relationship.note,
                        _iso(relationship.updated_at),
                        relationship.actor.id,
                    ),
                )
                if updated.rowcount != 1:
                    raise RuntimeError("Remote relationship does not exist.")
                if not relationship.friend or relationship.blocked:
                    self._connection.execute(
                        "DELETE FROM circle_members WHERE actor_id = ?",
                        (relationship.actor.id,),
                    )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        result = self.relationship(relationship.actor.id)
        if result is None:
            raise RuntimeError("Remote relationship disappeared after update.")
        return result

    def create_circle(self, circle: Circle) -> Circle:
        with self._lock:
            self._connection.execute(
                "INSERT INTO circles(id, name, created_at) VALUES (?, ?, ?)",
                (circle.id, circle.name, _iso(circle.created_at)),
            )
        return circle

    def circles(self) -> tuple[Circle, ...]:
        with self._lock:
            rows = self._connection.execute(
                """SELECT c.id, c.name, c.created_at, m.actor_id
                FROM circles c LEFT JOIN circle_members m ON m.circle_id = c.id
                ORDER BY c.name, m.actor_id"""
            ).fetchall()
        return _circles_from_rows(rows)

    def set_circle_members(self, circle_id: str, actor_ids: Sequence[str]) -> Circle:
        members = tuple(dict.fromkeys(actor_ids))
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                circle_row = self._connection.execute(
                    "SELECT id, name, created_at FROM circles WHERE id = ?", (circle_id,)
                ).fetchone()
                if circle_row is None:
                    raise RuntimeError("Circle does not exist.")
                if members:
                    eligible = {
                        str(row[0])
                        for row in self._connection.execute(
                            """SELECT r.actor_id FROM relationships r
                            JOIN remote_actors a ON a.id = r.actor_id
                            WHERE r.outbound_state = 'following'
                              AND r.inbound_state = 'follower'
                              AND r.blocked = 0
                              AND NOT EXISTS(
                                SELECT 1 FROM domain_blocks b WHERE b.domain = a.domain
                              )"""
                        )
                    }
                    if not set(members).issubset(eligible):
                        raise ValueError("Circle members must be current unblocked friends.")
                self._connection.execute(
                    "DELETE FROM circle_members WHERE circle_id = ?", (circle_id,)
                )
                self._connection.executemany(
                    "INSERT INTO circle_members(circle_id, actor_id) VALUES (?, ?)",
                    [(circle_id, actor_id) for actor_id in members],
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return Circle(
            id=str(circle_row["id"]),
            name=str(circle_row["name"]),
            member_actor_ids=tuple(sorted(members)),
            created_at=_datetime(circle_row["created_at"]),
        )

    def block_actor(self, actor_id: str, *, now: datetime) -> Relationship:
        self._apply_actor_block(actor_id, now=now, blocked=True)
        result = self.relationship(actor_id)
        if result is None:
            raise RuntimeError("Remote relationship does not exist.")
        return result

    def unblock_actor(self, actor_id: str, *, now: datetime) -> Relationship:
        self._apply_actor_block(actor_id, now=now, blocked=False)
        result = self.relationship(actor_id)
        if result is None:
            raise RuntimeError("Remote relationship does not exist.")
        return result

    def _apply_actor_block(self, actor_id: str, *, now: datetime, blocked: bool) -> None:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                updated = self._connection.execute(
                    """UPDATE relationships SET outbound_state = 'removed',
                    inbound_state = 'removed', outbound_follow_id = NULL,
                    inbound_follow_id = NULL, pinned = 0, muted = 0, blocked = ?,
                    updated_at = ? WHERE actor_id = ?""",
                    (blocked, _iso(now), actor_id),
                )
                if updated.rowcount != 1:
                    raise RuntimeError("Remote relationship does not exist.")
                self._connection.execute(
                    "DELETE FROM circle_members WHERE actor_id = ?", (actor_id,)
                )
                self._connection.execute(
                    """UPDATE deliveries SET status = 'discarded',
                    last_error = 'cancelled by block', updated_at = ?
                    WHERE inbox_url = (SELECT inbox_url FROM remote_actors WHERE id = ?)
                      AND status IN ('pending', 'retrying')""",
                    (_iso(now), actor_id),
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def block_domain(self, domain: str, *, now: datetime) -> None:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    "INSERT OR IGNORE INTO domain_blocks(domain, created_at) VALUES (?, ?)",
                    (domain, _iso(now)),
                )
                actor_ids = tuple(
                    str(row[0])
                    for row in self._connection.execute(
                        "SELECT id FROM remote_actors WHERE domain = ?", (domain,)
                    )
                )
                for actor_id in actor_ids:
                    self._connection.execute(
                        """UPDATE relationships SET outbound_state = 'removed',
                        inbound_state = 'removed', outbound_follow_id = NULL,
                        inbound_follow_id = NULL, pinned = 0, muted = 0, updated_at = ?
                        WHERE actor_id = ?""",
                        (_iso(now), actor_id),
                    )
                    self._connection.execute(
                        "DELETE FROM circle_members WHERE actor_id = ?", (actor_id,)
                    )
                self._connection.execute(
                    """UPDATE deliveries SET status = 'discarded',
                    last_error = 'cancelled by domain block', updated_at = ?
                    WHERE inbox_url IN (SELECT inbox_url FROM remote_actors WHERE domain = ?)
                      AND status IN ('pending', 'retrying')""",
                    (_iso(now), domain),
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def unblock_domain(self, domain: str) -> None:
        with self._lock:
            self._connection.execute("DELETE FROM domain_blocks WHERE domain = ?", (domain,))

    def blocked_domains(self) -> tuple[str, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT domain FROM domain_blocks ORDER BY domain"
            ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def is_blocked(self, actor_id: str | None = None, domain: str | None = None) -> bool:
        with self._lock:
            if (
                domain is not None
                and self._connection.execute(
                    "SELECT 1 FROM domain_blocks WHERE domain = ?", (domain,)
                ).fetchone()
            ):
                return True
            if actor_id is None:
                return False
            row = self._connection.execute(
                """SELECT r.blocked, a.domain FROM relationships r
                JOIN remote_actors a ON a.id = r.actor_id WHERE r.actor_id = ?""",
                (actor_id,),
            ).fetchone()
            if row is None:
                return False
            return bool(row[0]) or bool(
                self._connection.execute(
                    "SELECT 1 FROM domain_blocks WHERE domain = ?", (str(row[1]),)
                ).fetchone()
            )


class PostgresStore:
    """Production PostgreSQL adapter with transactional single-owner setup."""

    def __init__(
        self,
        database_url: str,
        *,
        max_active_deliveries: int = MAX_ACTIVE_DELIVERIES,
    ) -> None:
        from psycopg_pool import ConnectionPool

        self._pool = ConnectionPool(database_url, min_size=1, max_size=5, open=True)
        self._max_active_deliveries = max_active_deliveries

    def migrate(self) -> None:
        with self._pool.connection() as connection, connection.transaction():
            for statement in POSTGRES_MIGRATION:
                connection.execute(statement)
            connection.execute(
                """ALTER TABLE inbox_receipts
                ADD COLUMN IF NOT EXISTS body_hash TEXT NOT NULL DEFAULT ''"""
            )
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
            connection.execute(
                """INSERT INTO schema_migrations(version, name) VALUES (3, %s)
                ON CONFLICT (version) DO NOTHING""",
                ("durable federation activities and deliveries",),
            )
            connection.execute(
                """INSERT INTO schema_migrations(version, name) VALUES (4, %s)
                ON CONFLICT (version) DO NOTHING""",
                ("asymmetric relationships and local circles",),
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

    def record_inbox_receipt(self, receipt: InboxReceipt) -> str:
        with self._pool.connection() as connection, connection.transaction():
            row = connection.execute(
                """INSERT INTO inbox_receipts(
                    signature_hash, activity_id, body_hash, activity_type,
                    status, diagnostic, received_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING RETURNING signature_hash""",
                (
                    receipt.signature_hash,
                    receipt.activity_id,
                    receipt.body_hash,
                    receipt.activity_type,
                    receipt.status,
                    receipt.diagnostic,
                    receipt.received_at,
                ),
            ).fetchone()
            if row is not None:
                return "created"
            replay = connection.execute(
                "SELECT 1 FROM inbox_receipts WHERE signature_hash = %s",
                (receipt.signature_hash,),
            ).fetchone()
            if replay is not None:
                return "replay"
            existing = connection.execute(
                "SELECT body_hash FROM inbox_receipts WHERE activity_id = %s",
                (receipt.activity_id,),
            ).fetchone()
            if existing is not None:
                return "duplicate" if existing[0] == receipt.body_hash else "conflict"
            return "replay"

    def inbox_receipts(self) -> tuple[InboxReceipt, ...]:
        with self._pool.connection() as connection:
            rows = connection.execute(
                """SELECT signature_hash, activity_id, body_hash, activity_type,
                status, diagnostic, received_at FROM inbox_receipts ORDER BY received_at"""
            ).fetchall()
        return tuple(_inbox_receipt_from_sequence(row) for row in rows)

    def enqueue_activity(
        self, activity: OutboundActivity, inbox_urls: Sequence[str]
    ) -> tuple[Delivery, ...]:
        if len(inbox_urls) > 500:
            raise ValueError("Federation fan-out cannot exceed 500 inboxes.")
        destinations = tuple(dict.fromkeys(inbox_urls))
        with self._pool.connection() as connection, connection.transaction():
            connection.execute("SELECT pg_advisory_xact_lock(794)")
            existing = connection.execute(
                "SELECT body FROM outbound_activities WHERE id = %s", (activity.id,)
            ).fetchone()
            if existing is None:
                connection.execute(
                    """INSERT INTO outbound_activities(
                        id, actor_id, activity_type, object_id, body, body_hash, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                    (
                        activity.id,
                        activity.actor_id,
                        activity.activity_type,
                        activity.object_id,
                        activity.body,
                        hashlib.sha256(activity.body).hexdigest(),
                        activity.created_at,
                    ),
                )
            elif bytes(existing[0]) != activity.body:
                raise RuntimeError("Outbound activity ID already has different content.")
            existing_destinations = {
                str(row[0])
                for row in connection.execute(
                    "SELECT inbox_url FROM deliveries WHERE activity_id = %s", (activity.id,)
                ).fetchall()
            }
            new_delivery_count = len(set(destinations) - existing_destinations)
            active_row = connection.execute(
                """SELECT COUNT(*) FROM deliveries
                WHERE status IN ('pending', 'retrying')"""
            ).fetchone()
            active_count = int(active_row[0]) if active_row is not None else 0
            if active_count + new_delivery_count > self._max_active_deliveries:
                raise RuntimeError("Federation delivery queue is full.")
            for inbox_url in destinations:
                connection.execute(
                    """INSERT INTO deliveries(
                        id, activity_id, inbox_url, status, attempts, next_attempt_at,
                        last_error, created_at, updated_at
                    ) VALUES (%s, %s, %s, 'pending', 0, %s, NULL, %s, %s)
                    ON CONFLICT (activity_id, inbox_url) DO NOTHING""",
                    (
                        str(uuid.uuid7()),
                        activity.id,
                        inbox_url,
                        activity.created_at,
                        activity.created_at,
                        activity.created_at,
                    ),
                )
            rows = connection.execute(
                """SELECT id, activity_id, inbox_url, status, attempts, next_attempt_at,
                last_error, created_at, updated_at FROM deliveries
                WHERE activity_id = %s ORDER BY inbox_url""",
                (activity.id,),
            ).fetchall()
        return tuple(_delivery_from_sequence(row) for row in rows)

    def due_delivery_jobs(self, *, now: datetime, limit: int) -> tuple[DeliveryJob, ...]:
        with self._pool.connection() as connection, connection.transaction():
            rows = connection.execute(
                """SELECT
                    d.id, d.activity_id, d.inbox_url, d.status, d.attempts,
                    d.next_attempt_at, d.last_error, d.created_at, d.updated_at,
                    a.actor_id, a.activity_type, a.object_id, a.body, a.created_at
                FROM deliveries d
                JOIN outbound_activities a ON a.id = d.activity_id
                LEFT JOIN delivery_peers p ON p.inbox_url = d.inbox_url
                WHERE d.status IN ('pending', 'retrying')
                  AND d.next_attempt_at <= %s
                  AND (p.circuit_open_until IS NULL OR p.circuit_open_until <= %s)
                  AND NOT EXISTS (
                    SELECT 1 FROM deliveries earlier
                    WHERE earlier.inbox_url = d.inbox_url
                      AND earlier.status IN ('pending', 'retrying')
                      AND (earlier.created_at < d.created_at OR (
                        earlier.created_at = d.created_at AND earlier.id < d.id
                      ))
                )
                ORDER BY d.next_attempt_at, d.created_at, d.id
                LIMIT %s
                FOR UPDATE OF d SKIP LOCKED""",
                (now, now, max(0, limit)),
            ).fetchall()
            lease_until = now + timedelta(minutes=5)
            connection.cursor().executemany(
                "UPDATE deliveries SET next_attempt_at = %s WHERE id = %s",
                [(lease_until, row[0]) for row in rows],
            )
        return tuple(_delivery_job_from_sequence(row) for row in rows)

    def update_delivery(
        self, delivery: Delivery, *, circuit_open_until: datetime | None = None
    ) -> None:
        with self._pool.connection() as connection, connection.transaction():
            updated = connection.execute(
                """UPDATE deliveries SET status = %s, attempts = %s,
                next_attempt_at = %s, last_error = %s, updated_at = %s
                WHERE id = %s RETURNING id""",
                (
                    delivery.status,
                    delivery.attempts,
                    delivery.next_attempt_at,
                    delivery.last_error,
                    delivery.updated_at,
                    delivery.id,
                ),
            ).fetchone()
            if updated is None:
                raise RuntimeError("Federation delivery no longer exists.")
            if delivery.status == "delivered":
                connection.execute(
                    """INSERT INTO delivery_peers(
                        inbox_url, consecutive_failures, circuit_open_until, updated_at
                    ) VALUES (%s, 0, NULL, %s)
                    ON CONFLICT(inbox_url) DO UPDATE SET
                        consecutive_failures = 0, circuit_open_until = NULL,
                        updated_at = excluded.updated_at""",
                    (delivery.inbox_url, delivery.updated_at),
                )
            elif delivery.status in {"retrying", "dead"}:
                connection.execute(
                    """INSERT INTO delivery_peers(
                        inbox_url, consecutive_failures, circuit_open_until, updated_at
                    ) VALUES (%s, 1, %s, %s)
                    ON CONFLICT(inbox_url) DO UPDATE SET
                        consecutive_failures = delivery_peers.consecutive_failures + 1,
                        circuit_open_until = COALESCE(
                            excluded.circuit_open_until, delivery_peers.circuit_open_until
                        ),
                        updated_at = excluded.updated_at""",
                    (delivery.inbox_url, circuit_open_until, delivery.updated_at),
                )

    def delivery(self, delivery_id: str) -> Delivery | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                """SELECT id, activity_id, inbox_url, status, attempts, next_attempt_at,
                last_error, created_at, updated_at FROM deliveries WHERE id = %s""",
                (delivery_id,),
            ).fetchone()
        return _delivery_from_sequence(row) if row is not None else None

    def retry_delivery(self, delivery_id: str, *, now: datetime) -> bool:
        with self._pool.connection() as connection, connection.transaction():
            row = connection.execute(
                """UPDATE deliveries SET status = 'pending', attempts = 0,
                next_attempt_at = %s, last_error = NULL, created_at = %s, updated_at = %s
                WHERE id = %s AND status = 'dead' RETURNING inbox_url""",
                (now, now, now, delivery_id),
            ).fetchone()
            if row is not None:
                connection.execute(
                    """UPDATE delivery_peers SET consecutive_failures = 0,
                    circuit_open_until = NULL, updated_at = %s WHERE inbox_url = %s""",
                    (now, row[0]),
                )
        return row is not None

    def discard_delivery(self, delivery_id: str, *, now: datetime) -> bool:
        with self._pool.connection() as connection:
            row = connection.execute(
                """UPDATE deliveries SET status = 'discarded', updated_at = %s
                WHERE id = %s AND status IN ('pending', 'retrying', 'dead') RETURNING id""",
                (now, delivery_id),
            ).fetchone()
        return row is not None

    def queue_health(self, *, now: datetime) -> QueueHealth:
        with self._pool.connection() as connection:
            counts = {
                str(row[0]): int(row[1])
                for row in connection.execute(
                    "SELECT status, COUNT(*) FROM deliveries GROUP BY status"
                ).fetchall()
            }
            circuit_row = connection.execute(
                "SELECT COUNT(*) FROM delivery_peers WHERE circuit_open_until > %s",
                (now,),
            ).fetchone()
            circuits = int(circuit_row[0]) if circuit_row is not None else 0
        return _queue_health(counts, circuits)

    def upsert_remote_actor(self, actor: RemoteActor) -> Relationship:
        with self._pool.connection() as connection, connection.transaction():
            connection.execute(
                """INSERT INTO remote_actors(
                    id, inbox_url, preferred_username, display_name, domain,
                    last_contact_at, deleted_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(id) DO UPDATE SET
                    inbox_url = excluded.inbox_url,
                    preferred_username = excluded.preferred_username,
                    display_name = excluded.display_name,
                    domain = excluded.domain,
                    last_contact_at = excluded.last_contact_at,
                    deleted_at = excluded.deleted_at""",
                (
                    actor.id,
                    actor.inbox_url,
                    actor.preferred_username,
                    actor.display_name,
                    actor.domain,
                    actor.last_contact_at,
                    actor.deleted_at,
                ),
            )
            connection.execute(
                """INSERT INTO relationships(
                    actor_id, outbound_state, inbound_state, updated_at
                ) VALUES (%s, 'none', 'none', %s)
                ON CONFLICT(actor_id) DO NOTHING""",
                (actor.id, actor.last_contact_at),
            )
        result = self.relationship(actor.id)
        if result is None:
            raise RuntimeError("Remote actor persistence did not create a relationship.")
        return result

    def relationship(self, actor_id: str) -> Relationship | None:
        with self._pool.connection() as connection:
            row = connection.execute(
                f"{RELATIONSHIP_SELECT} WHERE a.id = %s", (actor_id,)
            ).fetchone()
        return _relationship_from_sequence(row) if row is not None else None

    def relationships(self) -> tuple[Relationship, ...]:
        with self._pool.connection() as connection:
            rows = connection.execute(
                f"{RELATIONSHIP_SELECT} ORDER BY r.pinned DESC, a.display_name, a.id"
            ).fetchall()
        return tuple(_relationship_from_sequence(row) for row in rows)

    def save_relationship(self, relationship: Relationship) -> Relationship:
        with self._pool.connection() as connection, connection.transaction():
            row = connection.execute(
                """UPDATE relationships SET outbound_state = %s, inbound_state = %s,
                outbound_follow_id = %s, inbound_follow_id = %s, pinned = %s, muted = %s,
                blocked = %s, unavailable = %s, note = %s, updated_at = %s
                WHERE actor_id = %s RETURNING actor_id""",
                (
                    relationship.outbound_state,
                    relationship.inbound_state,
                    relationship.outbound_follow_id,
                    relationship.inbound_follow_id,
                    relationship.pinned,
                    relationship.muted,
                    relationship.blocked,
                    relationship.unavailable,
                    relationship.note,
                    relationship.updated_at,
                    relationship.actor.id,
                ),
            ).fetchone()
            if row is None:
                raise RuntimeError("Remote relationship does not exist.")
            if not relationship.friend or relationship.blocked:
                connection.execute(
                    "DELETE FROM circle_members WHERE actor_id = %s",
                    (relationship.actor.id,),
                )
        result = self.relationship(relationship.actor.id)
        if result is None:
            raise RuntimeError("Remote relationship disappeared after update.")
        return result

    def create_circle(self, circle: Circle) -> Circle:
        with self._pool.connection() as connection:
            connection.execute(
                "INSERT INTO circles(id, name, created_at) VALUES (%s, %s, %s)",
                (circle.id, circle.name, circle.created_at),
            )
        return circle

    def circles(self) -> tuple[Circle, ...]:
        with self._pool.connection() as connection:
            rows = connection.execute(
                """SELECT c.id, c.name, c.created_at, m.actor_id
                FROM circles c LEFT JOIN circle_members m ON m.circle_id = c.id
                ORDER BY c.name, m.actor_id"""
            ).fetchall()
        return _circles_from_rows(rows)

    def set_circle_members(self, circle_id: str, actor_ids: Sequence[str]) -> Circle:
        members = tuple(dict.fromkeys(actor_ids))
        with self._pool.connection() as connection, connection.transaction():
            circle_row = connection.execute(
                "SELECT id, name, created_at FROM circles WHERE id = %s FOR UPDATE", (circle_id,)
            ).fetchone()
            if circle_row is None:
                raise RuntimeError("Circle does not exist.")
            if members:
                eligible = {
                    str(row[0])
                    for row in connection.execute(
                        """SELECT r.actor_id FROM relationships r
                        JOIN remote_actors a ON a.id = r.actor_id
                        WHERE r.actor_id = ANY(%s)
                          AND r.outbound_state = 'following'
                          AND r.inbound_state = 'follower'
                          AND r.blocked = FALSE
                          AND NOT EXISTS(
                            SELECT 1 FROM domain_blocks b WHERE b.domain = a.domain
                          )""",
                        (list(members),),
                    ).fetchall()
                }
                if eligible != set(members):
                    raise ValueError("Circle members must be current unblocked friends.")
            connection.execute("DELETE FROM circle_members WHERE circle_id = %s", (circle_id,))
            connection.cursor().executemany(
                "INSERT INTO circle_members(circle_id, actor_id) VALUES (%s, %s)",
                [(circle_id, actor_id) for actor_id in members],
            )
        return Circle(
            id=str(circle_row[0]),
            name=str(circle_row[1]),
            member_actor_ids=tuple(sorted(members)),
            created_at=_datetime(circle_row[2]),
        )

    def block_actor(self, actor_id: str, *, now: datetime) -> Relationship:
        self._apply_actor_block(actor_id, now=now, blocked=True)
        result = self.relationship(actor_id)
        if result is None:
            raise RuntimeError("Remote relationship does not exist.")
        return result

    def unblock_actor(self, actor_id: str, *, now: datetime) -> Relationship:
        self._apply_actor_block(actor_id, now=now, blocked=False)
        result = self.relationship(actor_id)
        if result is None:
            raise RuntimeError("Remote relationship does not exist.")
        return result

    def _apply_actor_block(self, actor_id: str, *, now: datetime, blocked: bool) -> None:
        with self._pool.connection() as connection, connection.transaction():
            row = connection.execute(
                """UPDATE relationships SET outbound_state = 'removed',
                inbound_state = 'removed', outbound_follow_id = NULL,
                inbound_follow_id = NULL, pinned = FALSE, muted = FALSE,
                blocked = %s, updated_at = %s WHERE actor_id = %s RETURNING actor_id""",
                (blocked, now, actor_id),
            ).fetchone()
            if row is None:
                raise RuntimeError("Remote relationship does not exist.")
            connection.execute("DELETE FROM circle_members WHERE actor_id = %s", (actor_id,))
            connection.execute(
                """UPDATE deliveries SET status = 'discarded',
                last_error = 'cancelled by block', updated_at = %s
                WHERE inbox_url = (SELECT inbox_url FROM remote_actors WHERE id = %s)
                  AND status IN ('pending', 'retrying')""",
                (now, actor_id),
            )

    def block_domain(self, domain: str, *, now: datetime) -> None:
        with self._pool.connection() as connection, connection.transaction():
            connection.execute(
                """INSERT INTO domain_blocks(domain, created_at) VALUES (%s, %s)
                ON CONFLICT(domain) DO NOTHING""",
                (domain, now),
            )
            connection.execute(
                """DELETE FROM circle_members WHERE actor_id IN (
                    SELECT id FROM remote_actors WHERE domain = %s
                )""",
                (domain,),
            )
            connection.execute(
                """UPDATE relationships SET outbound_state = 'removed',
                inbound_state = 'removed', outbound_follow_id = NULL,
                inbound_follow_id = NULL, pinned = FALSE, muted = FALSE, updated_at = %s
                WHERE actor_id IN (SELECT id FROM remote_actors WHERE domain = %s)""",
                (now, domain),
            )
            connection.execute(
                """UPDATE deliveries SET status = 'discarded',
                last_error = 'cancelled by domain block', updated_at = %s
                WHERE inbox_url IN (SELECT inbox_url FROM remote_actors WHERE domain = %s)
                  AND status IN ('pending', 'retrying')""",
                (now, domain),
            )

    def unblock_domain(self, domain: str) -> None:
        with self._pool.connection() as connection:
            connection.execute("DELETE FROM domain_blocks WHERE domain = %s", (domain,))

    def blocked_domains(self) -> tuple[str, ...]:
        with self._pool.connection() as connection:
            rows = connection.execute("SELECT domain FROM domain_blocks ORDER BY domain").fetchall()
        return tuple(str(row[0]) for row in rows)

    def is_blocked(self, actor_id: str | None = None, domain: str | None = None) -> bool:
        with self._pool.connection() as connection:
            if (
                domain is not None
                and connection.execute(
                    "SELECT 1 FROM domain_blocks WHERE domain = %s", (domain,)
                ).fetchone()
            ):
                return True
            if actor_id is None:
                return False
            row = connection.execute(
                """SELECT r.blocked, a.domain FROM relationships r
                JOIN remote_actors a ON a.id = r.actor_id WHERE r.actor_id = %s""",
                (actor_id,),
            ).fetchone()
            if row is None:
                return False
            return bool(row[0]) or bool(
                connection.execute(
                    "SELECT 1 FROM domain_blocks WHERE domain = %s", (str(row[1]),)
                ).fetchone()
            )


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
        body_hash=str(row[2]),
        activity_type=str(row[3]),
        status=str(row[4]),
        diagnostic=str(row[5]),
        received_at=_datetime(row[6]),
    )


def _delivery_from_mapping(row: sqlite3.Row) -> Delivery:
    return Delivery(
        id=str(row["id"]),
        activity_id=str(row["activity_id"]),
        inbox_url=str(row["inbox_url"]),
        status=str(row["status"]),
        attempts=int(row["attempts"]),
        next_attempt_at=_datetime(row["next_attempt_at"]),
        last_error=str(row["last_error"]) if row["last_error"] else None,
        created_at=_datetime(row["created_at"]),
        updated_at=_datetime(row["updated_at"]),
    )


def _delivery_from_sequence(row: Sequence[object]) -> Delivery:
    return Delivery(
        id=str(row[0]),
        activity_id=str(row[1]),
        inbox_url=str(row[2]),
        status=str(row[3]),
        attempts=int(str(row[4])),
        next_attempt_at=_datetime(row[5]),
        last_error=str(row[6]) if row[6] else None,
        created_at=_datetime(row[7]),
        updated_at=_datetime(row[8]),
    )


def _delivery_job_from_mapping(row: sqlite3.Row) -> DeliveryJob:
    delivery = Delivery(
        id=str(row["delivery_id"]),
        activity_id=str(row["activity_id"]),
        inbox_url=str(row["inbox_url"]),
        status=str(row["status"]),
        attempts=int(row["attempts"]),
        next_attempt_at=_datetime(row["next_attempt_at"]),
        last_error=str(row["last_error"]) if row["last_error"] else None,
        created_at=_datetime(row["delivery_created_at"]),
        updated_at=_datetime(row["updated_at"]),
    )
    activity = OutboundActivity(
        id=str(row["activity_id"]),
        actor_id=str(row["actor_id"]),
        activity_type=str(row["activity_type"]),
        object_id=str(row["object_id"]) if row["object_id"] else None,
        body=bytes(row["body"]),
        created_at=_datetime(row["activity_created_at"]),
    )
    return DeliveryJob(delivery, activity)


def _delivery_job_from_sequence(row: Sequence[object]) -> DeliveryJob:
    return DeliveryJob(
        _delivery_from_sequence(row[:9]),
        OutboundActivity(
            id=str(row[1]),
            actor_id=str(row[9]),
            activity_type=str(row[10]),
            object_id=str(row[11]) if row[11] else None,
            body=_bytes(row[12]),
            created_at=_datetime(row[13]),
        ),
    )


def _queue_health(counts: dict[str, int], circuits: int) -> QueueHealth:
    return QueueHealth(
        pending=counts.get("pending", 0),
        retrying=counts.get("retrying", 0),
        delivered=counts.get("delivered", 0),
        dead=counts.get("dead", 0),
        discarded=counts.get("discarded", 0),
        open_circuits=circuits,
    )


def _bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise TypeError("Database binary value is not bytes-like.")


def _relationship_from_mapping(row: sqlite3.Row) -> Relationship:
    actor = RemoteActor(
        id=str(row["id"]),
        inbox_url=str(row["inbox_url"]),
        preferred_username=str(row["preferred_username"]),
        display_name=str(row["display_name"]),
        domain=str(row["domain"]),
        last_contact_at=_datetime(row["last_contact_at"]),
        deleted_at=_datetime(row["deleted_at"]) if row["deleted_at"] else None,
    )
    return Relationship(
        actor=actor,
        outbound_state=str(row["outbound_state"]),
        inbound_state=str(row["inbound_state"]),
        outbound_follow_id=(str(row["outbound_follow_id"]) if row["outbound_follow_id"] else None),
        inbound_follow_id=(str(row["inbound_follow_id"]) if row["inbound_follow_id"] else None),
        pinned=bool(row["pinned"]),
        muted=bool(row["muted"]),
        blocked=bool(row["effective_blocked"]),
        unavailable=bool(row["unavailable"]),
        note=str(row["note"]),
        updated_at=_datetime(row["updated_at"]),
    )


def _relationship_from_sequence(row: Sequence[object]) -> Relationship:
    actor = RemoteActor(
        id=str(row[0]),
        inbox_url=str(row[1]),
        preferred_username=str(row[2]),
        display_name=str(row[3]),
        domain=str(row[4]),
        last_contact_at=_datetime(row[5]),
        deleted_at=_datetime(row[6]) if row[6] else None,
    )
    return Relationship(
        actor=actor,
        outbound_state=str(row[7]),
        inbound_state=str(row[8]),
        outbound_follow_id=str(row[9]) if row[9] else None,
        inbound_follow_id=str(row[10]) if row[10] else None,
        pinned=bool(row[11]),
        muted=bool(row[12]),
        blocked=bool(row[13]),
        unavailable=bool(row[14]),
        note=str(row[15]),
        updated_at=_datetime(row[16]),
    )


def _circles_from_rows(rows: Sequence[Sequence[object]]) -> tuple[Circle, ...]:
    grouped: dict[str, tuple[str, datetime, list[str]]] = {}
    for row in rows:
        circle_id = str(row[0])
        if circle_id not in grouped:
            grouped[circle_id] = (str(row[1]), _datetime(row[2]), [])
        if row[3] is not None:
            grouped[circle_id][2].append(str(row[3]))
    return tuple(
        Circle(
            id=circle_id,
            name=name,
            member_actor_ids=tuple(members),
            created_at=created_at,
        )
        for circle_id, (name, created_at, members) in grouped.items()
    )
