"""Database-backed federation budgets, emergency controls, and safe diagnostics."""

from __future__ import annotations

import hashlib
import hmac
import uuid
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from chirp_space.models import FederationControl, SecurityEvent
from chirp_space.store import Store

EVENT_RETENTION = timedelta(days=30)
LEASE_TTL = timedelta(seconds=30)


class SafetyLimitError(RuntimeError):
    def __init__(self, code: str, message: str, *, status: int, retry_after: int = 0) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.retry_after = retry_after


class FederationSafety:
    """Apply accepted #798 limits without process-local counters or raw identifiers."""

    def __init__(
        self,
        store: Store,
        secret_key: str,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self._secret = secret_key.encode()
        self._now = now or (lambda: datetime.now(UTC))

    def control(self) -> FederationControl:
        return self.store.federation_control()

    def update_control(
        self,
        *,
        expected_revision: int,
        inbound_paused: bool,
        outbound_paused: bool,
        reason: str,
    ) -> FederationControl:
        normalized_reason = " ".join(reason.split())[:200]
        current = self.control()
        updated = replace(
            current,
            inbound_paused=inbound_paused,
            outbound_paused=outbound_paused,
            reason=normalized_reason,
            revision=expected_revision + 1,
            updated_at=self._now(),
        )
        result = self.store.update_federation_control(updated, expected_revision=expected_revision)
        self.record(
            "control",
            "pause-updated",
            "owner",
            detail={"inbound": int(inbound_paused), "outbound": int(outbound_paused)},
        )
        return result

    def begin_inbound(self, *, client_key: str, actor: str) -> str:
        now = self._now()
        domain = (urlsplit(actor).hostname or "unknown-actor").casefold()
        if self.control().inbound_paused:
            self.record("inbox", "denied-paused", client_key, domain=domain, actor=actor)
            raise SafetyLimitError(
                "inbound-paused", "Federation inbox is temporarily paused.", status=503
            )
        buckets = (
            ("ip", client_key, 20, 1.0),
            ("domain", domain, 50, 300 / 3600),
            ("actor", actor, 20, 120 / 3600),
        )
        for scope, principal, capacity, refill in buckets:
            allowed, retry = self.store.consume_rate_bucket(
                f"inbound:{scope}:{self._token(principal)}",
                capacity=capacity,
                refill_per_second=refill,
                now=now,
            )
            if not allowed:
                self.record(
                    "inbox",
                    f"denied-{scope}-rate",
                    client_key,
                    domain=domain,
                    actor=actor,
                    detail={"retry_after": retry},
                )
                raise SafetyLimitError(
                    "rate-limit",
                    f"Federation {scope} request budget is exhausted.",
                    status=429,
                    retry_after=retry,
                )
        lease_id = str(uuid.uuid7())
        limits = (
            ("inbound-global", "all", 16),
            ("inbound-ip", self._token(client_key), 2),
            ("inbound-domain", self._token(domain), 4),
            ("inbound-actor", self._token(actor), 1),
        )
        if not self.store.acquire_federation_lease(lease_id, limits, now=now, ttl=LEASE_TTL):
            self.record("inbox", "denied-concurrency", client_key, domain=domain, actor=actor)
            raise SafetyLimitError(
                "concurrency-limit",
                "Federation inbox concurrency budget is exhausted.",
                status=503,
                retry_after=1,
            )
        return lease_id

    def begin_outbound(self, *, inbox_url: str) -> str:
        domain = (urlsplit(inbox_url).hostname or "invalid-destination").casefold()
        if self.control().outbound_paused:
            raise SafetyLimitError(
                "outbound-paused", "Federation delivery is temporarily paused.", status=503
            )
        lease_id = str(uuid.uuid7())
        limits = (
            ("outbound-global", "all", 16),
            ("outbound-domain", self._token(domain), 2),
            ("outbound-inbox", self._token(inbox_url), 1),
        )
        if not self.store.acquire_federation_lease(
            lease_id, limits, now=self._now(), ttl=LEASE_TTL
        ):
            raise SafetyLimitError(
                "outbound-concurrency",
                "Federation delivery concurrency budget is exhausted.",
                status=503,
                retry_after=1,
            )
        return lease_id

    def check_follow_budget(self, *, actor: str, inbox_url: str) -> None:
        now = self._now()
        domain = (urlsplit(inbox_url).hostname or "invalid-destination").casefold()
        for scope, principal, capacity in (
            ("domain", domain, 20),
            ("actor", actor, 5),
        ):
            allowed, retry = self.store.consume_rate_bucket(
                f"follow:{scope}:{self._token(principal)}",
                capacity=capacity,
                refill_per_second=capacity / 3600,
                now=now,
            )
            if not allowed:
                self.record(
                    "follow",
                    f"denied-{scope}-rate",
                    "owner",
                    domain=domain,
                    actor=actor,
                    detail={"retry_after": retry},
                )
                raise SafetyLimitError(
                    "follow-rate-limit",
                    f"Follow {scope} budget is exhausted.",
                    status=429,
                    retry_after=retry,
                )

    def release(self, lease_id: str) -> None:
        self.store.release_federation_lease(lease_id)

    def record(
        self,
        surface: str,
        decision: str,
        principal: str,
        *,
        domain: str | None = None,
        actor: str | None = None,
        detail: Mapping[str, int | str] | None = None,
    ) -> None:
        now = self._now()
        bounded_detail = {
            str(key)[:40]: (value if isinstance(value, int) else str(value)[:200])
            for key, value in (detail or {}).items()
        }
        self.store.record_security_event(
            SecurityEvent(
                id=str(uuid.uuid7()),
                surface=surface[:40],
                decision=decision[:80],
                principal_token=self._token(principal),
                domain=domain[:253] if domain else None,
                actor_token=self._token(actor) if actor else None,
                detail=bounded_detail,
                created_at=now,
            )
        )
        self.store.purge_security_events(before=now - EVENT_RETENTION)

    def _token(self, value: str) -> str:
        return hmac.new(self._secret, value.encode(), hashlib.sha256).hexdigest()[:24]
