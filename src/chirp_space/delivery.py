"""Durable, ordered, bounded ActivityPub delivery owned by the Space app."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, Protocol
from urllib.parse import urlsplit

from chirp_space.federation import (
    SUPPORTED_ACTIVITIES,
    FederationError,
    FederationService,
    FetchResponse,
    pinned_post_activity,
    resolve_public_addresses,
    validate_public_address,
    validate_remote_url,
)
from chirp_space.models import Delivery, OutboundActivity, QueueHealth
from chirp_space.store import Store

RETRYABLE_STATUSES = frozenset({408, 409, 425, 429})
RETRY_DELAYS = (
    timedelta(minutes=1),
    timedelta(minutes=5),
    timedelta(minutes=30),
    timedelta(hours=2),
    timedelta(hours=12),
    timedelta(days=1),
)
DELIVERY_LIFETIME = timedelta(days=7)
MAX_DELIVERIES_PER_RUN = 16
CIRCUIT_THRESHOLD = 3


@dataclass(frozen=True, slots=True)
class DeliveryResponse:
    status: int
    headers: Mapping[str, str]


class DeliveryTransport(Protocol):
    def send(
        self, inbox_url: str, *, headers: Mapping[str, str], body: bytes
    ) -> DeliveryResponse: ...


PostRequester = Callable[
    [str, str, int, Mapping[str, str], bytes, float],
    FetchResponse,
]


class HTTPSDeliveryTransport:
    """Validate and pin every destination before sending one signed POST."""

    def __init__(
        self,
        *,
        resolver: Callable[[str, int], Sequence[str]] | None = None,
        requester: PostRequester | None = None,
    ) -> None:
        self._resolver = resolver or resolve_public_addresses
        self._requester = requester or pinned_post_activity

    def send(self, inbox_url: str, *, headers: Mapping[str, str], body: bytes) -> DeliveryResponse:
        host, port = validate_remote_url(inbox_url)
        addresses = tuple(self._resolver(host, port))
        if not addresses:
            raise FederationError("dns-empty", "Remote inbox did not resolve.", status=502)
        for address in addresses:
            validate_public_address(address)
        response = self._requester(inbox_url, addresses[0], port, headers, body, 15.0)
        return DeliveryResponse(response.status, response.headers)


class DeliveryService:
    def __init__(
        self,
        store: Store,
        federation: FederationService,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.federation = federation
        self._now = now or (lambda: datetime.now(UTC))

    def enqueue(
        self, activity: Mapping[str, Any], *, inbox_urls: Sequence[str]
    ) -> tuple[Delivery, ...]:
        if not self.federation.config.federation_enabled:
            raise RuntimeError("Federation is disabled for this Space.")
        activity_id = _https_identifier(activity.get("id"), "Activity ID")
        actor_id = _https_identifier(activity.get("actor"), "Activity actor")
        origin = self.federation.config.canonical_origin
        if actor_id != f"{origin}/ap/actor" or not activity_id.startswith(
            f"{origin}/ap/activities/"
        ):
            raise ValueError("Outbound activity identity must belong to this Space.")
        activity_type = str(activity.get("type", ""))
        if activity_type not in SUPPORTED_ACTIVITIES:
            raise ValueError("Outbound activity type is not supported.")
        body = json.dumps(
            dict(activity), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
        object_value = activity.get("object")
        if isinstance(object_value, Mapping):
            object_value = object_value.get("id")
        object_id = _https_identifier(object_value, "Activity object") if object_value else None
        for inbox_url in inbox_urls:
            validate_remote_url(inbox_url)
        outbound = OutboundActivity(
            id=activity_id,
            actor_id=actor_id,
            activity_type=activity_type,
            object_id=object_id,
            body=body,
            created_at=self._now(),
        )
        return self.store.enqueue_activity(outbound, inbox_urls)

    def retry_dead_letter(self, delivery_id: str) -> None:
        if not self.store.retry_delivery(delivery_id, now=self._now()):
            raise RuntimeError("Only an existing dead delivery can be retried.")

    def discard(self, delivery_id: str) -> None:
        if not self.store.discard_delivery(delivery_id, now=self._now()):
            raise RuntimeError("Delivery cannot be discarded from its current state.")

    def health(self) -> QueueHealth:
        return self.store.queue_health(now=self._now())


class DeliveryWorker:
    """Run bounded delivery work outside request ownership."""

    def __init__(
        self,
        store: Store,
        federation: FederationService,
        transport: DeliveryTransport,
        *,
        now: Callable[[], datetime] | None = None,
        is_blocked: Callable[[str], bool] | None = None,
    ) -> None:
        self.store = store
        self.federation = federation
        self.transport = transport
        self._now = now or (lambda: datetime.now(UTC))
        self._is_blocked = is_blocked or (lambda _inbox: False)

    def run_once(self, *, limit: int = MAX_DELIVERIES_PER_RUN) -> tuple[Delivery, ...]:
        now = self._now()
        jobs = self.store.due_delivery_jobs(
            now=now, limit=min(max(0, limit), MAX_DELIVERIES_PER_RUN)
        )
        outcomes: list[Delivery] = []
        for job in jobs:
            delivery = job.delivery
            if self._is_blocked(delivery.inbox_url):
                outcome = replace(
                    delivery,
                    status="dead",
                    attempts=delivery.attempts + 1,
                    last_error="blocked by local policy",
                    updated_at=now,
                )
                self.store.update_delivery(outcome)
                outcomes.append(outcome)
                continue
            headers = self.federation.sign_request("POST", delivery.inbox_url, job.activity.body)
            try:
                response = self.transport.send(
                    delivery.inbox_url, headers=headers, body=job.activity.body
                )
            except FederationError as exc:
                outcome, circuit = self._failure(
                    delivery, now=now, error=exc.code, retry_after=None, retryable=True
                )
            else:
                if 200 <= response.status < 300:
                    outcome = replace(
                        delivery,
                        status="delivered",
                        attempts=delivery.attempts + 1,
                        next_attempt_at=now,
                        last_error=None,
                        updated_at=now,
                    )
                    circuit = None
                else:
                    retryable = response.status in RETRYABLE_STATUSES or response.status >= 500
                    outcome, circuit = self._failure(
                        delivery,
                        now=now,
                        error=f"HTTP {response.status}",
                        retry_after=response.headers.get("retry-after"),
                        retryable=retryable,
                    )
            self.store.update_delivery(outcome, circuit_open_until=circuit)
            outcomes.append(outcome)
        return tuple(outcomes)

    def _failure(
        self,
        delivery: Delivery,
        *,
        now: datetime,
        error: str,
        retry_after: str | None,
        retryable: bool,
    ) -> tuple[Delivery, datetime | None]:
        attempts = delivery.attempts + 1
        deadline = delivery.created_at + DELIVERY_LIFETIME
        if not retryable or now >= deadline:
            return (
                replace(
                    delivery,
                    status="dead",
                    attempts=attempts,
                    next_attempt_at=now,
                    last_error=error,
                    updated_at=now,
                ),
                None,
            )
        delay = RETRY_DELAYS[min(attempts - 1, len(RETRY_DELAYS) - 1)]
        requested_delay = _retry_after(retry_after, now=now)
        if requested_delay is not None:
            delay = max(delay, requested_delay)
        next_attempt = min(now + delay, deadline)
        circuit = next_attempt if attempts >= CIRCUIT_THRESHOLD else None
        return (
            replace(
                delivery,
                status="retrying",
                attempts=attempts,
                next_attempt_at=next_attempt,
                last_error=error,
                updated_at=now,
            ),
            circuit,
        )


def _retry_after(value: str | None, *, now: datetime) -> timedelta | None:
    if not value:
        return None
    try:
        delay = timedelta(seconds=max(0, int(value)))
    except OverflowError, ValueError:
        try:
            retry_at = parsedate_to_datetime(value).astimezone(UTC)
        except AttributeError, OverflowError, TypeError, ValueError:
            return None
        delay = max(timedelta(0), retry_at - now)
    return min(delay, timedelta(days=1))


def _https_identifier(value: object, field: str) -> str:
    candidate = str(value or "")
    parsed = urlsplit(candidate)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or len(candidate) > 2048
    ):
        raise ValueError(f"{field} must be a bounded HTTPS URL.")
    return candidate
