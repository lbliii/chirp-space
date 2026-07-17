"""Asymmetric relationship state and local-only audience controls."""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit

from chirp_space.delivery import DeliveryService
from chirp_space.federation import ACTIVITY_JSON, DocumentFetcher, FederationError
from chirp_space.models import AudiencePreview, Circle, Relationship, RemoteActor
from chirp_space.store import Store

HANDLE_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_.-]{0,62}[a-z0-9])?$")
CIRCLE_NAME_RE = re.compile(r"^[^<>\x00-\x1f\x7f]{1,60}$")


class RelationshipService:
    def __init__(
        self,
        store: Store,
        delivery: DeliveryService,
        fetcher: DocumentFetcher,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.delivery = delivery
        self.fetcher = fetcher
        self._now = now or (lambda: datetime.now(UTC))

    def discover(self, reference: str) -> Relationship:
        actor_url, expected_handle = self._resolve_reference(reference)
        actor_document = self.fetcher.fetch_json(actor_url)
        if actor_document.get("id") != actor_url or actor_document.get("type") != "Person":
            raise FederationError(
                "actor-identity", "Remote actor identity document does not match discovery."
            )
        inbox = _https_identifier(actor_document.get("inbox"), "Remote inbox")
        actor_host = urlsplit(actor_url).hostname
        inbox_host = urlsplit(inbox).hostname
        if actor_host is None or inbox_host != actor_host:
            raise FederationError(
                "actor-inbox", "Remote actor inbox must use the actor canonical host."
            )
        if self.store.is_blocked(domain=actor_host):
            raise PermissionError("Remote actor domain is blocked.")
        username = _plain_text(actor_document.get("preferredUsername"), "Remote username", 64)
        if not HANDLE_RE.fullmatch(username.casefold()) or (
            expected_handle is not None and username.casefold() != expected_handle
        ):
            raise FederationError("actor-handle", "Remote actor username does not match discovery.")
        display_name = _plain_text(actor_document.get("name") or username, "Remote name", 100)
        actor = RemoteActor(
            id=actor_url,
            inbox_url=inbox,
            preferred_username=username,
            display_name=display_name,
            domain=actor_host.casefold(),
            last_contact_at=self._now(),
        )
        return self.store.upsert_remote_actor(actor)

    def send_follow(self, actor_id: str) -> Relationship:
        relationship = self._required(actor_id)
        if relationship.blocked:
            raise PermissionError("Blocked actors cannot be followed.")
        if relationship.outbound_state not in {"none", "removed", "rejected"}:
            raise ValueError("This relationship already has an active follow state.")
        follow_id = self._activity_id()
        self._enqueue(
            relationship,
            {
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": follow_id,
                "type": "Follow",
                "actor": self._local_actor_id,
                "object": relationship.actor.id,
            },
        )
        return self.store.save_relationship(
            replace(
                relationship,
                outbound_state="pending",
                outbound_follow_id=follow_id,
                unavailable=False,
                updated_at=self._now(),
            )
        )

    def accept_follower(self, actor_id: str) -> Relationship:
        return self._answer_follow(actor_id, accepted=True)

    def reject_follower(self, actor_id: str) -> Relationship:
        return self._answer_follow(actor_id, accepted=False)

    def _answer_follow(self, actor_id: str, *, accepted: bool) -> Relationship:
        relationship = self._required(actor_id)
        if relationship.blocked or relationship.inbound_state != "pending":
            raise ValueError("Only a current unblocked follow request can be answered.")
        follow_id = relationship.inbound_follow_id
        if follow_id is None:
            raise RuntimeError("Pending follow request is missing its activity ID.")
        activity_type = "Accept" if accepted else "Reject"
        self._enqueue(
            relationship,
            {
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": self._activity_id(),
                "type": activity_type,
                "actor": self._local_actor_id,
                "object": {
                    "id": follow_id,
                    "type": "Follow",
                    "actor": relationship.actor.id,
                    "object": self._local_actor_id,
                },
            },
        )
        return self.store.save_relationship(
            replace(
                relationship,
                inbound_state="follower" if accepted else "rejected",
                updated_at=self._now(),
            )
        )

    def unfollow(self, actor_id: str) -> Relationship:
        relationship = self._required(actor_id)
        if relationship.outbound_state not in {"pending", "following"}:
            raise ValueError("Only a pending or accepted follow can be removed.")
        follow_id = relationship.outbound_follow_id
        if follow_id is None:
            raise RuntimeError("Active outbound follow is missing its activity ID.")
        self._enqueue(
            relationship,
            {
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": self._activity_id(),
                "type": "Undo",
                "actor": self._local_actor_id,
                "object": {
                    "id": follow_id,
                    "type": "Follow",
                    "actor": self._local_actor_id,
                    "object": relationship.actor.id,
                },
            },
        )
        return self.store.save_relationship(
            replace(relationship, outbound_state="removed", updated_at=self._now())
        )

    def remove_follower(self, actor_id: str) -> Relationship:
        relationship = self._required(actor_id)
        if relationship.inbound_state not in {"pending", "follower"}:
            raise ValueError("This actor is not a current follower or pending request.")
        return self.store.save_relationship(
            replace(relationship, inbound_state="removed", updated_at=self._now())
        )

    def receive(self, activity: Mapping[str, Any]) -> str:
        actor_id = _https_identifier(activity.get("actor"), "Activity actor")
        relationship = self.store.relationship(actor_id)
        if relationship is None:
            relationship = self.discover(actor_id)
        if relationship.blocked:
            return "blocked"
        activity_id = _https_identifier(activity.get("id"), "Activity ID")
        activity_type = str(activity.get("type", ""))
        if activity_type == "Follow":
            if activity.get("object") != self._local_actor_id:
                return "ignored-object"
            if relationship.inbound_state in {"none", "removed", "rejected"}:
                self.store.save_relationship(
                    replace(
                        relationship,
                        inbound_state="pending",
                        inbound_follow_id=activity_id,
                        updated_at=self._now(),
                    )
                )
                return "pending-follow"
            return "duplicate-follow"
        if activity_type in {"Accept", "Reject"}:
            referenced = _object_id(activity.get("object"))
            if (
                relationship.outbound_state != "pending"
                or referenced != relationship.outbound_follow_id
            ):
                return "stale-response"
            self.store.save_relationship(
                replace(
                    relationship,
                    outbound_state="following" if activity_type == "Accept" else "rejected",
                    updated_at=self._now(),
                )
            )
            return "following" if activity_type == "Accept" else "rejected"
        if activity_type == "Undo":
            undo = activity.get("object")
            if not isinstance(undo, Mapping) or undo.get("type") != "Follow":
                return "ignored-undo"
            if _object_id(undo) != relationship.inbound_follow_id:
                return "stale-undo"
            self.store.save_relationship(
                replace(relationship, inbound_state="removed", updated_at=self._now())
            )
            return "removed"
        if activity_type == "Delete" and _object_id(activity.get("object")) == actor_id:
            deleted_actor = replace(relationship.actor, deleted_at=self._now())
            self.store.upsert_remote_actor(deleted_actor)
            self.store.save_relationship(
                replace(
                    relationship,
                    actor=deleted_actor,
                    outbound_state="remote-deleted",
                    inbound_state="removed",
                    unavailable=True,
                    updated_at=self._now(),
                )
            )
            return "remote-deleted"
        return "no-relationship-effect"

    def set_preference(
        self, actor_id: str, *, preference: str, enabled: bool, note: str | None = None
    ) -> Relationship:
        relationship = self._required(actor_id)
        if relationship.blocked:
            raise PermissionError("Blocked relationships cannot retain local preferences.")
        if preference == "pinned":
            relationship = replace(relationship, pinned=enabled)
        elif preference == "muted":
            relationship = replace(relationship, muted=enabled)
        elif preference == "note":
            note_value = (note or "").strip()
            if len(note_value) > 500 or any(
                character in note_value for character in ("<", ">", "\x00")
            ):
                raise ValueError("Relationship note must be at most 500 plain-text characters.")
            relationship = replace(relationship, note=note_value)
        else:
            raise ValueError("Unknown relationship preference.")
        return self.store.save_relationship(replace(relationship, updated_at=self._now()))

    def block_actor(self, actor_id: str) -> Relationship:
        return self.store.block_actor(actor_id, now=self._now())

    def unblock_actor(self, actor_id: str) -> Relationship:
        return self.store.unblock_actor(actor_id, now=self._now())

    def block_domain(self, domain: str) -> None:
        normalized = _domain(domain)
        self.store.block_domain(normalized, now=self._now())

    def unblock_domain(self, domain: str) -> None:
        self.store.unblock_domain(_domain(domain))

    def mark_unavailable(self, actor_id: str, *, unavailable: bool = True) -> Relationship:
        relationship = self._required(actor_id)
        return self.store.save_relationship(
            replace(relationship, unavailable=unavailable, updated_at=self._now())
        )

    def create_circle(self, name: str) -> Circle:
        normalized = name.strip()
        if not CIRCLE_NAME_RE.fullmatch(normalized):
            raise ValueError("Circle name must be 1 to 60 plain-text characters.")
        return self.store.create_circle(Circle(str(uuid.uuid7()), normalized, (), self._now()))

    def set_circle_members(self, circle_id: str, actor_ids: Sequence[str]) -> Circle:
        return self.store.set_circle_members(circle_id, actor_ids)

    def audience_preview(self, visibility: str, *, circle_id: str | None = None) -> AudiencePreview:
        relationships = tuple(
            relationship
            for relationship in self.store.relationships()
            if not relationship.blocked and not relationship.actor.deleted_at
        )
        if visibility in {"public", "unlisted", "followers"}:
            recipients = tuple(
                item.actor.id for item in relationships if item.inbound_state == "follower"
            )
        elif visibility == "friends":
            recipients = tuple(item.actor.id for item in relationships if item.friend)
        elif visibility == "circle":
            circle = next((item for item in self.store.circles() if item.id == circle_id), None)
            if circle is None:
                raise ValueError("Choose an existing circle.")
            friend_ids = {item.actor.id for item in relationships if item.friend}
            recipients = tuple(
                actor_id for actor_id in circle.member_actor_ids if actor_id in friend_ids
            )
        elif visibility in {"local", "draft"}:
            recipients = ()
        else:
            raise ValueError("Unknown audience visibility.")
        if visibility in {"followers", "friends", "circle"} and not recipients:
            raise ValueError("This restricted audience has no eligible recipients.")
        disclosure = {
            "public": "Anyone can access and reshare this post.",
            "unlisted": "Anyone with the URL can access and reshare this post.",
            "followers": "Accepted followers receive this; delivery is not encryption or DRM.",
            "friends": "Mutual accepted relationships receive this; remote copies cannot be revoked.",
            "circle": "The listed circle members receive this; remote copies cannot be revoked.",
            "local": "This stays on this Space and is never federated.",
            "draft": "This remains unpublished and is never federated.",
        }[visibility]
        return AudiencePreview(visibility, tuple(sorted(recipients)), disclosure)

    @property
    def _local_actor_id(self) -> str:
        return f"{self.delivery.federation.config.canonical_origin}/ap/actor"

    def _activity_id(self) -> str:
        return f"{self.delivery.federation.config.canonical_origin}/ap/activities/{uuid.uuid7()}"

    def _enqueue(self, relationship: Relationship, activity: Mapping[str, Any]) -> None:
        self.delivery.enqueue(activity, inbox_urls=[relationship.actor.inbox_url])

    def _required(self, actor_id: str) -> Relationship:
        relationship = self.store.relationship(actor_id)
        if relationship is None:
            raise ValueError("Remote relationship was not found.")
        return relationship

    def _resolve_reference(self, reference: str) -> tuple[str, str | None]:
        candidate = reference.strip()
        if candidate.startswith("https://"):
            actor_url = _https_identifier(candidate, "Actor URL")
            domain = urlsplit(actor_url).hostname
            if domain is not None and self.store.is_blocked(domain=domain.casefold()):
                raise PermissionError("Remote actor domain is blocked.")
            if self.store.is_blocked(actor_id=actor_url):
                raise PermissionError("Remote actor is blocked.")
            return actor_url, None
        if candidate.startswith("acct:"):
            candidate = candidate.removeprefix("acct:")
        candidate = candidate.removeprefix("@")
        if "@" not in candidate:
            raise ValueError("Enter an HTTPS actor URL or @handle@domain.")
        handle, domain = candidate.rsplit("@", 1)
        handle = handle.casefold()
        domain = _domain(domain)
        if not HANDLE_RE.fullmatch(handle):
            raise ValueError("Remote handle is invalid.")
        if self.store.is_blocked(domain=domain):
            raise PermissionError("Remote actor domain is blocked.")
        if any(
            relationship.blocked
            and relationship.actor.domain == domain
            and relationship.actor.preferred_username.casefold() == handle
            for relationship in self.store.relationships()
        ):
            raise PermissionError("Remote actor is blocked.")
        subject = f"acct:{handle}@{domain}"
        jrd = self.fetcher.fetch_json(
            f"https://{domain}/.well-known/webfinger?resource={quote(subject, safe='')}"
        )
        links = jrd.get("links")
        if jrd.get("subject") != subject or not isinstance(links, list):
            raise FederationError("webfinger", "Remote WebFinger response is invalid.")
        actor_url = next(
            (
                str(link.get("href"))
                for link in links
                if isinstance(link, Mapping)
                and link.get("rel") == "self"
                and link.get("type") == ACTIVITY_JSON
            ),
            "",
        )
        actor_url = _https_identifier(actor_url, "WebFinger actor URL")
        if urlsplit(actor_url).hostname != domain:
            raise FederationError(
                "webfinger-host", "WebFinger actor must use the discovered canonical host."
            )
        if self.store.is_blocked(actor_id=actor_url):
            raise PermissionError("Remote actor is blocked.")
        return actor_url, handle


def _object_id(value: object) -> str:
    if isinstance(value, Mapping):
        value = value.get("id")
    return _https_identifier(value, "Referenced object")


def _https_identifier(value: object, field: str) -> str:
    candidate = str(value or "")
    parsed = urlsplit(candidate)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or parsed.fragment
        or len(candidate) > 2048
    ):
        raise FederationError("identifier", f"{field} must be a bounded HTTPS URL.")
    return candidate


def _plain_text(value: object, field: str, limit: int) -> str:
    candidate = str(value or "").strip()
    if (
        not candidate
        or len(candidate) > limit
        or any(character in candidate for character in ("<", ">", "\x00"))
    ):
        raise FederationError("plain-text", f"{field} must be bounded plain text.")
    return candidate


def _domain(value: str) -> str:
    candidate = value.strip().casefold().rstrip(".")
    parsed = urlsplit(f"https://{candidate}")
    if not parsed.hostname or parsed.hostname != candidate or parsed.port is not None:
        raise ValueError("Domain must be a hostname without a port or path.")
    return candidate
