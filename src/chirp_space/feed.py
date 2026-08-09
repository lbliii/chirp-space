"""Chronological home feed, interactions, and local notifications (#797 / #795)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from chirp_space.config import SpaceConfig
from chirp_space.delivery import DeliveryService
from chirp_space.models import (
    Bookmark,
    FeedEntry,
    Interaction,
    Notification,
    Relationship,
    RemoteObject,
)
from chirp_space.store import Store

CLOCK_SKEW = timedelta(days=1)
DEFAULT_PAGE_SIZE = 50
MENTION_RE = re.compile(r"@([a-z0-9](?:[a-z0-9_.-]{0,62}[a-z0-9])?)@([a-z0-9.-]+\.[a-z]{2,})", re.I)
HANDLE_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_.-]{0,62}[a-z0-9])?$", re.I)


class FeedService:
    """Assemble the owner feed and apply bounded interaction side effects."""

    def __init__(
        self,
        store: Store,
        config: SpaceConfig,
        delivery: DeliveryService,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.config = config
        self.delivery = delivery
        self._now = now or (lambda: datetime.now(UTC))

    # --- Home feed ---------------------------------------------------------

    def home_feed(
        self,
        *,
        cursor: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        include_muted: bool = False,
    ) -> tuple[tuple[FeedEntry, ...], str | None]:
        if not 1 <= limit <= DEFAULT_PAGE_SIZE:
            raise ValueError("Feed page size must be between 1 and 50.")
        before = self._decode_cursor(cursor) if cursor else None
        entries = self._assemble_entries(include_muted=include_muted)
        if before is not None:
            sort_at, actor_id, object_id = before
            entries = [
                entry
                for entry in entries
                if self._before_cursor(entry, sort_at, actor_id, object_id)
            ]
        page = tuple(entries[:limit])
        next_cursor = self._encode_cursor(page[-1]) if len(entries) > limit and page else None
        return page, next_cursor

    def _before_cursor(
        self, entry: FeedEntry, sort_at: datetime, actor_id: str, object_id: str
    ) -> bool:
        """True when entry sorts after the cursor in DESC(sort_at), ASC(actor), ASC(object)."""
        if entry.sort_at < sort_at:
            return True
        if entry.sort_at > sort_at:
            return False
        if entry.actor_id > actor_id:
            return True
        if entry.actor_id < actor_id:
            return False
        return entry.object_id > object_id

    def _assemble_entries(self, *, include_muted: bool) -> list[FeedEntry]:
        state = self.store.state()
        if state is None:
            return []
        local_actor = f"{state.settings.canonical_origin}/ap/actor"
        relationships = {item.actor.id: item for item in self.store.relationships()}
        bookmarks = {item.object_id for item in self.store.bookmarks()}
        likes = self.store.interaction_counts("like")
        reposts = self.store.interaction_counts("repost")
        owner_likes = {
            item.object_id
            for item in self.store.interactions(kind="like", actor_id=local_actor, active_only=True)
        }
        owner_reposts = {
            item.object_id
            for item in self.store.interactions(
                kind="repost", actor_id=local_actor, active_only=True
            )
        }
        delivery_by_object = self.store.delivery_status_by_object()

        entries: list[FeedEntry] = []
        for item in self.store.content_items(public_only=False, limit=500):
            if item.state not in {"public", "local_only"} or item.published_at is None:
                continue
            if item.state == "deleted":
                continue
            object_id = f"{state.settings.canonical_origin}{self._local_path(item.kind, item.id)}"
            entries.append(
                FeedEntry(
                    event_id=f"local-post:{item.id}",
                    event_kind="post",
                    object_id=object_id,
                    actor_id=local_actor,
                    actor_display_name=state.owner.display_name,
                    actor_handle=state.owner.handle,
                    actor_domain=urlsplit(state.settings.canonical_origin).hostname or "localhost",
                    origin="local",
                    canonical_url=object_id,
                    content_text=item.source,
                    summary=item.title or item.source[:80],
                    published_at=item.published_at,
                    sort_at=item.published_at,
                    status="fresh",
                    like_count=likes.get(object_id, 0),
                    repost_count=reposts.get(object_id, 0),
                    liked_by_owner=object_id in owner_likes,
                    reposted_by_owner=object_id in owner_reposts,
                    bookmarked=object_id in bookmarks,
                    delivery_status=delivery_by_object.get(item.id),
                )
            )

        for remote in self.store.remote_objects(limit=500):
            relationship = relationships.get(remote.actor_id)
            if relationship is None or relationship.blocked:
                continue
            if relationship.outbound_state != "following":
                continue
            if relationship.muted and not include_muted:
                continue
            if self.store.is_blocked(actor_id=remote.actor_id, domain=relationship.actor.domain):
                continue
            status = self._remote_status(remote, relationship)
            if status == "blocked-hidden":
                continue
            entries.append(
                FeedEntry(
                    event_id=f"remote-post:{remote.id}",
                    event_kind="post",
                    object_id=remote.id,
                    actor_id=remote.actor_id,
                    actor_display_name=relationship.actor.display_name,
                    actor_handle=relationship.actor.preferred_username,
                    actor_domain=relationship.actor.domain,
                    origin="remote",
                    canonical_url=remote.id,
                    content_text="" if status == "tombstone" else remote.content_text,
                    summary=(
                        "Deleted remotely"
                        if status == "tombstone"
                        else (remote.summary or remote.content_text[:80])
                    ),
                    published_at=remote.published_at,
                    sort_at=remote.published_at,
                    status=status,
                    in_reply_to=remote.in_reply_to,
                    like_count=likes.get(remote.id, 0),
                    repost_count=reposts.get(remote.id, 0),
                    liked_by_owner=remote.id in owner_likes,
                    reposted_by_owner=remote.id in owner_reposts,
                    bookmarked=remote.id in bookmarks,
                    updated_at=remote.updated_at,
                )
            )

        for interaction in self.store.interactions(kind="repost", active_only=True):
            if interaction.actor_id == local_actor:
                actor_name = state.owner.display_name
                actor_handle = state.owner.handle
                actor_domain = urlsplit(state.settings.canonical_origin).hostname or "localhost"
                origin = "local"
            else:
                relationship = relationships.get(interaction.actor_id)
                if relationship is None or relationship.blocked:
                    continue
                if (
                    relationship.outbound_state != "following"
                    and interaction.actor_id != local_actor
                ):
                    continue
                if relationship.muted and not include_muted:
                    continue
                actor_name = relationship.actor.display_name
                actor_handle = relationship.actor.preferred_username
                actor_domain = relationship.actor.domain
                origin = "remote"
            target = self._object_snapshot(interaction.object_id, relationships)
            if target is None:
                continue
            entries.append(
                FeedEntry(
                    event_id=f"repost:{interaction.id}",
                    event_kind="repost",
                    object_id=interaction.object_id,
                    actor_id=interaction.actor_id,
                    actor_display_name=actor_name,
                    actor_handle=actor_handle,
                    actor_domain=actor_domain,
                    origin=origin,
                    canonical_url=interaction.object_id,
                    content_text=target["content_text"],
                    summary=f"Reposted: {target['summary']}",
                    published_at=interaction.created_at,
                    sort_at=interaction.created_at,
                    status=str(target["status"]),
                    like_count=likes.get(interaction.object_id, 0),
                    repost_count=reposts.get(interaction.object_id, 0),
                    liked_by_owner=interaction.object_id in owner_likes,
                    reposted_by_owner=interaction.object_id in owner_reposts,
                    bookmarked=interaction.object_id in bookmarks,
                )
            )

        entries.sort(
            key=lambda entry: (-entry.sort_at.timestamp(), entry.actor_id, entry.object_id)
        )
        return entries

    def _remote_status(self, remote: RemoteObject, relationship: Relationship) -> str:
        if relationship.blocked or self.store.is_blocked(
            actor_id=remote.actor_id, domain=relationship.actor.domain
        ):
            return "blocked-hidden"
        if remote.deleted_at is not None or remote.object_type == "Tombstone":
            return "tombstone"
        if remote.unavailable or relationship.unavailable or relationship.actor.deleted_at:
            return "unavailable"
        if remote.updated_at is not None:
            return "updated"
        return "fresh"

    def _object_snapshot(
        self, object_id: str, relationships: Mapping[str, Relationship]
    ) -> dict[str, str] | None:
        remote = self.store.remote_object(object_id)
        if remote is not None:
            relationship = relationships.get(remote.actor_id)
            if relationship is None or relationship.blocked:
                return None
            status = self._remote_status(remote, relationship)
            return {
                "content_text": "" if status == "tombstone" else remote.content_text,
                "summary": "Deleted remotely" if status == "tombstone" else remote.summary,
                "status": status,
            }
        state = self.store.state()
        if state is None:
            return None
        for item in self.store.content_items(public_only=False, limit=500):
            path = self._local_path(item.kind, item.id)
            if f"{state.settings.canonical_origin}{path}" == object_id:
                if item.state == "deleted":
                    return {
                        "content_text": "",
                        "summary": "Deleted locally",
                        "status": "tombstone",
                    }
                return {
                    "content_text": item.source,
                    "summary": item.title or item.source[:80],
                    "status": "fresh",
                }
        return {
            "content_text": "",
            "summary": "Original unavailable",
            "status": "unavailable",
        }

    @staticmethod
    def _local_path(kind: str, item_id: str) -> str:
        mapping = {"short": "posts", "journal": "journal", "photo": "photos", "link": "links"}
        return f"/{mapping[kind]}/{item_id}"

    # --- Remote author -----------------------------------------------------

    def remote_author(
        self, domain: str, username: str
    ) -> tuple[Relationship | None, tuple[FeedEntry, ...]]:
        domain = domain.casefold()
        username = username.casefold()
        if self.store.is_blocked(domain=domain):
            return None, ()
        relationship = next(
            (
                item
                for item in self.store.relationships()
                if item.actor.domain == domain
                and item.actor.preferred_username.casefold() == username
            ),
            None,
        )
        if relationship is None or relationship.blocked:
            return relationship, ()
        entries = [
            entry
            for entry in self._assemble_entries(include_muted=True)
            if entry.actor_id == relationship.actor.id and entry.event_kind == "post"
        ]
        return relationship, tuple(entries)

    # --- Inbound federation dispatch --------------------------------------

    def receive(self, activity: Mapping[str, Any]) -> str:
        activity_type = str(activity.get("type", ""))
        actor_id = _https_identifier(activity.get("actor"), "Activity actor")
        if self.store.is_blocked(actor_id=actor_id, domain=_domain(actor_id)):
            return "blocked"
        relationship = self.store.relationship(actor_id)
        if relationship is not None and relationship.blocked:
            return "blocked"
        if activity_type == "Create":
            return self._receive_create(activity, actor_id)
        if activity_type == "Update":
            return self._receive_update(activity, actor_id)
        if activity_type == "Delete":
            return self._receive_delete(activity, actor_id)
        if activity_type == "Like":
            return self._receive_edge(activity, actor_id, kind="like")
        if activity_type == "Announce":
            return self._receive_edge(activity, actor_id, kind="repost")
        if activity_type == "Undo":
            return self._receive_undo(activity, actor_id)
        if activity_type in {"Follow", "Accept", "Reject"}:
            return self._notify_relationship(activity_type, activity, actor_id)
        return "no-feed-effect"

    def _receive_create(self, activity: Mapping[str, Any], actor_id: str) -> str:
        relationship = self.store.relationship(actor_id)
        if relationship is None or relationship.outbound_state != "following":
            return "ignored-unfollowed"
        obj = activity.get("object")
        if not isinstance(obj, Mapping):
            raise ValueError("Create activities require an embedded object.")
        object_id = _https_identifier(obj.get("id"), "Object ID")
        object_type = str(obj.get("type", ""))
        if object_type not in {"Note", "Article", "Image"}:
            return "ignored-object-type"
        if self.store.remote_object(object_id) is not None:
            return "duplicate"
        now = self._now()
        published = _clamp_published(obj.get("published"), received_at=now, now=now)
        content = _plain_text(obj.get("content") or obj.get("name") or "", "Remote content", 8_000)
        summary = _plain_text(obj.get("summary") or content[:80], "Remote summary", 280)
        in_reply_to = None
        if obj.get("inReplyTo"):
            in_reply_to = _https_identifier(obj.get("inReplyTo"), "inReplyTo")
        remote = RemoteObject(
            id=object_id,
            actor_id=actor_id,
            object_type=object_type,
            content_text=content,
            summary=summary,
            in_reply_to=in_reply_to,
            published_at=published,
            received_at=now,
            activity_id=_https_identifier(activity.get("id"), "Activity ID"),
        )
        self.store.upsert_remote_object(remote)
        self.store.touch_remote_actor(actor_id, now=now)
        if in_reply_to and self._is_local_object(in_reply_to):
            self._notify(
                kind="reply",
                actor_id=actor_id,
                object_id=object_id,
                activity_id=str(activity.get("id")),
                summary=f"{relationship.actor.display_name} replied to your post",
            )
        for mention in _mentions(obj):
            if mention == self._local_actor_id:
                self._notify(
                    kind="mention",
                    actor_id=actor_id,
                    object_id=object_id,
                    activity_id=str(activity.get("id")),
                    summary=f"{relationship.actor.display_name} mentioned you",
                )
        return "created"

    def _receive_update(self, activity: Mapping[str, Any], actor_id: str) -> str:
        obj = activity.get("object")
        if not isinstance(obj, Mapping):
            raise ValueError("Update activities require an embedded object.")
        object_id = _https_identifier(obj.get("id"), "Object ID")
        existing = self.store.remote_object(object_id)
        if existing is None:
            return "missing-object"
        if existing.actor_id != actor_id:
            raise PermissionError("Only the original actor may update a remote object.")
        content = _plain_text(
            obj.get("content") or obj.get("name") or existing.content_text,
            "Remote content",
            8_000,
        )
        summary = _plain_text(
            obj.get("summary") or content[:80] or existing.summary, "Remote summary", 280
        )
        updated = replace(
            existing,
            content_text=content,
            summary=summary,
            updated_at=self._now(),
            activity_id=_https_identifier(activity.get("id"), "Activity ID"),
            object_type=str(obj.get("type") or existing.object_type),
        )
        self.store.upsert_remote_object(updated)
        return "updated"

    def _receive_delete(self, activity: Mapping[str, Any], actor_id: str) -> str:
        object_id = _object_id(activity.get("object"))
        if object_id == actor_id:
            return "actor-delete"
        existing = self.store.remote_object(object_id)
        if existing is None:
            return "missing-object"
        if existing.actor_id != actor_id:
            raise PermissionError("Only the original actor may delete a remote object.")
        now = self._now()
        self.store.upsert_remote_object(
            replace(
                existing,
                object_type="Tombstone",
                content_text="",
                summary="Deleted remotely",
                deleted_at=now,
                updated_at=now,
                activity_id=_https_identifier(activity.get("id"), "Activity ID"),
            )
        )
        return "tombstone"

    def _receive_edge(self, activity: Mapping[str, Any], actor_id: str, *, kind: str) -> str:
        object_id = _object_id(activity.get("object"))
        activity_id = _https_identifier(activity.get("id"), "Activity ID")
        if self.store.interaction_by_activity(activity_id) is not None:
            return "duplicate"
        existing = self.store.active_interaction(kind=kind, actor_id=actor_id, object_id=object_id)
        if existing is not None:
            return "duplicate"
        now = self._now()
        self.store.save_interaction(
            Interaction(
                id=activity_id,
                kind=kind,
                actor_id=actor_id,
                object_id=object_id,
                created_at=now,
            )
        )
        if self._is_local_object(object_id):
            relationship = self.store.relationship(actor_id)
            name = relationship.actor.display_name if relationship else actor_id
            self._notify(
                kind=kind,
                actor_id=actor_id,
                object_id=object_id,
                activity_id=activity_id,
                summary=f"{name} {'liked' if kind == 'like' else 'reposted'} your post",
            )
        return kind

    def _receive_undo(self, activity: Mapping[str, Any], actor_id: str) -> str:
        target = activity.get("object")
        if not isinstance(target, Mapping):
            return "ignored-undo"
        target_type = str(target.get("type", ""))
        if target_type not in {"Like", "Announce"}:
            return "ignored-undo"
        kind = "like" if target_type == "Like" else "repost"
        object_id = _object_id(target.get("object"))
        existing = self.store.active_interaction(kind=kind, actor_id=actor_id, object_id=object_id)
        if existing is None:
            return "stale-undo"
        self.store.save_interaction(replace(existing, undone_at=self._now()))
        return "undone"

    def _notify_relationship(
        self, activity_type: str, activity: Mapping[str, Any], actor_id: str
    ) -> str:
        relationship = self.store.relationship(actor_id)
        name = relationship.actor.display_name if relationship else actor_id
        kind = {
            "Follow": "follow-pending",
            "Accept": "follow-accepted",
            "Reject": "follow-rejected",
        }[activity_type]
        summary = {
            "Follow": f"{name} asked to follow you",
            "Accept": f"{name} accepted your follow",
            "Reject": f"{name} rejected your follow",
        }[activity_type]
        self._notify(
            kind=kind,
            actor_id=actor_id,
            object_id=None,
            activity_id=str(activity.get("id")),
            summary=summary,
        )
        return "notified"

    # --- Owner interactions -----------------------------------------------

    def like(self, object_id: str) -> Interaction:
        return self._edge("like", object_id)

    def unlike(self, object_id: str) -> Interaction | None:
        return self._undo_edge("like", object_id)

    def repost(self, object_id: str) -> Interaction:
        remote = self.store.remote_object(object_id)
        if remote is not None and remote.deleted_at is not None:
            raise ValueError("Deleted objects cannot be reposted.")
        # Restricted local content cannot be announced publicly.
        if self._is_local_object(object_id) and not self._is_public_local(object_id):
            raise PermissionError("Restricted objects cannot be reposted publicly.")
        return self._edge("repost", object_id)

    def unrepost(self, object_id: str) -> Interaction | None:
        return self._undo_edge("repost", object_id)

    def reply(self, object_id: str, *, source: str, visibility: str = "public") -> FeedEntry:
        text = _plain_text(source, "Reply", 4_000, required=True)
        if visibility not in {
            "public",
            "unlisted",
            "followers",
            "friends",
            "circle",
            "local",
            "draft",
        }:
            raise ValueError("Unknown reply visibility.")
        parent_visibility = self._object_visibility(object_id)
        if not _same_or_narrower(visibility, parent_visibility):
            raise ValueError("A reply cannot broaden the parent audience.")
        state = self._require_state()
        now = self._now()
        reply_id = str(uuid.uuid7())
        object_url = f"{state.settings.canonical_origin}/posts/{reply_id}"
        # Persist as a short local content item for stable permalinks.
        from chirp_space.models import ContentItem

        owner = state.owner
        item = ContentItem(
            id=reply_id,
            owner_id=owner.id,
            kind="short",
            state="public" if visibility == "public" else "local_only",
            title="",
            source=text,
            external_url=None,
            media=None,
            tags=(),
            revision=1,
            created_at=now,
            updated_at=now,
            published_at=now if visibility != "draft" else None,
            deleted_at=None,
        )
        if visibility == "draft":
            item = replace(item, state="draft", published_at=None)
        self.store.create_content(item)
        interaction = Interaction(
            id=str(uuid.uuid7()),
            kind="reply",
            actor_id=self._local_actor_id,
            object_id=object_id,
            created_at=now,
            reply_object_id=object_url,
        )
        self.store.save_interaction(interaction)
        if visibility not in {"local", "draft"}:
            self._enqueue_create_note(
                object_url,
                text,
                in_reply_to=object_id,
                to_followers=visibility in {"public", "unlisted", "followers"},
            )
        for entry in self._assemble_entries(include_muted=True):
            if entry.object_id == object_url:
                return replace(entry, in_reply_to=object_id)
        return FeedEntry(
            event_id=f"local-post:{reply_id}",
            event_kind="post",
            object_id=object_url,
            actor_id=self._local_actor_id,
            actor_display_name=owner.display_name,
            actor_handle=owner.handle,
            actor_domain=urlsplit(state.settings.canonical_origin).hostname or "localhost",
            origin="local",
            canonical_url=object_url,
            content_text=text,
            summary=text[:80],
            published_at=now,
            sort_at=now,
            status="fresh",
            in_reply_to=object_id,
            delivery_status="queued",
        )

    def bookmark(self, object_id: str) -> Bookmark:
        _https_identifier(object_id, "Bookmark object")
        bookmark = Bookmark(object_id=object_id, created_at=self._now())
        return self.store.save_bookmark(bookmark)

    def unbookmark(self, object_id: str) -> None:
        self.store.delete_bookmark(object_id)

    def bookmarks(self) -> tuple[Bookmark, ...]:
        return self.store.bookmarks()

    def mark_unavailable(self, object_id: str, *, unavailable: bool = True) -> RemoteObject:
        remote = self.store.remote_object(object_id)
        if remote is None:
            raise LookupError("Remote object not found.")
        updated = replace(remote, unavailable=unavailable, updated_at=self._now())
        return self.store.upsert_remote_object(updated)

    # --- Notifications ----------------------------------------------------

    def notifications(
        self, *, unread_only: bool = False, limit: int = 50
    ) -> tuple[Notification, ...]:
        return self.store.notifications(unread_only=unread_only, limit=limit)

    def unread_notification_count(self) -> int:
        return self.store.unread_notification_count()

    def mark_notification_read(self, notification_id: str) -> Notification:
        return self.store.mark_notification_read(notification_id, read_at=self._now())

    def mark_all_notifications_read(self) -> int:
        return self.store.mark_all_notifications_read(read_at=self._now())

    def dismiss_notification(self, notification_id: str) -> None:
        self.store.delete_notification(notification_id)

    def _notify(
        self,
        *,
        kind: str,
        summary: str,
        actor_id: str | None,
        object_id: str | None,
        activity_id: str | None,
    ) -> None:
        if (
            actor_id
            and self._is_muted(actor_id)
            and kind
            not in {
                "follow-pending",
                "follow-accepted",
                "follow-rejected",
                "delivery-failure",
            }
        ):
            return
        if activity_id and self.store.notification_for_activity(activity_id) is not None:
            return
        self.store.save_notification(
            Notification(
                id=str(uuid.uuid7()),
                kind=kind,
                summary=summary,
                created_at=self._now(),
                actor_id=actor_id,
                object_id=object_id,
                activity_id=activity_id,
            )
        )

    def notify_delivery_failure(self, *, object_id: str, detail: str) -> None:
        self._notify(
            kind="delivery-failure",
            actor_id=None,
            object_id=object_id,
            activity_id=None,
            summary=f"Delivery needs attention: {detail}",
        )

    # --- Helpers ----------------------------------------------------------

    def _edge(self, kind: str, object_id: str) -> Interaction:
        object_id = _https_identifier(object_id, "Interaction object")
        actor_id = self._local_actor_id
        existing = self.store.active_interaction(kind=kind, actor_id=actor_id, object_id=object_id)
        if existing is not None:
            return existing
        now = self._now()
        activity_id = (
            f"{self._require_state().settings.canonical_origin}/ap/activities/{uuid.uuid7()}"
        )
        interaction = Interaction(
            id=activity_id,
            kind=kind,
            actor_id=actor_id,
            object_id=object_id,
            created_at=now,
        )
        self.store.save_interaction(interaction)
        activity_type = "Like" if kind == "like" else "Announce"
        self._enqueue_simple(activity_type, activity_id, object_id)
        return interaction

    def _undo_edge(self, kind: str, object_id: str) -> Interaction | None:
        object_id = _https_identifier(object_id, "Interaction object")
        existing = self.store.active_interaction(
            kind=kind, actor_id=self._local_actor_id, object_id=object_id
        )
        if existing is None:
            return None
        undone = replace(existing, undone_at=self._now())
        self.store.save_interaction(undone)
        undo_id = f"{self._require_state().settings.canonical_origin}/ap/activities/{uuid.uuid7()}"
        self._enqueue_undo(kind, undo_id, existing)
        return undone

    def _enqueue_simple(self, activity_type: str, activity_id: str, object_id: str) -> None:
        if not self.config.federation_enabled:
            return
        state = self._require_state()
        inboxes = [
            item.actor.inbox_url
            for item in self.store.relationships()
            if item.inbound_state == "follower" and not item.blocked
        ]
        if not inboxes:
            return
        body = {
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": activity_id,
            "type": activity_type,
            "actor": f"{state.settings.canonical_origin}/ap/actor",
            "object": object_id,
        }
        try:
            self.delivery.enqueue(body, inbox_urls=inboxes)
        except RuntimeError:
            return

    def _enqueue_undo(self, kind: str, undo_id: str, interaction: Interaction) -> None:
        if not self.config.federation_enabled:
            return
        state = self._require_state()
        inboxes = [
            item.actor.inbox_url
            for item in self.store.relationships()
            if item.inbound_state == "follower" and not item.blocked
        ]
        if not inboxes:
            return
        body = {
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": undo_id,
            "type": "Undo",
            "actor": f"{state.settings.canonical_origin}/ap/actor",
            "object": {
                "id": interaction.id,
                "type": "Like" if kind == "like" else "Announce",
                "actor": interaction.actor_id,
                "object": interaction.object_id,
            },
        }
        try:
            self.delivery.enqueue(body, inbox_urls=inboxes)
        except RuntimeError:
            return

    def _enqueue_create_note(
        self,
        object_url: str,
        text: str,
        *,
        in_reply_to: str,
        to_followers: bool,
    ) -> None:
        if not self.config.federation_enabled:
            return
        state = self._require_state()
        inboxes = [
            item.actor.inbox_url
            for item in self.store.relationships()
            if item.inbound_state == "follower" and not item.blocked
        ]
        if not to_followers or not inboxes:
            return
        activity_id = f"{state.settings.canonical_origin}/ap/activities/{uuid.uuid7()}"
        body = {
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": activity_id,
            "type": "Create",
            "actor": f"{state.settings.canonical_origin}/ap/actor",
            "object": {
                "id": object_url,
                "type": "Note",
                "attributedTo": f"{state.settings.canonical_origin}/ap/actor",
                "content": text,
                "inReplyTo": in_reply_to,
                "published": self._now().isoformat().replace("+00:00", "Z"),
            },
        }
        try:
            self.delivery.enqueue(body, inbox_urls=inboxes)
        except RuntimeError:
            return

    @property
    def _local_actor_id(self) -> str:
        return f"{self._require_state().settings.canonical_origin}/ap/actor"

    def _require_state(self):
        state = self.store.state()
        if state is None:
            raise RuntimeError("Space is not claimed.")
        return state

    def _is_local_object(self, object_id: str) -> bool:
        origin = self._require_state().settings.canonical_origin
        return object_id.startswith(f"{origin}/")

    def _is_public_local(self, object_id: str) -> bool:
        state = self._require_state()
        for item in self.store.content_items(public_only=False, limit=500):
            if (
                f"{state.settings.canonical_origin}{self._local_path(item.kind, item.id)}"
                == object_id
            ):
                return item.state == "public"
        return False

    def _object_visibility(self, object_id: str) -> str:
        remote = self.store.remote_object(object_id)
        if remote is not None:
            return "public"
        state = self._require_state()
        for item in self.store.content_items(public_only=False, limit=500):
            if (
                f"{state.settings.canonical_origin}{self._local_path(item.kind, item.id)}"
                == object_id
            ):
                if item.state == "local_only":
                    return "local"
                if item.state == "draft":
                    return "draft"
                return "public"
        return "public"

    def _is_muted(self, actor_id: str) -> bool:
        relationship = self.store.relationship(actor_id)
        return relationship is not None and relationship.muted

    def _encode_cursor(self, entry: FeedEntry) -> str:
        payload = f"{entry.sort_at.isoformat()}|{entry.actor_id}|{entry.object_id}".encode()
        signature = hmac.new(self.config.secret_key.encode(), payload, hashlib.sha256).digest()
        return (
            f"{base64.urlsafe_b64encode(payload).decode().rstrip('=')}."
            f"{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"
        )

    def _decode_cursor(self, cursor: str) -> tuple[datetime, str, str]:
        try:
            encoded_payload, encoded_signature = cursor.split(".")
            payload = base64.urlsafe_b64decode(encoded_payload + "=" * (-len(encoded_payload) % 4))
            signature = base64.urlsafe_b64decode(
                encoded_signature + "=" * (-len(encoded_signature) % 4)
            )
            expected = hmac.new(self.config.secret_key.encode(), payload, hashlib.sha256).digest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError
            timestamp, actor_id, object_id = payload.decode().split("|", 2)
            return datetime.fromisoformat(timestamp).astimezone(UTC), actor_id, object_id
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("Feed cursor is invalid or expired.") from exc


def _clamp_published(value: object, *, received_at: datetime, now: datetime) -> datetime:
    if value in (None, ""):
        return received_at
    try:
        published = datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return received_at
    earliest = now - CLOCK_SKEW
    latest = now + CLOCK_SKEW
    if published < earliest or published > latest:
        return received_at
    return published


def _same_or_narrower(reply: str, parent: str) -> bool:
    order = ("public", "unlisted", "followers", "friends", "circle", "local", "draft")
    try:
        return order.index(reply) >= order.index(parent)
    except ValueError:
        return False


def _mentions(obj: Mapping[str, Any]) -> tuple[str, ...]:
    tags = obj.get("tag")
    found: list[str] = []
    if isinstance(tags, Sequence) and not isinstance(tags, (str, bytes)):
        for tag in tags:
            if isinstance(tag, Mapping) and tag.get("type") == "Mention":
                href = tag.get("href")
                if isinstance(href, str) and href.startswith(("https://", "http://")):
                    found.append(href)
    content = str(obj.get("content") or "")
    for match in MENTION_RE.finditer(content):
        found.append(f"https://{match.group(2).casefold()}/ap/actor")
    return tuple(dict.fromkeys(found))


def _object_id(value: object) -> str:
    if isinstance(value, Mapping):
        return _https_identifier(value.get("id"), "Object ID")
    return _https_identifier(value, "Object ID")


def _https_identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.startswith(("https://", "http://")):
        raise ValueError(f"{field} must be an HTTP(S) URL.")
    parsed = urlsplit(value)
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError(f"{field} must be a clean HTTP(S) URL.")
    if not parsed.hostname:
        raise ValueError(f"{field} must include a hostname.")
    return value


def _plain_text(value: object, field: str, limit: int, *, required: bool = False) -> str:
    if value is None:
        text = ""
    elif isinstance(value, str):
        text = value.strip()
    else:
        raise ValueError(f"{field} must be plain text.")
    if required and not text:
        raise ValueError(f"{field} is required.")
    if len(text) > limit or any(character in text for character in ("<", ">", "\x00")):
        raise ValueError(f"{field} must be at most {limit} plain-text characters.")
    return text


def _domain(actor_id: str) -> str:
    host = urlsplit(actor_id).hostname
    if host is None:
        raise ValueError("Actor ID is missing a hostname.")
    return host.casefold()
