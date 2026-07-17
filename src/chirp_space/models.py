"""Typed application-owned identity and customization primitives."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

MODULE_KINDS = (
    "identity",
    "links",
    "featured",
    "recent_posts",
    "journal",
    "photos",
    "tags",
    "guestbook",
)


@dataclass(frozen=True, slots=True)
class Owner:
    id: str
    handle: str
    display_name: str
    bio: str
    location: str
    website_url: str | None
    password_hash: str
    claimed_at: datetime


@dataclass(frozen=True, slots=True)
class Theme:
    palette: str = "system"
    font: str = "system"
    scale: str = "standard"
    density: str = "comfortable"
    radius: str = "soft"
    layout_width: str = "standard"

    @property
    def class_names(self) -> str:
        values = (
            ("theme", self.palette),
            ("font", self.font),
            ("scale", self.scale),
            ("density", self.density),
            ("radius", self.radius),
            ("width", self.layout_width),
        )
        return " ".join(f"{prefix}-{value}" for prefix, value in values)


@dataclass(frozen=True, slots=True)
class SiteSettings:
    id: str
    canonical_origin: str
    theme: Theme
    revision: int
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ProfileModule:
    kind: str
    enabled: bool
    position: int
    config: dict[str, Any]


@dataclass(frozen=True, slots=True)
class SiteState:
    owner: Owner
    settings: SiteSettings
    modules: tuple[ProfileModule, ...]


@dataclass(frozen=True, slots=True)
class Customization:
    display_name: str
    bio: str
    location: str
    website_url: str | None
    theme: Theme
    modules: tuple[ProfileModule, ...]
    expected_revision: int


@dataclass(frozen=True, slots=True)
class FederationKey:
    id: str
    public_pem: str
    encrypted_private_pem: bytes
    created_at: datetime
    retired_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class InboxReceipt:
    signature_hash: str
    activity_id: str
    body_hash: str
    activity_type: str
    status: str
    diagnostic: str
    received_at: datetime


@dataclass(frozen=True, slots=True)
class OutboundActivity:
    id: str
    actor_id: str
    activity_type: str
    object_id: str | None
    body: bytes
    created_at: datetime


@dataclass(frozen=True, slots=True)
class Delivery:
    id: str
    activity_id: str
    inbox_url: str
    status: str
    attempts: int
    next_attempt_at: datetime
    last_error: str | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class DeliveryJob:
    delivery: Delivery
    activity: OutboundActivity


@dataclass(frozen=True, slots=True)
class QueueHealth:
    pending: int
    retrying: int
    delivered: int
    dead: int
    discarded: int
    open_circuits: int


@dataclass(frozen=True, slots=True)
class RemoteActor:
    id: str
    inbox_url: str
    preferred_username: str
    display_name: str
    domain: str
    last_contact_at: datetime
    deleted_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class Relationship:
    actor: RemoteActor
    outbound_state: str
    inbound_state: str
    outbound_follow_id: str | None
    inbound_follow_id: str | None
    pinned: bool
    muted: bool
    blocked: bool
    unavailable: bool
    note: str
    updated_at: datetime

    @property
    def friend(self) -> bool:
        return self.outbound_state == "following" and self.inbound_state == "follower"


@dataclass(frozen=True, slots=True)
class Circle:
    id: str
    name: str
    member_actor_ids: tuple[str, ...]
    created_at: datetime


@dataclass(frozen=True, slots=True)
class AudiencePreview:
    visibility: str
    recipient_actor_ids: tuple[str, ...]
    disclosure: str


@dataclass(frozen=True, slots=True)
class MediaVariant:
    name: str
    object_key: str
    media_type: str
    width: int
    height: int
    byte_size: int
    checksum: str


@dataclass(frozen=True, slots=True)
class MediaAsset:
    id: str
    object_key: str
    media_type: str
    width: int
    height: int
    byte_size: int
    checksum: str
    alt_text: str
    status: str
    created_at: datetime
    variants: tuple[MediaVariant, ...] = ()


@dataclass(frozen=True, slots=True)
class ContentItem:
    id: str
    owner_id: str
    kind: str
    state: str
    title: str
    source: str
    external_url: str | None
    media: MediaAsset | None
    tags: tuple[str, ...]
    revision: int
    created_at: datetime
    updated_at: datetime
    published_at: datetime | None
    deleted_at: datetime | None


@dataclass(frozen=True, slots=True)
class GuestbookEntry:
    id: str
    display_name: str
    message: str
    website_url: str | None
    status: str
    abuse_token: str
    submission_hash: str
    created_at: datetime
    moderated_at: datetime | None
