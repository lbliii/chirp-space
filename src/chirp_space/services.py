"""Single-owner claim, authentication, and customization workflows."""

from __future__ import annotations

import re
import secrets
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from chirp.security.passwords import hash_password, verify_login

from chirp_space.config import SpaceConfig
from chirp_space.models import (
    MODULE_KINDS,
    Customization,
    Owner,
    ProfileModule,
    SiteSettings,
    SiteState,
    Theme,
)
from chirp_space.store import Store, token_hash

SESSION_TTL = timedelta(days=30)
HANDLE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,29}$")
THEME_CHOICES = {
    "palette": frozenset({"system", "light", "dark"}),
    "font": frozenset({"system", "serif"}),
    "scale": frozenset({"compact", "standard", "generous"}),
    "density": frozenset({"compact", "comfortable"}),
    "radius": frozenset({"square", "soft", "round"}),
    "layout_width": frozenset({"narrow", "standard", "wide"}),
}


@dataclass(frozen=True, slots=True)
class SetupResult:
    state: SiteState
    session_token: str
    recovery_codes: tuple[str, ...]


class SpaceService:
    def __init__(self, store: Store, config: SpaceConfig) -> None:
        self.store = store
        self.config = config

    def setup(
        self,
        *,
        claim_token: str,
        canonical_origin: str,
        handle: str,
        display_name: str,
        bio: str,
        password: str,
    ) -> SetupResult:
        if self.store.state() is not None:
            raise PermissionError("Space setup is already complete.")
        if not secrets.compare_digest(claim_token, self.config.claim_token):
            raise PermissionError("The owner claim token is not valid.")
        if canonical_origin.strip().rstrip("/") != self.config.canonical_origin:
            raise ValueError(
                "Canonical origin must match SPACE_CANONICAL_ORIGIN before this Space is claimed."
            )
        normalized_handle = _validate_handle(handle)
        normalized_name = _bounded_required(display_name, "Display name", 80)
        normalized_bio = _bounded_optional(bio, "Bio", 500)
        _validate_password(password)
        now = datetime.now(UTC)
        owner = Owner(
            id=str(uuid.uuid7()),
            handle=normalized_handle,
            display_name=normalized_name,
            bio=normalized_bio,
            location="",
            website_url=None,
            password_hash=hash_password(password),
            claimed_at=now,
        )
        settings = SiteSettings(
            id=str(uuid.uuid7()),
            canonical_origin=self.config.canonical_origin,
            theme=Theme(),
            revision=1,
            updated_at=now,
        )
        modules = default_modules()
        recovery_codes = tuple(_new_recovery_code() for _ in range(8))
        self.store.bootstrap(
            owner=owner,
            settings=settings,
            modules=modules,
            recovery_code_hashes=[token_hash(code) for code in recovery_codes],
        )
        state = self.store.state()
        if state is None:
            raise RuntimeError("Space setup did not persist its owner state.")
        return SetupResult(state, self._issue_session(owner.id), recovery_codes)

    def login(self, handle: str, password: str) -> tuple[Owner, str]:
        state = self.store.state()
        owner = (
            state.owner
            if state and secrets.compare_digest(state.owner.handle, handle.strip().casefold())
            else None
        )
        verified = verify_login(password, owner.password_hash if owner else None)
        if not verified or owner is None:
            raise PermissionError("Handle or password is incorrect.")
        return owner, self._issue_session(owner.id)

    def login_with_recovery_code(self, handle: str, code: str) -> tuple[Owner, str]:
        state = self.store.state()
        owner = (
            state.owner
            if state and secrets.compare_digest(state.owner.handle, handle.strip().casefold())
            else None
        )
        normalized_code = code.strip().upper()
        valid = bool(
            owner
            and normalized_code
            and self.store.consume_recovery_code(owner.id, token_hash(normalized_code))
        )
        if not valid or owner is None:
            raise PermissionError("Handle or recovery code is incorrect.")
        self.store.revoke_all_sessions(owner.id)
        return owner, self._issue_session(owner.id)

    def current_owner(self, session_token: str | None) -> Owner | None:
        if not session_token:
            return None
        return self.store.owner_for_session(token_hash(session_token), datetime.now(UTC))

    def logout(self, session_token: str | None) -> None:
        if session_token:
            self.store.revoke_session(token_hash(session_token))

    def build_customization(
        self,
        owner: Owner | None,
        *,
        display_name: str,
        bio: str,
        location: str,
        website_url: str,
        palette: str,
        font: str,
        scale: str,
        density: str,
        radius: str,
        layout_width: str,
        module_order: str,
        enabled: Mapping[str, bool],
        module_values: Mapping[str, object],
        expected_revision: int,
    ) -> Customization:
        self._require_owner(owner)
        theme = validate_theme(
            Theme(
                palette=palette,
                font=font,
                scale=scale,
                density=density,
                radius=radius,
                layout_width=layout_width,
            )
        )
        order = tuple(item.strip() for item in module_order.split(",") if item.strip())
        if len(order) != len(MODULE_KINDS) or set(order) != set(MODULE_KINDS):
            raise ValueError("Module order must contain every built-in module exactly once.")
        modules = tuple(
            ProfileModule(
                kind=kind,
                enabled=bool(enabled.get(kind, False)),
                position=position,
                config=_module_config(kind, module_values),
            )
            for position, kind in enumerate(order)
        )
        if not modules[order.index("identity")].enabled:
            raise ValueError("The identity module cannot be disabled.")
        return Customization(
            display_name=_bounded_required(display_name, "Display name", 80),
            bio=_bounded_optional(bio, "Bio", 500),
            location=_bounded_optional(location, "Location", 80),
            website_url=_https_url(website_url, field="Website"),
            theme=theme,
            modules=modules,
            expected_revision=expected_revision,
        )

    def save_customization(self, owner: Owner | None, customization: Customization) -> SiteState:
        current = self._require_owner(owner)
        state = self.store.state()
        if state is None:
            raise RuntimeError("Space setup is incomplete.")
        now = datetime.now(UTC)
        updated_owner = replace(
            current,
            display_name=customization.display_name,
            bio=customization.bio,
            location=customization.location,
            website_url=customization.website_url,
        )
        updated_settings = replace(
            state.settings,
            theme=customization.theme,
            revision=customization.expected_revision + 1,
            updated_at=now,
        )
        return self.store.update_customization(
            owner=updated_owner,
            settings=updated_settings,
            modules=customization.modules,
            expected_revision=customization.expected_revision,
        )

    def reset_customization(self, owner: Owner | None, *, expected_revision: int) -> SiteState:
        current = self._require_owner(owner)
        state = self.store.state()
        if state is None:
            raise RuntimeError("Space setup is incomplete.")
        customization = Customization(
            display_name=current.display_name,
            bio=current.bio,
            location=current.location,
            website_url=current.website_url,
            theme=Theme(),
            modules=default_modules(),
            expected_revision=expected_revision,
        )
        return self.save_customization(current, customization)

    def _require_owner(self, owner: Owner | None) -> Owner:
        state = self.store.state()
        if owner is None or state is None or owner.id != state.owner.id:
            raise PermissionError("Owner sign-in is required.")
        return state.owner

    def _issue_session(self, owner_id: str) -> str:
        token = secrets.token_urlsafe(48)
        self.store.create_session(
            owner_id,
            token_hash(token),
            datetime.now(UTC) + SESSION_TTL,
        )
        return token


def default_modules() -> tuple[ProfileModule, ...]:
    configs: dict[str, dict[str, object]] = {
        "identity": {"tagline": ""},
        "links": {"items": []},
        "featured": {"content_id": None},
        "recent_posts": {"limit": 5},
        "journal": {"limit": 5},
        "photos": {"columns": 3},
        "tags": {"limit": 12},
        "guestbook": {"prompt": "Leave a note"},
    }
    return tuple(
        ProfileModule(
            kind=kind,
            enabled=kind in {"identity", "links"},
            position=position,
            config=configs[kind],
        )
        for position, kind in enumerate(MODULE_KINDS)
    )


def validate_theme(theme: Theme) -> Theme:
    for field, choices in THEME_CHOICES.items():
        value = str(getattr(theme, field))
        if value not in choices:
            raise ValueError(f"Choose an approved {field.replace('_', ' ')} value.")
    return theme


def _module_config(kind: str, values: Mapping[str, object]) -> dict[str, object]:
    if kind == "identity":
        return {"tagline": _bounded_optional(str(values.get("tagline", "")), "Tagline", 120)}
    if kind == "links":
        return {"items": _parse_links(str(values.get("links", "")))}
    if kind == "featured":
        content_id = str(values.get("featured_id", "")).strip()
        if content_id:
            try:
                uuid.UUID(content_id)
            except ValueError as exc:
                raise ValueError("Featured content ID must be a valid UUID.") from exc
        return {"content_id": content_id or None}
    if kind in {"recent_posts", "journal"}:
        key = "recent_limit" if kind == "recent_posts" else "journal_limit"
        return {"limit": _bounded_integer(values.get(key, 5), f"{kind} limit", 1, 12)}
    if kind == "photos":
        return {"columns": _bounded_integer(values.get("photo_columns", 3), "Photo columns", 2, 4)}
    if kind == "tags":
        return {"limit": _bounded_integer(values.get("tag_limit", 12), "Tag limit", 1, 24)}
    if kind == "guestbook":
        prompt = _bounded_optional(str(values.get("guestbook_prompt", "")), "Guestbook prompt", 120)
        return {"prompt": prompt or "Leave a note"}
    raise ValueError("Unknown profile module.")


def _parse_links(value: str) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for line in value.splitlines():
        if not line.strip():
            continue
        label, separator, raw_url = line.partition("|")
        if not separator:
            raise ValueError("Each external link must use Label | https://example.com format.")
        items.append(
            {
                "label": _bounded_required(label, "Link label", 60),
                "url": _https_url(raw_url, field="External link") or "",
            }
        )
    if len(items) > 8:
        raise ValueError("Profiles may contain at most eight external links.")
    return items


def _https_url(value: str, *, field: str) -> str | None:
    candidate = value.strip()
    if not candidate:
        return None
    if any(ord(char) < 32 for char in candidate):
        raise ValueError(f"{field} contains invalid control characters.")
    parsed = urlsplit(candidate)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError(f"{field} must be an HTTPS URL without embedded credentials.")
    if len(candidate) > 500:
        raise ValueError(f"{field} must be 500 characters or fewer.")
    return candidate


def _validate_handle(value: str) -> str:
    normalized = value.strip().casefold()
    if not HANDLE_RE.fullmatch(normalized):
        raise ValueError("Handle must be 3-30 lowercase letters, numbers, underscores, or hyphens.")
    return normalized


def _validate_password(value: str) -> None:
    if not 12 <= len(value) <= 128 or value.isspace():
        raise ValueError("Password must contain 12-128 characters.")


def _bounded_required(value: str, field: str, limit: int) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field} is required.")
    if len(normalized) > limit:
        raise ValueError(f"{field} must be {limit} characters or fewer.")
    return normalized


def _bounded_optional(value: str, field: str, limit: int) -> str:
    normalized = value.strip()
    if len(normalized) > limit:
        raise ValueError(f"{field} must be {limit} characters or fewer.")
    return normalized


def _bounded_integer(value: object, field: str, minimum: int, maximum: int) -> int:
    try:
        number = int(str(value))
    except ValueError as exc:
        raise ValueError(f"{field} must be a whole number.") from exc
    if not minimum <= number <= maximum:
        raise ValueError(f"{field} must be between {minimum} and {maximum}.")
    return number


def _new_recovery_code() -> str:
    return f"{secrets.token_hex(3)}-{secrets.token_hex(3)}".upper()
