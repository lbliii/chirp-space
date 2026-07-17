"""Bounded ActivityPub identity, HTTP signatures, and hostile remote fetching."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import http.client
import ipaddress
import json
import re
import secrets
import socket
import ssl
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime, parsedate_to_datetime
from threading import RLock
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from chirp_space.config import SpaceConfig
from chirp_space.models import FederationKey, InboxReceipt, SiteState
from chirp_space.store import Store

ACTIVITY_JSON = "application/activity+json"
AS_CONTEXT = "https://www.w3.org/ns/activitystreams"
PUBLIC = "https://www.w3.org/ns/activitystreams#Public"
SUPPORTED_ACTIVITIES = frozenset(
    {"Follow", "Accept", "Reject", "Create", "Update", "Delete", "Like", "Announce", "Undo"}
)
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_DOCUMENT_DEPTH = 32
MAX_DOCUMENT_SCALARS = 10_000
MAX_STRING_BYTES = 256 * 1024
SIGNATURE_WINDOW = timedelta(minutes=10)
RETIRED_KEY_TTL = timedelta(days=30)
SIGNATURE_FIELDS = ("(request-target)", "host", "date", "digest")
SIGNATURE_PARAMETER_RE = re.compile(r'([A-Za-z][A-Za-z0-9_-]*)="([^"]*)"')
RFC9421_INPUT_RE = re.compile(
    r'^sig1=\("@method" "@target-uri" "content-digest" "content-type"\)'
    r';created=([0-9]+);keyid="([^"]+)";alg="rsa-v1_5-sha256"$'
)
RFC9421_SIGNATURE_RE = re.compile(r"^sig1=:([A-Za-z0-9+/]+={0,2}):$")


class FederationError(ValueError):
    def __init__(self, code: str, message: str, *, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass(frozen=True, slots=True)
class FetchResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class DocumentFetcher(Protocol):
    def fetch_json(self, url: str) -> dict[str, Any]: ...


Resolver = Callable[[str, int], Sequence[str]]
Requester = Callable[[str, str, int, float, int], FetchResponse]


class SafeFetcher:
    """HTTPS-only, address-pinned, size-bounded remote document fetcher."""

    def __init__(
        self,
        *,
        resolver: Resolver | None = None,
        requester: Requester | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._resolver = resolver or _resolve_public_addresses
        self._requester = requester or _pinned_get
        self._now = now or (lambda: datetime.now(UTC))
        self._cache: dict[str, tuple[datetime, dict[str, Any]]] = {}
        self._lock = RLock()

    def fetch_json(self, url: str) -> dict[str, Any]:
        with self._lock:
            cached = self._cache.get(url)
            if cached and cached[0] > self._now():
                return copy.deepcopy(cached[1])
        current = url
        for redirect_number in range(4):
            host, port = validate_remote_url(current)
            addresses = tuple(self._resolver(host, port))
            if not addresses:
                raise FederationError("dns-empty", "Remote host did not resolve.", status=502)
            for address in addresses:
                validate_public_address(address)
            response = self._requester(current, addresses[0], port, 15.0, MAX_DOCUMENT_BYTES)
            if response.status in {301, 302, 303, 307, 308}:
                if redirect_number == 3:
                    raise FederationError(
                        "redirect-limit", "Remote document redirected too often.", status=502
                    )
                location = response.headers.get("location", "")
                if not location:
                    raise FederationError(
                        "redirect-location", "Remote redirect omitted Location.", status=502
                    )
                current = urljoin(current, location)
                continue
            if response.status != 200:
                raise FederationError(
                    "remote-status", f"Remote document returned HTTP {response.status}.", status=502
                )
            media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if media_type not in {ACTIVITY_JSON, "application/ld+json", "application/json"}:
                raise FederationError(
                    "remote-type", "Remote document is not ActivityPub JSON.", status=502
                )
            if response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
                raise FederationError(
                    "remote-encoding", "Compressed remote documents are not accepted.", status=502
                )
            document = parse_json_object(response.body)
            with self._lock:
                self._cache[url] = (self._now() + timedelta(hours=24), copy.deepcopy(document))
            return document
        raise FederationError("redirect-limit", "Remote document redirected too often.", status=502)


class FederationService:
    def __init__(
        self,
        store: Store,
        config: SpaceConfig,
        *,
        fetcher: DocumentFetcher | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.config = config
        self.fetcher = fetcher or SafeFetcher()
        self._now = now or (lambda: datetime.now(UTC))
        self._key_lock = RLock()

    def ensure_key(self) -> FederationKey:
        self._state()
        existing = self.store.active_federation_key()
        if existing is not None:
            return existing
        with self._key_lock:
            existing = self.store.active_federation_key()
            if existing is not None:
                return existing
            key = self._new_key()
            try:
                self.store.create_federation_key(key)
            except RuntimeError:
                winner = self.store.active_federation_key()
                if winner is None:
                    raise
                return winner
            return key

    def rotate_key(self) -> FederationKey:
        """Atomically replace the active key while retaining its public overlap."""
        self.ensure_key()
        with self._key_lock:
            key = self._new_key()
            self.store.rotate_federation_key(key, retired_at=self._now())
            return key

    def actor_document(self) -> dict[str, Any]:
        state = self._state()
        key = self.ensure_key()
        origin = state.settings.canonical_origin
        actor_id = f"{origin}/ap/actor"
        return {
            "@context": [AS_CONTEXT, "https://w3id.org/security/v1"],
            "id": actor_id,
            "type": "Person",
            "preferredUsername": state.owner.handle,
            "name": state.owner.display_name,
            "summary": state.owner.bio,
            "url": f"{origin}/@{state.owner.handle}",
            "inbox": f"{origin}/ap/inbox",
            "outbox": f"{origin}/ap/outbox",
            "followers": f"{origin}/ap/followers",
            "following": f"{origin}/ap/following",
            "publicKey": {
                "id": f"{origin}/ap/keys/{key.id}",
                "owner": actor_id,
                "publicKeyPem": key.public_pem,
            },
        }

    def key_document(self, key_id: str) -> dict[str, Any]:
        self.ensure_key()
        key = self.store.federation_key(key_id)
        if key is None or (
            key.retired_at is not None and self._now() - key.retired_at > RETIRED_KEY_TTL
        ):
            raise FederationError("key-not-found", "Federation key not found.", status=404)
        origin = self._state().settings.canonical_origin
        return {
            "id": f"{origin}/ap/keys/{key.id}",
            "owner": f"{origin}/ap/actor",
            "publicKeyPem": key.public_pem,
        }

    def tombstone_document(
        self, object_id: str, *, former_type: str, deleted_at: datetime
    ) -> dict[str, Any]:
        """Return the fixed deletion projection used by later content dispatch."""
        identifier = _https_identifier(object_id, "Tombstone ID")
        if former_type not in {"Note", "Article", "Image"}:
            raise FederationError("tombstone-type", "Tombstone former type is unsupported.")
        return {
            "@context": AS_CONTEXT,
            "id": identifier,
            "type": "Tombstone",
            "formerType": former_type,
            "deleted": deleted_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        }

    def webfinger(self, resource: str) -> dict[str, Any]:
        state = self._state()
        host = urlsplit(state.settings.canonical_origin).hostname
        expected = f"acct:{state.owner.handle}@{host}"
        actor_id = f"{state.settings.canonical_origin}/ap/actor"
        if resource not in {expected, actor_id}:
            raise FederationError("resource-not-found", "WebFinger resource not found.", status=404)
        return {
            "subject": expected,
            "aliases": [f"{state.settings.canonical_origin}/@{state.owner.handle}", actor_id],
            "links": [{"rel": "self", "type": ACTIVITY_JSON, "href": actor_id}],
        }

    def collection(self, name: str) -> dict[str, Any]:
        if name not in {"outbox", "followers", "following"}:
            raise FederationError("collection-not-found", "Collection not found.", status=404)
        origin = self._state().settings.canonical_origin
        return {
            "@context": AS_CONTEXT,
            "id": f"{origin}/ap/{name}",
            "type": "OrderedCollection",
            "totalItems": 0,
            "orderedItems": [],
        }

    def sign_request(self, method: str, target_url: str, body: bytes = b"") -> dict[str, str]:
        key = self.ensure_key()
        parsed = urlsplit(target_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise FederationError("sign-target", "Signed requests require an HTTPS target.")
        target = parsed.path or "/"
        if parsed.query:
            target = f"{target}?{parsed.query}"
        date = format_datetime(self._now(), usegmt=True)
        digest = _digest(body)
        host = parsed.hostname if parsed.port in {None, 443} else f"{parsed.hostname}:{parsed.port}"
        values = {
            "(request-target)": f"{method.lower()} {target}",
            "host": host,
            "date": date,
            "digest": digest,
        }
        signature_base = "\n".join(f"{name}: {values[name]}" for name in SIGNATURE_FIELDS)
        signature = self._private_key(key).sign(
            signature_base.encode(), padding.PKCS1v15(), hashes.SHA256()
        )
        origin = self._state().settings.canonical_origin
        signature_header = (
            f'keyId="{origin}/ap/keys/{key.id}",algorithm="rsa-sha256",'
            f'headers="{" ".join(SIGNATURE_FIELDS)}",signature="{base64.b64encode(signature).decode()}"'
        )
        return {
            "Host": host,
            "Date": date,
            "Digest": digest,
            "Content-Type": ACTIVITY_JSON,
            "Signature": signature_header,
        }

    def receive_inbox(
        self,
        *,
        method: str,
        target: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> InboxReceipt:
        if len(body) > MAX_DOCUMENT_BYTES:
            raise FederationError("body-size", "Inbox body exceeds 1 MiB.", status=413)
        lowered = {str(key).lower(): str(value) for key, value in headers.items()}
        media_type = lowered.get("content-type", "").split(";", 1)[0].strip().lower()
        if media_type not in {ACTIVITY_JSON, "application/ld+json"}:
            raise FederationError("content-type", "Inbox requires ActivityPub JSON.", status=415)
        activity = parse_json_object(body)
        activity_id = _https_identifier(activity.get("id"), "Activity ID")
        activity_type = str(activity.get("type", ""))
        actor = _https_identifier(activity.get("actor"), "Activity actor")
        if "signature-input" in lowered:
            signature_hash = self._verify_rfc9421(
                method=method, target=target, headers=lowered, body=body, actor=actor
            )
        else:
            signature_hash = self._verify_legacy(
                method=method, target=target, headers=lowered, body=body, actor=actor
            )
        status = "accepted" if activity_type in SUPPORTED_ACTIVITIES else "unsupported"
        diagnostic = (
            "validated for typed dispatch" if status == "accepted" else "activity type ignored"
        )
        receipt = InboxReceipt(
            signature_hash=signature_hash,
            activity_id=activity_id,
            activity_type=activity_type or "unknown",
            status=status,
            diagnostic=diagnostic,
            received_at=self._now(),
        )
        if not self.store.record_inbox_receipt(receipt):
            raise FederationError(
                "replay", "Inbox activity or signature was already processed.", status=409
            )
        return receipt

    def _verify_legacy(
        self,
        *,
        method: str,
        target: str,
        headers: Mapping[str, str],
        body: bytes,
        actor: str,
    ) -> str:
        lowered = headers
        signature = _parse_signature(lowered.get("signature", ""))
        if signature["algorithm"] != "rsa-sha256":
            raise FederationError(
                "signature-algorithm", "Unsupported signature algorithm.", status=401
            )
        covered = tuple(signature["headers"].split())
        if covered != SIGNATURE_FIELDS:
            raise FederationError(
                "signature-components", "Signature covered components are invalid.", status=401
            )
        date = _signed_date(lowered.get("date", ""), now=self._now())
        _ = date
        expected_digest = _digest(body)
        if not secrets.compare_digest(lowered.get("digest", ""), expected_digest):
            raise FederationError("digest", "Inbox body digest is invalid.", status=401)
        key_id = _https_identifier(signature["keyId"], "Signature key ID")
        public_key = self._remote_public_key(key_id, actor)
        values = {
            "(request-target)": f"{method.lower()} {target}",
            "host": lowered.get("host", ""),
            "date": lowered.get("date", ""),
            "digest": lowered.get("digest", ""),
        }
        if not values["host"]:
            raise FederationError("host", "Signed Host header is required.", status=401)
        canonical_host = urlsplit(self._state().settings.canonical_origin).netloc
        if not secrets.compare_digest(values["host"].casefold(), canonical_host.casefold()):
            raise FederationError("host", "Signed Host does not match this Space.", status=401)
        signature_base = "\n".join(f"{name}: {values[name]}" for name in SIGNATURE_FIELDS)
        try:
            signature_bytes = base64.b64decode(signature["signature"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise FederationError(
                "signature-header", "Legacy signature encoding is invalid.", status=401
            ) from exc
        try:
            public_key.verify(
                signature_bytes,
                signature_base.encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature as exc:
            raise FederationError(
                "signature", "Inbox signature verification failed.", status=401
            ) from exc
        return hashlib.sha256(f"{target}:{signature['signature']}".encode()).hexdigest()

    def _verify_rfc9421(
        self,
        *,
        method: str,
        target: str,
        headers: Mapping[str, str],
        body: bytes,
        actor: str,
    ) -> str:
        signature_input = headers.get("signature-input", "")
        matched_input = RFC9421_INPUT_RE.fullmatch(signature_input)
        matched_signature = RFC9421_SIGNATURE_RE.fullmatch(headers.get("signature", ""))
        if matched_input is None or matched_signature is None:
            raise FederationError(
                "signature-header", "RFC 9421 signature fields are malformed.", status=401
            )
        created = datetime.fromtimestamp(int(matched_input.group(1)), UTC)
        if abs(self._now() - created) > SIGNATURE_WINDOW:
            raise FederationError(
                "signature-date", "Signed creation time is outside the replay window.", status=401
            )
        content_digest = headers.get("content-digest", "")
        expected_digest = _content_digest(body)
        if not secrets.compare_digest(content_digest, expected_digest):
            raise FederationError("digest", "Inbox Content-Digest is invalid.", status=401)
        content_type = headers.get("content-type", "")
        key_id = _https_identifier(matched_input.group(2), "Signature key ID")
        target_uri = _canonical_target_uri(self._state(), target)
        signature_base = "\n".join(
            (
                f'"@method": {method.upper()}',
                f'"@target-uri": {target_uri}',
                f'"content-digest": {content_digest}',
                f'"content-type": {content_type}',
                f'"@signature-params": {signature_input.removeprefix("sig1=")}',
            )
        )
        public_key = self._remote_public_key(key_id, actor)
        signature_value = matched_signature.group(1)
        try:
            signature_bytes = base64.b64decode(signature_value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise FederationError(
                "signature-header", "RFC 9421 signature encoding is invalid.", status=401
            ) from exc
        try:
            public_key.verify(
                signature_bytes,
                signature_base.encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature as exc:
            raise FederationError(
                "signature", "Inbox signature verification failed.", status=401
            ) from exc
        return hashlib.sha256(f"{target_uri}:{signature_value}".encode()).hexdigest()

    def _remote_public_key(self, key_id: str, actor: str) -> RSAPublicKey:
        key_document = self.fetcher.fetch_json(key_id)
        if key_document.get("id") != key_id or key_document.get("owner") != actor:
            raise FederationError(
                "key-owner", "Signature key does not belong to the activity actor.", status=401
            )
        try:
            public_key = serialization.load_pem_public_key(
                str(key_document.get("publicKeyPem", "")).encode()
            )
        except (TypeError, ValueError) as exc:
            raise FederationError(
                "signature-key", "Remote public key is invalid.", status=401
            ) from exc
        if not isinstance(public_key, RSAPublicKey) or public_key.key_size < 2048:
            raise FederationError(
                "signature-key", "Remote public key must be RSA 2048 or stronger.", status=401
            )
        return public_key

    def _new_key(self) -> FederationKey:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_pem = (
            private.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        encrypted = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(self._encryption_password()),
        )
        return FederationKey(
            id=str(uuid.uuid7()),
            public_pem=public_pem,
            encrypted_private_pem=encrypted,
            created_at=self._now(),
        )

    def _private_key(self, key: FederationKey) -> RSAPrivateKey:
        loaded = serialization.load_pem_private_key(
            key.encrypted_private_pem, password=self._encryption_password()
        )
        if not isinstance(loaded, RSAPrivateKey):
            raise RuntimeError("Stored federation key is not RSA.")
        return loaded

    def _encryption_password(self) -> bytes:
        return hashlib.sha256(self.config.key_encryption_key.encode()).digest()

    def _state(self) -> SiteState:
        state = self.store.state()
        if state is None:
            raise FederationError("setup-incomplete", "Space setup is incomplete.", status=409)
        return state


def parse_json_object(body: bytes) -> dict[str, Any]:
    if len(body) > MAX_DOCUMENT_BYTES:
        raise FederationError("document-size", "Remote document exceeds 1 MiB.", status=413)

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise FederationError("json-duplicate", "JSON contains a duplicate key.")
            result[key] = value
        return result

    try:
        value = json.loads(body, object_pairs_hook=unique_pairs)
    except UnicodeDecodeError as exc:
        raise FederationError("json-encoding", "JSON must be valid UTF-8.") from exc
    except json.JSONDecodeError as exc:
        raise FederationError("json", "Malformed JSON document.") from exc
    if not isinstance(value, dict):
        raise FederationError("json-shape", "ActivityPub document must be a JSON object.")
    _validate_json_bounds(value)
    return value


def _validate_json_bounds(value: dict[str, Any]) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    scalar_count = 0
    while stack:
        item, depth = stack.pop()
        if depth > MAX_DOCUMENT_DEPTH:
            raise FederationError("json-depth", "JSON nesting exceeds 32 levels.")
        if isinstance(item, dict):
            for key, child in item.items():
                scalar_count += 1
                if len(key.encode()) > MAX_STRING_BYTES:
                    raise FederationError("json-string", "JSON string exceeds 256 KiB.")
                stack.append((child, depth + 1))
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        else:
            scalar_count += 1
            if isinstance(item, str) and len(item.encode()) > MAX_STRING_BYTES:
                raise FederationError("json-string", "JSON string exceeds 256 KiB.")
        if scalar_count > MAX_DOCUMENT_SCALARS:
            raise FederationError("json-scalars", "JSON contains too many values.")


def validate_remote_url(url: str) -> tuple[str, int]:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or parsed.fragment
    ):
        raise FederationError(
            "remote-url", "Remote URLs require HTTPS on port 443 without credentials or fragments."
        )
    return parsed.hostname, 443


def validate_public_address(value: str) -> None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise FederationError(
            "dns-address", "DNS returned an invalid address.", status=502
        ) from exc
    if not address.is_global:
        raise FederationError(
            "ssrf-address", "Remote address is not globally routable.", status=403
        )


def _resolve_public_addresses(host: str, port: int) -> Sequence[str]:
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise FederationError("dns", "Remote host could not be resolved.", status=502) from exc
    return tuple(dict.fromkeys(str(record[4][0]) for record in records))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float) -> None:
        self._ssl_context = ssl.create_default_context()
        super().__init__(host, port=port, timeout=timeout, context=self._ssl_context)
        self._address = address

    def connect(self) -> None:
        plain = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._ssl_context.wrap_socket(plain, server_hostname=self.host)


def _pinned_get(url: str, address: str, port: int, timeout: float, limit: int) -> FetchResponse:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"
    connection = _PinnedHTTPSConnection(host, address, port, timeout)
    try:
        connection.request(
            "GET",
            target,
            headers={
                "Host": host,
                "Accept": f'{ACTIVITY_JSON}, application/ld+json; profile="{AS_CONTEXT}"',
                "User-Agent": "Chirp-Space/0.1",
            },
        )
        response = connection.getresponse()
        body = response.read(limit + 1)
        if len(body) > limit:
            raise FederationError("remote-size", "Remote document exceeds 1 MiB.", status=502)
        headers = {key.lower(): value for key, value in response.getheaders()}
        return FetchResponse(response.status, headers, body)
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise FederationError(
            "remote-network", "Remote document fetch failed.", status=502
        ) from exc
    finally:
        connection.close()


def _parse_signature(value: str) -> dict[str, str]:
    parameters = {key: item for key, item in SIGNATURE_PARAMETER_RE.findall(value)}
    required = {"keyId", "algorithm", "headers", "signature"}
    if set(parameters) != required:
        raise FederationError("signature-header", "Signature header is malformed.", status=401)
    return parameters


def _signed_date(value: str, *, now: datetime) -> datetime:
    try:
        parsed = parsedate_to_datetime(value).astimezone(UTC)
    except (TypeError, ValueError) as exc:
        raise FederationError(
            "signature-date", "Signed Date header is invalid.", status=401
        ) from exc
    if abs(now - parsed) > SIGNATURE_WINDOW:
        raise FederationError(
            "signature-date", "Signed Date is outside the replay window.", status=401
        )
    return parsed


def _digest(body: bytes) -> str:
    return f"SHA-256={base64.b64encode(hashlib.sha256(body).digest()).decode()}"


def _content_digest(body: bytes) -> str:
    return f"sha-256=:{base64.b64encode(hashlib.sha256(body).digest()).decode()}:"


def _canonical_target_uri(state: SiteState, target: str) -> str:
    parsed = urlsplit(target)
    if not target.startswith("/") or parsed.scheme or parsed.netloc or parsed.fragment:
        raise FederationError("signature-target", "Signed target URI is invalid.", status=401)
    return f"{state.settings.canonical_origin}{target}"


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
        raise FederationError("identifier", f"{field} must be a bounded HTTPS URL.")
    return candidate
