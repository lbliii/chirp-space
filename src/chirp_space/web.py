"""Chirp application factory and server-rendered Space routes."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from email.utils import format_datetime
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree import ElementTree

from chirp.app import App
from chirp.config import AppConfig
from chirp.health import HealthCheck
from chirp.http.cookies import SetCookie
from chirp.http.request import Request
from chirp.http.response import JSONResponse, Redirect, Response
from chirp.middleware.auth_rate_limit import AuthRateLimitConfig, AuthRateLimitMiddleware
from chirp.middleware.security_headers import SecurityHeadersConfig
from chirp.middleware.sessions import get_session
from chirp.middleware.stack import secure_stack
from chirp.middleware.static import StaticFiles
from chirp.templating.returns import Page

from chirp_space.config import SpaceConfig
from chirp_space.content import (
    GuestbookService,
    ImageNormalizer,
    LocalObjectStorage,
    ObjectStorage,
    PublishingService,
    RecoverableMediaError,
    content_path,
    present_content,
)
from chirp_space.delivery import DeliveryService
from chirp_space.federation import (
    ACTIVITY_JSON,
    DocumentFetcher,
    FederationError,
    FederationService,
    SafeFetcher,
    parse_json_object,
)
from chirp_space.media import PillowImageNormalizer
from chirp_space.models import ContentItem, Customization, Owner, SiteState
from chirp_space.relationships import RelationshipService
from chirp_space.services import SpaceService
from chirp_space.store import Store, store_from_url

ROOT = Path(__file__).parent
TEMPLATES = ROOT / "templates"
STATIC = ROOT / "static"
SESSION_COOKIE = "space_owner_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 30
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; "
    "object-src 'none'"
)


def create_app(
    *,
    debug: bool = True,
    store: Store | None = None,
    space_config: SpaceConfig | None = None,
    federation_fetcher: DocumentFetcher | None = None,
    object_storage: ObjectStorage | None = None,
    image_normalizer: ImageNormalizer | None = None,
) -> App:
    config = space_config or SpaceConfig.from_env(debug=debug)
    database = store or store_from_url(config.database_url)
    database.migrate()
    service = SpaceService(database, config)
    storage = object_storage or LocalObjectStorage(Path.cwd() / ".chirp-space" / "media")
    normalizer = image_normalizer or PillowImageNormalizer()
    publishing = PublishingService(database, config, storage, normalizer)
    guestbook = GuestbookService(database, config)
    protocol_fetcher = federation_fetcher or SafeFetcher()
    federation = FederationService(database, config, fetcher=protocol_fetcher)
    delivery = DeliveryService(database, federation)
    relationships = RelationshipService(database, delivery, protocol_fetcher)
    app_config = AppConfig(
        template_dir=TEMPLATES,
        debug=debug,
        env=config.env,
        secret_key=config.secret_key,
        allowed_hosts=_allowed_hosts(config),
        htmx=True,
        health_path="/livez",
        workers=1,
        worker_mode="async" if config.production else "auto",
    )
    app = App(app_config)
    app.on_shutdown(database.close)
    app.add_health_check(
        HealthCheck("database", check=database.probe, message="Space database unavailable")
    )
    app.add_middleware(
        AuthRateLimitMiddleware(
            AuthRateLimitConfig(
                paths=("/setup", "/login", "/recover"),
                requests=10,
                window_seconds=60,
                block_seconds=300,
            )
        ),
        priority=-10,
    )
    for middleware in secure_stack(
        app_config,
        headers=SecurityHeadersConfig(content_security_policy=CONTENT_SECURITY_POLICY),
    ):
        app.add_middleware(middleware, priority=0)
    app.add_middleware(StaticFiles(directory=str(STATIC), prefix="/space-static"), priority=20)

    def viewer(request: Request) -> Owner | None:
        return service.current_owner(_cookie(request))

    def render(request: Request, template: str, **context: object) -> Page:
        state = database.state()
        return Page(
            template,
            "page_content",
            page_block_name="page_root",
            state=state,
            viewer=viewer(request),
            canonical_origin=config.canonical_origin,
            current_path=request.path,
            **context,
        )

    def profile_context() -> dict[str, object]:
        recent, _ = publishing.list_public(limit=6)
        journals, _ = publishing.list_public(kind="journal", limit=5)
        photos, _ = publishing.list_public(kind="photo", limit=6)
        state = database.state()
        featured: ContentItem | None = None
        if state is not None:
            module = next((item for item in state.modules if item.kind == "featured"), None)
            featured_id = str(module.config.get("content_id", "")) if module else ""
            if featured_id:
                featured = publishing.get(featured_id)
        return {
            "recent_content": tuple(present_content(item) for item in recent),
            "journal_content": tuple(present_content(item) for item in journals),
            "photo_content": tuple(present_content(item) for item in photos),
            "featured_content": present_content(featured) if featured else None,
            "tag_counts": publishing.tag_counts(),
            "guestbook_entries": database.guestbook_entries(public_only=True),
        }

    def listing_page(
        request: Request,
        *,
        title: str,
        kind: str | None = None,
        tag: str | None = None,
        year: int | None = None,
        month: int | None = None,
    ) -> Page | Response:
        cursor = str(request.query.get("cursor", "")).strip() or None
        query = str(request.query.get("q", "")).strip() or None
        try:
            items, next_cursor = publishing.list_public(
                cursor=cursor,
                kind=kind,
                tag=tag,
                year=year,
                month=month,
                query=query,
            )
        except ValueError as exc:
            return Response(str(exc), status=400)
        return render(
            request,
            "content_list.html",
            title=title,
            content=tuple(present_content(item) for item in items),
            next_cursor=next_cursor,
            query=query or "",
            archive=publishing.archive(),
            tag_counts=publishing.tag_counts(),
        )

    def content_page(request: Request, item_id: str, *, expected_kind: str) -> Page | Response:
        item = publishing.get(item_id, owner=viewer(request) is not None)
        if item is None or item.kind != expected_kind:
            return Response("Content not found", status=404)
        return render(
            request,
            "content_detail.html",
            content=present_content(item),
            message=get_session().pop("space_message", None),
        )

    def owner_content_page(
        request: Request,
        *,
        error: str | None = None,
        values: Mapping[str, object] | None = None,
        item: ContentItem | None = None,
        preview: ContentItem | None = None,
    ) -> Page | Redirect:
        if viewer(request) is None:
            return Redirect("/login")
        if values is not None:
            return render(
                request,
                "content_form.html",
                error=error,
                values=values,
                item=item,
                preview=present_content(preview) if preview else None,
            )
        return render(
            request,
            "owner_content.html",
            content=tuple(present_content(entry) for entry in publishing.owner_items()),
            guestbook_entries=database.guestbook_entries(public_only=False),
            message=get_session().pop("space_message", None),
        )

    @app.route("/health", referenced=True)
    def health() -> Response:
        return Response("ok", headers=(("Content-Type", "text/plain; charset=utf-8"),))

    @app.route("/.well-known/webfinger", referenced=True)
    def webfinger(request: Request):
        if not config.federation_enabled:
            return Response("Not found", status=404)
        try:
            document = federation.webfinger(str(request.query.get("resource", "")))
        except FederationError as exc:
            return _federation_error(exc)
        return _protocol_json(document, content_type="application/jrd+json")

    @app.route("/ap/actor", referenced=True)
    def actor(request: Request):
        if not config.federation_enabled:
            return Response("Not found", status=404)
        if not _accepts_activity(request):
            return _federation_error(
                FederationError("accept", "ActivityPub response type is required.", status=406)
            )
        try:
            return _protocol_json(federation.actor_document())
        except FederationError as exc:
            return _federation_error(exc)

    @app.route("/ap/keys/{key_id}", referenced=True)
    def federation_key(request: Request, key_id: str):
        if not config.federation_enabled:
            return Response("Not found", status=404)
        if not _accepts_activity(request):
            return _federation_error(
                FederationError("accept", "ActivityPub response type is required.", status=406)
            )
        try:
            return _protocol_json(federation.key_document(key_id))
        except FederationError as exc:
            return _federation_error(exc)

    @app.route("/ap/outbox", referenced=True)
    def outbox(request: Request):
        return _collection_response(request, federation, config, "outbox")

    @app.route("/ap/followers", referenced=True)
    def followers(request: Request):
        return _collection_response(request, federation, config, "followers")

    @app.route("/ap/following", referenced=True)
    def following(request: Request):
        return _collection_response(request, federation, config, "following")

    @app.route("/ap/inbox", methods=["POST"], referenced=True)
    async def inbox(request: Request):
        if not config.federation_enabled:
            return Response("Not found", status=404)
        body = await request.body()
        try:
            receipt = federation.receive_inbox(
                method=request.method,
                target=request.path,
                headers=request.headers,
                body=body,
            )
            transition = (
                relationships.receive(parse_json_object(body))
                if receipt.status in {"accepted", "duplicate"}
                else receipt.diagnostic
            )
        except FederationError as exc:
            return _federation_error(exc)
        except (PermissionError, ValueError) as exc:
            return _federation_error(FederationError("relationship", str(exc), status=422))
        return _protocol_json(
            {
                "status": receipt.status,
                "activityType": receipt.activity_type,
                "transition": transition,
            },
            status=202,
        )

    @app.route("/", template="setup_pending.html")
    def home(request: Request):
        state = database.state()
        if state is None:
            return render(request, "setup_pending.html")
        return render(request, "profile.html", profile=state, preview=False, **profile_context())

    @app.route("/archive", template="content_list.html")
    def archive_page(request: Request):
        return listing_page(request, title="Archive")

    @app.route("/archive/{year}", template="content_list.html")
    def archive_year(request: Request, year: int):
        return listing_page(request, title=f"Archive for {year}", year=year)

    @app.route("/archive/{year}/{month}", template="content_list.html")
    def archive_month(request: Request, year: int, month: int):
        return listing_page(
            request, title=f"Archive for {year}-{month:02d}", year=year, month=month
        )

    @app.route("/tags/{tag}", template="content_list.html")
    def tag_page(request: Request, tag: str):
        return listing_page(request, title=f"Topic: {tag}", tag=tag)

    @app.route("/posts", template="content_list.html")
    def posts_page(request: Request):
        return listing_page(request, title="Posts", kind="short")

    @app.route("/journal", template="content_list.html")
    def journal_page(request: Request):
        return listing_page(request, title="Journal", kind="journal")

    @app.route("/photos", template="content_list.html")
    def photos_page(request: Request):
        return listing_page(request, title="Photos", kind="photo")

    @app.route("/links", template="content_list.html")
    def links_page(request: Request):
        return listing_page(request, title="Links", kind="link")

    @app.route("/posts/{item_id}", template="content_detail.html")
    def post_page(request: Request, item_id: str):
        return content_page(request, item_id, expected_kind="short")

    @app.route("/journal/{item_id}", template="content_detail.html")
    def journal_item_page(request: Request, item_id: str):
        return content_page(request, item_id, expected_kind="journal")

    @app.route("/photos/{item_id}", template="content_detail.html")
    def photo_page(request: Request, item_id: str):
        return content_page(request, item_id, expected_kind="photo")

    @app.route("/links/{item_id}", template="content_detail.html")
    def link_page(request: Request, item_id: str):
        return content_page(request, item_id, expected_kind="link")

    @app.route("/media/{asset_id}", referenced=True)
    def media(request: Request, asset_id: str):
        _ = request
        asset = database.media(asset_id)
        if asset is None:
            return Response("Media not found", status=404)
        try:
            data = publishing.media_bytes(asset)
        except FileNotFoundError:
            return Response("Media not found", status=404)
        return Response(
            data,
            content_type=asset.media_type,
            headers=(
                ("Cache-Control", "public, max-age=31536000, immutable"),
                ("X-Content-Type-Options", "nosniff"),
            ),
        )

    @app.route("/media/{asset_id}/{variant}", referenced=True)
    def media_variant(request: Request, asset_id: str, variant: str):
        _ = request
        asset = database.media(asset_id)
        selected = (
            next((item for item in asset.variants if item.name == variant), None)
            if asset is not None
            else None
        )
        if asset is None or selected is None:
            return Response("Media not found", status=404)
        try:
            data = publishing.media_bytes(asset, variant=variant)
        except FileNotFoundError:
            return Response("Media not found", status=404)
        return Response(
            data,
            content_type=selected.media_type,
            headers=(
                ("Cache-Control", "public, max-age=31536000, immutable"),
                ("X-Content-Type-Options", "nosniff"),
            ),
        )

    @app.route("/feed.xml", referenced=True)
    def feed(request: Request):
        _ = request
        state = database.state()
        if state is None:
            return Response("Feed not found", status=404)
        items, _ = publishing.list_public(limit=50)
        root = ElementTree.Element("rss", version="2.0")
        channel = ElementTree.SubElement(root, "channel")
        ElementTree.SubElement(channel, "title").text = state.owner.display_name
        ElementTree.SubElement(channel, "link").text = config.canonical_origin
        ElementTree.SubElement(channel, "description").text = state.owner.bio or "Recent posts"
        for item in items:
            node = ElementTree.SubElement(channel, "item")
            title = item.title or item.source[:80] or f"{item.kind.title()} entry"
            ElementTree.SubElement(node, "title").text = title
            url = f"{config.canonical_origin}{content_path(item)}"
            ElementTree.SubElement(node, "link").text = url
            ElementTree.SubElement(node, "guid", isPermaLink="true").text = url
            ElementTree.SubElement(node, "description").text = item.source
            if item.published_at is not None:
                ElementTree.SubElement(node, "pubDate").text = format_datetime(item.published_at)
        return Response(
            ElementTree.tostring(root, encoding="utf-8", xml_declaration=True),
            content_type="application/rss+xml; charset=utf-8",
        )

    @app.route("/guestbook", template="guestbook.html")
    def guestbook_page(request: Request):
        return render(
            request,
            "guestbook.html",
            entries=database.guestbook_entries(public_only=True),
            error=None,
            submitted=str(request.query.get("submitted", "")) == "1",
            values={"display_name": "", "message": "", "website_url": ""},
        )

    @app.route("/guestbook", methods=["POST"], template="guestbook.html")
    async def guestbook_submit(request: Request):
        form = await request.form()
        values = {
            "display_name": str(form.get("display_name", "")),
            "message": str(form.get("message", "")),
            "website_url": str(form.get("website_url", "")),
        }
        client_key = request.client[0] if request.client else "unknown-client"
        try:
            guestbook.submit(
                display_name=values["display_name"],
                message=values["message"],
                website_url=values["website_url"] or None,
                client_key=client_key,
                honeypot=str(form.get("company", "")),
            )
        except (PermissionError, RuntimeError, ValueError) as exc:
            return render(
                request,
                "guestbook.html",
                entries=database.guestbook_entries(public_only=True),
                error=str(exc),
                submitted=False,
                values=values,
            )
        return Redirect("/guestbook?submitted=1")

    @app.route("/{profile}", template="profile.html")
    def public_profile(request: Request, profile: str):
        state = database.state()
        if (
            state is None
            or not profile.startswith("@")
            or profile[1:].casefold() != state.owner.handle
        ):
            return Response("Profile not found", status=404)
        return render(request, "profile.html", profile=state, preview=False, **profile_context())

    @app.route("/setup", template="setup.html")
    def setup_page(request: Request):
        if database.state() is not None:
            return Redirect("/")
        return render(
            request,
            "setup.html",
            error=None,
            show_development_hint=not config.production,
            values=_setup_values(config),
        )

    @app.route("/setup", methods=["POST"], template="setup.html")
    async def setup_submit(request: Request):
        if database.state() is not None:
            return Redirect("/")
        form = await request.form()
        values = {
            "canonical_origin": str(form.get("canonical_origin", "")),
            "handle": str(form.get("handle", "")),
            "display_name": str(form.get("display_name", "")),
            "bio": str(form.get("bio", "")),
        }
        try:
            result = service.setup(
                claim_token=str(form.get("claim_token", "")),
                canonical_origin=values["canonical_origin"],
                handle=values["handle"],
                display_name=values["display_name"],
                bio=values["bio"],
                password=str(form.get("password", "")),
            )
        except (PermissionError, RuntimeError, ValueError) as exc:
            return render(
                request,
                "setup.html",
                error=str(exc),
                show_development_hint=not config.production,
                values=values,
            )
        get_session()["space_recovery_codes"] = list(result.recovery_codes)
        return _session_redirect("/owner", result.session_token, config)

    @app.route("/login", template="login.html")
    def login_page(request: Request):
        if database.state() is None:
            return Redirect("/setup")
        if viewer(request) is not None:
            return Redirect("/owner")
        return render(request, "login.html", error=None, handle="")

    @app.route("/login", methods=["POST"], template="login.html")
    async def login_submit(request: Request):
        form = await request.form()
        handle = str(form.get("handle", ""))
        try:
            _owner, session_token = service.login(handle, str(form.get("password", "")))
        except PermissionError as exc:
            return render(request, "login.html", error=str(exc), handle=handle)
        return _session_redirect("/owner", session_token, config)

    @app.route("/recover", template="recover.html")
    def recover_page(request: Request):
        if database.state() is None:
            return Redirect("/setup")
        return render(request, "recover.html", error=None, handle="")

    @app.route("/recover", methods=["POST"], template="recover.html")
    async def recover_submit(request: Request):
        form = await request.form()
        handle = str(form.get("handle", ""))
        try:
            _owner, session_token = service.login_with_recovery_code(
                handle, str(form.get("recovery_code", ""))
            )
        except PermissionError as exc:
            return render(request, "recover.html", error=str(exc), handle=handle)
        return _session_redirect("/owner", session_token, config)

    @app.route("/logout", methods=["POST"])
    def logout(request: Request):
        service.logout(_cookie(request))
        return Response(
            "",
            status=302,
            headers=(("Location", "/"),),
            cookies=(_clear_session_cookie(config),),
        )

    @app.route("/owner", template="owner.html")
    def owner_page(request: Request):
        owner = viewer(request)
        if owner is None:
            return Redirect("/login")
        recovery_codes = tuple(get_session().pop("space_recovery_codes", ()))
        return render(
            request,
            "owner.html",
            recovery_codes=recovery_codes,
            message=get_session().pop("space_message", None),
        )

    @app.route("/owner/content", template="owner_content.html")
    def owner_content(request: Request):
        return owner_content_page(request)

    @app.route("/owner/content/new", template="content_form.html")
    def content_new(request: Request):
        return owner_content_page(
            request,
            values={
                "kind": "short",
                "state": "draft",
                "title": "",
                "source": "",
                "tags": "",
                "external_url": "",
                "alt_text": "",
                "revision": "0",
            },
        )

    @app.route("/owner/content/new", methods=["POST"], template="content_form.html")
    async def content_create(request: Request):
        if viewer(request) is None:
            return Redirect("/login")
        form = await request.form()
        values: dict[str, object] = {
            "kind": str(form.get("kind", "short")),
            "state": str(form.get("state", "draft")),
            "title": str(form.get("title", "")),
            "source": str(form.get("source", "")),
            "tags": str(form.get("tags", "")),
            "external_url": str(form.get("external_url", "")),
            "alt_text": str(form.get("alt_text", "")),
            "revision": "0",
        }
        upload = form.files.get("image")
        image_bytes = await upload.read() if upload is not None and upload.size else None
        try:
            if str(form.get("intent", "save")) == "preview":
                preview = publishing.preview(
                    kind=str(values["kind"]),
                    state=str(values["state"]),
                    title=str(values["title"]),
                    source=str(values["source"]),
                    tags=str(values["tags"]),
                    external_url=str(values["external_url"]) or None,
                    image_bytes=image_bytes,
                    alt_text=str(values["alt_text"]),
                )
                return owner_content_page(request, values=values, preview=preview)
            item = publishing.create(
                kind=str(values["kind"]),
                state=str(values["state"]),
                title=str(values["title"]),
                source=str(values["source"]),
                tags=str(values["tags"]),
                external_url=str(values["external_url"]) or None,
                image_bytes=image_bytes,
                alt_text=str(values["alt_text"]),
            )
        except RecoverableMediaError as exc:
            return owner_content_page(request, error=str(exc), values=values, item=exc.draft)
        except (OSError, RuntimeError, ValueError) as exc:
            return owner_content_page(request, error=str(exc), values=values)
        get_session()["space_message"] = (
            "Content published." if item.state == "public" else "Content saved."
        )
        return Redirect(content_path(item) if item.state == "public" else "/owner/content")

    @app.route("/owner/content/{item_id}/edit", template="content_form.html")
    def content_edit(request: Request, item_id: str):
        if viewer(request) is None:
            return Redirect("/login")
        item = publishing.get(item_id, owner=True)
        if item is None or item.state == "deleted":
            return Response("Content not found", status=404)
        return owner_content_page(
            request,
            item=item,
            values={
                "kind": item.kind,
                "state": item.state,
                "title": item.title,
                "source": item.source,
                "tags": ", ".join(item.tags),
                "external_url": item.external_url or "",
                "alt_text": item.media.alt_text if item.media else "",
                "revision": str(item.revision),
            },
        )

    @app.route("/owner/content/{item_id}/edit", methods=["POST"], template="content_form.html")
    async def content_update(request: Request, item_id: str):
        if viewer(request) is None:
            return Redirect("/login")
        form = await request.form()
        current = publishing.get(item_id, owner=True)
        if current is None or current.state == "deleted":
            return Response("Content not found", status=404)
        values: dict[str, object] = {
            "kind": current.kind,
            "state": str(form.get("state", "draft")),
            "title": str(form.get("title", "")),
            "source": str(form.get("source", "")),
            "tags": str(form.get("tags", "")),
            "external_url": str(form.get("external_url", "")),
            "alt_text": str(form.get("alt_text", "")),
            "revision": str(form.get("revision", "0")),
        }
        upload = form.files.get("image")
        image_bytes = await upload.read() if upload is not None and upload.size else None
        try:
            item = publishing.update(
                item_id,
                expected_revision=int(str(values["revision"])),
                state=str(values["state"]),
                title=str(values["title"]),
                source=str(values["source"]),
                tags=str(values["tags"]),
                external_url=str(values["external_url"]) or None,
                alt_text=str(values["alt_text"]),
                image_bytes=image_bytes,
            )
        except (RuntimeError, ValueError) as exc:
            return owner_content_page(request, error=str(exc), values=values, item=current)
        get_session()["space_message"] = (
            "Content published." if item.state == "public" else "Content updated."
        )
        return Redirect(content_path(item) if item.state == "public" else "/owner/content")

    @app.route("/owner/content/{item_id}/delete", methods=["POST"])
    async def content_delete(request: Request, item_id: str):
        if viewer(request) is None:
            return Redirect("/login")
        form = await request.form()
        if str(form.get("confirm", "")) != "delete":
            get_session()["space_message"] = "Type delete to confirm content removal."
            return Redirect(f"/owner/content/{item_id}/edit")
        try:
            publishing.delete(item_id, expected_revision=int(str(form.get("revision", "0"))))
        except (RuntimeError, ValueError) as exc:
            get_session()["space_message"] = str(exc)
            return Redirect(f"/owner/content/{item_id}/edit")
        get_session()["space_message"] = "Content deleted; its stable permalink is a tombstone."
        return Redirect("/owner/content")

    @app.route("/owner/guestbook/{entry_id}", methods=["POST"])
    async def guestbook_moderate(request: Request, entry_id: str):
        if viewer(request) is None:
            return Redirect("/login")
        form = await request.form()
        try:
            guestbook.moderate(entry_id, str(form.get("action", "")))
        except (RuntimeError, ValueError) as exc:
            get_session()["space_message"] = str(exc)
        else:
            get_session()["space_message"] = "Guestbook moderation updated."
        return Redirect("/owner/content")

    @app.route("/owner/customize", template="customize.html")
    def customize_page(request: Request):
        owner = viewer(request)
        if owner is None:
            return Redirect("/login")
        state = database.state()
        if state is None:
            return Redirect("/setup")
        return render(
            request,
            "customize.html",
            error=None,
            message=get_session().pop("space_message", None),
            values=_customization_values(state),
            preview=None,
        )

    @app.route("/owner/customize", methods=["POST"], template="customize.html")
    async def customize_submit(request: Request):
        owner = viewer(request)
        if owner is None:
            return Redirect("/login")
        form = await request.form()
        values = _form_values(form)
        try:
            customization = _customization_from_form(service, owner, form)
            if str(form.get("intent", "save")) == "preview":
                current = database.state()
                if current is None:
                    return Redirect("/setup")
                preview = _preview_state(current, customization)
                return render(
                    request,
                    "customize.html",
                    error=None,
                    message="Preview is session-only. Save to publish these choices.",
                    values=values,
                    preview=preview,
                )
            service.save_customization(owner, customization)
        except (PermissionError, RuntimeError, ValueError) as exc:
            return render(
                request,
                "customize.html",
                error=str(exc),
                message=None,
                values=values,
                preview=None,
            )
        get_session()["space_message"] = "Profile and theme published."
        return Redirect("/owner/customize")

    @app.route("/owner/customize/reset", methods=["POST"])
    async def customize_reset(request: Request):
        owner = viewer(request)
        if owner is None:
            return Redirect("/login")
        form = await request.form()
        try:
            revision = int(str(form.get("revision", "0")))
            service.reset_customization(owner, expected_revision=revision)
        except (PermissionError, RuntimeError, ValueError) as exc:
            get_session()["space_message"] = str(exc)
        else:
            get_session()["space_message"] = "Accessible theme and module defaults restored."
        return Redirect("/owner/customize")

    def connection_page(
        request: Request,
        *,
        error: str | None = None,
        audience_preview: object | None = None,
    ) -> Page | Redirect:
        if viewer(request) is None:
            return Redirect("/login")
        return render(
            request,
            "connections.html",
            error=error,
            message=get_session().pop("space_message", None),
            relationships=database.relationships(),
            circles=database.circles(),
            blocked_domains=database.blocked_domains(),
            audience_preview=audience_preview,
        )

    @app.route("/owner/connections", template="connections.html")
    def connections_page(request: Request):
        return connection_page(request)

    @app.route("/owner/connections", methods=["POST"], template="connections.html")
    async def connections_submit(request: Request):
        if viewer(request) is None:
            return Redirect("/login")
        form = await request.form()
        action = str(form.get("action", ""))
        actor_id = str(form.get("actor_id", ""))
        try:
            if action == "discover":
                relationship = relationships.discover(str(form.get("reference", "")))
                message = f"Discovered {relationship.actor.display_name}. Review before following."
            elif action == "follow":
                relationships.send_follow(actor_id)
                message = "Follow request queued."
            elif action == "accept":
                relationships.accept_follower(actor_id)
                message = "Follower accepted; the Accept activity is queued."
            elif action == "reject":
                relationships.reject_follower(actor_id)
                message = "Follow request rejected."
            elif action == "unfollow":
                relationships.unfollow(actor_id)
                message = "Unfollow queued. The remote server may show stale state."
            elif action == "remove":
                relationships.remove_follower(actor_id)
                message = "Follower removed from future restricted audiences."
            elif action in {"pin", "unpin", "mute", "unmute"}:
                preference = "pinned" if action in {"pin", "unpin"} else "muted"
                relationships.set_preference(
                    actor_id,
                    preference=preference,
                    enabled=action in {"pin", "mute"},
                )
                message = f"Local {preference} preference updated."
            elif action == "note":
                relationships.set_preference(
                    actor_id,
                    preference="note",
                    enabled=True,
                    note=str(form.get("note", "")),
                )
                message = "Private relationship note saved."
            elif action == "block":
                if str(form.get("confirm", "")) != "block":
                    raise ValueError("Confirm that blocking does not erase remote copies.")
                relationships.block_actor(actor_id)
                message = "Actor blocked locally; relationships and queued delivery were removed."
            elif action == "unblock":
                relationships.unblock_actor(actor_id)
                message = "Actor unblocked. No relationship was restored."
            elif action == "block-domain":
                if str(form.get("confirm", "")) != "block":
                    raise ValueError("Confirm the domain-wide block.")
                relationships.block_domain(str(form.get("domain", "")))
                message = "Domain blocked locally."
            elif action == "unblock-domain":
                relationships.unblock_domain(str(form.get("domain", "")))
                message = "Domain unblocked. No relationship was restored."
            elif action == "create-circle":
                relationships.create_circle(str(form.get("name", "")))
                message = "Local-only circle created."
            elif action == "circle-members":
                member_ids = tuple(
                    item.strip()
                    for item in str(form.get("member_actor_ids", "")).splitlines()
                    if item.strip()
                )
                relationships.set_circle_members(str(form.get("circle_id", "")), member_ids)
                message = "Circle membership updated."
            elif action == "audience-preview":
                preview = relationships.audience_preview(
                    str(form.get("visibility", "")),
                    circle_id=str(form.get("circle_id", "")) or None,
                )
                return connection_page(request, audience_preview=preview)
            else:
                raise ValueError("Unknown connection action.")
        except (FederationError, PermissionError, RuntimeError, ValueError) as exc:
            return connection_page(request, error=str(exc))
        get_session()["space_message"] = message
        return Redirect("/owner/connections")

    return app


def _customization_from_form(
    service: SpaceService, owner: Owner, form: Mapping[str, object]
) -> Customization:
    getter = form.get
    return service.build_customization(
        owner,
        display_name=str(getter("display_name", "")),
        bio=str(getter("bio", "")),
        location=str(getter("location", "")),
        website_url=str(getter("website_url", "")),
        palette=str(getter("palette", "")),
        font=str(getter("font", "")),
        scale=str(getter("scale", "")),
        density=str(getter("density", "")),
        radius=str(getter("radius", "")),
        layout_width=str(getter("layout_width", "")),
        module_order=str(getter("module_order", "")),
        enabled={kind: str(getter(f"enable_{kind}", "")) == "on" for kind in _module_kinds()},
        module_values={
            "tagline": getter("tagline", ""),
            "links": getter("links", ""),
            "featured_id": getter("featured_id", ""),
            "recent_limit": getter("recent_limit", "5"),
            "journal_limit": getter("journal_limit", "5"),
            "photo_columns": getter("photo_columns", "3"),
            "tag_limit": getter("tag_limit", "12"),
            "guestbook_prompt": getter("guestbook_prompt", "Leave a note"),
        },
        expected_revision=int(str(getter("revision", "0"))),
    )


def _module_kinds() -> tuple[str, ...]:
    from chirp_space.models import MODULE_KINDS

    return MODULE_KINDS


def _setup_values(config: SpaceConfig) -> dict[str, str]:
    return {
        "canonical_origin": config.canonical_origin,
        "handle": "",
        "display_name": "",
        "bio": "",
    }


def _customization_values(state: SiteState) -> dict[str, object]:
    module_map = {module.kind: module for module in state.modules}
    links = module_map["links"].config.get("items", [])
    return {
        "display_name": state.owner.display_name,
        "bio": state.owner.bio,
        "location": state.owner.location,
        "website_url": state.owner.website_url or "",
        "palette": state.settings.theme.palette,
        "font": state.settings.theme.font,
        "scale": state.settings.theme.scale,
        "density": state.settings.theme.density,
        "radius": state.settings.theme.radius,
        "layout_width": state.settings.theme.layout_width,
        "module_order": ",".join(module.kind for module in state.modules),
        "enabled": {module.kind: module.enabled for module in state.modules},
        "tagline": module_map["identity"].config.get("tagline", ""),
        "links": "\n".join(f"{item['label']} | {item['url']}" for item in links),
        "featured_id": module_map["featured"].config.get("content_id") or "",
        "recent_limit": module_map["recent_posts"].config.get("limit", 5),
        "journal_limit": module_map["journal"].config.get("limit", 5),
        "photo_columns": module_map["photos"].config.get("columns", 3),
        "tag_limit": module_map["tags"].config.get("limit", 12),
        "guestbook_prompt": module_map["guestbook"].config.get("prompt", "Leave a note"),
        "revision": state.settings.revision,
    }


def _form_values(form: Mapping[str, object]) -> dict[str, object]:
    getter = form.get
    enabled = {kind: str(getter(f"enable_{kind}", "")) == "on" for kind in _module_kinds()}
    return {
        key: getter(key, "")
        for key in (
            "display_name",
            "bio",
            "location",
            "website_url",
            "palette",
            "font",
            "scale",
            "density",
            "radius",
            "layout_width",
            "module_order",
            "tagline",
            "links",
            "featured_id",
            "recent_limit",
            "journal_limit",
            "photo_columns",
            "tag_limit",
            "guestbook_prompt",
            "revision",
        )
    } | {"enabled": enabled}


def _preview_state(current: SiteState, customization: Customization) -> SiteState:
    return SiteState(
        owner=replace(
            current.owner,
            display_name=customization.display_name,
            bio=customization.bio,
            location=customization.location,
            website_url=customization.website_url,
        ),
        settings=replace(current.settings, theme=customization.theme),
        modules=customization.modules,
    )


def _cookie(request: Request) -> str | None:
    value = request.cookies.get(SESSION_COOKIE)
    return str(value) if value else None


def _session_cookie(value: str, config: SpaceConfig) -> SetCookie:
    return SetCookie(
        SESSION_COOKIE,
        value,
        max_age=SESSION_MAX_AGE,
        path="/",
        secure=config.production,
        httponly=True,
        samesite="lax",
    )


def _clear_session_cookie(config: SpaceConfig) -> SetCookie:
    return SetCookie(
        SESSION_COOKIE,
        "",
        max_age=0,
        path="/",
        secure=config.production,
        httponly=True,
        samesite="lax",
    )


def _session_redirect(location: str, value: str, config: SpaceConfig) -> Response:
    return Response(
        "",
        status=302,
        headers=(("Location", location),),
        cookies=(_session_cookie(value, config),),
    )


def _allowed_hosts(config: SpaceConfig) -> tuple[str, ...]:
    if not config.production:
        return ("*",)
    canonical = urlsplit(config.canonical_origin).hostname
    hosts = [item for item in (canonical, *config.host_aliases) if item]
    for railway_host in (".up.railway.app", ".railway.app"):
        if railway_host not in hosts:
            hosts.append(railway_host)
    return tuple(hosts)


def _accepts_activity(request: Request) -> bool:
    accept = str(request.headers.get("accept", ""))
    return (
        not accept or ACTIVITY_JSON in accept or "application/ld+json" in accept or "*/*" in accept
    )


def _protocol_json(
    value: object, *, content_type: str = ACTIVITY_JSON, status: int = 200
) -> JSONResponse:
    return replace(
        JSONResponse.from_value(value, status=status, headers={"Content-Type": content_type}),
        content_type=content_type,
    )


def _federation_error(error: FederationError) -> JSONResponse:
    return _protocol_json(
        {"error": error.code, "message": str(error)},
        content_type="application/problem+json",
        status=error.status,
    )


def _collection_response(
    request: Request, federation: FederationService, config: SpaceConfig, name: str
):
    if not config.federation_enabled:
        return Response("Not found", status=404)
    if not _accepts_activity(request):
        return _federation_error(
            FederationError("accept", "ActivityPub response type is required.", status=406)
        )
    try:
        return _protocol_json(federation.collection(name))
    except FederationError as exc:
        return _federation_error(exc)
