"""Chirp application factory and server-rendered Space routes."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

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
from chirp_space.federation import (
    ACTIVITY_JSON,
    DocumentFetcher,
    FederationError,
    FederationService,
)
from chirp_space.models import Customization, Owner, SiteState
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
) -> App:
    config = space_config or SpaceConfig.from_env(debug=debug)
    database = store or store_from_url(config.database_url)
    database.migrate()
    service = SpaceService(database, config)
    federation = FederationService(database, config, fetcher=federation_fetcher)
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
        except FederationError as exc:
            return _federation_error(exc)
        return _protocol_json(
            {"status": receipt.status, "activityType": receipt.activity_type}, status=202
        )

    @app.route("/", template="setup_pending.html")
    def home(request: Request):
        state = database.state()
        if state is None:
            return render(request, "setup_pending.html")
        return render(request, "profile.html", profile=state, preview=False)

    @app.route("/{profile}", template="profile.html")
    def public_profile(request: Request, profile: str):
        state = database.state()
        if (
            state is None
            or not profile.startswith("@")
            or profile[1:].casefold() != state.owner.handle
        ):
            return Response("Profile not found", status=404)
        return render(request, "profile.html", profile=state, preview=False)

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
