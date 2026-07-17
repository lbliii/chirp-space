# Chirp Space Agent Guide

Chirp Space is a single-owner, local-first personal site with an explicitly bounded federation roadmap.

## Product invariants

- One deployment has one owner, one canonical origin, and one public profile.
- Server-rendered Chirp pages, typed returns, and named blocks remain the architecture.
- PostgreSQL is the production persistence contract; SQLite exists for local development and tests.
- Initial deployment requires no hand-authored secrets or infrastructure wiring.
- Claim, password, recovery-code, session, CSRF, and canonical-origin behavior fail closed.
- Themes and profile modules are fixed typed choices; never accept arbitrary HTML, CSS, JavaScript, templates, or imports.
- Stable app-owned UUIDv7 identifiers never depend on display names, handles, titles, or domains.

## Stop and ask

- A change alters the single-owner model, canonical identity, authentication/recovery semantics, public routes, schema compatibility, or Railway topology.
- A new required service, runtime dependency, environment variable, Chirp public API, or federation surface is proposed.
- Destructive database, media, deployment, or remote GitHub work is required.

## Done

- Run Ruff, Ruff format check, Ty, app.check(), and pytest.
- Mark behavioral coverage with the originating Chirp issue number.
- Update README, changelog, migrations, and deployment guidance with user-visible behavior.
