# Chirp Space

A one-owner, local-first personal site powered by Chirp's server-rendered hypermedia stack.
The first slice is useful without federation: claim one stable identity, publish an accessible
profile, and customize it through typed modules and constrained theme tokens.

## Security and product boundary

- One deployment has one owner and one explicit canonical origin.
- First claim requires a high-entropy deployment token and succeeds once.
- Passwords use Chirp's password primitive; sessions and recovery codes are hashed and revocable.
- Recovery codes are displayed once, work once, and recovery revokes existing sessions.
- Theme/module forms accept no arbitrary HTML, CSS, JavaScript, templates, or imports.
- Owner and site UUIDv7 identifiers survive display-name, handle, theme, and domain changes.
- PostgreSQL is the production contract. SQLite supports local development and restart proof.

Publishing, media, guestbook behavior, federation, relationships, export, deletion, and Railway
template publication remain deliberately gated by their Chirp backlog issues.

## Local development

```bash
uv sync --group dev
uv run chirp-space serve
```

Open `http://localhost:8000/setup` and use `development-owner-claim-token`. Local state is
in-memory unless `DATABASE_URL=sqlite:///space.db` is set.

Run the complete quality gate:

```bash
uv run ruff check .
uv run ruff format . --check
uv run ty check src/chirp_space/ tests/
uv run pytest
uv run chirp-space check
```

## Railway-facing variables

The later public template will generate or reference every required value:

```text
DATABASE_URL=${{Postgres.DATABASE_URL}}
SPACE_ENV=production
SPACE_CANONICAL_ORIGIN=https://${{RAILWAY_PUBLIC_DOMAIN}}
CHIRP_SECRET_KEY=${{ secret(32, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") }}
SPACE_OWNER_CLAIM_TOKEN=${{ secret(32, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") }}
```

The app listens on Railway's `PORT`, uses `/ready` for deployment readiness, runs migrations as a
pre-deploy command, and keeps one replica until the accepted federation worker gate is reached.
