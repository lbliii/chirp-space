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

Publishing, media, guestbook behavior, relationships, export, deletion, and Railway template
publication remain deliberately gated by their Chirp backlog issues.

## Federation identity boundary

Federation is dark by default. Set `SPACE_FEDERATION_ENABLED=true` only after the owner-facing
consent gate is ready. The bounded protocol surface exposes WebFinger, one ActivityPub actor,
one active RSA signing key, inbox/outbox endpoints, and followers/following collections. It does
not yet advertise follows or publish posts.

Private signing-key material is encrypted at rest with `SPACE_KEY_ENCRYPTION_KEY`. Signed inbox
requests accept the deployed RSA-SHA256 HTTP Signature profile over
`(request-target) host date digest` and the bounded RFC 9421 RSA profile; replayed activity IDs or
signatures are accepted only once. Rotation is atomic and keeps retired public keys available for
30 days without retaining them as signing keys.
Remote key fetching is HTTPS-only, address-pinned, redirect-revalidated, size-bounded, and rejects
private, loopback, link-local, multicast, reserved, or otherwise non-global destinations.

Outbound activities and per-inbox deliveries commit together as immutable database rows. Delivery
runs outside web requests in batches of at most 16, preserves creation order per inbox, and retries
after 1 minute, 5 minutes, 30 minutes, 2 hours, 12 hours, 24 hours, then daily through day 7.
Retryable HTTP failures are `408`, `409`, `425`, `429`, and `5xx`; other `4xx` responses become
visible dead letters. Valid `Retry-After` values are capped at 24 hours. Operators can inspect and
act on the bounded queue without editing the database:

```bash
uv run chirp-space queue
uv run chirp-space deliver --limit 16
uv run chirp-space retry-delivery DELIVERY_ID
uv run chirp-space discard-delivery DELIVERY_ID
```

The worker validates and pins every destination address immediately before the signed POST. A
delivery never logs or stores plaintext signing keys, raw response bodies, or remote markup.

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
SPACE_KEY_ENCRYPTION_KEY=${{ secret(32, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") }}
SPACE_FEDERATION_ENABLED=false
```

The app listens on Railway's `PORT`, uses `/ready` for deployment readiness, runs migrations as a
pre-deploy command, and keeps one replica until the accepted federation worker gate is reached.
