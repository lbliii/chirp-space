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

Export, whole-site deletion, and Railway template publication remain deliberately gated by their
Chirp backlog issues.

## Publishing and guestbook

The owner publishing surface at `/owner/content` supports short posts, journals, photos, and
explicit HTTPS links. Every item has an app-owned UUIDv7 permalink, optimistic revision, tags,
and one of four lifecycle states: `draft`, `local_only`, `public`, or the permanent `deleted`
tombstone. Ordinary forms provide create, private preview, edit, publish, unpublish, and confirmed
delete flows; htmx enhances the same handlers and named template blocks.

Visitors can browse type feeds, signed-cursor pagination, year/month archives, tags, bounded local
search, stable permalinks, and `/feed.xml`. The guestbook is the only anonymous write: submissions
are honeypot checked, keyed-rate-limited without retaining raw IP addresses, deduplicated, private
until moderation, and safely rendered as plain text.

Media storage is an app-owned `ObjectStorage` contract with a filesystem adapter for development.
Untrusted JPEG, PNG, and WebP uploads cross a separate `ImageNormalizer` boundary before storage;
the production Pillow 12.3 normalizer decodes and re-encodes the full image, removes metadata,
rejects animation and trailing-data polyglots, applies EXIF orientation, and produces 480 px and
1280 px responsive variants when useful. Object keys are random, checksums are verified on read,
missing objects become visible state, and deletion cleanup is idempotent and retryable. Failed
normalization or storage saves a recoverable draft instead of accepting unprocessed bytes.

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

## Federation safety and recovery

The accepted federation budgets are database-backed so restarts, multiple workers, and
free-threaded execution cannot create independent process-local allowances. Inbox requests are
bounded globally and by pseudonymous client, domain, and actor tokens; delivery uses global,
domain, and inbox leases. Follow creation has separate domain and actor budgets. All leases expire
automatically after interrupted work.

The owner can pause inbound, outbound, or all federation from `/owner/connections` without taking
the local site or publishing offline. That page also shows queue health, per-peer failure state,
dead letters, and recent bounded security decisions. Evidence export contains keyed tokens rather
than raw client addresses or actor paths, and events expire after 30 days. Blocking and pausing do
not delete local content, restore relationships, or claim to erase remote copies.

## Relationship and audience semantics

Connections are asymmetric. `Following` means this owner received a matching Accept; `Follower`
means this owner accepted a remote Follow; `Friend` is only the derived display state when both are
active. Circles, pins, mutes, and private notes are local preferences and are never federated.

The owner page at `/owner/connections` supports URL or WebFinger discovery, explicit follow
accept/reject/remove flows, local circles, mute/pin, actor and domain blocks, and exact audience
previews with ordinary forms or htmx. Blocking is enforced before discovery and delivery, removes
circle eligibility, cancels queued work, and restores no relationship when undone. Followers,
friends, and circles are access-control intentions—not encryption, DRM, or remote revocation—and
the preview names exact recipients before restricted publication.

## Local development

```bash
uv sync --group dev
uv run chirp-space serve
```

Open `http://localhost:8000/setup` and use `development-owner-claim-token`. Local state is
in-memory unless `DATABASE_URL=sqlite:///space.db` is set. Development media uses
`.chirp-space/media/`; inject an object-storage adapter before relying on durable production media.

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
