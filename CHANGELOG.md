# Changelog

## Unreleased

- Add issue #799 database-backed federation rate and concurrency budgets, emergency inbound and
  outbound pause controls, per-peer queue diagnostics, bounded pseudonymous security evidence,
  owner recovery controls, and 30-day event retention while local publishing remains available.
- Add the issue #791 local publishing and guestbook surface: short posts, journals, normalized
  photos, links, drafts and lifecycle controls, stable archives and feeds, moderated anonymous
  entries, responsive Pillow media, storage-integrity checks, and shared plain-request/htmx flows.
- Add the issue #796 asymmetric relationship state machines, safe actor/WebFinger discovery,
  Follow/Accept/Reject/Undo flows, derived friends, local circles/pins/mutes/notes, actor and domain
  blocks, exact audience previews, and shared plain-request/htmx owner controls.
- Add the issue #794 durable federation delivery spine: immutable activity and per-inbox delivery
  rows, ordered bounded workers, the accepted retry/dead-letter schedule, persistent peer circuits,
  SSRF-safe signed POSTs, restart proof, and operator queue/retry/discard commands.
- Add the issue #793 federation identity foundation: WebFinger and ActivityPub actor discovery,
  encrypted RSA signing keys, signed inbox verification with durable replay protection, narrow
  protocol collections, and SSRF-hardened remote document fetching behind a default-off gate.
- Add the issue #790 single-owner foundation: secure first claim, stable UUIDv7 identity,
  password and recovery-code access, revocable sessions, constrained themes, typed profile
  modules, private preview, atomic customization, and SQLite/PostgreSQL migrations.
