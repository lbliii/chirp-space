# Changelog

## Unreleased

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
