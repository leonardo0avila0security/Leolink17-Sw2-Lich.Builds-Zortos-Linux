---
title: Versioning and changelog
description: What v1 clients can rely on and how to handle additive changes.
---

## v1 stability

Catalog endpoints use `/api/v1/`. Within v1, existing endpoints and documented
field types and meanings stay compatible. Incompatible contract changes need
a new API version. A capability such as `github-v1` opts clients into new
catalog behavior without changing what existing clients see.

Code for additive changes. Ignore fields you don't use. Handle omitted or
nullable fields as documented; don't treat those cases as empty strings or
zeroes. If your app doesn't know a new source, type, or download kind, it can
display available attribution and link to the source without offering an install.

The catalog is not a snapshot API. Listings, counts, build records, source
URLs, and availability can change independently of the API version. Save
listing IDs rather than row positions, resolve the detail again before
downloading, and handle removals. Follow current HTTP caching headers rather
than hard-coding them as part of the v1 schema.

## Changelog

| Change | What it means for clients |
| --- | --- |
| v1 catalog | Browse games and mod summaries, fetch details, and read approved managed assets when present. GameBanana listings point to the original pages and files. |
| November 2026: GitHub opt-in | `X-Lichii-Catalog-Features: github-v1` adds GitHub listings with pinned builds and, where available, verified download metadata. Legacy requests keep their existing catalog. |
| November 2026: conditional catalog reads | Catalog JSON now advertises freshness and ETags in production. See [Caching and fair use](/guides/caching/) for the current headers. |
