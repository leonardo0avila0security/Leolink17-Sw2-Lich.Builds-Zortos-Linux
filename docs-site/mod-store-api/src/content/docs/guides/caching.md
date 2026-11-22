---
title: Caching and fair use
description: Reuse catalog pages, revalidate with ETags, and avoid unnecessary requests.
---

## Reuse pages and revalidate them

Production currently sends these headers on successful JSON responses from
[list games](/reference/games/), [list mods](/reference/mods/), and
[get a mod](/reference/detail/):

| Header | Observed behavior |
| --- | --- |
| `Cache-Control` | `public, max-age=300`. Honor the freshness lifetime and any `Age` header. |
| `ETag` | An opaque quoted validator. It can be weak (`W/`); keep it as received. |
| `Vary` | `X-Lichii-Catalog-Features, Accept-Encoding`. Cache entries must distinguish these request headers. |
| `Content-Encoding` | Production can gzip catalog JSON. Use your HTTP client's decompression support. |

Cloudflare caches catalog GETs with `github-v1` at the edge for five minutes.
Expect catalog changes to take up to five minutes to appear in those
responses. A request without the feature header can receive the same browser
freshness headers without being cached at the edge. Health checks and
managed assets do not share this catalog caching contract.

Use the cached body while it's fresh. When revalidating, send its `ETag`
back as `If-None-Match` with the same URL, query and headers. A `304 Not
Modified` has no JSON body. Use your cached body. A `200 OK` replaces it.
If a response has no validator, use its cache policy and fetch it normally
when it expires.

```sh
url='https://lichii-api.zortos.me/api/v1/games?limit=1'
feature='X-Lichii-Catalog-Features: github-v1'
agent='LichiiDocsExample/1.0'
curl --fail --silent --show-error --compressed -A "$agent" -H "$feature" \
  -D games.headers -o games.json "$url"
etag=$(awk 'tolower($1) == "etag:" { sub(/\r$/, "", $2); print $2 }' games.headers)
test -n "$etag"
curl --fail --silent --show-error --compressed -A "$agent" -H "$feature" \
  -H "If-None-Match: $etag" -D - -o /dev/null "$url"
```

Output from an unchanged production page, trimmed:

```http
HTTP/2 304
cache-control: public, max-age=300
vary: X-Lichii-Catalog-Features, Accept-Encoding
cf-cache-status: HIT
```

## Page only as far as you need

Use a descriptive `User-Agent` such as `YourEmulator/2.1 ModStore`. Filter
by the installed `title_id` instead of walking the whole catalog to fill
one game's view. Send the returned `next_offset` with the same filters,
sort, page size, and feature header. Stop at `null`. Offset pages aren't an
immutable snapshot, so deduplicate by ID if a new listing moves results while
you page.

Load previews and details on demand. Avoid opening many parallel requests
to warm a cache. On transient failures, retry with backoff and respect
`Retry-After` if present. Don't retry a `400` or `404` in a loop.

The public API does not currently grant cross-origin browser access. Make
requests from the emulator or a trusted backend rather than relying on
`fetch()` in a public web page. Don't use a public proxy to bypass a
source's restrictions.
