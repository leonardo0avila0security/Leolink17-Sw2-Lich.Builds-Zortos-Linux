---
title: Get a mod preview
description: Fetch an original PNG or JPEG for an available managed mod.
---

`GET /api/v1/mods/{id}/preview`

`id` is the case-sensitive mod ID. This route takes no query parameters. A preview is available here only if the store has a PNG or JPEG for a managed mod and both the mod and at least one of its versions are approved.

A [mod summary](/reference/schemas/) gives the image location in `preview_url`. A path beginning with `/api/v1/` is relative to the API origin. A GameBanana preview URL points to GameBanana's image host. The Mod Store does not proxy that image. GitHub listings have no preview.

## Successful response

The body is the original image, with `Content-Type: image/png` or `image/jpeg`. A satisfiable byte-range request returns `206 Partial Content`. These trimmed headers come from a local server with the [managed demo fixture](/reference/detail/), which is absent from the public catalog:

```http
HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Length: 34231
Content-Type: image/png
```

## Errors

| HTTP status | Code | Meaning |
| --- | --- | --- |
| `404 Not Found` | `not_found` | No public managed preview is available for the ID. |
| `416 Requested Range Not Satisfiable` | None | The byte range is invalid or cannot be satisfied. The body can be plain text. |
| `500 Internal Server Error` | `internal_error` | The server could not read the catalog or open a stored image. |

For example, the Looping Routes preview is hosted on GameBanana, so this request returns `404 Not Found`:

```sh
curl --silent --show-error -A 'LichiiDocsExample/1.0' \
	https://lichii-api.zortos.me/api/v1/mods/gb-742301/preview
```

```json
{"error":{"code":"not_found","message":"not found"}}
```
