---
title: Download a managed version
description: Download the validated ZIP for an approved managed Mod Store version.
---

`GET /api/v1/mods/{id}/versions/{version_id}/download`

| Path parameter | Meaning |
| --- | --- |
| `id` | The case-sensitive mod ID. |
| `version_id` | The case-sensitive version ID within that mod. |

The route takes no query parameters. Both the mod and the version must be approved. The version's `download_url` in [Get mod details](/reference/detail/) gives the same-origin path. GameBanana files and GitHub blobs are hosted by their respective providers and are not available from this route.

## Successful response

The body is a binary ZIP. These trimmed headers come from a local server with the [managed demo fixture](/reference/detail/), which is absent from the public catalog:

```http
HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Disposition: attachment; filename="demo-kart-translation-1.0.0-demo.zip"
Content-Length: 446
Content-Type: application/zip
```

`Content-Length` on a full response is the ZIP size. `Content-Disposition` suggests `{id}-{version_id}.zip`. The server validates and repacks managed uploads, so the served ZIP may differ from the original upload. Verify the full file against the [managed version's](/reference/schemas/) `size_bytes` and `sha256` before extraction.

### Byte range response

A request with `Range: bytes=0-15` returns the first 16 bytes of the ZIP. These trimmed headers are from the same fixture:

```http
HTTP/1.1 206 Partial Content
Content-Length: 16
Content-Range: bytes 0-15/446
Content-Type: application/zip
```

## Errors

| HTTP status | Code | Meaning |
| --- | --- | --- |
| `404 Not Found` | `not_found` | The mod or version is absent, is not approved, or the ID belongs to an external listing without managed versions. |
| `416 Requested Range Not Satisfiable` | None | The byte range is invalid or cannot be satisfied. The body can be plain text. |
| `500 Internal Server Error` | `internal_error` | The server could not read the catalog or open a stored ZIP. |

For example, a GameBanana file ID is not a managed version ID. The following request returns `404 Not Found`:

```sh
curl --silent --show-error -A 'LichiiDocsExample/1.0' \
	https://lichii-api.zortos.me/api/v1/mods/gb-742301/versions/1898456/download
```

```json
{"error":{"code":"not_found","message":"not found"}}
```
