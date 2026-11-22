---
title: Response schemas
description: Public JSON fields for mod summaries, managed versions, external listings, and errors.
---

JSON responses use UTF-8. Treat display text as plain text, not as HTML or Markdown. A nullable field is present and can be `null`. An optional field may be absent.

## Mod summary

[List mods](/reference/mods/) returns an array of these objects. [Get mod details](/reference/detail/) returns the same fields plus the detail fields.

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | String | Catalog ID and path key. Managed mod IDs are lowercase slugs of at most 63 characters. GameBanana IDs have the form `gb-<id>`. GitHub IDs begin with `gh-`. |
| `title_ids` | Array of strings | Sorted, distinct available game title IDs. Each is 16 uppercase hexadecimal digits. An external listing has one title. |
| `name` | String | Mod name. |
| `summary` | String | Short description. |
| `author` | String | Display credit for the creator or creators. |
| `type` | String | `graphics`, `fps`, `cheats`, `translation`, or `gameplay`. |
| `demo` | Boolean | `true` for an inert sample with a synthetic compatibility target. Ineligible for normal installation. |
| `source` | String | `submission` for a managed release, `demo` for an inert sample, `gamebanana` or `github` for an external listing. |
| `source_url` | String, optional | Canonical GameBanana listing URL or GitHub repository URL pinned to the full commit SHA. Omitted for managed releases and demos. |
| `preview_url` | String or null | Same-origin [preview path](/reference/preview/) for a managed image, the first remote preview URL for a GameBanana listing, or `null` if none. GitHub listings always return `null`. |
| `updated_at` | String | Public update time in UTC RFC 3339 with millisecond precision. |

## Managed version

A version applies to one exact game title, game version, and executable build. Match all three fields against the installed game and its active update. A 16-digit cheat prefix is not a full managed build ID. A different target has a separate version ID even when it uses the same ZIP.

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | String | Version ID, unique within its mod. It starts with a lowercase letter or digit. The remaining characters can also include periods, underscores, and hyphens. Maximum length is 63 characters. |
| `title_id` | String | Game title ID as 16 uppercase hexadecimal digits. |
| `game_version` | String | Exact game display version. |
| `build_id` | String | Full 32-byte executable build ID as 64 uppercase hexadecimal digits. |
| `min_lichii_build` | String, required | Minimum emulator release tag, `build-<number>`. The number is a positive unsigned 64-bit integer in decimal with no leading zero. The running build's number must be at least this minimum. A missing or invalid client release tag does not establish compatibility. |
| `download_url` | String | Same-origin [ZIP download path](/reference/download/). |
| `sha256` | String | Lowercase 64-digit SHA-256 hex digest of the served ZIP. |
| `size_bytes` | Integer | Exact ZIP size in bytes. |
| `unpacked_size_bytes` | Integer | Total uncompressed file size in bytes. |

## GameBanana metadata

The `external` object describes a listing on GameBanana. The Mod Store does not host its images or files.

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | Integer | Numeric GameBanana mod ID. |
| `category` | String | Original GameBanana category. |
| `credits` | Array of objects | Credits from the listing. |
| `credits[].name` | String | Credited name. |
| `credits[].role` | String | Credited role or contribution. |
| `credits[].url` | String | GameBanana profile URL, or an empty string if none is known. |
| `preview_urls` | Array of strings | HTTPS preview URLs on `images.gamebanana.com`. Empty if the listing has no preview. |
| `compatibility` | String | Always `"unverified"`. |
| `files` | Array of objects | Files on the listing. |
| `files[].id` | Integer | Numeric GameBanana file ID. |
| `files[].name` | String | Original filename, including its extension. |
| `files[].size_bytes` | Integer | File size in bytes. |
| `files[].uploaded_at` | String | Upload time in UTC RFC 3339. |
| `files[].download_url` | String | External download URL of the form `https://gamebanana.com/dl/<file ID>`. |
| `files[].sha256` | String or null | Lowercase 64-digit SHA-256 hex digest. `null` means the catalog has no digest to compare against. |
| `files[].build_ids` | Array of strings | Build IDs or prefixes found in the file, as 64 or 16 uppercase hexadecimal digits. Empty if none are known. These values do not identify the executable module or establish compatibility. |
| `files[].ambiguous_layout` | Boolean, optional | `true` means the file contains independent components that the client cannot select. The file is link-only. An absent value is equivalent to `false`. |

## GitHub metadata

The `github` object describes a GitHub repository at a pinned commit. The Mod Store does not host or proxy the files.

| Field | Type | Meaning |
| --- | --- | --- |
| `repository` | String | Repository in `owner/name` form. |
| `commit` | String | Full 40-digit lowercase Git commit SHA. |
| `license` | String | `"NOASSERTION"` means the catalog does not assert redistribution terms. |
| `builds` | Array of objects | Known build targets. Can be empty. |
| `builds[].id` | String | Build ID as 64 uppercase hexadecimal digits, or 16 digits for a prefix. |
| `builds[].target` | String | `main` identifies the main executable. `unknown` means the module is not identified. |
| `builds[].download` | Object, optional | Metadata for a specific blob at the pinned commit. Without it, the build is link-only. |
| `builds[].download.path` | String | Repository-relative path to the raw patch or ZIP. |
| `builds[].download.size_bytes` | Integer | Exact byte size of the Git blob, not the size of a selected ZIP member. |
| `builds[].download.sha256` | String | Lowercase 64-digit SHA-256 hex digest of that blob. |
| `builds[].download.kind` | String | `pchtxt`, `ips`, or `cheat`. |
| `builds[].download.member` | String, optional | Path of the selected patch within the ZIP. Omitted for raw patches. |
| `builds[].download.tag` | String, optional | Name of the selected cheat section. Required for ZIP cheats. A raw cheat without a tag must contain exactly one section. |

A 16-digit `main` build ID matches the first eight bytes of the full main build ID. A mismatched `unknown` build ID does not rule out an add-on because it could target another module. When `download` is present, the file URL is `https://raw.githubusercontent.com/<repository>/<commit>/<path>`, with the path segments URL-encoded as needed.

## Error response

| Field | Type | Meaning |
| --- | --- | --- |
| `error` | Object | Error details. |
| `error.code` | String | Stable code for programmatic handling. |
| `error.message` | String | Human-readable message. Do not match on this text. |

| HTTP status | Code | Meaning |
| --- | --- | --- |
| `400` | `invalid_input` | Invalid list query. |
| `404` | `not_found` | The requested mod, preview, or version is missing or unavailable. |
| `500` | `internal_error` | An unexpected server error. For example, a catalog asset exists in the database but its file cannot be opened. |
| `503` | `unavailable` | The [health check](/reference/health/) could not access the catalog database or asset directory. |
| `503` | `server_busy` | The public listener is at its concurrent request limit. |

Unmatched routes, unsupported methods, HTTP range errors, or errors from the hosting infrastructure can return non-JSON bodies. Check the HTTP status before decoding a success body. See the [caching guide](/guides/caching/) for bodyless revalidation responses.
