---
title: Get mod details
description: Read a mod's description, approved managed versions, or external listing metadata.
---

`GET /api/v1/mods/{id}`

| Path parameter | Meaning |
| --- | --- |
| `id` | The case-sensitive mod ID from [List mods](/reference/mods/). |

The route takes no query parameters. For a GitHub mod, send exactly one `X-Lichii-Catalog-Features: github-v1` header. See the [caching guide](/guides/caching/) for response headers and revalidation.

## Response

`200 OK` returns a single JSON object with all [mod summary fields](/reference/schemas/) and the fields below.

| Field | Type | Meaning |
| --- | --- | --- |
| `description` | String | Full description as plain text. May contain line breaks. |
| `versions` | Array of objects | Approved [managed versions](/reference/schemas/), newest upload first, then by version ID. External listings return `[]`. |
| `external` | Object, optional | [GameBanana metadata](/reference/schemas/). Present only for `source: "gamebanana"`. |
| `github` | Object, optional | [GitHub metadata](/reference/schemas/). Present only for `source: "github"`. |

### GameBanana example

```sh
curl --silent --show-error -A 'LichiiDocsExample/1.0' \
	https://lichii-api.zortos.me/api/v1/mods/gb-742301
```

Response excerpt. Only the first preview URL is shown.

```json
{
  "id": "gb-742301",
  "source": "gamebanana",
  "source_url": "https://gamebanana.com/mods/742301",
  "versions": [],
  "external": {
    "id": 742301,
    "category": "Other/Misc",
    "credits": [
      {"name":"LiamWins","role":"Key Authors: Made the mod","url":"https://gamebanana.com/members/6164904"},
      {"name":"Shortcat","role":"Special Thanks: Inspiration","url":""}
    ],
    "preview_urls": ["https://images.gamebanana.com/img/ss/mods/6afd4d0cef640.jpg"],
    "files": [
      {
        "id": 1898456,
        "name": "loopingroutes_6de68.zip",
        "size_bytes": 1520584,
        "uploaded_at": "2026-11-21T14:44:20Z",
        "download_url": "https://gamebanana.com/dl/1898456",
        "sha256": null,
        "build_ids": []
      }
    ],
    "compatibility": "unverified"
  }
}
```

### GitHub example

```sh
curl --silent --show-error -A 'LichiiDocsExample/1.0' \
	--header 'X-Lichii-Catalog-Features: github-v1' \
	https://lichii-api.zortos.me/api/v1/mods/gh-kenji-nx-1008p-2c180c0864849275
```

Response excerpt:

```json
{
  "id": "gh-kenji-nx-1008p-2c180c0864849275",
  "source": "github",
  "preview_url": null,
  "description": "Check the source for supported versions, credits, and notes.",
  "versions": [],
  "github": {
    "repository": "Kenji-NX/switch-pchtxt-mods",
    "commit": "13f0e6559136ead857e7c66d53f1ef1775d339f4",
    "license": "NOASSERTION",
    "builds": [
      {
        "id": "646761F643AFEBB379EDD5E6A5151AF2CEF93DC1000000000000000000000000",
        "target": "unknown",
        "download": {
          "path": "Metroid Dread/010093801237C000/1008p/exefs/2.1.0.pchtxt",
          "size_bytes": 234,
          "sha256": "36f043f72b844362a86cbac968ab50a717904a7a392185cf91303cba7f2a62c9",
          "kind": "pchtxt"
        }
      }
    ]
  }
}
```

### Managed version example

This response excerpt comes from a local server with the bundled `seed-demo` fixture. The demo uses a synthetic compatibility target and is absent from the public catalog.

```json
{
  "id": "demo-kart-translation",
  "demo": true,
  "source": "demo",
  "preview_url": "/api/v1/mods/demo-kart-translation/preview",
  "versions": [
    {
      "id": "1.0.0-demo",
      "title_id": "0400C3F00006E000",
      "game_version": "modstore-demo",
      "build_id": "0000000000000000000000000000000000000000000000000000000000000000",
      "min_lichii_build": "build-1",
      "download_url": "/api/v1/mods/demo-kart-translation/versions/1.0.0-demo/download",
      "sha256": "a53664e7772c0c722cb2d19754d097ef8740e86e1ebf194e354543b5f4ad9d37",
      "size_bytes": 446,
      "unpacked_size_bytes": 112
    }
  ]
}
```

## Errors

`404 Not Found` with code `not_found` means the mod is missing or unavailable. The same response covers a managed mod with no approved version and a GitHub mod requested without the feature header.
