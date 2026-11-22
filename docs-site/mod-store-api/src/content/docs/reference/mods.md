---
title: List mods
description: Search and filter public Mod Store listings.
---

`GET /api/v1/mods`

The list contains approved mods with at least one available target. Each entry is a summary. [Get mod details](/reference/detail/) returns the description, approved managed versions, and source-specific metadata.

## Query parameters

| Parameter | Type | Default | Meaning |
| --- | --- | --- | --- |
| `title_id` | String | No filter | Exactly 16 hexadecimal digits, case-insensitive. Matches an approved managed version or an included external listing for the title. |
| `q` | String | No filter | Literal substring of the name, summary, description, or author. The API trims surrounding whitespace. An empty term applies no filter. Nonempty terms can contain up to 128 Unicode code points and no control characters. Matching ignores ASCII case only. |
| `type` | String | No filter | `graphics`, `fps`, `cheats`, `translation`, or `gameplay`. |
| `sort` | String | `updated` | `updated` sorts by most recent change first. `name` sorts by name with ASCII case ignored. Both break ties by mod ID. An empty value uses the default. |
| `limit` | Integer | `50` | Page size from `1` to `100`. |
| `offset` | Integer | `0` | Number of matching records to skip, from `0` to `1000000`. |

Filters combine with AND. Within `q`, any of the four text fields can match. The `title_ids` array still lists all available titles for each mod, even when the request filters by one title.

Send exactly one `X-Lichii-Catalog-Features: github-v1` header to include GitHub listings in the results and pagination. Keep the header, filters, sort, and `limit` the same when following `next_offset`. See the [caching guide](/guides/caching/) for response headers and revalidation.

## Example

```sh
curl --silent --show-error -A 'LichiiDocsExample/1.0' \
	'https://lichii-api.zortos.me/api/v1/mods?title_id=0400c3f00006e000&type=gameplay&q=looping&sort=name&limit=2'
```

`200 OK`:

```json
{
  "mods": [
    {
      "id": "gb-742301",
      "title_ids": ["0400C3F00006E000"],
      "name": "Looping Routes",
      "summary": "Adds custom routes that loop back to their starting track",
      "author": "LiamWins, Shortcat",
      "type": "gameplay",
      "demo": false,
      "source": "gamebanana",
      "source_url": "https://gamebanana.com/mods/742301",
      "preview_url": "https://images.gamebanana.com/img/ss/mods/6afd4d0cef640.jpg",
      "updated_at": "2026-11-21T14:48:26.000Z"
    }
  ],
  "next_offset": null
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `mods` | Array of objects | [Mod summaries](/reference/schemas/) on this page. An empty page contains `[]`. |
| `next_offset` | Integer or null | Offset of the next page, or `null` if this is the last page. |

## Errors

`400 Bad Request` with code `invalid_input` means the query is malformed, a parameter is unknown or repeated, or a value does not meet the rules above. For example, `title_id=123` returns:

```json
{"error":{"code":"invalid_input","message":"title_id must contain 16 hexadecimal digits"}}
```

An unknown but well-formed title ID returns an empty page, not `404 Not Found`. See [response schemas](/reference/schemas/) for other public API errors.
