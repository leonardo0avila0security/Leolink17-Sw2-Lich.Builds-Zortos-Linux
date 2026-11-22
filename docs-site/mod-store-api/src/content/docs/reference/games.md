---
title: List games
description: List games with at least one public Mod Store listing and count their distinct mods.
---

`GET /api/v1/games`

The API returns only games with at least one available mod. It sorts by name with ASCII case ignored, then by title ID.

## Query parameters

| Parameter | Type | Default | Accepted values |
| --- | --- | --- | --- |
| `limit` | Integer | `50` | `1` to `100`. |
| `offset` | Integer | `0` | `0` to `1000000`. |

Send exactly one `X-Lichii-Catalog-Features: github-v1` header to include GitHub listings. This can add games and increase counts. Keep the header and `limit` the same when following `next_offset`. See the [caching guide](/guides/caching/) for response headers and revalidation.

## Example

```sh
curl --silent --show-error -A 'LichiiDocsExample/1.0' \
	'https://lichii-api.zortos.me/api/v1/games?limit=2'
```

`200 OK`:

```json
{
  "games": [
    {"title_id":"040074A01BF12000","name":"Donkey Kong Bananza","mod_count":4},
    {"title_id":"04007EF01F8AE000","name":"Fire Emblem: Fortune's Weave","mod_count":15}
  ],
  "next_offset": 2
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `games` | Array of objects | Games on this page. An empty page contains `[]`. |
| `games[].title_id` | String | Game title ID as 16 uppercase hexadecimal digits. Use it with the `title_id` filter in [List mods](/reference/mods/). |
| `games[].name` | String | Game name as plain text. |
| `games[].mod_count` | Integer | Count of distinct available mods for the game, not the number of versions or files. |
| `next_offset` | Integer or null | Offset of the next page, or `null` if this is the last page. |

## Errors

`400 Bad Request` with code `invalid_input` means the query is malformed, a parameter is unknown or repeated, or `limit` or `offset` is outside its range or is not an integer. See [response schemas](/reference/schemas/) for the error body.
