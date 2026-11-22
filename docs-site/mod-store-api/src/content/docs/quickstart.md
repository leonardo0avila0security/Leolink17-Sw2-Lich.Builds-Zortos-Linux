---
title: Quickstart
description: List games, find a mod, and verify a pinned download in under five minutes.
---

Use a shell with `curl`, `jq`, and `sha256sum`. Run the commands in an empty
scratch directory. We'll find a mod for 13 Sentinels Aegis Rim and verify
the original ZIP without installing anything.

## 1. List games

```sh
api='https://lichii-api.zortos.me/api/v1'
feature='X-Lichii-Catalog-Features: github-v1'
agent='MyEmulator/1.0 ModStoreQuickstart'
curl --fail --silent --show-error -A "$agent" -H "$feature" \
  "$api/games?limit=1" | jq .
```

The live response was:

```json
{
  "games": [
    {
      "title_id": "01003FC01670C000",
      "name": "13 Sentinels Aegis Rim",
      "mod_count": 2
    }
  ],
  "next_offset": 1
}
```

The first game can change as the catalog grows. Use the title ID below to
reproduce the example. In your emulator, use the installed game's title ID.
If you need more games, use `next_offset` as the next request's `offset`.

## 2. Find a mod and read its detail

```sh
curl --fail --silent --show-error -A "$agent" -H "$feature" \
  "$api/mods?title_id=01003FC01670C000&limit=2&sort=name" -o mods.json
jq '{mods: [.mods[] | {id, name, source}], next_offset}' mods.json
```

This projection shows the two listings returned by production:

```json
{
  "mods": [
    {
      "id": "gh-fl4sh9174-16-10-ultrawide-d1a9cf61a887cb32",
      "name": "16.10 Ultrawide",
      "source": "github"
    },
    {
      "id": "gh-fl4sh9174-21-9-ultrawide-38308febbf6434e3",
      "name": "21.9 Ultrawide",
      "source": "github"
    }
  ],
  "next_offset": null
}
```

```sh
id='gh-fl4sh9174-16-10-ultrawide-d1a9cf61a887cb32'
curl --fail --silent --show-error -A "$agent" -H "$feature" \
  "$api/mods/$id" -o detail.json
jq '.github.builds[0]' detail.json
```

The live build record was:

```json
{
  "id": "4B632573CA5C160EABB70519FB622718956D70EA000000000000000000000000",
  "target": "unknown",
  "download": {
    "path": "13 Sentinels Aegis Rim [01003FC01670C000][USA][mods].zip",
    "size_bytes": 2584,
    "sha256": "64c5a22e022a7ce4c2cdf948a09dae627a93567d62e70d02425a4d21f27a757b",
    "kind": "pchtxt",
    "member": "[16.10 Ultrawide v1.10]/exefs/1.10.pchtxt"
  }
}
```

This example chooses a specific build for demonstration. In an installer,
choose a build for the user's game version and executable rather than using
array position. A listing can change or be removed. Read
[Get a mod](/reference/detail/) for the other detail shapes and error responses.

## 3. Download and verify the original file

For this GitHub listing, use the pinned repository and commit from the detail
response. Encode each path segment separately to preserve the slashes, then
fetch from GitHub directly. Don't follow redirects.

```sh
(
  set -eu
  repo=$(jq -er '.github.repository' detail.json)
  commit=$(jq -er '.github.commit' detail.json)
  meta='.github.builds[0].download'
  path=$(jq -er "$meta.path | split(\"/\") | map(@uri) | join(\"/\")" detail.json)
  size=$(jq -er "$meta.size_bytes" detail.json)
  sha=$(jq -er "$meta.sha256" detail.json)
  curl --fail --silent --show-error --proto '=https' --max-time 30 \
    --max-filesize "$size" -A "$agent" \
    "https://raw.githubusercontent.com/$repo/$commit/$path" -o mod.zip
  test "$(wc -c < mod.zip)" -eq "$size"
  printf '%s  %s\n' "$sha" mod.zip | sha256sum -c -
)
```

The verified download printed `mod.zip: OK`. This verifies the whole ZIP,
not compatibility or safety. If either check fails, discard the ZIP. If it
passes, the installer should validate and extract only the exact `member`
named in the metadata. See [Install mods](/guides/installation/) before
writing anything to a player's mod directory.
