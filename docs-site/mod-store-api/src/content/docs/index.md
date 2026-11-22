---
title: Lichii Mod Store API
description: Find Switch mods, read compatibility metadata, and verify original downloads in your emulator.
---

The Lichii Mod Store API is a public, read-only catalog of community mods,
patches, and cheats for Nintendo Switch and Switch 2 games. Use it to show
players what's available for their installed games and to find downloads your
emulator can verify and install.

The API origin is `https://lichii-api.zortos.me`. No account or token is
required. Send `X-Lichii-Catalog-Features: github-v1` on catalog requests to
include GitHub listings alongside GameBanana listings.

For third-party mods, Lichii serves metadata. Your client gets files and
previews from the original source. The API also has routes for Lichii-managed
releases, if any are published; those are separate from GameBanana and GitHub.

## Start here

- [Quickstart](/quickstart/) lists games, finds a mod, and verifies an original
  download with curl in under five minutes.
- [Catalog concepts](/concepts/) explains title IDs, compatibility, sources,
  and what the feature header changes.
- [API reference](/reference/games/) lists the endpoints and their response fields.
- [Install mods](/guides/installation/) maps downloads to the game's mod layout.
- [Client examples](/guides/client-examples/) shows Python, TypeScript, and C++ integrations.
