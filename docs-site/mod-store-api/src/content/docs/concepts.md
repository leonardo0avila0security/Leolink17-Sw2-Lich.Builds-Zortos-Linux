---
title: Catalog concepts
description: Understand title IDs, catalog variants, sources, and compatibility.
---

## Use the game's exact title ID

A title ID is a 16-digit hexadecimal string. Keep it as a string, including
the leading zero. For example, `0100152000022000` identifies Mario Kart 8
Deluxe on Switch and `0400C3F00006E000` identifies Mario Kart World on Switch
2. Use the title ID reported by the emulator for the installed game. Don't
infer a match from the game's display name or substitute an ID for a different
edition. The mod filter accepts either hex case, but the API returns uppercase.

## Listings, versions, and files

A [listing](/reference/mods/) identifies an item in the catalog. Its `id`
identifies the listing, not a file, and `title_ids` lists the games it targets.
Fetch the [detail](/reference/detail/) before deciding what to install. The
detail stores downloads differently for each source:

| Source | Where to find downloads | What to match |
| --- | --- | --- |
| GameBanana (`gamebanana`) | `external.files` points to GameBanana. | Match the listing's title ID. File metadata can contain build hints, but the catalog doesn't establish exact compatibility. |
| Community GitHub repositories (`github`) | `github.builds[].download` describes a file at a pinned commit. It may select one ZIP member or one cheat section. | Match the title ID and interpret the build's `target` and `id`. |
| Lichii-managed releases | `versions` describes catalog-hosted ZIPs, when published. | Match the version row's title ID, display version, and full build ID. The `min_lichii_build` requirement applies to Lichii, not to other emulators. |

GameBanana and GitHub listings have `versions: []`. An empty array on an
external listing does not say whether you can download anything.

The public `type` values are `graphics`, `fps`, `cheats`, `translation`,
and `gameplay`. These describe what the mod changes. They don't tell you
whether to expect a ZIP, a patch file, or a cheat section. Choose the installer
using the detail response and the actual file format.

## Decide what to offer the player

- **Verified bytes.** You can verify a pinned GitHub file or managed ZIP by
  matching its exact `size_bytes` and `sha256`. Some GameBanana files also
  have a SHA-256. Byte verification doesn't establish compatibility or prove
  that content is safe.
- **Unverified compatibility.** GameBanana reports `external.compatibility:
  "unverified"`. Build IDs in its file records may identify a different
  executable module. On GitHub, a `target: "main"` build must match the
  installed main executable. Compare a 16-digit ID with the main build ID's first eight bytes;
  for a 64-digit ID, compare the full build ID. A different `target: "unknown"`
  ID is inconclusive because it may belong to another module.
- **Link-only.** A GitHub build without a `download` or a GameBanana file with
  `ambiguous_layout: true` has no automatic install path. Your client can
  also treat unsupported formats or downloads without a digest as link-only.
  In each case, offer the original `source_url`.
- **Demo.** `demo: true` identifies an inert test listing. Keep demo records
  separate from production recommendations. It does not certify a file.

Use the effective program build ID and game display version after applying
the installed update, not values from the base game when a different update
is active. See the [installation guide](/guides/installation/) for format-specific checks.

## Opt into the GitHub catalog

Send exactly one `X-Lichii-Catalog-Features: github-v1` header on game lists,
mod lists, and mod details. Without it, the server excludes GitHub listings
from results, pagination, and game counts, and GitHub detail URLs return
`404`. GameBanana and available managed listings remain visible. Keep the
header the same across pages and in cache lookups.

On 22 November 2026, walking all live pages found 659 games and 11,218
listings with the header, including 11,018 GitHub and 200 GameBanana listings.
Without the header, the same check found 20 games and 200 GameBanana
listings. These figures are a snapshot, not API limits. See
[Attribution and licensing](/attribution/) for the five GitHub sources.
