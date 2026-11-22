---
title: Download integrity and updates
description: What Lichii verifies before installing a download, when it stays link-only, and how updates are identified.
---

A verified download matches the byte count and SHA-256 in the catalog. That check detects different bytes. It does not establish that the mod is safe, licensed for redistribution, or compatible with a game. See [how Lichii selects a game and build](/guides/installation/).

## Verify before installing

Lichii streams the download into a temporary file, checks the exact byte count, and computes SHA-256. A managed ZIP or a GitHub download needs a catalog digest. A GameBanana file can have `sha256: null`. In that case Lichii still checks the size and computes a digest, but it has no catalog digest to compare. The local digest cannot verify the publisher's bytes. The installer copies the temporary file and checks SHA-256 again so it parses the same bytes the downloader checked.

The download source determines where the client can fetch those bytes:

- Managed releases come from the configured catalog origin. Lichii does not follow redirects for them.
- GameBanana downloads start at the file's official link. Lichii follows only allowed HTTPS redirects to GameBanana file hosts and does not bypass a login or access block.
- GitHub downloads come directly from `raw.githubusercontent.com` at the full commit in the listing. Lichii does not follow redirects. If the download is a ZIP, the digest covers the whole ZIP, not just the selected patch. The catalog does not proxy or rehost the files.

Lichii limits ZIPs to 64 MiB compressed, 256 MiB expanded, and 4,096 entries. A raw or selected GitHub patch is limited to 2 MiB. The installer checks entry sizes and CRCs and rejects unsafe paths, links, duplicate paths, and filename collisions before publishing the add-on. ZIPs must be single-disk and use stored or deflated entries.

Treat downloaded content as untrusted data. Never run a host executable, installer, or script from a mod download. Lichii stages patches and cheats as data. At game launch, an enabled mod can still replace game files or executable code. An enabled cheat can change the game's memory while it runs.

## Keep a source link when installation is unavailable

A GitHub build with no `download` is link-only. Open the pinned GitHub source for the author's files and instructions. A source can stay link-only when it forbids downloads by third-party tools or when the catalog cannot establish the format, target, or selected component. A pinned commit and `NOASSERTION` license status do not grant redistribution rights.

A GameBanana file marked `ambiguous_layout`, a non-ZIP file, or a ZIP over the client limit also falls back to the source. A missing GameBanana digest alone does not make a supported ZIP link-only. If the download or extraction fails, leave the existing add-on alone and offer the source page rather than bypass the check.

## Tell an update from a reinstall

Lichii stores the installed version and the full digest of the downloaded file in `.lichii-mod-store.json`, along with the title ID and mod ID. An update stages a replacement before moving it into place. The client replaces or removes only store-owned folders with matching metadata. It does not merge with a manually installed folder that happens to use the same name. An update can discard manual edits inside a store-owned folder.

- **Managed release.** The version ID identifies the installed release. A different eligible version ID is an update.
- **GameBanana file.** With a catalog digest, Lichii compares the selected file ID and full SHA-256 against the installed record. The stored version string uses the file ID and the first 16 hex digits of the digest. Older records without the full digest fall back to that string. Without a catalog digest, Lichii offers **Reinstall** for the same file ID because it cannot know whether the remote bytes changed.
- **GitHub patch.** The local version combines the build ID and a SHA-256 fingerprint of the download digest, patch kind, ZIP member path, and cheat tag. Changing the member or tag changes the fingerprint even if the downloaded ZIP stays the same.

These are Lichii's local update rules. The fingerprint tracks the selected download and patch, not the installed files on disk. It does not establish which release is newer or check whether someone modified the add-on after installation.
