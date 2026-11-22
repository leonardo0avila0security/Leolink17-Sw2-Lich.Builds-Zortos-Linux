---
title: Install mods and cheats
description: How Lichii selects compatible downloads and turns Atmosphère packages into local add-ons.
---

The [mod detail response](/reference/detail/) identifies downloads and the games they target. Lichii decides what it can install for the selected game. Other clients can use the same catalog without copying Lichii's directory layout, add-on controls, or update tracking.

## Select the game and build

A title ID identifies the game. A game version is the display version, such as the version shown in the library. A build ID identifies a particular executable module. The full build ID is 32 bytes, written as 64 hexadecimal digits. A cheat filename uses the first eight bytes of the game's main build ID, written as 16 hexadecimal digits.

- **Managed release.** Match the title ID, the effective game display version, and the full main build ID. Use the game and update that the loader will actually use. Lichii also requires its own `build-<number>` release tag to meet `min_lichii_build`. It compares the numbers, not the strings. Missing identity information, a mismatch, or a demo entry prevents a normal install.
- **GameBanana file.** Choose a ZIP for a game in the local library. The catalog's `build_ids` are clues from patch files, not a compatibility verdict. Even a checksum match does not confirm game compatibility. Lichii treats it as unverified.
- **GitHub patch.** Match a full build marked `main` against the full main build ID. For a cheat, match the 16-digit `main` prefix. A known main build mismatch blocks installation. A 64-digit build marked `unknown` can match main, but a different ID may belong to another module, so compatibility stays unverified. With an eligible download and an installed title, Lichii can offer an install for an unverified build.

## Find the ZIP's payload

An Atmosphère package commonly places its payload under `atmosphere/contents/<title-id>/`. The directories immediately under that title identify the kind of payload: `romfs/` for game file overlays, `exefs/` for executable files or patches, and `cheats/` for cheat text. Lichii also accepts `romfslite/` and `romfs_ext/` as payload directories.

Managed ZIPs put the lowercase payload directories at the archive root. They do not include the title directory or an add-on directory. For GameBanana ZIPs, Lichii also accepts a single outer folder, the matching `atmosphere/contents/<title-id>/` tree, or both. It removes those enclosing directories and normalizes the payload directory names to lowercase.

A ZIP needs at least one file under a supported payload directory, and all payload files must share one package root. A README or license file can sit alongside the payload directories. An archive that mixes titles or competing package roots fails instead of making a guess. The whole-ZIP installer does not accept `atmosphere/exefs_patches/` as a payload root.

Choose the intended file when a GameBanana listing offers several downloads. Lichii does not offer a component picker inside the chosen ZIP. If the catalog marks the file `ambiguous_layout`, open the source page for manual selection. A checksum does not override that marker.

## Install only the selected GitHub patch

If a GitHub download names a ZIP `member`, Lichii uses that exact relative path. It validates the archive but writes no other members to the add-on. Without a `member`, the download is the raw patch. Lichii checks an IPSwitch `.pchtxt` patch's `@nsobid-` directive against the target build. For IPS and IPS32 it checks the build ID in the source filename and validates the binary format. It installs both binary formats with an `.ips` extension, which the Lichii loader recognizes.

Cheat text uses `[Name]` headers followed by eight-digit hexadecimal words. A ZIP cheat must supply a `tag` that exactly matches a section name. Lichii writes only that section. The tag is optional for a raw cheat, but without one the file must contain exactly one nonempty section. This GitHub install path rejects duplicate names, master sections, and malformed words. Those checks do not prove that the selected cheat works on its own in the game.

## Find the add-on in Lichii

The store writes to `<mods-root>/<TITLE-ID>/<mod-id>/`. In a default profile the mods root is `load/`. Use the game's **Open Mod Data Location** action to find the configured title folder. The store puts GitHub patches in `exefs/<BUILD-ID>.pchtxt` or `exefs/<BUILD-ID>.ips`, and cheats in `cheats/<BUILD-ID-PREFIX>.txt`.

The extra `<mod-id>/` directory is Lichii's way to keep add-ons separate. It isn't part of the Atmosphère SD card layout. Lichii's loader looks inside each enabled add-on for the payload directories; it matches executable patches to the module being loaded. Use the [download integrity guide](/guides/integrity/) to decide when an install should stop or fall back to the source page.
