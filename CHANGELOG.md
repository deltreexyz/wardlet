# Changelog

## 0.2.0

First public release.

- Renamed the product concept from “vault” to **keyring** (keys + recovery
  that unlock files in place). Default path is `~/.config/wardlet/keyring`,
  config field `keyring_id`, export marker `WARDLET-KEYRING`. Pre-release
  test installs under `…/vault` are not migrated—delete and run `init` again.
- Early Linux GUI (`wardlet-gui`) links the same core library as the CLI:
  set up a keyring, lock a file, open a locked file.
- Encrypt and decrypt files where they are (`wardlet enc`, `wardlet dec`),
  unlocked by a FIDO2 hardware key. No key file on disk.
- `wardlet init` creates a keyring and shows one recovery code, once.
- `wardlet config` adds and removes keys in one visit; the keyring is saved
  once when you quit, and older files keep opening with the keys that remain.
- `wardlet edit` and `wardlet new` open a file in your editor and encrypt it
  again when you quit.
- `wardlet export` / `wardlet import` move the keyring between computers as a
  single file. The recovery code is never inside the export.
- `wardlet status` and `wardlet keys` report keyring health without unlocking.
- Safety pass: corrupt wrappers and label files no longer block unlock,
  recovery codes are typed without echo, deletions and recovery-code
  confirmations default to No, and large files are streamed instead of
  loaded into memory.
