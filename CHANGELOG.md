# Changelog

## 0.2.0

First public release.

- Encrypt and decrypt files where they are (`wardlet enc`, `wardlet dec`),
  unlocked by a FIDO2 hardware key. No key file on disk.
- `wardlet init` creates a vault and shows one recovery code, once.
- `wardlet config` adds and removes keys in one visit; the vault is saved
  once when you quit, and older files keep opening with the keys that remain.
- `wardlet edit` and `wardlet new` open a file in your editor and encrypt it
  again when you quit.
- `wardlet export` / `wardlet import` move the vault between computers as a
  single file. The recovery code is never inside the export.
- `wardlet status` and `wardlet keys` report vault health without unlocking.
- Safety pass: corrupt wrappers and label files no longer block unlock,
  recovery codes are typed without echo, deletions and recovery-code
  confirmations default to No, and large files are streamed instead of
  loaded into memory.
