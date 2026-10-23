# Wardlet

Your key is the lock.

Wardlet locks files with the security key you already own. The locked copy sits next to the original, and nothing opens it without your key. No password, no account, no upload.

Free and open source. A command-line tool for Linux today, with a desktop app later that opens the same files.

## How it works

1. **Set up with your keys.** `wardlet init` adds your first security key and shows a recovery code once. Save it. Add more keys later so a lost key is not the end.
2. **Lock a file.** `wardlet enc taxes.pdf` writes a locked copy beside the original, in the same folder. You decide when to delete the original.
3. **Tap to open.** `wardlet dec taxes.pdf.age` — plug in the key and tap it. Without the key, the file can't be read.

Good for: SSH keys, `.env` files, tax documents, password-manager exports, scans, and private notes.

Keys that work are listed at [wardlet.com/#devices](https://wardlet.com/#devices).

## Why it's different

- **Your key, not a password.** Nothing to invent, type or forget. Works with YubiKey, Trezor and similar FIDO2 keys.
- **Files stay where they are.** No mounted drive, no container, no sync conflicts.
- **Several keys, one lock.** Any key you add opens the files. Adding a key doesn't rewrite them.
- **A recovery code, shown once.** The way back in if every key is lost. Wardlet keeps no copy.
- **Nothing leaves your machine.** No account, no cloud, no upload.
- **Open format, open source.** Files use the age format. The source is public, so you can audit the lock yourself.

## The details

`wardlet new notes.txt` creates a locked file in your editor, and `wardlet edit notes.txt.age` opens one and locks it again when you quit. The editor is `$EDITOR` if set, otherwise nano, falling back to vi.

`wardlet config` adds or removes keys, then saves the vault once when you quit and shows a new recovery code. After a change, export the vault and import it on every other computer. An older copy cannot open files locked after the change. The recovery code is not inside the export.

`wardlet status` prints the vault version without unlocking. Version 1 has never been updated after creation.

An existing locked file is not overwritten unless you pass `--force`.

## Install

Build from source today (a packaged GitHub release comes next):

```bash
cargo test --workspace
cargo build --release
install -m 755 target/release/wardlet ~/.local/bin/wardlet
sudo install -m 644 packaging/udev/99-wardlet-fido2.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
```

Re-plug your key, then run `wardlet init`. Linux x86_64 with glibc 2.34 or
newer is needed. Rust 1.95 or newer is needed to build.

When a release is published, you can also download the binary and udev rule
from [GitHub Releases](https://github.com/deltreexyz/wardlet/releases) and
check the SHA256 checksum instead of building.

See [CHANGELOG.md](CHANGELOG.md) for releases, [SECURITY.md](SECURITY.md)
for the threat model and how to report a problem, and
[docs/manual-hardware-checklist.md](docs/manual-hardware-checklist.md) for
the hardware checks run before a release.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
