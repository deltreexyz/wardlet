# Wardlet

A stolen laptop shouldn't hand over your files.

Wardlet locks any file with the security key you already own. Tap the key to open it. Without the key, the file is unreadable. No password to invent, type, or forget.

## The problem

Laptops get stolen. Drives get copied. Backups get shared wider than you meant. And the files that matter most — SSH keys, tax records, scans of documents, private notes — are usually sitting there readable by anyone who gets the machine.

## How it works

1. Plug in your security key and run `wardlet init` once. Wardlet shows you a recovery code. Save it somewhere safe. It is shown once.
2. Name any file to lock it: `wardlet enc taxes.pdf`. The locked copy sits beside the original, and your files stay in their folders. Nothing is moved, mounted, or uploaded.
3. To open it later, plug in your key and tap it: `wardlet dec taxes.pdf.age`.

The vault is a small folder of keys Wardlet keeps for you. Copying that folder does not copy a way to open your files. Only your key, or the recovery code, can do that.

Good for: SSH keys, `.env` files, tax documents, password-manager exports, scans, and private notes.

Keys that work are listed at [wardlet.com/#devices](https://wardlet.com/#devices).

## The details

`wardlet new notes.txt` creates a locked file in your editor, and `wardlet edit notes.txt.age` opens one and locks it again when you quit. The editor is `$EDITOR` if set, otherwise nano, falling back to vi.

You can add more keys, so one lost key is not a disaster. `wardlet config` adds or removes keys, then saves the vault once when you quit and shows a new recovery code. After a change, export the vault and import it on every other computer. An older copy cannot open files locked after the change. The recovery code is not inside the export.

`wardlet status` prints the vault version without unlocking. Version 1 has never been updated after creation.

Under the hood, files are age ciphertext and keys are FIDO2. The source is here to audit.

## Install

Download `wardlet` and the udev rule from the
[latest release](https://github.com/deltreexyz/wardlet/releases), check the
SHA256 checksum, then:

```bash
install -m 755 wardlet ~/.local/bin/wardlet
sudo install -m 644 99-wardlet-fido2.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
```

Re-plug your key, then run `wardlet init`. Linux x86_64 with glibc 2.34 or
newer is needed.

## Build

Rust 1.95 or newer.

```bash
cargo test --workspace
cargo build --release
```

The binary is `target/release/wardlet`.

See [CHANGELOG.md](CHANGELOG.md) for releases, [SECURITY.md](SECURITY.md)
for the threat model and how to report a problem, and
[docs/manual-hardware-checklist.md](docs/manual-hardware-checklist.md) for
the hardware checks run before a release.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
