# Wardlet

Encrypt files where they are. A FIDO2-compatible key unlocks them.

Wardlet is a Linux command. It does not mount a drive, and it does not collect files into a container. The vault is a directory of keys. Your files stay where they are.

Supported devices are listed at [wardlet.com/#devices](https://wardlet.com/#devices).

## Status

This is early.

`wardlet init` creates the vault, enrolls the FIDO2 keys you add, and shows a recovery code once. `wardlet enc` and `wardlet dec` encrypt and decrypt the files you name. `wardlet new` creates a vault file in your editor. `wardlet edit` opens an existing one and encrypts it again when you quit. The editor is `$EDITOR` if set, otherwise nano, falling back to vi. Ciphertext is an `.age` file beside the source. There is no file catalog.

`wardlet config` adds or removes keys, then saves the vault once when you quit and shows a new recovery code. Export that vault and import it on every other computer. An older copy cannot open files encrypted after the change. The recovery code is not inside the export.

`wardlet status` prints the vault version without unlocking. Version 1 has never been updated after creation.

## Build

Rust 1.85 or newer.

```bash
cargo test --workspace
cargo build --release
```

The binary is `target/release/wardlet`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
