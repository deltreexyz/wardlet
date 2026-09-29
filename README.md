# Wardlet

Encrypt files where they are. A FIDO2-compatible key unlocks them.

Wardlet is a Linux command. It does not mount a drive, and it does not collect files into a container. The vault is a directory of keys. Your files stay where they are.

Supported devices are listed at [wardlet.com/#devices](https://wardlet.com/#devices).

## Status

This is early. Creating a vault, enrolling and removing keys, and a recovery code work. Encrypting and decrypting files does not, yet.

Removing a key deletes that key from this vault. An older copy of the vault still opens with the removed key.

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
