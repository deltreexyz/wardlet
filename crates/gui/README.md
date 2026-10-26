# wardlet-gui

Linux desktop front-end for Wardlet. Links `wardlet-core` directly (same vault
directory and `.age` files as the CLI). It does not shell out to `wardlet`.

Built with egui so it compiles without system GTK development headers. The
product architecture matches the planned GTK app: FIDO/PIN in the GUI, crypto
and vault logic in core.

```bash
cargo run -p wardlet-gui
# or
cargo build --release -p wardlet-gui
install -m 755 target/release/wardlet-gui ~/.local/bin/wardlet-gui
```

MVP: set up a vault, lock a file, open a locked file. Key management beyond
first enrollment still uses `wardlet config` on the CLI.
