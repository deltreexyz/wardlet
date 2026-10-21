use std::process::Command;

fn wardlet(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_wardlet"))
        .args(args)
        .output()
        .expect("run wardlet")
}

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut bytes = [0u8; 6];
        rand_bytes(&mut bytes);
        let suffix: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("wardlet-cli-{tag}-{suffix}"));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn rand_bytes(bytes: &mut [u8]) {
    // Tests do not need cryptographic randomness for directory names.
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (seed >> ((index % 8) * 8)) as u8;
    }
}

/// Seed a real vault with a fake hmac, as the core tests do. The binary
/// cannot unlock it without hardware, but every command that does not need
/// an unlock can run against it end to end.
fn seed_vault(dir: &std::path::Path) {
    let hmac = [0x55u8; 32];
    let params = wardlet_core::vault::HardwareMemberParams {
        credential_id: vec![1, 2, 3, 4],
        rp_id: "wardlet.com".into(),
        salt: [0x22u8; 32],
        public_key: vec![9, 9],
        key_product: "YubiKey".into(),
        label: "desk".into(),
    };
    wardlet_core::vault::init_hardware_vault(dir, "desk", &hmac, &params).unwrap();
}

#[test]
fn version_prints_the_package_version() {
    let output = wardlet(&["version"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout, format!("wardlet {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn debug_flag_logs_the_step_and_not_a_master_key() {
    let output = wardlet(&["--debug", "version"]);
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("debug: starting version"));
    assert!(!stderr.contains("AGE-SECRET-KEY"));
}

#[test]
fn help_lists_phase0_commands() {
    let output = wardlet(&["--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for name in [
        "init", "config", "enc", "dec", "edit", "new", "status", "keys", "recover", "export",
        "import", "version",
    ] {
        assert!(stdout.contains(name), "help missing {name}");
    }
    assert!(
        !stdout.contains("--passphrase"),
        "help still offers a passphrase"
    );
    assert!(stdout.contains("--debug"), "help missing --debug");
    assert!(
        !stdout.contains("including the master key"),
        "help still offers to print the master key"
    );
    assert!(stdout.contains("wardlet init"), "help missing init example");
    assert!(
        stdout.contains("First run"),
        "help missing the first-run hint"
    );
    assert!(
        stdout.contains("wardlet config"),
        "help missing config example"
    );
    assert!(
        stdout.contains("wardlet enc README.md"),
        "help missing enc example"
    );
    assert!(
        stdout.contains("wardlet dec README.md.age"),
        "help missing dec example"
    );
    assert!(
        stdout.contains("wardlet edit notes.txt.age"),
        "help missing edit example"
    );
    assert!(
        stdout.contains("wardlet new notes.txt"),
        "help missing new example"
    );
}

#[test]
fn keys_without_a_vault_exits_10() {
    let dir = std::env::temp_dir().join("wardlet-missing-vault-for-keys-test");
    let _ = std::fs::remove_dir_all(&dir);
    let output = wardlet(&["--dir", dir.to_str().expect("temp path is utf-8"), "keys"]);
    assert_eq!(output.status.code(), Some(10));
}

#[test]
fn enc_without_a_path_is_a_usage_error() {
    let output = wardlet(&["enc"]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn status_without_a_vault_exits_10() {
    let dir = std::env::temp_dir().join("wardlet-missing-vault-for-status-test");
    let _ = std::fs::remove_dir_all(&dir);
    let output = wardlet(&["--dir", dir.to_str().expect("temp path is utf-8"), "status"]);
    assert_eq!(output.status.code(), Some(10));
}

#[test]
fn status_and_keys_succeed_on_a_seeded_vault() {
    let dir = TempDir::new("seeded");
    let vault = dir.0.join("vault");
    seed_vault(&vault);
    let vault_arg = vault.to_str().unwrap().to_owned();

    let output = wardlet(&["--dir", &vault_arg, "status"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Version: 1"), "{stdout}");
    assert!(stdout.contains("Health: ok"), "{stdout}");

    let output = wardlet(&["--dir", &vault_arg, "keys"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("1 key."), "{stdout}");
    assert!(stdout.contains("fido2-hmac"), "{stdout}");
    assert!(stdout.contains("Names are sealed"), "{stdout}");
}

#[test]
fn export_import_round_trip_through_the_binary() {
    let dir = TempDir::new("roundtrip");
    let vault = dir.0.join("vault");
    seed_vault(&vault);
    let export = dir.0.join("vault.wardlet");
    let output = wardlet(&[
        "--dir",
        vault.to_str().unwrap(),
        "export",
        export.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let restored = dir.0.join("restored");
    let output = wardlet(&[
        "--dir",
        restored.to_str().unwrap(),
        "import",
        export.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = wardlet(&["--dir", restored.to_str().unwrap(), "keys"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("1 key."), "{stdout}");
}

#[test]
fn edit_refuses_a_foreign_age_file_before_any_unlock() {
    let dir = TempDir::new("edit-foreign");
    let vault = dir.0.join("vault");
    seed_vault(&vault);
    let foreign = dir.0.join("foreign.txt.age");
    std::fs::write(&foreign, b"age-encryption.org/v1\n-> X25519 abc\n").unwrap();
    let output = wardlet(&[
        "--dir",
        vault.to_str().unwrap(),
        "edit",
        foreign.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        format!("{stdout}{stderr}").contains("was not encrypted with a Wardlet vault"),
        "{stdout}{stderr}"
    );
}

#[test]
fn new_refuses_an_existing_file_before_any_unlock() {
    let dir = TempDir::new("new-existing");
    let vault = dir.0.join("vault");
    seed_vault(&vault);
    let existing = dir.0.join("notes.txt");
    std::fs::write(&existing, b"already here").unwrap();
    let output = wardlet(&[
        "--dir",
        vault.to_str().unwrap(),
        "new",
        existing.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        format!("{stdout}{stderr}").contains("already exists"),
        "{stdout}{stderr}"
    );
    assert_eq!(std::fs::read(&existing).unwrap(), b"already here");
}

#[test]
fn enc_without_a_vault_exits_10() {
    let dir = std::env::temp_dir().join("wardlet-missing-vault-for-enc-test");
    let _ = std::fs::remove_dir_all(&dir);
    let file = dir.join("note.txt");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(&file, b"secret").unwrap();
    let output = wardlet(&[
        "--dir",
        dir.join("vault").to_str().expect("temp path is utf-8"),
        "enc",
        file.to_str().expect("temp path is utf-8"),
    ]);
    assert_eq!(output.status.code(), Some(10));
    assert_eq!(std::fs::read(&file).unwrap(), b"secret");
    let _ = std::fs::remove_dir_all(&dir);
}
