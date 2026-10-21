use std::process::Command;

fn wardlet(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_wardlet"))
        .args(args)
        .output()
        .expect("run wardlet")
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
