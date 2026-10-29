//! One-file copy of a keyring directory.
//!
//! The container is not an archive tool's format. Wardlet is the only reader,
//! so the same bytes import on Linux, macOS, and Windows.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

use crate::Error;
use crate::keyring::{create_private_dir, load_config, sync_dir};

const MARKER: &str = "WARDLET-KEYRING";
const CONTAINER_VERSION: u32 = 1;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

pub fn export_keyring(dir: &Path, destination: &Path) -> Result<(), Error> {
    if !dir.join("config.toml").is_file() {
        return Err(Error::KeyringNotFound);
    }
    if destination.exists() {
        return Err(Error::Other(format!(
            "{} already exists",
            destination.display()
        )));
    }
    let entries = list_entries(dir)?;
    if let Some(parent) = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(Error::io)?;
    }
    let mut file = create_private_output(destination)?;
    writeln!(file, "{MARKER} {CONTAINER_VERSION}").map_err(Error::io)?;
    for relative in entries {
        let bytes = fs::read(dir.join(&relative)).map_err(Error::io)?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            let _ = fs::remove_file(destination);
            return Err(Error::Other(format!("{relative} is too large to export")));
        }
        writeln!(file, "{relative}").map_err(Error::io)?;
        writeln!(file, "{}", bytes.len()).map_err(Error::io)?;
        file.write_all(&bytes).map_err(Error::io)?;
    }
    file.sync_all().map_err(Error::io)?;
    sync_dir(output_directory(destination))?;
    Ok(())
}

/// A bare file name such as `keyring.wardlet` has an empty parent. Sync `.` instead.
fn output_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

pub fn import_keyring(file: &Path, destination: &Path) -> Result<(), Error> {
    if destination.join("config.toml").exists() {
        return Err(Error::KeyringExists);
    }
    let mut reader = BufReader::new(File::open(file).map_err(Error::io)?);
    let mut header = String::new();
    reader.read_line(&mut header).map_err(Error::io)?;
    if header.trim_end() != format!("{MARKER} {CONTAINER_VERSION}") {
        return Err(Error::Other(
            "this file is not a Wardlet keyring export".into(),
        ));
    }
    let mut stored = Vec::new();
    loop {
        let mut path_line = String::new();
        let read = reader.read_line(&mut path_line).map_err(Error::io)?;
        if read == 0 {
            break;
        }
        let relative = path_line.trim_end();
        if relative.is_empty() {
            continue;
        }
        if !allowed_path(relative) {
            return Err(Error::Other(format!("refusing keyring entry {relative}")));
        }
        if stored.iter().any(|(path, _)| path == relative) {
            return Err(Error::Other(format!("keyring export lists {relative} twice")));
        }
        let mut length_line = String::new();
        if reader.read_line(&mut length_line).map_err(Error::io)? == 0 {
            return Err(Error::Other("keyring export ended early".into()));
        }
        let length: u64 = length_line
            .trim_end()
            .parse()
            .map_err(|_| Error::Other(format!("keyring entry {relative} has a bad length")))?;
        if length > MAX_FILE_BYTES {
            return Err(Error::Other(format!("{relative} is too large to import")));
        }
        let mut bytes = vec![0u8; length as usize];
        reader.read_exact(&mut bytes).map_err(Error::io)?;
        stored.push((relative.to_owned(), bytes));
    }
    let Some((_, config_bytes)) = stored.iter().find(|(path, _)| path == "config.toml") else {
        return Err(Error::Other("keyring export is missing config.toml".into()));
    };
    let config_text = String::from_utf8(config_bytes.clone())
        .map_err(|_| Error::InvalidConfig("config.toml is not UTF-8".into()))?;
    let config = load_config(&config_text)?;
    let present: std::collections::HashSet<&str> =
        stored.iter().map(|(path, _)| path.as_str()).collect();
    let mut required: Vec<String> = config
        .keys
        .iter()
        .map(|key| {
            if key.mechanism == "recovery" {
                format!("keys/{}.age", key.id)
            } else {
                format!("keys/{}.mask", key.id)
            }
        })
        .collect();
    for generation in &config.generations {
        required.push(format!("epochs/{}.age", generation.epoch));
    }
    for relative in &required {
        if !present.contains(relative.as_str()) {
            return Err(Error::Other(format!(
                "keyring export is missing {relative}, which config.toml names"
            )));
        }
    }
    ensure_private_dir(destination)?;
    for (relative, bytes) in &stored {
        let path = destination.join(relative);
        if let Some(parent) = path.parent() {
            ensure_private_dir(parent)?;
        }
        write_private(&path, bytes)?;
    }
    sync_dir(destination)?;
    Ok(())
}

pub fn copy_keyring(source: &Path, destination: &Path) -> Result<(), Error> {
    if destination.exists() {
        return Err(Error::Other(format!(
            "{} already exists",
            destination.display()
        )));
    }
    ensure_private_dir(destination)?;
    for relative in list_entries(source)? {
        let from = source.join(&relative);
        let to = destination.join(&relative);
        if let Some(parent) = to.parent() {
            ensure_private_dir(parent)?;
        }
        let bytes = fs::read(from).map_err(Error::io)?;
        write_private(&to, &bytes)?;
    }
    sync_dir(destination)
}

fn list_entries(dir: &Path) -> Result<Vec<String>, Error> {
    let mut found = Vec::new();
    walk(dir, dir, &mut found)?;
    found.sort();
    Ok(found)
}

fn walk(root: &Path, dir: &Path, found: &mut Vec<String>) -> Result<(), Error> {
    let entries = fs::read_dir(dir).map_err(Error::io)?;
    for entry in entries {
        let entry = entry.map_err(Error::io)?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(Error::io)?;
        if meta.file_type().is_symlink() {
            return Err(Error::Other(format!(
                "refusing to follow symlink {}",
                path.display()
            )));
        }
        if meta.is_dir() {
            walk(root, &path, found)?;
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| Error::InvalidConfig("entry path is not valid UTF-8".into()))?
            .to_str()
            .ok_or_else(|| Error::Other(format!("{} has no file name", path.display())))?;
        if local_only_path(relative) {
            continue;
        }
        if allowed_path(relative) {
            found.push(relative.to_owned());
        } else {
            return Err(Error::Other(format!(
                "refusing to export: {relative} is in the keyring but Wardlet does not recognize it"
            )));
        }
    }
    Ok(())
}

/// Host-local files that must not travel with export/import.
fn local_only_path(path: &str) -> bool {
    path == crate::keyring::index::FILE_NAME
}

fn allowed_path(path: &str) -> bool {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path
            .split(['/', '\\'])
            .any(|part| part == ".." || part == ".")
    {
        return false;
    }
    if path == "config.toml" || path == "names.age" {
        return true;
    }
    if let Some(name) = path.strip_prefix("keys/") {
        return member_file(name);
    }
    if let Some(name) = path.strip_prefix("epochs/") {
        return epoch_file(name);
    }
    false
}

fn member_file(name: &str) -> bool {
    let Some((id, ext)) = name.rsplit_once('.') else {
        return false;
    };
    (ext == "age" || ext == "mask")
        && !id.contains('/')
        && id.len() == 32
        && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn epoch_file(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".age") else {
        return false;
    };
    if stem.is_empty() || stem.contains('/') {
        return false;
    }
    let digits = stem.strip_prefix("recovery-").unwrap_or(stem);
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

fn ensure_private_dir(path: &Path) -> Result<(), Error> {
    if path.is_dir() {
        return Ok(());
    }
    create_private_dir(path)
}

fn create_private_output(path: &Path) -> Result<File, Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(Error::io)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(Error::io)?;
    file.write_all(bytes).map_err(Error::io)?;
    file.sync_all().map_err(Error::io)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{allowed_path, export_keyring, import_keyring, output_directory};
    use crate::keyring::init_hardware_keyring;
    use crate::keyring::members::HardwareMemberParams;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let mut bytes = [0u8; 8];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            let name: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = std::env::temp_dir().join(format!("wardlet-bundle-{name}"));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sample_keyring(dir: &std::path::Path) {
        let hmac = [0x11u8; 32];
        let params = HardwareMemberParams {
            credential_id: vec![1, 2, 3, 4],
            rp_id: "wardlet.com".into(),
            salt: [0x22u8; 32],
            public_key: vec![9, 9],
            key_product: "YubiKey".into(),
            label: "desk".into(),
        };
        init_hardware_keyring(dir, "desk", &hmac, &params).unwrap();
    }

    #[test]
    fn export_then_import_round_trips_the_keyring() {
        let dir = TempDir::new();
        let source = dir.0.join("keyring");
        sample_keyring(&source);
        let file = dir.0.join("keyring.wardlet");
        export_keyring(&source, &file).unwrap();
        let restored = dir.0.join("restored");
        import_keyring(&file, &restored).unwrap();
        let original = fs::read(source.join("config.toml")).unwrap();
        let copied = fs::read(restored.join("config.toml")).unwrap();
        assert_eq!(original, copied);
        assert!(restored.join("names.age").is_file());
        assert!(restored.join("keys").read_dir().unwrap().next().is_some());
    }

    #[test]
    fn export_skips_the_local_file_index() {
        let dir = TempDir::new();
        let source = dir.0.join("keyring");
        sample_keyring(&source);
        fs::write(source.join(crate::keyring::index::FILE_NAME), b"sealed").unwrap();
        let file = dir.0.join("keyring.wardlet");
        export_keyring(&source, &file).unwrap();
        let restored = dir.0.join("restored");
        import_keyring(&file, &restored).unwrap();
        assert!(!restored.join(crate::keyring::index::FILE_NAME).exists());
        assert!(restored.join("config.toml").is_file());
    }

    #[test]
    fn import_refuses_an_existing_keyring_and_a_bad_file() {
        let dir = TempDir::new();
        let source = dir.0.join("keyring");
        sample_keyring(&source);
        let file = dir.0.join("keyring.wardlet");
        export_keyring(&source, &file).unwrap();
        let err = import_keyring(&file, &source).unwrap_err();
        assert!(matches!(err, crate::Error::KeyringExists));

        let junk = dir.0.join("notes.txt");
        fs::write(&junk, b"hello").unwrap();
        let err = import_keyring(&junk, &dir.0.join("other")).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("not a Wardlet keyring export"));
    }

    #[test]
    fn export_refuses_a_stray_file_and_import_refuses_a_missing_wrapper() {
        let dir = TempDir::new();
        let source = dir.0.join("keyring");
        sample_keyring(&source);
        fs::write(source.join("stray.txt"), b"what is this").unwrap();
        let err = export_keyring(&source, &dir.0.join("out.wardlet")).unwrap_err();
        assert!(err.to_string().contains("stray.txt"), "{err}");
        fs::remove_file(source.join("stray.txt")).unwrap();

        // Export, then hand-build a bundle missing the recovery wrapper.
        let file = dir.0.join("keyring.wardlet");
        export_keyring(&source, &file).unwrap();
        let restored = dir.0.join("restored");
        import_keyring(&file, &restored).unwrap();
        let recovery = restored
            .join("keys")
            .read_dir()
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .find(|path| path.extension().is_some_and(|ext| ext == "age"))
            .unwrap();
        fs::remove_file(&recovery).unwrap();
        let broken = dir.0.join("broken.wardlet");
        export_keyring(&restored, &broken).unwrap();
        let err = import_keyring(&broken, &dir.0.join("again")).unwrap_err();
        assert!(err.to_string().contains("missing keys/"), "{err}");
        assert!(!dir.0.join("again").exists());
    }

    #[test]
    fn a_bare_filename_exports_into_the_current_directory() {
        assert_eq!(
            output_directory(std::path::Path::new("keyring.wardlet")),
            std::path::Path::new(".")
        );
        assert_eq!(
            output_directory(std::path::Path::new("out/keyring.wardlet")),
            std::path::Path::new("out")
        );
    }

    #[test]
    fn a_path_that_escapes_the_directory_is_refused() {
        assert!(!allowed_path("../config.toml"));
        assert!(!allowed_path("/etc/passwd"));
        assert!(!allowed_path("keys/../../config.toml"));
        assert!(allowed_path("config.toml"));
        assert!(allowed_path("keys/0123456789abcdef0123456789abcdef.mask"));
        assert!(allowed_path("epochs/1.age"));
        assert!(allowed_path("epochs/recovery-1.age"));
        assert!(!allowed_path("epochs/notes.age"));
    }
}
