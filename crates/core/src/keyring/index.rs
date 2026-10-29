//! Local index of locked file paths, sealed to the master.
//!
//! Host-specific: skipped on export/import. Used to find files locked months ago.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::x25519::{Identity, Recipient};
use age::{Decryptor, Encryptor};
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::master::Master;
use crate::keyring::{sync_dir, write_atomic};
use crate::keyring::format;

pub const FILE_NAME: &str = "index.age";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexEntry {
    pub path: String,
    pub version: u32,
    pub locked_at: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct IndexBook {
    entries: Vec<IndexEntry>,
}

pub fn load(dir: &Path, master: &Master) -> Result<Vec<IndexEntry>, Error> {
    let path = dir.join(FILE_NAME);
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(&path).map_err(Error::io)?;
    let plain = decrypt(master, &bytes)?;
    let book: IndexBook = serde_json::from_str(&plain)
        .map_err(|_| Error::InvalidConfig("the sealed file index is not valid".into()))?;
    Ok(book.entries)
}

pub fn save(dir: &Path, master: &Master, entries: &[IndexEntry]) -> Result<(), Error> {
    let book = IndexBook {
        entries: entries.to_vec(),
    };
    let text = serde_json::to_string(&book).map_err(|err| Error::Other(err.to_string()))?;
    let sealed = encrypt(master, text.as_bytes())?;
    write_atomic(&dir.join(FILE_NAME), &sealed)?;
    sync_dir(dir)
}

/// Record or refresh a locked ciphertext path. Newest first.
pub fn upsert(
    dir: &Path,
    master: &Master,
    ciphertext: &Path,
    version: u32,
) -> Result<(), Error> {
    let absolute = absolute_path(ciphertext)?;
    let mut entries = load(dir, master)?;
    entries.retain(|entry| entry.path != absolute);
    entries.insert(
        0,
        IndexEntry {
            path: absolute,
            version,
            locked_at: format::utc_now(),
        },
    );
    save(dir, master, &entries)
}

pub fn upsert_many(
    dir: &Path,
    master: &Master,
    ciphertexts: &[PathBuf],
    version: u32,
) -> Result<(), Error> {
    if ciphertexts.is_empty() {
        return Ok(());
    }
    let mut entries = load(dir, master)?;
    let locked_at = format::utc_now();
    for ciphertext in ciphertexts.iter().rev() {
        let absolute = absolute_path(ciphertext)?;
        entries.retain(|entry| entry.path != absolute);
        entries.insert(
            0,
            IndexEntry {
                path: absolute,
                version,
                locked_at: locked_at.clone(),
            },
        );
    }
    save(dir, master, &entries)
}

/// Drop entries whose files are missing. Returns how many were removed.
pub fn prune(dir: &Path, master: &Master) -> Result<(Vec<IndexEntry>, usize), Error> {
    let entries = load(dir, master)?;
    let before = entries.len();
    let kept: Vec<_> = entries
        .into_iter()
        .filter(|entry| Path::new(&entry.path).is_file())
        .collect();
    let removed = before - kept.len();
    if removed > 0 {
        save(dir, master, &kept)?;
    }
    Ok((kept, removed))
}

fn absolute_path(path: &Path) -> Result<String, Error> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(Error::io)?
            .join(path)
    };
    absolute
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::Other(format!("{} is not valid UTF-8", path.display())))
}

fn encrypt(master: &Master, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let recipient = Recipient::from_str(&master.recipient())
        .map_err(|_| Error::InvalidConfig("master recipient does not parse".into()))?;
    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .expect("a single recipient is valid");
    let mut output = Vec::new();
    let mut writer = encryptor.wrap_output(&mut output).map_err(Error::io)?;
    writer.write_all(plaintext).map_err(Error::io)?;
    writer.finish().map_err(Error::io)?;
    Ok(output)
}

fn decrypt(master: &Master, ciphertext: &[u8]) -> Result<String, Error> {
    let identity = Identity::from_str(master.expose_secret())
        .map_err(|_| Error::InvalidConfig("master recipient does not parse".into()))?;
    let decryptor = Decryptor::new(ciphertext).map_err(Error::io)?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| Error::Other("the sealed file index cannot be opened".into()))?;
    let mut plain = String::new();
    reader.read_to_string(&mut plain).map_err(Error::io)?;
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::init_hardware_keyring;
    use crate::keyring::members::HardwareMemberParams;
    use std::fs;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let mut bytes = [0u8; 8];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            let name: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = std::env::temp_dir().join(format!("wardlet-index-{name}"));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn params() -> HardwareMemberParams {
        HardwareMemberParams {
            credential_id: vec![1, 2, 3],
            rp_id: "wardlet.com".into(),
            salt: [9u8; 32],
            public_key: vec![4, 5],
            key_product: "YubiKey".into(),
            label: "desk".into(),
        }
    }

    #[test]
    fn upsert_updates_the_same_path_and_prune_drops_missing() {
        let dir = TempDir::new();
        let keyring = dir.0.join("keyring");
        let hmac = [0x44u8; 32];
        let created = init_hardware_keyring(&keyring, "desk", &hmac, &params()).unwrap();
        let locked = dir.0.join("secret.age");
        fs::write(&locked, b"age").unwrap();

        upsert(&keyring, &created.master, &locked, 1).unwrap();
        upsert(&keyring, &created.master, &locked, 2).unwrap();
        let entries = load(&keyring, &created.master).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].version, 2);

        fs::remove_file(&locked).unwrap();
        let (kept, removed) = prune(&keyring, &created.master).unwrap();
        assert_eq!(removed, 1);
        assert!(kept.is_empty());
    }
}
