//! Labels and device names, sealed to the master.
//!
//! `config.toml` keeps the credential material needed to unlock. It does not
//! keep the words a person would use to recognize a YubiKey or a Trezor.
//! Those words live in `names.age`, which opens only after the master is unwrapped.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;

use age::x25519::{Identity, Recipient};
use age::{Decryptor, Encryptor};
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::master::Master;
use crate::vault::format::{self, Config};
use crate::vault::{sync_dir, write_atomic};

const FILE_NAME: &str = "names.age";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredName {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub key_product: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct NameBook {
    members: Vec<StoredName>,
}

pub fn load(dir: &Path, master: &Master) -> Result<Vec<StoredName>, Error> {
    let path = dir.join(FILE_NAME);
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(&path).map_err(Error::io)?;
    let plain = decrypt(master, &bytes)?;
    let book: NameBook = toml::from_str(&plain)
        .map_err(|_| Error::InvalidConfig("the sealed labels are not valid".into()))?;
    Ok(book.members)
}

pub fn save(dir: &Path, master: &Master, members: &[StoredName]) -> Result<(), Error> {
    let book = NameBook {
        members: members.to_vec(),
    };
    let text = toml::to_string(&book).map_err(|err| Error::Other(err.to_string()))?;
    let sealed = encrypt(master, text.as_bytes())?;
    write_atomic(&dir.join(FILE_NAME), &sealed)?;
    sync_dir(dir)
}

/// Move any label or device name still sitting in `config.toml` into `names.age`.
pub fn absorb_plaintext(dir: &Path, master: &Master) -> Result<(), Error> {
    let mut config = load_config(dir)?;
    let mut changed = false;
    let mut members = load(dir, master)?;
    for key in &mut config.keys {
        if key.mechanism == "recovery" {
            continue;
        }
        if key.label.is_empty() && key.key_product.is_empty() {
            continue;
        }
        if let Some(existing) = members.iter_mut().find(|member| member.id == key.id) {
            if !key.label.is_empty() {
                existing.label = key.label.clone();
            }
            if !key.key_product.is_empty() {
                existing.key_product = key.key_product.clone();
            }
        } else {
            members.push(StoredName {
                id: key.id.clone(),
                label: key.label.clone(),
                key_product: key.key_product.clone(),
            });
        }
        key.label.clear();
        key.key_product.clear();
        changed = true;
    }
    if !changed {
        return Ok(());
    }
    save(dir, master, &members)?;
    save_config(dir, &config)
}

fn load_config(dir: &Path) -> Result<Config, Error> {
    let path = dir.join("config.toml");
    if !path.is_file() {
        return Err(Error::VaultNotFound);
    }
    let text = fs::read_to_string(path).map_err(Error::io)?;
    format::load_config(&text)
}

fn save_config(dir: &Path, config: &Config) -> Result<(), Error> {
    let text = config.to_toml()?;
    write_atomic(&dir.join("config.toml"), text.as_bytes())?;
    sync_dir(dir)
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
    let identity =
        Identity::from_str(master.expose_secret()).map_err(|_| Error::CorruptRecovery)?;
    let decryptor = Decryptor::new(ciphertext)
        .map_err(|_| Error::InvalidConfig("the sealed labels are not an age file".into()))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| Error::WrongPassphrase)?;
    let mut plain = String::new();
    reader.read_to_string(&mut plain).map_err(Error::io)?;
    Ok(plain)
}
