//! Passphrase and hardware members. Each one is a separate wrap of the master.
//!
//! age allows only one passphrase stanza per file, so a second user is a
//! second file. Hardware users use `keys/<id>.mask` (x25519 to a recipient
//! derived from FIDO2 hmac-secret).

use std::fs;
use std::path::{Path, PathBuf};

use age::secrecy::{ExposeSecret, SecretString};
use rand::RngCore;

use crate::Error;
use crate::crypto::passphrase;
use crate::crypto::recovery_code;
use crate::master::Master;
use crate::vault::format::{self, Config, KeyEntry};
use crate::vault::keys;
use crate::vault::{create_private_dir, sync_dir, write_atomic};

pub const FIDO2_MECHANISM: &str = "fido2-hmac";
pub const RECOVERY_MECHANISM: &str = "recovery";
pub const DEFAULT_RP_ID: &str = "wardlet.com";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberInfo {
    pub id: String,
    pub label: String,
    pub mechanism: String,
    pub key_product: String,
    pub last_used: String,
}

/// Persisted FIDO2 fields needed to call `get_hmac_secret` again.
#[derive(Debug, Clone)]
pub struct HardwareMemberParams {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub salt: [u8; 32],
    pub public_key: Vec<u8>,
    /// HID product string, such as "YubiKey OTP+FIDO+CCID" or "TREZOR".
    pub key_product: String,
    pub label: String,
}

pub fn list_members(dir: &Path) -> Result<Vec<MemberInfo>, Error> {
    let config = load_config_file(dir)?;
    Ok(config
        .keys
        .iter()
        .filter(|key| key.mechanism != RECOVERY_MECHANISM)
        .map(MemberInfo::from)
        .collect())
}

pub fn recovery_replacement_due(dir: &Path) -> Result<bool, Error> {
    Ok(load_config_file(dir)?.recovery_replacement_due)
}

pub fn add_passphrase_member(
    dir: &Path,
    existing_passphrase: &str,
    label: &str,
    new_passphrase: &str,
) -> Result<MemberInfo, Error> {
    let master = unlock_with_passphrase(dir, existing_passphrase)?;
    add_passphrase_member_unlocked(dir, &master, label, new_passphrase)
}

pub fn add_passphrase_member_unlocked(
    dir: &Path,
    master: &Master,
    label: &str,
    new_passphrase: &str,
) -> Result<MemberInfo, Error> {
    let label = normalize_label(label)?;
    if new_passphrase.is_empty() {
        return Err(Error::PassphraseRequired);
    }
    let mut config = load_config_file(dir)?;
    if config.keys.iter().any(|key| key.label == label) {
        return Err(Error::DuplicateLabel(label));
    }

    let new_passphrase = SecretString::from(new_passphrase.to_owned());
    let id = random_member_id();
    let wrapped = seal_member(master, &new_passphrase)?;

    let path = member_age_path(dir, &id)?;
    write_atomic(&path, &wrapped)?;
    config
        .keys
        .push(KeyEntry::passphrase(id.clone(), label.clone()));
    if let Err(err) = save_config(dir, &config) {
        let _ = fs::remove_file(&path);
        return Err(err);
    }
    Ok(MemberInfo::from(config.keys.last().expect("just pushed")))
}

pub fn add_hardware_member_unlocked(
    dir: &Path,
    master: &Master,
    label: &str,
    hmac: &[u8; 32],
    params: &HardwareMemberParams,
) -> Result<MemberInfo, Error> {
    let label = normalize_label(label)?;
    let mut config = load_config_file(dir)?;
    if config.keys.iter().any(|key| key.label == label) {
        return Err(Error::DuplicateLabel(label));
    }

    let card = keys::identity_from_hmac(hmac)?;
    let card_recipient = card.recipient();
    let wrapped = keys::seal_mask(master, &card_recipient)?;
    drop(card);

    let id = random_member_id();
    let path = member_mask_path(dir, &id)?;
    write_atomic(&path, &wrapped)?;
    config.keys.push(KeyEntry::fido2_hmac(
        id.clone(),
        label.clone(),
        card_recipient,
        bytes_to_hex(&params.credential_id),
        params.rp_id.clone(),
        bytes_to_hex(&params.salt),
        bytes_to_hex(&params.public_key),
        params.key_product.clone(),
    ));
    if let Err(err) = save_config(dir, &config) {
        let _ = fs::remove_file(&path);
        return Err(err);
    }
    Ok(MemberInfo::from(config.keys.last().expect("just pushed")))
}

pub fn remove_member(dir: &Path, passphrase: &str, label_or_id: &str) -> Result<(), Error> {
    let master = unlock_with_passphrase(dir, passphrase)?;
    remove_member_unlocked(dir, &master, label_or_id)
}

pub fn remove_member_unlocked(
    dir: &Path,
    _master: &Master,
    label_or_id: &str,
) -> Result<(), Error> {
    let mut config = load_config_file(dir)?;
    let access_keys = config
        .keys
        .iter()
        .filter(|key| key.mechanism != RECOVERY_MECHANISM)
        .count();
    if access_keys <= 1 {
        return Err(Error::LastMember);
    }
    let name = label_or_id.trim();
    let index = config
        .keys
        .iter()
        .position(|key| key.label == name || key.id == name)
        .ok_or_else(|| Error::UnknownMember(name.to_owned()))?;
    if config.keys[index].mechanism == RECOVERY_MECHANISM {
        return Err(Error::Other(
            "the recovery code is replaced after you add a hardware key, not from this menu".into(),
        ));
    }

    let removed = config.keys.remove(index);
    save_config(dir, &config)?;
    let path = member_wrapper_path(dir, &removed)?;
    fs::remove_file(path).map_err(Error::io)?;
    Ok(())
}

pub fn unlock_with_passphrase(dir: &Path, passphrase: &str) -> Result<Master, Error> {
    if passphrase.is_empty() {
        return Err(Error::PassphraseRequired);
    }
    let config = load_config_file(dir)?;
    let passphrase = SecretString::from(passphrase.to_owned());
    unlock_passphrase_keys(dir, &config, &passphrase)
}

/// Open a hardware member's `.mask` using hmac-secret output.
pub fn unlock_with_hmac(dir: &Path, hmac: &[u8; 32]) -> Result<Master, Error> {
    let config = load_config_file(dir)?;
    let card = keys::identity_from_hmac(hmac)?;
    let mut saw_hardware = false;
    for key in &config.keys {
        if key.mechanism != FIDO2_MECHANISM {
            continue;
        }
        saw_hardware = true;
        let path = member_mask_path(dir, &key.id)?;
        let bytes = fs::read(&path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                Error::Other(format!("missing wrapper for user {}", key.label))
            } else {
                Error::io(err)
            }
        })?;
        match keys::open_mask(&bytes, &card) {
            Ok(master) => {
                mark_member_used(dir, &key.id)?;
                return Ok(master);
            }
            Err(Error::WrongPassphrase) => continue,
            Err(err) => return Err(err),
        }
    }
    if saw_hardware {
        Err(Error::WrongPassphrase)
    } else {
        Err(Error::Other("vault has no hardware user".into()))
    }
}

pub(crate) fn write_first_member(
    dir: &Path,
    label: &str,
    passphrase: &SecretString,
) -> Result<(String, KeyEntry, String), Error> {
    let label = normalize_label(label)?;
    create_private_dir(dir)?;
    create_private_dir(&dir.join("keys"))?;

    let master = Master::generate();
    let recipient = master.recipient();
    let debug_secret = master.expose_secret().to_owned();
    let id = random_member_id();
    let wrapped = seal_member(&master, passphrase)?;
    drop(master);

    write_atomic(&member_age_path(dir, &id)?, &wrapped)?;
    Ok((recipient, KeyEntry::passphrase(id, label), debug_secret))
}

pub(crate) fn write_first_hardware_member(
    dir: &Path,
    label: &str,
    hmac: &[u8; 32],
    params: &HardwareMemberParams,
) -> Result<(String, KeyEntry, String, KeyEntry, String), Error> {
    let label = normalize_label(label)?;
    create_private_dir(dir)?;
    create_private_dir(&dir.join("keys"))?;

    let master = Master::generate();
    let recipient = master.recipient();
    let debug_secret = master.expose_secret().to_owned();

    let card = keys::identity_from_hmac(hmac)?;
    let card_recipient = card.recipient();
    let wrapped = keys::seal_mask(&master, &card_recipient)?;
    drop(card);
    let (recovery_entry, recovery_code) = issue_recovery_member(dir, &master)?;
    drop(master);

    let id = random_member_id();
    write_atomic(&member_mask_path(dir, &id)?, &wrapped)?;
    let entry = KeyEntry::fido2_hmac(
        id,
        label,
        card_recipient,
        bytes_to_hex(&params.credential_id),
        params.rp_id.clone(),
        bytes_to_hex(&params.salt),
        bytes_to_hex(&params.public_key),
        params.key_product.clone(),
    );
    Ok((
        recipient,
        entry,
        debug_secret,
        recovery_entry,
        recovery_code,
    ))
}

/// Seal a new recovery wrapper in memory. The caller stores it only after
/// the person confirms they wrote the code down.
pub fn stage_recovery_wrapper(master: &Master) -> Result<(String, Vec<u8>), Error> {
    let code = recovery_code::generate();
    let bytes = seal_recovery_wrapper(master, code.canonical.expose_secret())?;
    Ok((code.display, bytes))
}

pub fn unlock_with_recovery_code(dir: &Path, typed: &str) -> Result<Master, Error> {
    let canonical = recovery_code::normalize(typed);
    if canonical.len() != 32 {
        return Err(Error::WrongPassphrase);
    }
    let mut config = load_config_file(dir)?;
    let secret = SecretString::from(canonical);
    let ids: Vec<String> = config
        .keys
        .iter()
        .filter(|key| key.mechanism == RECOVERY_MECHANISM)
        .map(|key| key.id.clone())
        .collect();
    for id in ids {
        let path = member_age_path(dir, &id)?;
        let bytes = fs::read(&path).map_err(Error::io)?;
        match passphrase::open_recovery(&bytes, &secret) {
            Ok(master) => {
                config.recovery_replacement_due = true;
                if let Some(entry) = config.keys.iter_mut().find(|entry| entry.id == id) {
                    entry.last_used = format::utc_now();
                }
                save_config(dir, &config)?;
                return Ok(master);
            }
            Err(Error::WrongPassphrase) => continue,
            Err(err) => return Err(err),
        }
    }
    Err(Error::WrongPassphrase)
}

/// Replace every recovery wrapper in this directory with `ciphertext`.
pub fn commit_recovery_wrapper(dir: &Path, ciphertext: &[u8]) -> Result<(), Error> {
    let mut config = load_config_file(dir)?;
    let old: Vec<_> = config
        .keys
        .iter()
        .filter(|key| key.mechanism == RECOVERY_MECHANISM)
        .map(|key| key.id.clone())
        .collect();
    config
        .keys
        .retain(|key| key.mechanism != RECOVERY_MECHANISM);
    let entry = KeyEntry::recovery(random_member_id());
    write_atomic(&member_age_path(dir, &entry.id)?, ciphertext)?;
    config.keys.push(entry);
    config.recovery_replacement_due = false;
    save_config(dir, &config)?;
    for id in old {
        let path = member_age_path(dir, &id)?;
        if path.is_file() {
            fs::remove_file(path).map_err(Error::io)?;
        }
    }
    Ok(())
}

fn issue_recovery_member(dir: &Path, master: &Master) -> Result<(KeyEntry, String), Error> {
    let (display, bytes) = stage_recovery_wrapper(master)?;
    let entry = KeyEntry::recovery(random_member_id());
    write_atomic(&member_age_path(dir, &entry.id)?, &bytes)?;
    Ok((entry, display))
}

fn seal_recovery_wrapper(master: &Master, canonical: &str) -> Result<Vec<u8>, Error> {
    let secret = SecretString::from(canonical.to_owned());
    #[cfg(test)]
    {
        passphrase::seal_recovery_with_work_factor(master, &secret, 10)
    }
    #[cfg(not(test))]
    {
        passphrase::seal_recovery(master, &secret)
    }
}

fn unlock_passphrase_keys(
    dir: &Path,
    config: &Config,
    passphrase: &SecretString,
) -> Result<Master, Error> {
    let mut saw_passphrase_user = false;
    for key in &config.keys {
        if key.mechanism != "passphrase" {
            continue;
        }
        saw_passphrase_user = true;
        let path = member_age_path(dir, &key.id)?;
        let bytes = fs::read(&path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                Error::Other(format!("missing wrapper for user {}", key.label))
            } else {
                Error::io(err)
            }
        })?;
        match passphrase::open_recovery(&bytes, passphrase) {
            Ok(master) => {
                mark_member_used(dir, &key.id)?;
                return Ok(master);
            }
            Err(Error::WrongPassphrase) => continue,
            Err(err) => return Err(err),
        }
    }
    if saw_passphrase_user {
        Err(Error::WrongPassphrase)
    } else {
        Err(Error::Other("vault has no passphrase user".into()))
    }
}

fn seal_member(master: &Master, passphrase: &SecretString) -> Result<Vec<u8>, Error> {
    // Unit tests use a cheap scrypt work factor. The installed binary uses
    // age's human passphrase cost, about one second.
    #[cfg(test)]
    {
        passphrase::seal_recovery_with_work_factor(master, passphrase, 10)
    }
    #[cfg(not(test))]
    {
        passphrase::seal_recovery(master, passphrase)
    }
}

fn load_config_file(dir: &Path) -> Result<Config, Error> {
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

fn member_age_path(dir: &Path, id: &str) -> Result<PathBuf, Error> {
    validate_member_id(id)?;
    Ok(dir.join("keys").join(format!("{id}.age")))
}

fn member_mask_path(dir: &Path, id: &str) -> Result<PathBuf, Error> {
    validate_member_id(id)?;
    Ok(dir.join("keys").join(format!("{id}.mask")))
}

fn member_wrapper_path(dir: &Path, entry: &KeyEntry) -> Result<PathBuf, Error> {
    if entry.mechanism == FIDO2_MECHANISM {
        member_mask_path(dir, &entry.id)
    } else {
        member_age_path(dir, &entry.id)
    }
}

fn validate_member_id(id: &str) -> Result<(), Error> {
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::InvalidConfig);
    }
    Ok(())
}

fn normalize_label(label: &str) -> Result<String, Error> {
    let label = label.trim();
    if label.is_empty() {
        return Err(Error::LabelRequired);
    }
    if label.contains('/') || label.contains('\\') {
        return Err(Error::Other(
            "a label cannot contain a path separator".into(),
        ));
    }
    Ok(label.to_owned())
}

fn random_member_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes_to_hex(&bytes)
}

pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, Error> {
    if hex.len() % 2 != 0 {
        return Err(Error::InvalidConfig);
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| Error::InvalidConfig))
        .collect()
}

/// Hardware member params needed to call `get_hmac_secret` for unlock.
pub fn list_hardware_params(dir: &Path) -> Result<Vec<HardwareMemberParams>, Error> {
    let config = load_config_file(dir)?;
    config
        .keys
        .iter()
        .filter(|key| key.mechanism == FIDO2_MECHANISM)
        .map(|key| {
            Ok(HardwareMemberParams {
                credential_id: hex_to_bytes(&key.credential_id)?,
                rp_id: key.rp_id.clone(),
                salt: hex_to_salt(&key.salt)?,
                public_key: hex_to_bytes(&key.public_key)?,
                key_product: key.key_product.clone(),
                label: key.label.clone(),
            })
        })
        .collect()
}

pub fn has_passphrase_member(dir: &Path) -> Result<bool, Error> {
    let config = load_config_file(dir)?;
    Ok(config.keys.iter().any(|key| key.mechanism == "passphrase"))
}

pub fn has_hardware_member(dir: &Path) -> Result<bool, Error> {
    let config = load_config_file(dir)?;
    Ok(config
        .keys
        .iter()
        .any(|key| key.mechanism == FIDO2_MECHANISM))
}

pub fn hex_to_salt(hex: &str) -> Result<[u8; 32], Error> {
    let bytes = hex_to_bytes(hex)?;
    bytes.try_into().map_err(|_| Error::InvalidConfig)
}

fn mark_member_used(dir: &Path, id: &str) -> Result<(), Error> {
    let mut config = load_config_file(dir)?;
    let Some(key) = config.keys.iter_mut().find(|key| key.id == id) else {
        return Ok(());
    };
    key.last_used = format::utc_now();
    save_config(dir, &config)
}

impl From<&KeyEntry> for MemberInfo {
    fn from(key: &KeyEntry) -> Self {
        Self {
            id: key.id.clone(),
            label: key.label.clone(),
            mechanism: key.mechanism.clone(),
            key_product: key.key_product.clone(),
            last_used: key.last_used.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        HardwareMemberParams, add_hardware_member_unlocked, add_passphrase_member,
        commit_recovery_wrapper, list_members, recovery_replacement_due, remove_member,
        stage_recovery_wrapper, unlock_with_hmac, unlock_with_recovery_code,
    };
    use crate::Error;
    use crate::crypto::passphrase::open_recovery;
    use crate::vault::format::load_config;
    use crate::vault::{init_hardware_vault, init_vault};
    use rand::RngCore;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let mut bytes = [0u8; 8];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            let name: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            Self(std::env::temp_dir().join(format!("wardlet-members-{name}")))
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn wrapper_bytes(dir: &std::path::Path, id: &str) -> Vec<u8> {
        fs::read(dir.join("keys").join(format!("{id}.age"))).unwrap()
    }

    fn fake_params() -> HardwareMemberParams {
        HardwareMemberParams {
            credential_id: vec![0x01, 0x02, 0x03, 0x04],
            rp_id: "wardlet.com".into(),
            salt: [0xABu8; 32],
            public_key: vec![0xA5; 65],
            key_product: "YubiKey OTP+FIDO+CCID".into(),
            label: "yubikey".into(),
        }
    }

    #[test]
    fn two_passphrases_unwrap_the_same_master_and_the_last_user_stays() {
        let dir = TempDir::new();
        let created = init_vault(dir.path(), "personal", "passphrase-one").unwrap();
        let config_text = fs::read_to_string(dir.path().join("config.toml")).unwrap();
        assert!(!config_text.contains("AGE-SECRET-KEY"));
        assert!(!dir.path().join("recovery.age").exists());

        let first = list_members(dir.path()).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].label, "personal");
        assert_eq!(first[0].mechanism, "passphrase");
        let first_id = first[0].id.clone();
        let first_wrapper = wrapper_bytes(dir.path(), &first_id);
        assert!(
            !first_wrapper
                .windows(15)
                .any(|bytes| bytes == b"AGE-SECRET-KEY")
        );

        let added = add_passphrase_member(dir.path(), "passphrase-one", "backup", "passphrase-two")
            .unwrap();
        let second_wrapper = wrapper_bytes(dir.path(), &added.id);
        let opened_first = open_recovery(
            &first_wrapper,
            &age::secrecy::SecretString::from("passphrase-one".to_owned()),
        )
        .unwrap();
        let opened_second = open_recovery(
            &second_wrapper,
            &age::secrecy::SecretString::from("passphrase-two".to_owned()),
        )
        .unwrap();
        assert_eq!(opened_first.recipient(), created.recipient);
        assert_eq!(opened_second.recipient(), created.recipient);

        let err =
            add_passphrase_member(dir.path(), "nope", "other", "passphrase-three").unwrap_err();
        assert!(matches!(err, Error::WrongPassphrase));
        assert_eq!(err.exit_code(), 14);
        assert_eq!(list_members(dir.path()).unwrap().len(), 2);

        let err = remove_member(dir.path(), "nope", "backup").unwrap_err();
        assert!(matches!(err, Error::WrongPassphrase));
        assert_eq!(err.exit_code(), 14);
        assert!(
            dir.path()
                .join("keys")
                .join(format!("{}.age", added.id))
                .is_file()
        );

        remove_member(dir.path(), "passphrase-two", "backup").unwrap();
        assert!(
            !dir.path()
                .join("keys")
                .join(format!("{}.age", added.id))
                .exists()
        );
        let config =
            load_config(&fs::read_to_string(dir.path().join("config.toml")).unwrap()).unwrap();
        assert_eq!(config.keys.len(), 1);
        assert_eq!(config.keys[0].id, first_id);

        let err = remove_member(dir.path(), "passphrase-one", "personal").unwrap_err();
        assert!(matches!(err, Error::LastMember));
        assert!(
            dir.path()
                .join("keys")
                .join(format!("{first_id}.age"))
                .is_file()
        );
        let still = open_recovery(
            &wrapper_bytes(dir.path(), &first_id),
            &age::secrecy::SecretString::from("passphrase-one".to_owned()),
        )
        .unwrap();
        assert_eq!(still.recipient(), created.recipient);
    }

    #[test]
    fn hardware_init_writes_mask_and_config_without_secrets() {
        let dir = TempDir::new();
        let hmac = [0x55u8; 32];
        let params = fake_params();
        let created = init_hardware_vault(dir.path(), "yubikey", &hmac, &params).unwrap();

        let config_text = fs::read_to_string(dir.path().join("config.toml")).unwrap();
        let config = load_config(&config_text).unwrap();
        assert_eq!(config.master_recipient, created.recipient);
        assert_eq!(config.keys.len(), 2);
        assert_eq!(config.keys[0].mechanism, "fido2-hmac");
        assert_eq!(config.keys[0].label, "yubikey");
        assert_eq!(config.keys[0].rp_id, "wardlet.com");
        assert_eq!(config.keys[0].credential_id, "01020304");
        assert_eq!(config.keys[0].salt.len(), 64);
        assert!(!config.keys[0].public_key.is_empty());
        assert!(!config.keys[0].recipient.is_empty());
        assert_eq!(config.keys[0].key_product, "YubiKey OTP+FIDO+CCID");
        assert!(!config.keys[0].last_used.is_empty());

        assert!(!config_text.contains("AGE-SECRET-KEY"));
        assert!(!config_text.contains(&created.debug_master_secret));
        let hmac_hex: String = hmac.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!config_text.contains(&hmac_hex));

        let mask = fs::read(
            dir.path()
                .join("keys")
                .join(format!("{}.mask", config.keys[0].id)),
        )
        .unwrap();
        assert!(mask.starts_with(b"age-encryption.org/v1\n"));
        assert!(!mask.windows(15).any(|bytes| bytes == b"AGE-SECRET-KEY"));
        let mask_text = String::from_utf8_lossy(&mask);
        assert!(!mask_text.contains(&created.debug_master_secret));
        assert!(!mask_text.contains(&hmac_hex));

        let opened = unlock_with_hmac(dir.path(), &hmac).unwrap();
        assert_eq!(opened.recipient(), created.recipient);
        assert_eq!(opened.expose_secret(), created.debug_master_secret);

        assert_eq!(config.keys[1].mechanism, "recovery");
        assert!(!config_text.contains(&created.recovery_code));
        let recovery_path = dir
            .path()
            .join("keys")
            .join(format!("{}.age", config.keys[1].id));
        let recovery_bytes = fs::read(&recovery_path).unwrap();
        assert!(!String::from_utf8_lossy(&recovery_bytes).contains(&created.recovery_code));
        let recovered = unlock_with_recovery_code(dir.path(), &created.recovery_code).unwrap();
        assert_eq!(recovered.recipient(), created.recipient);
        assert!(recovery_replacement_due(dir.path()).unwrap());
        let err = unlock_with_recovery_code(dir.path(), "0000-0000-0000-0000-0000-0000-0000-0000")
            .unwrap_err();
        assert!(matches!(err, Error::WrongPassphrase));

        let (next, bytes) = stage_recovery_wrapper(&recovered).unwrap();
        commit_recovery_wrapper(dir.path(), &bytes).unwrap();
        assert!(!recovery_replacement_due(dir.path()).unwrap());
        assert!(!recovery_path.exists());
        let again = unlock_with_recovery_code(dir.path(), &next).unwrap();
        assert_eq!(again.recipient(), created.recipient);
        let stale = unlock_with_recovery_code(dir.path(), &created.recovery_code).unwrap_err();
        assert!(matches!(stale, Error::WrongPassphrase));
    }

    #[test]
    fn hardware_member_can_be_added_and_removed_deletes_mask() {
        let dir = TempDir::new();
        let created = init_vault(dir.path(), "personal", "passphrase-one").unwrap();
        let master = unlock_with_passphrase_for_test(dir.path(), "passphrase-one");

        let hmac = [0x66u8; 32];
        let added =
            add_hardware_member_unlocked(dir.path(), &master, "token", &hmac, &fake_params())
                .unwrap();
        assert_eq!(added.mechanism, "fido2-hmac");
        assert!(
            dir.path()
                .join("keys")
                .join(format!("{}.mask", added.id))
                .is_file()
        );

        let opened = unlock_with_hmac(dir.path(), &hmac).unwrap();
        assert_eq!(opened.recipient(), created.recipient);

        remove_member(dir.path(), "passphrase-one", "token").unwrap();
        assert!(
            !dir.path()
                .join("keys")
                .join(format!("{}.mask", added.id))
                .exists()
        );
    }

    fn unlock_with_passphrase_for_test(
        dir: &std::path::Path,
        passphrase: &str,
    ) -> crate::master::Master {
        super::unlock_with_passphrase(dir, passphrase).unwrap()
    }
}
