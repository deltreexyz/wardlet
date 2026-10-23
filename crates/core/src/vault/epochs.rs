//! Later masters created when a config visit adds or removes keys.
//!
//! The newest master opens every earlier one. An older copy of the vault
//! never receives the newest master, so it cannot open files encrypted after
//! the change.

use std::fs;
use std::path::Path;

use crate::Error;
use crate::master::Master;
use crate::vault::format::{self, FORMAT_VERSION_CHAIN, Generation};
use crate::vault::keys;
use crate::vault::members::{self, FIDO2_MECHANISM, RECOVERY_MECHANISM};
use crate::vault::names;
use crate::vault::{create_private_dir, sync_dir, write_atomic};

/// One new master for the vault in `dir`. Returns the recovery code to show once.
pub fn rotate_vault(dir: &Path, current: &Master) -> Result<String, Error> {
    let mut config = members::load_config_file(dir)?;
    if current.recipient() != config.master_recipient {
        return Err(Error::Other(
            "this recovery code opens an older version of the vault. Use the latest recovery code to add or remove a key.".into(),
        ));
    }
    let previous_epoch = format::vault_version(&config);
    let next = Master::generate();
    let next_recipient = next.recipient();
    let sealed_previous = keys::seal_mask(current, &next_recipient)?;

    let book = names::load(dir, current)?;
    let epoch_dir = dir.join("epochs");
    if !epoch_dir.is_dir() {
        create_private_dir(&epoch_dir)?;
    }
    write_atomic(
        &epoch_dir.join(format!("{previous_epoch}.age")),
        &sealed_previous,
    )?;

    for key in config
        .keys
        .iter()
        .filter(|key| key.mechanism == FIDO2_MECHANISM)
    {
        if key.recipient.is_empty() {
            return Err(Error::InvalidConfig("a key row has no recipient".into()));
        }
        let wrapped = keys::seal_mask(&next, &key.recipient)?;
        let path = dir.join("keys").join(format!("{}.mask", key.id));
        write_atomic(&path, &wrapped)?;
    }

    park_recovery(dir, &mut config, previous_epoch)?;
    let (display, entry) = install_recovery(dir, &next)?;
    config.keys.push(entry);
    names::save(dir, &next, &book)?;

    config.generations.push(Generation {
        epoch: previous_epoch,
        recipient: config.master_recipient.clone(),
    });
    config.master_recipient = next_recipient;
    config.epoch = previous_epoch + 1;
    config.format_version = FORMAT_VERSION_CHAIN;
    config.recovery_replacement_due = false;
    members::save_config(dir, &config)?;
    sync_dir(dir)?;
    Ok(display)
}

pub fn is_latest_master(dir: &Path, master: &Master) -> Result<bool, Error> {
    let config = members::load_config_file(dir)?;
    Ok(master.recipient() == config.master_recipient)
}

/// `unlocked` and every earlier master it can open, newest first.
pub fn masters_covering(dir: &Path, unlocked: Master) -> Result<Vec<Master>, Error> {
    let config = members::load_config_file(dir)?;
    let mut epoch = epoch_number(&config, &unlocked.recipient())?;
    let mut chain = vec![unlocked];
    while epoch > 1 {
        let relative = format!("epochs/{}.age", epoch - 1);
        let path = dir.join(&relative);
        if !path.is_file() {
            return Err(Error::Other(format!(
                "vault is missing {relative}; this copy is incomplete. Import the vault again."
            )));
        }
        let bytes = fs::read(&path).map_err(Error::io)?;
        let older = keys::open_mask(&bytes, chain.last().expect("chain is non-empty"))
            .map_err(|err| Error::Other(format!("{relative} cannot be opened: {err}")))?;
        if let Some(generation) = config
            .generations
            .iter()
            .find(|generation| generation.epoch == epoch - 1)
            && older.recipient() != generation.recipient
        {
            return Err(Error::Other(format!(
                "{relative} does not match the vault record for version {}",
                epoch - 1
            )));
        }
        epoch -= 1;
        chain.push(older);
    }
    Ok(chain)
}

fn epoch_number(config: &format::Config, recipient: &str) -> Result<u32, Error> {
    if recipient == config.master_recipient {
        return Ok(format::vault_version(config));
    }
    config
        .generations
        .iter()
        .find(|generation| generation.recipient == recipient)
        .map(|generation| generation.epoch)
        .ok_or_else(|| Error::Other("this key does not open this vault version".into()))
}

fn park_recovery(dir: &Path, config: &mut format::Config, epoch: u32) -> Result<(), Error> {
    let old: Vec<_> = config
        .keys
        .iter()
        .filter(|key| key.mechanism == RECOVERY_MECHANISM)
        .map(|key| key.id.clone())
        .collect();
    config
        .keys
        .retain(|key| key.mechanism != RECOVERY_MECHANISM);
    for id in old {
        let from = dir.join("keys").join(format!("{id}.age"));
        let bytes = fs::read(&from).map_err(Error::io)?;
        write_atomic(
            &dir.join("epochs").join(format!("recovery-{epoch}.age")),
            &bytes,
        )?;
        fs::remove_file(from).map_err(Error::io)?;
    }
    Ok(())
}

fn install_recovery(dir: &Path, master: &Master) -> Result<(String, format::KeyEntry), Error> {
    let (display, bytes) = members::stage_recovery_wrapper(master)?;
    let entry = format::KeyEntry::recovery(random_id());
    write_atomic(&dir.join("keys").join(format!("{}.age", entry.id)), &bytes)?;
    Ok((display, entry))
}

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{masters_covering, rotate_vault};
    use crate::master::Master;
    use crate::ops::{DecryptRequest, EncryptRequest, decrypt_vault, encrypt_paths};
    use crate::vault::format::{self, load_config};
    use crate::vault::init_hardware_vault;
    use crate::vault::members::{
        HardwareMemberParams, add_hardware_member_unlocked, unlock_with_hmac,
        unlock_with_recovery_code,
    };

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let mut bytes = [0u8; 8];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            let name: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = std::env::temp_dir().join(format!("wardlet-epoch-{name}"));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn params(label: &str) -> HardwareMemberParams {
        HardwareMemberParams {
            credential_id: label.as_bytes().to_vec(),
            rp_id: "wardlet.com".into(),
            salt: [0x44u8; 32],
            public_key: vec![1, 2, 3],
            key_product: "YubiKey".into(),
            label: label.into(),
        }
    }

    fn encrypt_to(master: &Master, path: &std::path::Path, bytes: &[u8], version: u32) {
        fs::write(path, bytes).unwrap();
        encrypt_paths(
            master,
            &EncryptRequest {
                paths: &[path.to_path_buf()],
                recursive: false,
                output: None,
                remove_source: true,
                stdout: false,
                force: false,
                suffix: ".age",
                stamp: Some(crate::ops::FileStamp {
                    vault_id: "vault".into(),
                    version,
                }),
            },
        )
        .unwrap();
    }

    #[test]
    fn a_later_master_opens_old_files_and_the_old_master_does_not_open_new_files() {
        let dir = TempDir::new();
        let vault = dir.0.join("vault");
        let hmac = [0x21u8; 32];
        let created = init_hardware_vault(&vault, "one", &hmac, &params("one")).unwrap();
        let old_code = created.recovery_code.clone();
        let first = created.master;
        let plain = dir.0.join("early.txt");
        encrypt_to(&first, &plain, b"early", 1);

        let second_hmac = [0x22u8; 32];
        add_hardware_member_unlocked(&vault, &first, "two", &second_hmac, &params("two")).unwrap();
        let third_hmac = [0x23u8; 32];
        add_hardware_member_unlocked(&vault, &first, "three", &third_hmac, &params("three"))
            .unwrap();
        let new_code = rotate_vault(&vault, &first).unwrap();
        let config = load_config(&fs::read_to_string(vault.join("config.toml")).unwrap()).unwrap();
        assert_eq!(format::vault_version(&config), 2);

        let latest = unlock_with_hmac(&vault, &hmac).unwrap();
        assert_ne!(latest.recipient(), first.recipient());
        let chain = masters_covering(&vault, latest).unwrap();
        assert!(
            chain
                .iter()
                .any(|master| master.recipient() == first.recipient())
        );

        let early = dir.0.join("early-out.txt");
        decrypt_vault(
            &chain,
            "vault",
            2,
            &DecryptRequest {
                paths: &[plain.with_extension("txt.age")],
                recursive: false,
                output: Some(&early),
                force: false,
                suffix: ".age",
            },
        )
        .unwrap();
        assert_eq!(fs::read(early.join("early.txt")).unwrap(), b"early");

        let later_plain = dir.0.join("later.txt");
        encrypt_to(chain.first().unwrap(), &later_plain, b"later", 2);
        let only_old = std::slice::from_ref(&first);
        let err = decrypt_vault(
            only_old,
            "vault",
            1,
            &DecryptRequest {
                paths: &[later_plain.with_extension("txt.age")],
                recursive: false,
                output: Some(&dir.0.join("nope")),
                force: false,
                suffix: ".age",
            },
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("version 2"));
        assert!(message.contains("version 1"));

        let old_master = unlock_with_recovery_code(&vault, &old_code).unwrap();
        assert_eq!(old_master.recipient(), first.recipient());
        let old_chain = masters_covering(&vault, old_master).unwrap();
        decrypt_vault(
            &old_chain,
            "vault",
            1,
            &DecryptRequest {
                paths: &[plain.with_extension("txt.age")],
                recursive: false,
                output: Some(&dir.0.join("from-old-code")),
                force: false,
                suffix: ".age",
            },
        )
        .unwrap();
        let err = decrypt_vault(
            &old_chain,
            "vault",
            1,
            &DecryptRequest {
                paths: &[later_plain.with_extension("txt.age")],
                recursive: false,
                output: Some(&dir.0.join("old-code-new-file")),
                force: false,
                suffix: ".age",
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("version 2"));

        let newest = unlock_with_recovery_code(&vault, &new_code).unwrap();
        assert_eq!(newest.recipient(), chain[0].recipient());

        let again = unlock_with_hmac(&vault, &hmac).unwrap();
        rotate_vault(&vault, &again).unwrap();
        let config = load_config(&fs::read_to_string(vault.join("config.toml")).unwrap()).unwrap();
        assert_eq!(format::vault_version(&config), 3);
        let chain = masters_covering(&vault, unlock_with_hmac(&vault, &hmac).unwrap()).unwrap();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn a_missing_epoch_file_is_named() {
        let dir = TempDir::new();
        let vault = dir.0.join("vault");
        let hmac = [0x32u8; 32];
        let created = init_hardware_vault(&vault, "one", &hmac, &params("one")).unwrap();
        rotate_vault(&vault, &created.master).unwrap();
        fs::remove_file(vault.join("epochs").join("1.age")).unwrap();
        let latest = unlock_with_hmac(&vault, &hmac).unwrap();
        let err = masters_covering(&vault, latest).unwrap_err();
        assert!(err.to_string().contains("epochs/1.age"), "{err}");
    }

    #[test]
    fn declining_the_new_recovery_code_leaves_the_original_vault() {
        let dir = TempDir::new();
        let vault = dir.0.join("vault");
        let hmac = [0x31u8; 32];
        let created = init_hardware_vault(&vault, "one", &hmac, &params("one")).unwrap();
        let copy = dir.0.join("copy");
        crate::vault::copy_vault(&vault, &copy).unwrap();
        let _code = rotate_vault(&copy, &created.master).unwrap();
        fs::remove_dir_all(&copy).unwrap();
        let config = load_config(&fs::read_to_string(vault.join("config.toml")).unwrap()).unwrap();
        assert_eq!(format::vault_version(&config), 1);
        let opened = unlock_with_hmac(&vault, &hmac).unwrap();
        assert_eq!(opened.recipient(), created.master.recipient());
    }
}
