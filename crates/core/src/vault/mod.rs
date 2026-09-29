//! The key directory: `config.toml` and one wrapper per member.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use rand::RngCore;

use crate::Error;

pub mod format;
pub mod keys;
pub mod members;

pub use format::{Config, FORMAT_VERSION, load_config};
pub use members::{
    DEFAULT_RP_ID, FIDO2_MECHANISM, HardwareMemberParams, MemberInfo, RECOVERY_MECHANISM,
    add_hardware_member_unlocked, add_passphrase_member, add_passphrase_member_unlocked,
    commit_recovery_wrapper, has_hardware_member, has_passphrase_member, list_hardware_params,
    list_members, recovery_replacement_due, remove_member, remove_member_unlocked,
    stage_recovery_wrapper, unlock_with_hmac, unlock_with_passphrase, unlock_with_recovery_code,
};

#[derive(Debug)]
pub struct CreatedVault {
    pub dir: PathBuf,
    pub recipient: String,
    /// Master bech32 for DEBUG print only. Never written to disk.
    pub debug_master_secret: String,
    /// Shown once at hardware vault creation. Empty for a passphrase vault.
    pub recovery_code: String,
}

pub fn default_dir() -> Result<PathBuf, Error> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("wardlet").join("vault"));
        }
    }
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .ok_or_else(|| Error::Other("HOME is not set".into()))?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("wardlet")
        .join("vault"))
}

pub fn init_vault(dir: &Path, label: &str, passphrase: &str) -> Result<CreatedVault, Error> {
    if passphrase.is_empty() {
        return Err(Error::PassphraseRequired);
    }
    let passphrase = SecretString::from(passphrase.to_owned());
    if dir.exists() {
        return Err(Error::VaultExists);
    }
    let parent = dir.parent().filter(|path| !path.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(Error::io)?;

    let tmp = parent.join(temporary_name(dir));
    let (recipient, debug_master_secret) = match write_vault(&tmp, label, &passphrase) {
        Ok(result) => result,
        Err(err) => {
            let _ = fs::remove_dir_all(&tmp);
            return Err(err);
        }
    };

    fs::rename(&tmp, dir).map_err(|err| {
        let _ = fs::remove_dir_all(&tmp);
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            Error::VaultExists
        } else {
            Error::io(err)
        }
    })?;
    sync_dir(parent)?;

    Ok(CreatedVault {
        dir: dir.to_path_buf(),
        recipient,
        debug_master_secret,
        recovery_code: String::new(),
    })
}

pub fn init_hardware_vault(
    dir: &Path,
    label: &str,
    hmac: &[u8; 32],
    params: &HardwareMemberParams,
) -> Result<CreatedVault, Error> {
    if dir.exists() {
        return Err(Error::VaultExists);
    }
    let parent = dir.parent().filter(|path| !path.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(Error::io)?;

    let tmp = parent.join(temporary_name(dir));
    let (recipient, debug_master_secret, recovery_code) =
        match write_hardware_vault(&tmp, label, hmac, params) {
            Ok(result) => result,
            Err(err) => {
                let _ = fs::remove_dir_all(&tmp);
                return Err(err);
            }
        };

    fs::rename(&tmp, dir).map_err(|err| {
        let _ = fs::remove_dir_all(&tmp);
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            Error::VaultExists
        } else {
            Error::io(err)
        }
    })?;
    sync_dir(parent)?;

    Ok(CreatedVault {
        dir: dir.to_path_buf(),
        recipient,
        debug_master_secret,
        recovery_code,
    })
}

fn write_vault(
    dir: &Path,
    label: &str,
    passphrase: &SecretString,
) -> Result<(String, String), Error> {
    let (recipient, member, debug_secret) = members::write_first_member(dir, label, passphrase)?;
    let mut config = format::Config::new(&recipient);
    config.keys.push(member);
    let text = config.to_toml()?;
    write_atomic(&dir.join("config.toml"), text.as_bytes())?;
    sync_dir(dir)?;
    Ok((recipient, debug_secret))
}

fn write_hardware_vault(
    dir: &Path,
    label: &str,
    hmac: &[u8; 32],
    params: &HardwareMemberParams,
) -> Result<(String, String, String), Error> {
    let (recipient, member, debug_secret, recovery, recovery_code) =
        members::write_first_hardware_member(dir, label, hmac, params)?;
    let mut config = format::Config::new(&recipient);
    config.auth_mode = FIDO2_MECHANISM.into();
    config.keys.push(member);
    config.keys.push(recovery);
    let text = config.to_toml()?;
    write_atomic(&dir.join("config.toml"), text.as_bytes())?;
    sync_dir(dir)?;
    Ok((recipient, debug_secret, recovery_code))
}

fn temporary_name(dir: &Path) -> String {
    let leaf = dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vault");
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let suffix: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(".{leaf}-{suffix}.tmp")
}

pub(crate) fn create_private_dir(path: &Path) -> Result<(), Error> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(Error::io)
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let tmp = path.with_extension("tmp");
    let write_result = (|| {
        let mut file = create_private_file(&tmp)?;
        file.write_all(bytes).map_err(Error::io)?;
        file.sync_all().map_err(Error::io)?;
        Ok(())
    })();
    if let Err(err) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    fs::rename(&tmp, path).map_err(|err| {
        let _ = fs::remove_file(&tmp);
        Error::io(err)
    })
}

fn create_private_file(path: &Path) -> Result<File, Error> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(Error::io)
}

pub(crate) fn sync_dir(path: &Path) -> Result<(), Error> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(Error::io)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use age::secrecy::SecretString;
    use rand::RngCore;

    use super::{init_hardware_vault, init_vault};
    use crate::Error;
    use crate::crypto::passphrase::open_recovery;
    use crate::vault::format::load_config;
    use crate::vault::members::HardwareMemberParams;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let mut bytes = [0u8; 8];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            let name: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = std::env::temp_dir().join(format!("wardlet-init-{name}"));
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn init_writes_a_vault_that_opens_with_the_passphrase() {
        let dir = TempDir::new();
        let passphrase = SecretString::from("test passphrase".to_owned());
        let created = init_vault(&dir.0, "personal", "test passphrase").unwrap();

        let config_text = fs::read_to_string(dir.0.join("config.toml")).unwrap();
        let config = load_config(&config_text).unwrap();
        assert_eq!(config.master_recipient, created.recipient);
        assert_eq!(config.auth_mode, "passphrase");
        assert_eq!(config.keys.len(), 1);
        assert_eq!(config.keys[0].label, "personal");
        assert_eq!(config.keys[0].mechanism, "passphrase");
        assert!(!config_text.contains("AGE-SECRET-KEY"));
        assert!(!config_text.contains(&created.debug_master_secret));
        assert!(!dir.0.join("recovery.age").exists());

        let recovery = fs::read(
            dir.0
                .join("keys")
                .join(format!("{}.age", config.keys[0].id)),
        )
        .unwrap();
        assert!(recovery.starts_with(b"age-encryption.org/v1\n"));
        assert!(!recovery.windows(15).any(|bytes| bytes == b"AGE-SECRET-KEY"));

        let opened = open_recovery(&recovery, &passphrase).unwrap();
        assert_eq!(opened.recipient(), created.recipient);

        let err = init_vault(&dir.0, "personal", "test passphrase").unwrap_err();
        assert!(matches!(err, Error::VaultExists));
        assert_eq!(err.exit_code(), 16);
    }

    #[test]
    fn init_hardware_vault_does_not_persist_secrets() {
        let dir = TempDir::new();
        let hmac = [0x7Eu8; 32];
        let params = HardwareMemberParams {
            credential_id: vec![9, 8, 7],
            rp_id: "wardlet.com".into(),
            salt: [0x10u8; 32],
            public_key: vec![1, 2, 3, 4],
            key_product: "TREZOR".into(),
            label: "card".into(),
        };
        let created = init_hardware_vault(&dir.0, "card", &hmac, &params).unwrap();
        let config_text = fs::read_to_string(dir.0.join("config.toml")).unwrap();
        assert!(!config_text.contains("AGE-SECRET-KEY"));
        assert!(!config_text.contains(&created.debug_master_secret));
        let hmac_hex: String = hmac.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!config_text.contains(&hmac_hex));
        assert!(matches!(
            init_hardware_vault(&dir.0, "card", &hmac, &params).unwrap_err(),
            Error::VaultExists
        ));
    }
}
