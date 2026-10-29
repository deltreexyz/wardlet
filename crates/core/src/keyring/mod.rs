//! The key directory: `config.toml` and one wrapper per member.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use rand::RngCore;

use crate::Error;
use crate::master::Master;

pub mod bundle;
pub mod epochs;
pub mod format;
pub mod index;
pub mod keys;
pub mod members;
pub(crate) mod names;

pub use bundle::{copy_keyring, export_keyring, import_keyring};
pub use epochs::{is_latest_master, masters_covering, rotate_keyring};
pub use format::{Config, FORMAT_VERSION, load_config, keyring_version};
pub use index::{IndexEntry, upsert, upsert_many, prune as prune_index, load as load_index};
pub use members::{
    DEFAULT_RP_ID, FIDO2_MECHANISM, HardwareMemberParams, MemberInfo, RECOVERY_MECHANISM,
    add_hardware_member_unlocked, commit_recovery_wrapper, has_hardware_member,
    list_hardware_params, list_members, list_members_unlocked, recovery_replacement_due,
    remove_member_unlocked, stage_recovery_wrapper, unlock_with_hmac, unlock_with_recovery_code,
};

#[derive(Debug)]
pub struct CreatedKeyring {
    pub dir: PathBuf,
    pub recipient: String,
    /// Live master for this command. Not written to disk.
    pub master: Master,
    /// Shown once at keyring creation.
    pub recovery_code: String,
}

pub fn default_dir() -> Result<PathBuf, Error> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return Ok(PathBuf::from(xdg).join("wardlet").join("keyring"));
    }
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .ok_or_else(|| Error::Other("HOME is not set".into()))?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("wardlet")
        .join("keyring"))
}

pub fn init_hardware_keyring(
    dir: &Path,
    label: &str,
    hmac: &[u8; 32],
    params: &HardwareMemberParams,
) -> Result<CreatedKeyring, Error> {
    if dir.exists() {
        return Err(Error::KeyringExists);
    }
    let parent = dir.parent().filter(|path| !path.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(Error::io)?;

    let tmp = parent.join(temporary_name(dir));
    let (recipient, master, recovery_code) = match write_hardware_keyring(&tmp, label, hmac, params) {
        Ok(result) => result,
        Err(err) => {
            let _ = fs::remove_dir_all(&tmp);
            return Err(err);
        }
    };

    fs::rename(&tmp, dir).map_err(|err| {
        let _ = fs::remove_dir_all(&tmp);
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            Error::KeyringExists
        } else {
            Error::io(err)
        }
    })?;
    sync_dir(parent)?;

    Ok(CreatedKeyring {
        dir: dir.to_path_buf(),
        recipient,
        master,
        recovery_code,
    })
}

fn write_hardware_keyring(
    dir: &Path,
    label: &str,
    hmac: &[u8; 32],
    params: &HardwareMemberParams,
) -> Result<(String, Master, String), Error> {
    let (recipient, member, master, recovery, recovery_code) =
        members::write_first_hardware_member(dir, label, hmac, params)?;
    let mut config = format::Config::new(&recipient);
    config.auth_mode = FIDO2_MECHANISM.into();
    config.keys.push(member);
    config.keys.push(recovery);
    let text = config.to_toml()?;
    write_atomic(&dir.join("config.toml"), text.as_bytes())?;
    sync_dir(dir)?;
    Ok((recipient, master, recovery_code))
}

fn temporary_name(dir: &Path) -> String {
    let leaf = dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("keyring");
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
    let _ = fs::remove_file(&tmp);
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
    options.write(true).create_new(true);
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

    use rand::RngCore;

    use super::init_hardware_keyring;
    use crate::Error;
    use crate::keyring::members::HardwareMemberParams;

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
    fn init_hardware_keyring_does_not_persist_secrets() {
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
        let created = init_hardware_keyring(&dir.0, "card", &hmac, &params).unwrap();
        let config_text = fs::read_to_string(dir.0.join("config.toml")).unwrap();
        assert!(!config_text.contains("AGE-SECRET-KEY"));
        assert!(!config_text.contains(created.master.expose_secret()));
        let hmac_hex: String = hmac.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!config_text.contains(&hmac_hex));
        assert!(matches!(
            init_hardware_keyring(&dir.0, "card", &hmac, &params).unwrap_err(),
            Error::KeyringExists
        ));
    }
}
