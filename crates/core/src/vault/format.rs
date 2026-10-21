//! `config.toml` types and the `format_version` gate.

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::Error;

pub const FORMAT_VERSION: u32 = 1;
/// On-disk layout once a vault has been given a later master.
pub const FORMAT_VERSION_CHAIN: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub format_version: u32,
    pub vault_id: String,
    pub auth_mode: String,
    pub master_recipient: String,
    /// 1 until a later config visit creates the next master. Missing on older files.
    #[serde(default)]
    pub epoch: u32,
    /// Public recipient of each earlier master. The current one is `master_recipient`.
    #[serde(default)]
    pub generations: Vec<Generation>,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub keys: Vec<KeyEntry>,
    /// Set after the recovery code unlocks the vault, until a new code replaces it.
    #[serde(default)]
    pub recovery_replacement_due: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Generation {
    pub epoch: u32,
    pub recipient: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Settings {
    pub session_timeout_secs: u64,
    pub encryption_output_suffix: String,
    pub default_recursion: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            session_timeout_secs: 900,
            encryption_output_suffix: ".age".into(),
            default_recursion: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyEntry {
    pub id: String,
    pub label: String,
    pub mechanism: String,
    /// Public age recipient for a hardware key. Empty for the recovery code.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub recipient: String,
    /// FIDO2 credential id (hex). Empty for the recovery code.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub credential_id: String,
    /// Relying-party id used at registration. Empty for the recovery code.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rp_id: String,
    /// 32-byte hmac-secret salt (hex). Empty for the recovery code.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub salt: String,
    /// Credential public key as COSE bytes (hex). Needed to call get_hmac_secret again.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub public_key: String,
    /// HID product string captured at enrollment, such as "YubiKey OTP+FIDO+CCID".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_product: String,
    /// When this user last unwrapped the vault. Empty until the first successful use.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_used: String,
    pub created: String,
    pub role: String,
}

impl KeyEntry {
    pub fn fido2_hmac(
        id: String,
        label: String,
        recipient: String,
        credential_id_hex: String,
        rp_id: String,
        salt_hex: String,
        public_key_hex: String,
        key_product: String,
    ) -> Self {
        let now = utc_now();
        Self {
            id,
            label,
            mechanism: "fido2-hmac".into(),
            recipient,
            credential_id: credential_id_hex,
            rp_id,
            salt: salt_hex,
            public_key: public_key_hex,
            key_product,
            last_used: now.clone(),
            created: now,
            role: "member".into(),
        }
    }

    pub fn recovery(id: String) -> Self {
        let now = utc_now();
        Self {
            id,
            label: "recovery".into(),
            mechanism: "recovery".into(),
            recipient: String::new(),
            credential_id: String::new(),
            rp_id: String::new(),
            salt: String::new(),
            public_key: String::new(),
            key_product: String::new(),
            last_used: String::new(),
            created: now,
            role: "recovery".into(),
        }
    }
}

pub(crate) fn utc_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = tod / 3600;
    let minute = (tod % 3600) / 60;
    let second = tod % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's civil-from-days conversion, shifted so day 0 is 1970-01-01.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    (year, month as u32, day)
}

impl Config {
    pub fn new(master_recipient: &str) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            vault_id: random_vault_id(),
            auth_mode: "fido2-hmac".into(),
            master_recipient: master_recipient.into(),
            epoch: 1,
            generations: Vec::new(),
            settings: Settings::default(),
            keys: Vec::new(),
            recovery_replacement_due: false,
        }
    }

    pub fn to_toml(&self) -> Result<String, Error> {
        toml::to_string(self).map_err(|_| Error::InvalidConfig)
    }
}

pub fn load_config(text: &str) -> Result<Config, Error> {
    let config: Config = toml::from_str(text).map_err(|_| Error::InvalidConfig)?;
    if config.format_version != FORMAT_VERSION && config.format_version != FORMAT_VERSION_CHAIN {
        return Err(Error::UnsupportedFormat(config.format_version));
    }
    Ok(config)
}

/// User-facing vault version. Older files omit `epoch` and are version 1.
pub fn vault_version(config: &Config) -> u32 {
    if config.epoch == 0 { 1 } else { config.epoch }
}

fn random_vault_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{Config, load_config};

    #[test]
    fn format_version_3_refuses_to_open() {
        let mut config = Config::new("age1example");
        config.format_version = 3;
        let text = config.to_toml().unwrap();
        let err = load_config(&text).unwrap_err();
        assert!(matches!(err, crate::Error::UnsupportedFormat(3)));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn format_version_2_is_the_chain_layout() {
        let mut config = Config::new("age1example");
        config.format_version = 2;
        config.epoch = 2;
        let loaded = load_config(&config.to_toml().unwrap()).unwrap();
        assert_eq!(super::vault_version(&loaded), 2);
    }

    #[test]
    fn a_written_config_loads_and_holds_no_secret_shape() {
        let config = Config::new("age1example");
        let text = config.to_toml().unwrap();
        let loaded = load_config(&text).unwrap();
        assert_eq!(loaded.format_version, 1);
        assert_eq!(super::vault_version(&loaded), 1);
        assert_eq!(loaded.auth_mode, "fido2-hmac");
        assert!(loaded.keys.is_empty());
        assert!(!text.contains("AGE-SECRET-KEY"));
    }

    #[test]
    fn unix_epoch_formats_as_utc() {
        let days = 0;
        let (year, month, day) = super::civil_from_days(days);
        assert_eq!((year, month, day), (1970, 1, 1));
    }
}
