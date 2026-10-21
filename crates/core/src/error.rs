//! Failures the CLI turns into process exit codes.
//!
//! Code 12 is "no hardware key found". Codes 11, 13, and 15 stay reserved.

use std::process::ExitCode;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("vault not found")]
    VaultNotFound,

    #[error("vault already exists")]
    VaultExists,

    #[error("this key or recovery code does not open this vault")]
    WrongPassphrase,

    #[error(
        "no FIDO2 key with hmac-secret found (plug one in, check hidraw permissions / udev rules, or the key may lack hmac-secret)"
    )]
    HardwareKeyNotFound,

    #[error("the last key cannot be removed")]
    LastMember,

    #[error("a key labeled {0} already exists")]
    DuplicateLabel(String),

    #[error("no key labeled {0}")]
    UnknownMember(String),

    #[error("a label for this key is required")]
    LabelRequired,

    #[error("output already exists")]
    Collision,

    #[error("unsupported vault format version {0}")]
    UnsupportedFormat(u32),

    #[error("recovery.age is not a valid age file")]
    CorruptRecovery,

    #[error("config.toml is not a valid vault config")]
    InvalidConfig,

    #[error("{0}")]
    Io(String),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn io(err: impl std::fmt::Display) -> Self {
        Error::Io(err.to_string())
    }

    pub fn exit_code(&self) -> u8 {
        match self {
            Error::VaultNotFound => 10,
            Error::HardwareKeyNotFound => 12,
            Error::WrongPassphrase => 14,
            Error::VaultExists | Error::Collision | Error::Io(_) => 16,
            Error::LastMember
            | Error::DuplicateLabel(_)
            | Error::UnknownMember(_)
            | Error::LabelRequired
            | Error::UnsupportedFormat(_)
            | Error::CorruptRecovery
            | Error::InvalidConfig
            | Error::Other(_) => 1,
        }
    }

    pub fn into_exit_code(self) -> ExitCode {
        ExitCode::from(self.exit_code())
    }
}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn exit_codes_match_the_phase0_contract() {
        assert_eq!(Error::VaultNotFound.exit_code(), 10);
        assert_eq!(Error::HardwareKeyNotFound.exit_code(), 12);
        assert_eq!(Error::WrongPassphrase.exit_code(), 14);
        assert_eq!(Error::VaultExists.exit_code(), 16);
        assert_eq!(Error::Collision.exit_code(), 16);
        assert_eq!(Error::Io("disk".into()).exit_code(), 16);
        assert_eq!(Error::UnsupportedFormat(2).exit_code(), 1);
        assert_eq!(Error::CorruptRecovery.exit_code(), 1);
        assert_eq!(Error::Other("boom".into()).exit_code(), 1);
        assert_eq!(Error::LastMember.exit_code(), 1);
    }
}
