//! The age x25519 master identity.
//!
//! Files encrypt to its public recipient. The secret stays in memory for one
//! command. `age::x25519::Identity` does not implement `Zeroize`, so the
//! bech32 string is the buffer that is locked and cleared.

use std::fmt;
use std::str::FromStr;

use age::secrecy::{ExposeSecret, SecretString};
use age::x25519::Identity;

use crate::Error;

pub struct Master {
    identity: Identity,
    secret: SecretString,
    locked: bool,
}

impl Master {
    pub fn generate() -> Self {
        let identity = Identity::generate();
        let secret = identity.to_string();
        Self::from_parts(identity, secret)
    }

    pub fn from_bech32(secret: &str) -> Result<Self, Error> {
        let identity = Identity::from_str(secret).map_err(|_| Error::CorruptRecovery)?;
        Ok(Self::from_parts(
            identity,
            SecretString::from(secret.to_owned()),
        ))
    }

    pub fn recipient(&self) -> String {
        self.identity.to_public().to_string()
    }

    pub(crate) fn expose_secret(&self) -> &str {
        self.secret.expose_secret()
    }

    fn from_parts(identity: Identity, secret: SecretString) -> Self {
        let locked = lock_secret(&secret);
        Self {
            identity,
            secret,
            locked,
        }
    }
}

impl Drop for Master {
    fn drop(&mut self) {
        if self.locked {
            unlock_secret(&self.secret);
        }
    }
}

impl fmt::Debug for Master {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Master")
            .field("recipient", &self.recipient())
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
fn lock_secret(secret: &SecretString) -> bool {
    let bytes = secret.expose_secret().as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let rc = unsafe { libc::mlock(bytes.as_ptr().cast(), bytes.len()) };
    rc == 0
}

#[cfg(not(target_os = "linux"))]
fn lock_secret(_secret: &SecretString) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn unlock_secret(secret: &SecretString) {
    let bytes = secret.expose_secret().as_bytes();
    if bytes.is_empty() {
        return;
    }
    unsafe {
        let _ = libc::munlock(bytes.as_ptr().cast(), bytes.len());
    }
}

#[cfg(not(target_os = "linux"))]
fn unlock_secret(_secret: &SecretString) {}

#[cfg(test)]
mod tests {
    use super::Master;

    #[test]
    fn debug_output_omits_the_secret() {
        let master = Master::generate();
        let rendered = format!("{master:?}");
        assert!(rendered.contains(&master.recipient()));
        assert!(!rendered.contains("AGE-SECRET-KEY"));
        assert!(!rendered.contains(master.expose_secret()));
    }

    #[test]
    fn parse_round_trip_keeps_the_recipient() {
        let master = Master::generate();
        let parsed = Master::from_bech32(master.expose_secret()).unwrap();
        assert_eq!(parsed.recipient(), master.recipient());
    }
}
