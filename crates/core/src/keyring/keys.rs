//! Wrap the master identity to an age x25519 recipient (`keys/<id>.mask`).
//!
//! Hardware members derive the recipient from a FIDO2 hmac-secret output via
//! HKDF-SHA256. The hmac bytes and the derived identity secret are never stored.

use std::io::{Read, Write};
use std::str::FromStr;

use age::Encryptor;
use age::x25519::{Identity, Recipient};
use bech32::{Bech32, Hrp};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::Error;
use crate::master::Master;

const HKDF_SALT: &[u8] = b"wardlet-hmac-secret-v1";
const HKDF_INFO: &[u8] = b"age-x25519-identity";
const AGE_SECRET_HRP: &str = "AGE-SECRET-KEY-";

/// Derive a stable age x25519 identity from 32 bytes of hmac-secret output.
pub fn identity_from_hmac(hmac: &[u8; 32]) -> Result<Master, Error> {
    let mut okm = [0u8; 32];
    {
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), hmac);
        hk.expand(HKDF_INFO, &mut okm)
            .map_err(|_| Error::Other("HKDF expand failed".into()))?;
    }
    let bech32 = encode_age_secret_key(&okm)?;
    okm.zeroize();
    let master = Master::from_bech32(&bech32);
    // Master holds its own copy; clear the temporary encoding.
    let mut bech32 = bech32;
    bech32.zeroize();
    master
}

/// Recipient string for the identity derived from `hmac`.
pub fn recipient_from_hmac(hmac: &[u8; 32]) -> Result<String, Error> {
    let identity = identity_from_hmac(hmac)?;
    Ok(identity.recipient())
}

/// Encrypt the master secret to an age x25519 recipient.
pub fn seal_mask(master: &Master, recipient: &str) -> Result<Vec<u8>, Error> {
    let recipient = Recipient::from_str(recipient)
        .map_err(|_| Error::InvalidConfig("recipient does not parse".into()))?;
    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .expect("a single x25519 recipient is valid");
    let mut output = Vec::new();
    let mut writer = encryptor.wrap_output(&mut output).map_err(Error::io)?;
    writer
        .write_all(master.expose_secret().as_bytes())
        .map_err(Error::io)?;
    writer.finish().map_err(Error::io)?;
    Ok(output)
}

/// Decrypt a `.mask` wrapper with the card-derived identity.
pub fn open_mask(ciphertext: &[u8], card_identity: &Master) -> Result<Master, Error> {
    let identity =
        Identity::from_str(card_identity.expose_secret()).map_err(|_| Error::CorruptRecovery)?;
    let decryptor = age::Decryptor::new(ciphertext).map_err(map_open_error)?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(map_open_error)?;
    let mut plain = String::new();
    reader.read_to_string(&mut plain).map_err(|err| {
        if err.kind() == std::io::ErrorKind::InvalidData {
            Error::WrongPassphrase
        } else {
            Error::io(err)
        }
    })?;
    let master = Master::from_bech32(&plain);
    plain.zeroize();
    master
}

fn encode_age_secret_key(secret: &[u8; 32]) -> Result<String, Error> {
    let hrp = Hrp::parse(AGE_SECRET_HRP).map_err(|_| Error::Other("invalid age HRP".into()))?;
    let encoded = bech32::encode_lower::<Bech32>(hrp, secret)
        .map_err(|_| Error::Other("bech32 encode failed".into()))?;
    Ok(encoded.to_uppercase())
}

fn map_open_error(err: age::DecryptError) -> Error {
    use age::DecryptError::{
        DecryptionFailed, InvalidHeader, InvalidMac, Io, KeyDecryptionFailed, NoMatchingKeys,
        UnknownFormat,
    };
    match err {
        NoMatchingKeys | DecryptionFailed | KeyDecryptionFailed => Error::WrongPassphrase,
        InvalidHeader | InvalidMac | UnknownFormat | Io(_) => Error::CorruptRecovery,
        other => Error::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{identity_from_hmac, open_mask, recipient_from_hmac, seal_mask};
    use crate::master::Master;

    #[test]
    fn same_hmac_always_derives_the_same_recipient() {
        let hmac = [0x42u8; 32];
        let a = recipient_from_hmac(&hmac).unwrap();
        let b = recipient_from_hmac(&hmac).unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with("age1"));

        let mut other = hmac;
        other[0] ^= 0xff;
        let c = recipient_from_hmac(&other).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn seal_and_open_mask_round_trips_the_master() {
        let master = Master::generate();
        let hmac = [0x11u8; 32];
        let card = identity_from_hmac(&hmac).unwrap();
        let sealed = seal_mask(&master, &card.recipient()).unwrap();
        assert!(sealed.starts_with(b"age-encryption.org/v1\n"));
        assert!(!sealed.windows(15).any(|bytes| bytes == b"AGE-SECRET-KEY"));

        let opened = open_mask(&sealed, &card).unwrap();
        assert_eq!(opened.recipient(), master.recipient());
        assert_eq!(opened.expose_secret(), master.expose_secret());
    }
}
