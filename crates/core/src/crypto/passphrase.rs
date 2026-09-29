//! Create and open `recovery.age` with age's scrypt passphrase stanza.

use std::io::{Read, Write};

use age::Encryptor;
use age::secrecy::{ExposeSecret, SecretString};

use crate::Error;
use crate::master::Master;

pub fn seal_recovery(master: &Master, passphrase: &SecretString) -> Result<Vec<u8>, Error> {
    let encryptor = Encryptor::with_user_passphrase(clone_passphrase(passphrase));
    seal_with(encryptor, master)
}

pub fn open_recovery(ciphertext: &[u8], passphrase: &SecretString) -> Result<Master, Error> {
    let decryptor = age::Decryptor::new(ciphertext).map_err(map_open_error)?;
    let identity = age::scrypt::Identity::new(clone_passphrase(passphrase));
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
    zeroize_string(&mut plain);
    master
}

#[cfg(test)]
pub(crate) fn seal_recovery_with_work_factor(
    master: &Master,
    passphrase: &SecretString,
    log_n: u8,
) -> Result<Vec<u8>, Error> {
    let mut recipient = age::scrypt::Recipient::new(clone_passphrase(passphrase));
    recipient.set_work_factor(log_n);
    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .expect("a single scrypt recipient is valid");
    seal_with(encryptor, master)
}

fn seal_with(encryptor: Encryptor, master: &Master) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    let mut writer = encryptor.wrap_output(&mut output).map_err(Error::io)?;
    writer
        .write_all(master.expose_secret().as_bytes())
        .map_err(Error::io)?;
    writer.finish().map_err(Error::io)?;
    Ok(output)
}

fn clone_passphrase(passphrase: &SecretString) -> SecretString {
    SecretString::from(passphrase.expose_secret().to_owned())
}

fn zeroize_string(value: &mut String) {
    use zeroize::Zeroize;
    value.zeroize();
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
    use age::secrecy::SecretString;

    use super::{open_recovery, seal_recovery_with_work_factor};
    use crate::Error;
    use crate::master::Master;

    fn passphrase(text: &str) -> SecretString {
        SecretString::from(text.to_owned())
    }

    #[test]
    fn recovery_round_trip_returns_the_same_recipient() {
        let master = Master::generate();
        let sealed =
            seal_recovery_with_work_factor(&master, &passphrase("correct horse"), 10).unwrap();
        let opened = open_recovery(&sealed, &passphrase("correct horse")).unwrap();
        assert_eq!(opened.recipient(), master.recipient());
        assert!(!sealed.windows(15).any(|bytes| bytes == b"AGE-SECRET-KEY"));
    }

    #[test]
    fn wrong_passphrase_maps_to_exit_code_14() {
        let master = Master::generate();
        let sealed =
            seal_recovery_with_work_factor(&master, &passphrase("correct horse"), 10).unwrap();
        let err = open_recovery(&sealed, &passphrase("wrong horse")).unwrap_err();
        assert!(matches!(err, Error::WrongPassphrase));
        assert_eq!(err.exit_code(), 14);
    }

    #[test]
    fn corrupt_recovery_returns_a_clean_error() {
        let err = open_recovery(b"not an age file", &passphrase("correct horse")).unwrap_err();
        assert!(matches!(err, Error::CorruptRecovery));
        assert_eq!(err.exit_code(), 1);
    }
}
