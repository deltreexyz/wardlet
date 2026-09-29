//! A recovery code is 160 bits from the operating-system random generator.
//!
//! Scrypt, used when the code wraps the master, slows guessing. It does not
//! add entropy. The entropy is these 20 random bytes.

use age::secrecy::SecretString;
use rand::RngCore;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Grouped form shown once, plus the canonical form that is actually sealed.
pub struct RecoveryCode {
    pub display: String,
    pub canonical: SecretString,
}

pub fn generate() -> RecoveryCode {
    let mut bytes = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let encoded = encode_base32(&bytes);
    let display = encoded
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).expect("ascii alphabet"))
        .collect::<Vec<_>>()
        .join("-");
    RecoveryCode {
        display,
        canonical: SecretString::from(encoded),
    }
}

/// Strip dashes and spaces and map letters to the Crockford alphabet.
pub fn normalize(typed: &str) -> String {
    typed
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '-')
        .map(|ch| match ch.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        })
        .collect()
}

fn encode_base32(bytes: &[u8]) -> String {
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    for &byte in bytes {
        bits = (bits << 8) | u32::from(byte);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            let index = ((bits >> nbits) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{generate, normalize};

    #[test]
    fn recovery_code_is_160_bits_of_grouped_base32() {
        let code = generate();
        let groups: Vec<_> = code.display.split('-').collect();
        assert_eq!(groups.len(), 8);
        assert!(groups.iter().all(|group| group.len() == 4));
        assert_eq!(normalize(&code.display).len(), 32);
        let again = generate();
        assert_ne!(code.display, again.display);
    }

    #[test]
    fn normalize_ignores_dashes_and_ambiguous_letters() {
        assert_eq!(normalize("oill-oooo"), "01110000");
    }
}
