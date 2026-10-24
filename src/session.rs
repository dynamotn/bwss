//! Transport encryption for secrets on the bus (Secret Service "sessions").
//!
//! * `plain`: secrets travel as-is (the bus is local, but any eavesdropper
//!   with access to it sees them).
//! * `dh-ietf1024-sha256-aes128-cbc-pkcs7`: Diffie-Hellman over the 1024-bit
//!   MODP group of RFC 2409, HKDF-SHA256 (no salt, no info) to a 128-bit key,
//!   AES-128-CBC with PKCS#7 and a random IV per secret. This is what
//!   libsecret and gnome-keyring implement.

use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const PLAIN: &str = "plain";
pub const DH_AES: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

/// RFC 2409 §6.2, Second Oakley Group (1024-bit MODP), generator 2.
const PRIME_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";
const KEY_BYTES: usize = 128;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("unsupported algorithm {0:?}")]
    Unsupported(String),
    #[error("invalid client public key")]
    BadPublicKey,
    #[error("invalid encrypted secret")]
    BadSecret,
}

pub enum Session {
    Plain,
    Aes(Zeroizing<[u8; 16]>),
}

fn prime() -> BigUint {
    BigUint::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("valid prime")
}

/// Known limitation: `num-bigint` cannot zeroize. The DH private exponent
/// and the shared secret live in `BigUint` values that are freed unwiped, and
/// `BigUint::modpow` makes further unwiped temporaries. Only the byte buffers
/// built here, and the derived AES key, are wiped.
fn to_fixed(n: &BigUint) -> Zeroizing<Vec<u8>> {
    let b = Zeroizing::new(n.to_bytes_be());
    let mut out = Zeroizing::new(vec![0u8; KEY_BYTES.saturating_sub(b.len())]);
    out.extend_from_slice(&b);
    out
}

impl Session {
    /// Negotiates a session; returns it with the output to send back.
    pub fn open(algorithm: &str, input: &[u8]) -> Result<(Session, Vec<u8>), SessionError> {
        match algorithm {
            PLAIN => Ok((Session::Plain, Vec::new())),
            DH_AES => {
                let p = prime();
                let client = BigUint::from_bytes_be(input);
                let one = BigUint::from(1u8);
                if input.is_empty() || input.len() > KEY_BYTES || client <= one || client >= &p - &one {
                    return Err(SessionError::BadPublicKey);
                }
                let mut priv_bytes = Zeroizing::new([0u8; KEY_BYTES]);
                rand::fill(priv_bytes.as_mut_slice());
                let private = BigUint::from_bytes_be(priv_bytes.as_ref());
                let public = BigUint::from(2u8).modpow(&private, &p);
                let shared = to_fixed(&client.modpow(&private, &p));
                let mut key = Zeroizing::new([0u8; 16]);
                Hkdf::<Sha256>::new(None, &shared).expand(&[], key.as_mut()).expect("16 bytes is a valid length");
                Ok((Session::Aes(key), to_fixed(&public).to_vec()))
            }
            other => Err(SessionError::Unsupported(other.to_owned())),
        }
    }

    /// Encodes a secret for the wire: (parameters, value).
    pub fn encrypt(&self, secret: &[u8]) -> (Vec<u8>, Vec<u8>) {
        match self {
            Session::Plain => (Vec::new(), secret.to_vec()),
            Session::Aes(key) => {
                let mut iv = [0u8; 16];
                rand::fill(&mut iv);
                let ct =
                    cbc::Encryptor::<aes::Aes128>::new(&(**key).into(), &iv.into()).encrypt_padded_vec::<Pkcs7>(secret);
                (iv.to_vec(), ct)
            }
        }
    }

    pub fn decrypt(&self, parameters: &[u8], value: &[u8]) -> Result<Zeroizing<Vec<u8>>, SessionError> {
        match self {
            Session::Plain => Ok(Zeroizing::new(value.to_vec())),
            Session::Aes(key) => {
                let iv: [u8; 16] = parameters.try_into().map_err(|_| SessionError::BadSecret)?;
                cbc::Decryptor::<aes::Aes128>::new(&(**key).into(), &iv.into())
                    .decrypt_padded_vec::<Pkcs7>(value)
                    .map(Zeroizing::new)
                    .map_err(|_| SessionError::BadSecret)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plays the client side of the exchange the way libsecret does.
    #[test]
    fn dh_handshake_matches_a_client_computation() {
        let p = prime();
        let client_priv = BigUint::from_bytes_be(&[7u8; 128]);
        let client_pub = BigUint::from(2u8).modpow(&client_priv, &p);
        let (session, server_pub) = Session::open(DH_AES, &client_pub.to_bytes_be()).unwrap();
        assert_eq!(server_pub.len(), 128);
        let shared = to_fixed(&BigUint::from_bytes_be(&server_pub).modpow(&client_priv, &p));
        let mut key = [0u8; 16];
        Hkdf::<Sha256>::new(None, &shared).expand(&[], &mut key).unwrap();

        let (iv, ct) = session.encrypt(b"top secret");
        let iv: [u8; 16] = iv.try_into().unwrap();
        let plain =
            cbc::Decryptor::<aes::Aes128>::new(&key.into(), &iv.into()).decrypt_padded_vec::<Pkcs7>(&ct).unwrap();
        assert_eq!(plain, b"top secret");
        assert_eq!(&*session.decrypt(&iv, &ct).unwrap(), b"top secret");
    }

    #[test]
    fn rejects_degenerate_keys_and_unknown_algorithms() {
        assert_eq!(Session::open(DH_AES, &[1]).err(), Some(SessionError::BadPublicKey));
        assert_eq!(Session::open(DH_AES, &[]).err(), Some(SessionError::BadPublicKey));
        let p_minus_1 = prime() - BigUint::from(1u8);
        assert_eq!(Session::open(DH_AES, &p_minus_1.to_bytes_be()).err(), Some(SessionError::BadPublicKey));
        assert!(matches!(Session::open("rot13", &[]), Err(SessionError::Unsupported(_))));
        let (plain, out) = Session::open(PLAIN, &[]).unwrap();
        assert!(out.is_empty());
        assert_eq!(plain.encrypt(b"x"), (vec![], b"x".to_vec()));
    }
}
