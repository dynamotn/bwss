//! Bitwarden client-side cryptography.
//!
//! Only the type-2 EncString (AES-256-CBC + HMAC-SHA256, encrypt-then-MAC) is
//! accepted; unauthenticated legacy types are refused.

use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Why a key could not be derived, or a value could not be opened.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("MAC verification failed (wrong password or tampered data)")]
    BadMac,
    #[error("malformed encrypted string")]
    Malformed,
    #[error("this vault uses the newer COSE encryption format, which is not supported yet")]
    Cose,
    #[error("unsupported or unauthenticated encryption type {0:?}")]
    UnsupportedType(String),
    #[error("decryption failed")]
    Decrypt,
    #[error("invalid key length {0}")]
    KeyLength(usize),
    #[error("KDF parameters out of range: {0}")]
    Kdf(String),
}

/// The KDF a Bitwarden account derives its master key with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum KdfParams {
    Pbkdf2 { iterations: u32 },
    Argon2id { iterations: u32, memory_mib: u32, parallelism: u32 },
}

impl KdfParams {
    /// Lower bounds stop a hostile server from downgrading the KDF; upper
    /// bounds stop it from pinning the CPU or exhausting memory.
    pub fn validate(&self) -> Result<(), CryptoError> {
        match *self {
            KdfParams::Pbkdf2 { iterations } if !(5_000..=2_000_000).contains(&iterations) => {
                Err(CryptoError::Kdf(format!("PBKDF2 iterations {iterations}")))
            }
            KdfParams::Argon2id { iterations, .. } if !(2..=10).contains(&iterations) => {
                Err(CryptoError::Kdf(format!("Argon2 iterations {iterations}")))
            }
            KdfParams::Argon2id { memory_mib, .. } if !(16..=1024).contains(&memory_mib) => {
                Err(CryptoError::Kdf(format!("Argon2 memory {memory_mib} MiB")))
            }
            KdfParams::Argon2id { parallelism, .. } if !(1..=16).contains(&parallelism) => {
                Err(CryptoError::Kdf(format!("Argon2 parallelism {parallelism}")))
            }
            _ => Ok(()),
        }
    }
}

/// The 32-byte key derived from the master password, wiped on drop.
pub type MasterKey = Zeroizing<[u8; 32]>;

/// Derives the 32-byte master key from the master password.
pub fn derive_master_key(password: &str, email: &str, kdf: KdfParams) -> Result<MasterKey, CryptoError> {
    kdf.validate()?;
    let salt = email.trim().to_lowercase();
    let mut out = Zeroizing::new([0u8; 32]);
    match kdf {
        KdfParams::Pbkdf2 { iterations } => {
            pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), iterations, out.as_mut());
        }
        KdfParams::Argon2id { iterations, memory_mib, parallelism } => {
            let params = argon2::Params::new(memory_mib * 1024, iterations, parallelism, Some(32))
                .map_err(|e| CryptoError::Kdf(e.to_string()))?;
            let salt = Sha256::digest(salt.as_bytes());
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                .hash_password_into(password.as_bytes(), &salt, out.as_mut())
                .map_err(|e| CryptoError::Kdf(e.to_string()))?;
        }
    }
    Ok(out)
}

/// The hash a server stores for password logins.
#[cfg(test)]
pub fn hash_master_password(master_key: &MasterKey, password: &str) -> String {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(master_key.as_ref(), password.as_bytes(), 1, &mut out);
    B64.encode(out)
}

#[expect(clippy::expect_used, reason = "HMAC accepts a key of any length")]
fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// A mark of `stored` (a value's decrypted text as kept in the vault, before
/// any base64 decoding) for the item `id`: HMAC-SHA256 of `id ‖ 0x00 ‖ stored`
/// under the MAC half of `mark_key`, as the Obsidian plugin computes it. Equal
/// marks mean the stored text is unchanged, whatever IV it was encrypted with;
/// two items holding the same secret still get different marks.
pub fn value_mark(mark_key: &SymmetricKey, id: &str, stored: &str) -> [u8; 32] {
    hmac(&mark_key.mac, &[id.as_bytes(), &[0], stored.as_bytes()])
}

/// HKDF-Expand (RFC 5869) for one 32-byte block.
fn hkdf_expand32(prk: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(hmac(prk, &[info, &[1u8]]))
}

/// A 64-byte Bitwarden symmetric key: AES-256 key followed by HMAC key.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SymmetricKey {
    enc: [u8; 32],
    mac: [u8; 32],
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SymmetricKey(..)")
    }
}

impl SymmetricKey {
    /// Builds a key from its 64-byte form (AES key, then HMAC key); any other
    /// length is [`CryptoError::KeyLength`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: &[u8; 64] = bytes.try_into().map_err(|_| CryptoError::KeyLength(bytes.len()))?;
        let (enc, mac) = bytes.split_at(32);
        let mut key = SymmetricKey { enc: [0; 32], mac: [0; 32] };
        key.enc.copy_from_slice(enc);
        key.mac.copy_from_slice(mac);
        Ok(key)
    }

    #[cfg(test)]
    pub fn generate() -> Self {
        let mut key = SymmetricKey { enc: [0; 32], mac: [0; 32] };
        rand::fill(key.enc.as_mut_slice());
        rand::fill(key.mac.as_mut_slice());
        key
    }

    #[cfg(test)]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(64));
        v.extend_from_slice(&self.enc);
        v.extend_from_slice(&self.mac);
        v
    }

    /// Turns the master key into the key that protects the user key.
    pub fn stretch(master_key: &MasterKey) -> Self {
        let enc = hkdf_expand32(master_key.as_ref(), b"enc");
        let mac = hkdf_expand32(master_key.as_ref(), b"mac");
        let mut key = SymmetricKey { enc: [0; 32], mac: [0; 32] };
        key.enc.copy_from_slice(enc.as_ref());
        key.mac.copy_from_slice(mac.as_ref());
        key
    }

    /// A key of its own for `purpose` (HKDF-Expand over this key), so that
    /// nothing encrypted with this key can pass for data of that purpose.
    pub fn derive(&self, purpose: &str) -> Self {
        let mut prk = Zeroizing::new([0u8; 64]);
        let (prk_enc, prk_mac) = prk.split_at_mut(32);
        prk_enc.copy_from_slice(&self.enc);
        prk_mac.copy_from_slice(&self.mac);
        let enc = hkdf_expand32(prk.as_ref(), format!("bwss {purpose} enc").as_bytes());
        let mac = hkdf_expand32(prk.as_ref(), format!("bwss {purpose} mac").as_bytes());
        let mut key = SymmetricKey { enc: [0; 32], mac: [0; 32] };
        key.enc.copy_from_slice(enc.as_ref());
        key.mac.copy_from_slice(mac.as_ref());
        key
    }

    /// Encrypts `plain` into a Bitwarden type-2 string
    /// (`2.iv|ciphertext|mac`, AES-256-CBC with an HMAC-SHA256 tag) under a
    /// fresh random IV.
    pub fn encrypt(&self, plain: &[u8]) -> String {
        let mut iv = [0u8; 16];
        rand::fill(&mut iv);
        self.encrypt_with_iv(plain, &iv)
    }

    fn encrypt_with_iv(&self, plain: &[u8], iv: &[u8; 16]) -> String {
        let ct = Aes256CbcEnc::new(&self.enc.into(), &(*iv).into()).encrypt_padded_vec::<Pkcs7>(plain);
        let mac = hmac(&self.mac, &[iv, &ct]);
        format!("2.{}|{}|{}", B64.encode(iv), B64.encode(&ct), B64.encode(mac))
    }

    /// [`encrypt`](Self::encrypt) for text.
    pub fn encrypt_str(&self, plain: &str) -> String {
        self.encrypt(plain.as_bytes())
    }

    #[expect(clippy::expect_used, reason = "HMAC accepts a key of any length")]
    /// Decrypts a type-2 string. The MAC is checked in constant time before
    /// anything is decrypted; a bad one is [`CryptoError::BadMac`].
    pub fn decrypt(&self, value: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let (iv, ct, mac) = parse_enc_string(value)?;
        let mut m = HmacSha256::new_from_slice(&self.mac).expect("any key length");
        m.update(&iv);
        m.update(&ct);
        // verify_slice is constant time; decrypting only afterwards keeps the
        // CBC padding oracle out of reach.
        m.verify_slice(&mac).map_err(|_| CryptoError::BadMac)?;
        let iv: [u8; 16] = iv.try_into().map_err(|_| CryptoError::Malformed)?;
        Aes256CbcDec::new(&self.enc.into(), &iv.into())
            .decrypt_padded_vec::<Pkcs7>(&ct)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::Decrypt)
    }

    /// [`decrypt`](Self::decrypt) for text; non-UTF-8 plaintext is
    /// [`CryptoError::Decrypt`].
    pub fn decrypt_str(&self, value: &str) -> Result<Zeroizing<String>, CryptoError> {
        let bytes = self.decrypt(value)?;
        // Validate in place: a failed `from_utf8` on an owned copy would leave
        // the plaintext unwiped inside its error.
        std::str::from_utf8(&bytes).map(|s| Zeroizing::new(s.to_owned())).map_err(|_| CryptoError::Decrypt)
    }

    /// Decrypts a wrapped key (a user key or an item key) held in a type-2 string.
    pub fn decrypt_key(&self, value: &str) -> Result<SymmetricKey, CryptoError> {
        SymmetricKey::from_bytes(&self.decrypt(value)?)
    }
}

/// (iv, ciphertext, mac)
type EncParts = (Vec<u8>, Vec<u8>, Vec<u8>);

fn parse_enc_string(value: &str) -> Result<EncParts, CryptoError> {
    let (ty, rest) = value.split_once('.').ok_or(CryptoError::Malformed)?;
    match ty {
        "2" => {}
        "7" => return Err(CryptoError::Cose),
        other => return Err(CryptoError::UnsupportedType(other.to_owned())),
    }
    let mut parts = rest.split('|');
    let (Some(iv), Some(ct), Some(mac), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(CryptoError::Malformed);
    };
    let dec = |s: &str| B64.decode(s).map_err(|_| CryptoError::Malformed);
    let (iv, ct, mac) = (dec(iv)?, dec(ct)?, dec(mac)?);
    if iv.len() != 16 || mac.len() != 32 || ct.is_empty() || ct.len() % 16 != 0 {
        return Err(CryptoError::Malformed);
    }
    Ok((iv, ct, mac))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../../tests/fixtures/vectors.json")).unwrap()
    }
    fn b64(v: &Value) -> Vec<u8> {
        B64.decode(v.as_str().unwrap()).unwrap()
    }

    #[test]
    fn decrypt_str_rejects_invalid_utf8_and_keeps_valid_text() {
        let key = SymmetricKey::generate();
        let good = key.encrypt(b"h\xc3\xa9llo");
        assert_eq!(key.decrypt_str(&good).unwrap().as_str(), "h\u{e9}llo");
        let bad = key.encrypt(&[0xff, 0xfe, b'x']);
        assert!(matches!(key.decrypt_str(&bad), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn pbkdf2_known_answers() {
        let v = vectors();
        let mk = derive_master_key(
            v["password"].as_str().unwrap(),
            v["email"].as_str().unwrap(),
            KdfParams::Pbkdf2 { iterations: 600_000 },
        )
        .unwrap();
        assert_eq!(mk.to_vec(), b64(&v["pbkdf2"]["masterKey"]));
        assert_eq!(SymmetricKey::stretch(&mk).to_bytes().to_vec(), b64(&v["pbkdf2"]["stretched"]));
        assert_eq!(hash_master_password(&mk, v["password"].as_str().unwrap()), v["pbkdf2"]["masterPasswordHash"]);
    }

    #[test]
    fn argon2id_known_answers() {
        let v = vectors();
        let mk = derive_master_key(
            v["password"].as_str().unwrap(),
            v["email"].as_str().unwrap(),
            KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 },
        )
        .unwrap();
        assert_eq!(mk.to_vec(), b64(&v["argon2id"]["masterKey"]));
        assert_eq!(SymmetricKey::stretch(&mk).to_bytes().to_vec(), b64(&v["argon2id"]["stretched"]));
    }

    #[test]
    fn enc_strings_known_answers_and_round_trip() {
        let v = vectors();
        let stretched = SymmetricKey::from_bytes(&b64(&v["pbkdf2"]["stretched"])).unwrap();
        let user = stretched.decrypt_key(v["protectedUserKey"].as_str().unwrap()).unwrap();
        assert_eq!(user.to_bytes().to_vec(), b64(&v["userKey"]));
        for e in v["encStrings"].as_array().unwrap() {
            let plain = e["plain"].as_str().unwrap();
            assert_eq!(&*user.decrypt_str(e["enc"].as_str().unwrap()).unwrap(), plain);
            assert_eq!(&*user.decrypt_str(&user.encrypt_str(plain)).unwrap(), plain);
        }
        // Deterministic given the IV: matches the Python reference byte for byte.
        let iv: [u8; 16] = core::array::from_fn(|i| 100 + i as u8);
        assert_eq!(user.encrypt_with_iv(b"a", &iv), v["encStrings"][1]["enc"].as_str().unwrap());
    }

    #[test]
    fn rejects_tampering_and_unauthenticated_types() {
        let v = vectors();
        let user = SymmetricKey::from_bytes(&b64(&v["userKey"])).unwrap();
        let enc = v["encStrings"][2]["enc"].as_str().unwrap();
        let (iv, rest) = enc[2..].split_once('|').unwrap();
        let (ct, mac) = rest.split_once('|').unwrap();
        let mut ctb = B64.decode(ct).unwrap();
        ctb[0] ^= 1;
        let tampered = format!("2.{iv}|{}|{mac}", B64.encode(ctb));
        assert_eq!(user.decrypt(&tampered).unwrap_err(), CryptoError::BadMac);
        assert_eq!(SymmetricKey::generate().decrypt(enc).unwrap_err(), CryptoError::BadMac);
        assert!(matches!(user.decrypt(&format!("0.{iv}|{ct}")), Err(CryptoError::UnsupportedType(_))));
        assert_eq!(user.decrypt("7.abc").unwrap_err(), CryptoError::Cose);
        assert_eq!(user.decrypt(&format!("2.{iv}|{ct}")).unwrap_err(), CryptoError::Malformed);
    }

    #[test]
    fn kdf_bounds() {
        assert!(KdfParams::Pbkdf2 { iterations: 1 }.validate().is_err());
        assert!(KdfParams::Argon2id { iterations: 3, memory_mib: 4096, parallelism: 4 }.validate().is_err());
        assert!(KdfParams::Pbkdf2 { iterations: 600_000 }.validate().is_ok());
    }

    #[test]
    fn derived_keys_are_separate() {
        let user = SymmetricKey::generate();
        let acl = user.derive("vault-acl");
        assert_eq!(acl.to_bytes(), user.derive("vault-acl").to_bytes());
        assert_ne!(acl.to_bytes(), user.to_bytes());
        assert_ne!(acl.to_bytes(), user.derive("other").to_bytes());
        // Text the user key encrypted (an item name, say) does not open with the derived key.
        assert!(acl.decrypt_str(&user.encrypt_str("{}")).is_err());
        assert_eq!(&*acl.decrypt_str(&acl.encrypt_str("{}")).unwrap(), "{}");
    }

    #[test]
    fn value_mark_depends_on_key_id_and_value() {
        let user = SymmetricKey::generate();
        let mark_key = user.derive("marks");
        assert_eq!(value_mark(&mark_key, "i", "a"), value_mark(&mark_key, "i", "a"));
        assert_ne!(value_mark(&mark_key, "i", "a"), value_mark(&mark_key, "i", "b"));
        assert_ne!(value_mark(&mark_key, "i", "a"), value_mark(&user.derive("other"), "i", "a"));
        // Two items holding the same secret do not share a mark.
        assert_ne!(value_mark(&mark_key, "i", "a"), value_mark(&mark_key, "j", "a"));
        // The separator keeps the id and the value apart.
        assert_ne!(value_mark(&mark_key, "ab", "c"), value_mark(&mark_key, "a", "bc"));
    }
}
