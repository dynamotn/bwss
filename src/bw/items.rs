//! Item-level helpers shared by the scan and the write path: dates, the
//! item key, response-only properties and Bitwarden's size limits.

use serde_json::Value;

use super::crypto::{CryptoError, SymmetricKey};

/// Bitwarden's limits on the encrypted size of a password and of notes.
pub(crate) const MAX_PASSWORD_ENC: usize = 5_000;
pub(crate) const MAX_NOTES_ENC: usize = 10_000;

pub fn parse_date(s: &str) -> u64 {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map(|t| u64::try_from(t.unix_timestamp()).unwrap_or(0))
        .unwrap_or(0)
}

pub(crate) fn format_date(secs: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp(i64::try_from(secs).unwrap_or(i64::MAX))
        .ok()
        .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
        .unwrap_or_default()
}

/// The key an item's fields are encrypted with: its own key if it has one.
pub fn item_key(cipher: &Value, user_key: &SymmetricKey) -> Result<SymmetricKey, CryptoError> {
    match cipher.get("key").and_then(Value::as_str) {
        Some(k) if !k.is_empty() => user_key.decrypt_key(k),
        _ => Ok(user_key.clone()),
    }
}

/// Response-only properties that must not be echoed back in a write.
pub(crate) const RESPONSE_ONLY: &[&str] = &[
    "id",
    "revisionDate",
    "creationDate",
    "deletedDate",
    "object",
    "edit",
    "viewPassword",
    "permissions",
    "collectionIds",
    "attachments",
    "organizationUseTotp",
    "data",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_round_trip_and_items_use_their_own_key() {
        assert_eq!(parse_date(&format_date(1_700_000_000)), 1_700_000_000);
        assert_eq!(parse_date("not a date"), 0);
        let user = SymmetricKey::generate();
        let own = SymmetricKey::generate();
        let cipher = serde_json::json!({ "key": user.encrypt(&own.to_bytes()) });
        let got = item_key(&cipher, &user).unwrap();
        assert_eq!(got.decrypt_str(&own.encrypt_str("x")).unwrap().as_str(), "x");
        let plain = item_key(&serde_json::json!({ "key": null }), &user).unwrap();
        assert_eq!(plain.decrypt_str(&user.encrypt_str("y")).unwrap().as_str(), "y");
    }
}
