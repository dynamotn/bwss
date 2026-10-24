//! Custom-field primitives: decrypt names without touching values, and one
//! value at a time, so secrets are decrypted only when asked for.

use serde_json::Value;
use zeroize::Zeroizing;

use super::crypto::{CryptoError, SymmetricKey};

pub const PREFIX: &str = "bwss:";
pub const F_ID: &str = "bwss:id";
pub const F_PASSWORD: &str = "bwss:password";
pub const F_LABEL: &str = "bwss:label";
pub const F_ATTR: &str = "bwss:attr:";
pub const F_COLLECTION: &str = "bwss:collection";
pub const F_CONTENT_TYPE: &str = "bwss:content-type";
pub const F_ENCODING: &str = "bwss:encoding";
pub const F_LOCATION: &str = "bwss:location";
pub const F_ACL: &str = "bwss:acl";
pub const F_CREATED: &str = "bwss:created";
pub const F_KIND: &str = "bwss:kind";

/// Derived attributes.
pub const A_ID: &str = "bwss:id";
pub const A_NAME: &str = "bwss:name";
pub const A_USERNAME: &str = "bwss:username";
pub const A_URI: &str = "bwss:uri";
/// Every derived attribute: kept out of the locked index unless this device
/// opted in (`bwss index derived on`).
pub const DERIVED: [&str; 4] = [A_ID, A_NAME, A_USERNAME, A_URI];

/// What the first `bwss:location` field says, compared after trimming (spec
/// §3.2, §6.4, ADR 0010, ADR 0014).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    /// No field, or a value empty or blank after trimming.
    Absent,
    /// `notes` after trimming: the notes hold bwss's secret.
    Notes,
    /// Any other value, which this version does not know.
    Unknown,
}

impl Location {
    pub fn classify(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            None | Some("") => Self::Absent,
            Some("notes") => Self::Notes,
            Some(_) => Self::Unknown,
        }
    }
}

/// What the first `bwss:encoding` field says (spec §3.2, ADR 0014).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// No field, or a value blank after trimming.
    Absent,
    /// `base64` after trimming.
    Base64,
    /// Any other value, which this version does not know.
    Unknown,
}

impl Encoding {
    pub fn classify(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            None | Some("") => Self::Absent,
            Some("base64") => Self::Base64,
            Some(_) => Self::Unknown,
        }
    }
}

fn field_array(cipher: &Value) -> &[Value] {
    cipher.get("fields").and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// Decrypts the name of every field, in order. A `null` name is `None`.
/// Values are not touched.
pub fn field_names(cipher: &Value, key: &SymmetricKey) -> Result<Vec<Option<String>>, CryptoError> {
    field_array(cipher)
        .iter()
        .map(|f| match f.get("name").and_then(Value::as_str) {
            Some(s) => key.decrypt_str(s).map(|n| Some(n.to_string())),
            None => Ok(None),
        })
        .collect()
}

/// Decrypts the value of the field at `index`. A `null` value is `""`; an
/// index with no field is a caller bug and gives `Malformed`.
pub fn field_value(cipher: &Value, index: usize, key: &SymmetricKey) -> Result<Zeroizing<String>, CryptoError> {
    let field = field_array(cipher).get(index).ok_or(CryptoError::Malformed)?;
    match field.get("value").and_then(Value::as_str) {
        Some(s) => key.decrypt_str(s),
        None => Ok(Zeroizing::new(String::new())),
    }
}

/// Index of the first field called `name`.
pub fn first_index(names: &[Option<String>], name: &str) -> Option<usize> {
    names.iter().position(|n| n.as_deref() == Some(name))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn location_classes() {
        assert_eq!(Location::classify(None), Location::Absent);
        for blank in ["", " ", "  ", "\t\n"] {
            assert_eq!(Location::classify(Some(blank)), Location::Absent, "{blank:?}");
        }
        for mark in ["notes", " notes ", "notes\n", "\tnotes"] {
            assert_eq!(Location::classify(Some(mark)), Location::Notes, "{mark:?}");
        }
        for other in ["Notes", "NOTES", "attachment", "field", "no tes"] {
            assert_eq!(Location::classify(Some(other)), Location::Unknown, "{other:?}");
        }
    }

    #[test]
    fn encoding_classes() {
        assert_eq!(Encoding::classify(None), Encoding::Absent);
        for blank in ["", " ", "\t\n"] {
            assert_eq!(Encoding::classify(Some(blank)), Encoding::Absent, "{blank:?}");
        }
        for mark in ["base64", " base64\n", "\tbase64 "] {
            assert_eq!(Encoding::classify(Some(mark)), Encoding::Base64, "{mark:?}");
        }
        for other in ["Base64", "hex", "base 64"] {
            assert_eq!(Encoding::classify(Some(other)), Encoding::Unknown, "{other:?}");
        }
    }

    #[test]
    fn names_only_are_decrypted() {
        let key = SymmetricKey::generate();
        let c = json!({ "fields": [
            { "type": 0, "name": key.encrypt_str("bwss:id"), "value": "2.garbage|x|y" },
        ]});
        assert_eq!(field_names(&c, &key).unwrap(), vec![Some("bwss:id".into())]);
    }

    #[test]
    fn null_names_and_values() {
        let key = SymmetricKey::generate();
        let c = json!({ "fields": [
            { "type": 0, "name": null, "value": key.encrypt_str("v") },
            { "type": 0, "name": key.encrypt_str("bwss:id"), "value": null },
        ]});
        assert_eq!(field_names(&c, &key).unwrap(), vec![None, Some("bwss:id".into())]);
        assert_eq!(field_value(&c, 1, &key).unwrap().as_str(), "");
        assert_eq!(field_value(&c, 0, &key).unwrap().as_str(), "v");
        assert_eq!(first_index(&field_names(&c, &key).unwrap(), "bwss:id"), Some(1));
        assert_eq!(field_value(&c, 2, &key).unwrap_err(), CryptoError::Malformed);
    }

    #[test]
    fn no_fields_key_is_no_fields() {
        let key = SymmetricKey::generate();
        assert!(field_names(&json!({ "fields": null }), &key).unwrap().is_empty());
        assert!(field_names(&json!({}), &key).unwrap().is_empty());
    }
}
