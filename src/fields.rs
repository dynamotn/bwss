//! The names of bwss's tool fields (data model §3.2) and of its derived
//! attributes (ADR 0015).

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
/// opted in (`bwss derive on`).
pub const DERIVED: [&str; 4] = [A_ID, A_NAME, A_USERNAME, A_URI];
