//! Storage backends behind the keyring.

pub mod bitwarden;
pub mod memory;
pub mod ops;
pub mod registry;
mod runner;
#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::bw::crypto::SymmetricKey;
use crate::model::{CollectionData, ItemData, Snapshot};

/// Where the ACL lines of a backend's items can have come from.
pub enum AclTrust {
    /// Only from this process: every line was granted here (memory backend).
    Local,
    /// From any device that syncs the vault: a line counts here only once
    /// this device confirmed it (design §6). Decisions are keyed by this key.
    PerDevice(SymmetricKey),
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("wrong master password")]
    WrongPassword,
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    Rejected(String),
    /// The value source changed on the server since bwss read it (§5.6).
    #[error("{0}")]
    Conflict(String),
    #[error("the keyring is locked")]
    Locked,
}

#[async_trait]
pub trait Backend: Send + Sync {
    /// Unlocks with the master password and returns everything stored.
    async fn unlock(&self, password: &str) -> Result<Snapshot, BackendError>;
    /// Forgets all key material.
    async fn lock(&self);
    /// Pulls remote changes and flushes queued writes; `None` when nothing changed.
    async fn refresh(&self) -> Result<Option<Snapshot>, BackendError>;
    async fn create_collection(&self, label: &str) -> Result<CollectionData, BackendError>;
    /// Deletes a collection and its items. `items` are the ones the caller
    /// authorized; a backend never deletes any other item.
    async fn delete_collection(&self, id: &str, items: &[String]) -> Result<(), BackendError>;
    /// Stores a new or changed item.
    async fn put_item(&self, item: &ItemData) -> Result<(), BackendError>;
    async fn delete_item(&self, item: &ItemData) -> Result<(), BackendError>;
    /// How far the ACL lines of the items can be trusted on this device;
    /// [`BackendError::Locked`] while locked.
    async fn acl_trust(&self) -> Result<AclTrust, BackendError>;
    /// Human-readable status for `bwss status`.
    async fn describe(&self) -> String;
}
