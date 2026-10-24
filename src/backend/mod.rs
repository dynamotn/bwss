//! Storage backends behind the keyring.

pub mod bitwarden;
pub mod memory;
pub mod ops;
pub mod registry;
mod runner;
#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::model::{CollectionData, ItemData, Snapshot};

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
    async fn delete_collection(&self, id: &str) -> Result<(), BackendError>;
    /// Stores a new or changed item.
    async fn put_item(&self, item: &ItemData) -> Result<(), BackendError>;
    async fn delete_item(&self, item: &ItemData) -> Result<(), BackendError>;
    /// Human-readable status for `bwss status`.
    async fn describe(&self) -> String;
}
