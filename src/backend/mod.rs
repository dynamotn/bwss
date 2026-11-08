//! Storage backends behind the keyring.

pub mod bitwarden;
pub mod memory;
pub mod ops;
pub mod registry;
pub(crate) mod runner;
#[cfg(test)]
mod tests;
mod worker;

use async_trait::async_trait;

use dybw_core::crypto::KdfParams;
use dybw_core::profile::KdfSource;
use dybw_core::vault::write::{HistoryAnswer, HistoryQuestion};

use crate::bw::crypto::SymmetricKey;
use crate::model::{CollectionData, ItemData, Snapshot};

/// KDF parameters as the user reads them in the web vault.
pub fn kdf_text(kdf: &KdfParams) -> String {
    match *kdf {
        KdfParams::Pbkdf2 { iterations } => format!("PBKDF2, {iterations} iterations"),
        KdfParams::Argon2id { iterations, memory_mib, parallelism } => {
            format!("Argon2id, {iterations} iterations, {memory_mib} MiB, parallelism {parallelism}")
        }
    }
}

/// What a history question asks about (ADR 0016): the item, and for an
/// eviction the password that would be lost.
pub fn question_text(label: &str, q: HistoryQuestion) -> String {
    match q {
        HistoryQuestion::FirstWriteBack => {
            format!("the first change from this device to the login password of \"{label}\"")
        }
        HistoryQuestion::EvictsForeign => format!(
            "a change to the login password of \"{label}\", whose password history is full: the oldest password \
             in its history, which this device did not write, would be lost"
        ),
    }
}

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
    /// The KDF offered is weaker than the one pinned on this device (ADR 0017).
    #[error(
        "the {kdf_source} ({}) is weaker than the one pinned on this device ({}): check it in the web vault, \
         then run `bwss kdf accept`",
        kdf_text(.offered),
        kdf_text(.pinned)
    )]
    KdfWeakened { pinned: KdfParams, offered: KdfParams, kdf_source: KdfSource },
    /// The signed security state is older than the one this device saw (ADR 0019).
    #[error(
        "the account's security state is older than the one this device saw (seen version {seen}, offered \
         {offered}): if this profile moved to another server or account, run `bwss security accept {offered}`"
    )]
    SecurityDowngrade { seen: u64, offered: u64 },
    /// The security state is missing or invalid, or the version saved on this device is unreadable.
    #[error("{0}")]
    SecurityState(String),
    #[error(
        "the KDF pin saved on this device is unreadable: check the KDF in the web vault, then run `bwss kdf accept`"
    )]
    KdfPinUnreadable,
    /// Nothing was written: the user must answer this question first (ADR 0016).
    #[error("the write needs your answer first ({})", .0.code())]
    Ask(HistoryQuestion),
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
    /// `put_item` again, with the user's answer to the question it asked
    /// ([`BackendError::Ask`], ADR 0016). A backend that never asks stores it.
    async fn put_item_answered(
        &self,
        item: &ItemData,
        _answer: (HistoryQuestion, HistoryAnswer),
    ) -> Result<(), BackendError> {
        self.put_item(item).await
    }
    /// The history question the queued change of item `id` waits on
    /// (ADR 0016); a backend that never asks has none.
    async fn queued_question(&self, _id: &str) -> Result<Option<HistoryQuestion>, BackendError> {
        Ok(None)
    }
    /// Puts the user's confirmed answer on the queued change of `id`; `None`
    /// cancels its value change. Only the daemon calls it, once the user
    /// confirmed the answer in its own pinentry (`cancel` needs none).
    async fn answer_queued(
        &self,
        _id: &str,
        _question: HistoryQuestion,
        _answer: Option<HistoryAnswer>,
    ) -> Result<(), BackendError> {
        Err(BackendError::Rejected("no queued change waits for an answer".into()))
    }
    async fn delete_item(&self, item: &ItemData) -> Result<(), BackendError>;
    /// How far the ACL lines of the items can be trusted on this device;
    /// [`BackendError::Locked`] while locked.
    async fn acl_trust(&self) -> Result<AclTrust, BackendError>;
    /// Human-readable status for `bwss status`.
    async fn describe(&self) -> String;
}
