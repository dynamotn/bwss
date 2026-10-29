//! In-memory backend for tests and for trying bwss without a Bitwarden account.

use std::sync::Mutex;

use async_trait::async_trait;

use super::{AclTrust, Backend, BackendError};
use crate::model::{CollectionData, ItemData, LOGIN_COLLECTION, Snapshot, now};
use crate::sync::lock;

pub struct MemoryBackend {
    password: String,
    data: Mutex<Snapshot>,
    unlocked: Mutex<bool>,
}

impl MemoryBackend {
    pub fn new(password: impl Into<String>) -> Self {
        let login =
            CollectionData { id: LOGIN_COLLECTION.into(), label: "Login".into(), created: now(), modified: now() };
        MemoryBackend {
            password: password.into(),
            data: Mutex::new(Snapshot { collections: vec![login], items: vec![], ..Default::default() }),
            unlocked: Mutex::new(false),
        }
    }

    fn check(&self) -> Result<(), BackendError> {
        if *lock(&self.unlocked) { Ok(()) } else { Err(BackendError::Locked) }
    }
}

#[async_trait]
impl Backend for MemoryBackend {
    async fn unlock(&self, password: &str) -> Result<Snapshot, BackendError> {
        if password != self.password {
            return Err(BackendError::WrongPassword);
        }
        *lock(&self.unlocked) = true;
        Ok(lock(&self.data).clone())
    }

    async fn lock(&self) {
        *lock(&self.unlocked) = false;
    }

    async fn refresh(&self) -> Result<Option<Snapshot>, BackendError> {
        self.check()?;
        Ok(None)
    }

    async fn create_collection(&self, label: &str) -> Result<CollectionData, BackendError> {
        self.check()?;
        let mut data = lock(&self.data);
        let mut id = label.trim().to_lowercase();
        while data.collections.iter().any(|c| c.id == id) {
            id.push('_');
        }
        let c = CollectionData { id, label: label.into(), created: now(), modified: now() };
        data.collections.push(c.clone());
        Ok(c)
    }

    async fn delete_collection(&self, id: &str, items: &[String]) -> Result<(), BackendError> {
        self.check()?;
        let mut data = lock(&self.data);
        if data.items.iter().any(|i| i.collection == id && !items.contains(&i.id)) {
            return Err(BackendError::Rejected("the collection changed meanwhile; try again".into()));
        }
        data.collections.retain(|c| c.id != id);
        data.items.retain(|i| i.collection != id);
        Ok(())
    }

    async fn put_item(&self, item: &ItemData) -> Result<(), BackendError> {
        self.check()?;
        let mut data = lock(&self.data);
        data.items.retain(|i| i.id != item.id);
        data.items.push(item.clone());
        Ok(())
    }

    async fn delete_item(&self, item: &ItemData) -> Result<(), BackendError> {
        self.check()?;
        lock(&self.data).items.retain(|i| i.id != item.id);
        Ok(())
    }

    async fn acl_trust(&self) -> Result<AclTrust, BackendError> {
        self.check()?;
        Ok(AclTrust::Local)
    }

    async fn describe(&self) -> String {
        format!("memory backend, {} item(s)", lock(&self.data).items.len())
    }
}
