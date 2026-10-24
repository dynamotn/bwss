//! In-memory backend for tests and for trying bwss without a Bitwarden account.

use std::sync::Mutex;

use async_trait::async_trait;

use super::{Backend, BackendError};
use crate::model::{CollectionData, ItemData, LOGIN_COLLECTION, Snapshot, now};

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
            data: Mutex::new(Snapshot { collections: vec![login], items: vec![] }),
            unlocked: Mutex::new(false),
        }
    }

    fn check(&self) -> Result<(), BackendError> {
        if *self.unlocked.lock().unwrap() { Ok(()) } else { Err(BackendError::Locked) }
    }
}

#[async_trait]
impl Backend for MemoryBackend {
    async fn unlock(&self, password: &str) -> Result<Snapshot, BackendError> {
        if password != self.password {
            return Err(BackendError::WrongPassword);
        }
        *self.unlocked.lock().unwrap() = true;
        Ok(self.data.lock().unwrap().clone())
    }

    async fn lock(&self) {
        *self.unlocked.lock().unwrap() = false;
    }

    async fn refresh(&self) -> Result<Option<Snapshot>, BackendError> {
        self.check()?;
        Ok(None)
    }

    async fn create_collection(&self, label: &str) -> Result<CollectionData, BackendError> {
        self.check()?;
        let mut data = self.data.lock().unwrap();
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
        let mut data = self.data.lock().unwrap();
        if data.items.iter().any(|i| i.collection == id && !items.contains(&i.id)) {
            return Err(BackendError::Rejected("the collection changed meanwhile; try again".into()));
        }
        data.collections.retain(|c| c.id != id);
        data.items.retain(|i| i.collection != id);
        Ok(())
    }

    async fn put_item(&self, item: &ItemData) -> Result<(), BackendError> {
        self.check()?;
        let mut data = self.data.lock().unwrap();
        data.items.retain(|i| i.id != item.id);
        data.items.push(item.clone());
        Ok(())
    }

    async fn delete_item(&self, item: &ItemData) -> Result<(), BackendError> {
        self.check()?;
        self.data.lock().unwrap().items.retain(|i| i.id != item.id);
        Ok(())
    }

    async fn describe(&self) -> String {
        format!("memory backend, {} item(s)", self.data.lock().unwrap().items.len())
    }
}
