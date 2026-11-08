//! The thread that owns the vault. dybw-core's futures are `!Send`, so every
//! object behind the Bitwarden backend lives on one thread, in a
//! `current_thread` runtime and a `LocalSet`; the daemon reaches it through
//! [`WorkerHandle`], which is `Send + Sync`.

use std::rc::Rc;

use dybw_core::vault::write::{HistoryAnswer, HistoryQuestion};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use super::bitwarden::Bitwarden;
use super::{AclTrust, BackendError};
use crate::model::{CollectionData, ItemData, Snapshot};

type Reply<T> = oneshot::Sender<Result<T, BackendError>>;

/// One request to the worker: one variant per [`Backend`] method.
pub(crate) enum Command {
    Unlock(Zeroizing<String>, Reply<Snapshot>),
    Lock(oneshot::Sender<()>),
    Refresh(Reply<Option<Snapshot>>),
    CreateCollection(String, Reply<CollectionData>),
    DeleteCollection(String, Vec<String>, Reply<()>),
    PutItem(ItemData, Option<(HistoryQuestion, HistoryAnswer)>, Reply<()>),
    QueuedQuestion(String, Reply<Option<HistoryQuestion>>),
    AnswerQueued(String, HistoryQuestion, Option<HistoryAnswer>, Reply<()>),
    DeleteItem(ItemData, Reply<()>),
    AclTrust(Reply<AclTrust>),
    Describe(oneshot::Sender<String>),
    /// Panics; with `true`, so does the lock that follows.
    #[cfg(test)]
    Panic(bool, oneshot::Sender<()>),
}

#[cfg(test)]
thread_local! {
    /// Set by `Command::Panic(true, _)`: the lock after that panic panics too.
    static PANIC_AGAIN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn stopped() -> BackendError {
    BackendError::Unavailable("bwss's vault worker stopped; it was restarted locked".into())
}

/// The sending side: cheap to clone, shared by every D-Bus task.
#[derive(Clone)]
pub(crate) struct WorkerHandle(mpsc::Sender<Command>);

impl WorkerHandle {
    /// Sends a command and waits for its answer. A worker that is gone, or a
    /// command that panicked, fails the call instead of hanging it.
    pub(crate) async fn call<T>(&self, command: impl FnOnce(oneshot::Sender<T>) -> Command) -> Result<T, BackendError> {
        let (reply, answer) = oneshot::channel();
        self.0.send(command(reply)).await.map_err(|_| stopped())?;
        answer.await.map_err(|_| stopped())
    }

    /// A handle whose worker is gone.
    #[cfg(test)]
    pub(crate) fn stopped() -> Self {
        Self(mpsc::channel(1).0)
    }
}

pub(crate) struct Worker {
    vault: Rc<Bitwarden>,
}

impl Worker {
    /// Starts the worker thread and builds the vault there with `init`.
    pub(crate) fn spawn(
        init: impl FnOnce() -> anyhow::Result<Bitwarden> + Send + 'static,
    ) -> anyhow::Result<WorkerHandle> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let (commands, inbox) = mpsc::channel(64);
        let (ready, started) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new().name("bwss-vault".into()).spawn(move || match init() {
            Ok(vault) => {
                let _ = ready.send(Ok(()));
                Worker { vault: Rc::new(vault) }.run(&runtime, inbox);
            }
            Err(e) => {
                let _ = ready.send(Err(e));
            }
        })?;
        started.recv()??;
        Ok(WorkerHandle(commands))
    }

    /// Serves commands until every handle is dropped. Each command runs as a
    /// task of its own, so a `lock` is handled between two awaits of a running
    /// unlock or flush, and a panic stays inside its task: the vault is then
    /// locked and the worker goes on. If that lock panics too, the worker
    /// stops: its tasks and the vault are dropped, and every call fails.
    fn run(self, runtime: &tokio::runtime::Runtime, mut inbox: mpsc::Receiver<Command>) {
        let local = tokio::task::LocalSet::new();
        let stop = Rc::new(tokio::sync::Notify::new());
        local.block_on(runtime, async move {
            loop {
                let next = tokio::select! {
                    command = inbox.recv() => command,
                    () = stop.notified() => None,
                };
                let Some(command) = next else { break };
                let (vault, stop) = (self.vault.clone(), stop.clone());
                tokio::task::spawn_local(async move {
                    let task = tokio::task::spawn_local(serve(vault.clone(), command));
                    if task.await.is_err_and(|e| e.is_panic()) {
                        tracing::error!("a vault command panicked; the keyring is locked");
                        let locking = async move {
                            #[cfg(test)]
                            if PANIC_AGAIN.take() {
                                panic!("a test made the lock after a panic panic too");
                            }
                            vault.lock().await;
                        };
                        if tokio::task::spawn_local(locking).await.is_err() {
                            // Fail closed: the keys may still be held, so nothing is served again.
                            tracing::error!("locking the keyring after a panic panicked too; the vault worker stops");
                            stop.notify_one();
                        }
                    }
                });
            }
        });
    }
}

/// Runs one command. A caller that stopped waiting is no error.
async fn serve(vault: Rc<Bitwarden>, command: Command) {
    match command {
        Command::Unlock(password, reply) => {
            let _ = reply.send(vault.unlock_and_follow(&password).await);
        }
        Command::Lock(reply) => {
            vault.lock().await;
            let _ = reply.send(());
        }
        Command::Refresh(reply) => {
            let _ = reply.send(vault.refresh().await);
        }
        Command::CreateCollection(label, reply) => {
            let _ = reply.send(vault.create_collection(&label).await);
        }
        Command::DeleteCollection(id, items, reply) => {
            let _ = reply.send(vault.delete_collection(&id, &items).await);
        }
        Command::PutItem(item, answer, reply) => {
            let _ = reply.send(vault.put_item_answered(&item, answer).await);
        }
        Command::QueuedQuestion(id, reply) => {
            let _ = reply.send(vault.queued_question(&id).await);
        }
        Command::AnswerQueued(id, question, answer, reply) => {
            let _ = reply.send(vault.answer_queued(&id, question, answer).await);
        }
        Command::DeleteItem(item, reply) => {
            let _ = reply.send(vault.delete_item(&item).await);
        }
        Command::AclTrust(reply) => {
            let _ = reply.send(vault.acl_trust().await);
        }
        Command::Describe(reply) => {
            let _ = reply.send(vault.describe().await);
        }
        #[cfg(test)]
        Command::Panic(again, _reply) => {
            PANIC_AGAIN.set(again);
            panic!("a test made the vault worker panic")
        }
    }
}
