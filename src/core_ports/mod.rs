//! Host ports for dybw-core: what the core asks of bwss (HTTP, files, time,
//! randomness, the Argon2id KDF). Wired in by later tasks.

pub mod clock;
pub mod events;
pub mod http;
pub mod kdf;
pub mod random;
pub mod storage;
