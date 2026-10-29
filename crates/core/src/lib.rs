//! Shared core of Passwords v2: crypto, data model, legacy import.

pub mod account;
pub mod aead;
pub mod backup;
pub mod collection;
pub mod csv_import;
mod error;
pub mod generator;
pub mod kdf;
pub mod legacy;
pub mod model;
pub mod proto;
pub mod totp;

pub use error::{Error, Result};
