//! Crypto and vault format for Wardlet.
//!
//! The `wardlet` binary is a thin command-line wrapper over this library.
//! User files stay where they are. This crate handles the master identity
//! and the key directory that unlocks it.

pub mod crypto;
pub mod error;
pub mod master;
pub mod ops;
pub mod vault;

pub use error::Error;
