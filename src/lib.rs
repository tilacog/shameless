// Internal library for testing purposes
// Not intended for external use as a library

#[cfg(feature = "cli")]
pub mod cli;

pub mod codec;
pub mod commands;
pub mod domain;

// WASM bindings (only for wasm32 target)
#[cfg(target_arch = "wasm32")]
pub mod wasm;

// Backward compatibility: re-export everything under shamir39 module name
pub mod shamir39 {
    //! Compatibility module - re-exports from domain and codec modules
    pub use crate::codec::{Shamir39Mnemonic, VERSION_WORD, create_share, parse_share};
    pub use crate::domain::{ShareCount, ShareIndex, SplitConfig, Threshold};
}
