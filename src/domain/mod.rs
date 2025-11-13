//! Domain types for Shamir Secret Sharing
//!
//! This module contains validated newtypes and configuration for secure secret sharing:
//! - [`Threshold`] - Minimum shares required for reconstruction (2..=255)
//! - [`ShareIndex`] - Share identifier (0..=254)
//! - [`ShareCount`] - Total number of shares to create (1..=254)
//! - [`SplitConfig`] - Validated threshold and share count pair

mod config;
mod share_count;
mod share_index;
mod threshold;

pub use config::SplitConfig;
pub use share_count::ShareCount;
pub use share_index::ShareIndex;
pub use threshold::Threshold;
