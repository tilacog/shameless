//! Property-based tests for shameless
//!
//! This test suite uses quickcheck to verify correctness across random inputs,
//! including random mnemonics, thresholds, and share selections.
//!
//! Run with: cargo test --test proptests

#[path = "proptests/shamir39.rs"]
mod shamir39;

#[path = "proptests/split_combine.rs"]
mod split_combine;
