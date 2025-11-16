use clap::{Parser, Subcommand};

use crate::shamir39::Threshold;

/// Validates that threshold is at least 2
/// A threshold of 1 defeats the purpose of Shamir Secret Sharing
/// (any single share would be able to recover the entire secret)
fn validate_threshold(s: &str) -> Result<Threshold, String> {
    let value: u8 = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid number"))?;

    Threshold::new(value).map_err(|e| e.to_string())
}

#[derive(Parser)]
#[command(name = "shameless")]
#[command(about = "Split Ethereum mnemonics into Shamir Secret Shares using shamir39 encoding")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Split a mnemonic into shares
    Split {
        /// Number of shares to create
        #[arg(short, long)]
        shares: u8,

        /// Threshold: minimum number of shares needed to reconstruct (must be >= 2)
        #[arg(short, long, value_parser = validate_threshold)]
        threshold: Threshold,
    },
    /// Combine shares to reconstruct the original mnemonic
    Combine,
}
