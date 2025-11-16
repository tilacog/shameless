use std::io::{self, BufRead};

use anyhow::{Context, Result};
use clap::Parser;
use zeroize::Zeroizing;

use shameless::cli::{Cli, Commands};
use shameless::commands::{combine_shares, split_mnemonic};
use shameless::shamir39::{ShareCount, SplitConfig};

/// Read a mnemonic securely from stdin (hidden input when TTY available)
fn read_mnemonic() -> Result<String> {
    // Try to use TTY for secure input
    if atty::is(atty::Stream::Stdin) {
        eprintln!("Enter mnemonic (12 or 24 words):");
        rpassword::read_password().context("Failed to read mnemonic from stdin")
    } else {
        // Non-interactive mode (piped input) - read directly from stdin
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        let mut mnemonic = String::new();
        handle
            .read_line(&mut mnemonic)
            .context("Failed to read mnemonic from stdin")?;
        Ok(mnemonic.trim().to_string())
    }
}

/// Read shares securely from stdin (hidden input when TTY available)
/// User should input shares one per line, followed by an empty line to finish
fn read_shares() -> Result<Vec<String>> {
    let mut shares = Vec::new();

    if atty::is(atty::Stream::Stdin) {
        // Interactive mode - use rpassword for hidden input
        eprintln!("Enter shamir39 shares (one per line, empty line to finish):");

        loop {
            let share = rpassword::read_password().context("Failed to read share from stdin")?;

            // Empty line signals we're done
            if share.trim().is_empty() {
                break;
            }

            shares.push(share.trim().to_string());
        }
    } else {
        // Non-interactive mode - read from stdin
        let stdin = io::stdin();
        let handle = stdin.lock();

        for line in handle.lines() {
            let line = line.context("Failed to read line from stdin")?;
            let trimmed = line.trim();

            // Empty line signals we're done
            if trimmed.is_empty() {
                break;
            }

            shares.push(trimmed.to_string());
        }
    }

    if shares.is_empty() {
        anyhow::bail!("No shares provided");
    }

    Ok(shares)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Split { shares, threshold } => {
            // Read mnemonic securely from stdin
            let mnemonic = Zeroizing::new(read_mnemonic()?);

            // Validate share count and create config
            let share_count = ShareCount::new(shares)?;
            let config = SplitConfig::new(threshold, share_count)?;

            split_mnemonic(&mnemonic, config)?;
        }
        Commands::Combine => {
            // Read shares securely from stdin
            let shares = read_shares()?;
            combine_shares(&shares)?;
        }
    }

    Ok(())
}
