use anyhow::Result;
use clap::Parser;

use shameless::cli::{Cli, Commands};
use shameless::commands::{combine_shares, split_mnemonic};
use shameless::shamir39::{ShareCount, SplitConfig};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Split {
            mnemonic,
            shares,
            threshold,
        } => {
            // Validate share count and create config
            let share_count = ShareCount::new(shares)?;
            let config = SplitConfig::new(threshold, share_count)?;

            split_mnemonic(&mnemonic, config)?;
        }
        Commands::Combine { shares } => {
            if shares.is_empty() {
                return Err(anyhow::anyhow!("No shares provided"));
            }

            combine_shares(&shares)?;
        }
    }

    Ok(())
}
