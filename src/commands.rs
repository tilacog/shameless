use anyhow::{Context, Result, anyhow, bail};
use bip39::{Language, Mnemonic};
use blahaj::Sharks;
use zeroize::Zeroizing;

use crate::codec;
use crate::domain::{ShareIndex, SplitConfig};

/// Split a mnemonic into Shamir Secret Shares encoded as shamir39 mnemonics
///
/// Returns a vector of shamir39-encoded share mnemonics.
///
/// # Errors
/// Returns an error if mnemonic parsing fails, share creation fails, or encoding fails
pub fn split_mnemonic(mnemonic_str: &str, config: SplitConfig) -> Result<Vec<String>> {
    // Parse the input mnemonic
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str)
        .context("Failed to parse input mnemonic")?;

    let entropy = Zeroizing::new(mnemonic.to_entropy());

    // Extract threshold and share count from config
    let threshold = config.threshold();
    let num_shares = *config.share_count();

    // Create Sharks dealer for this threshold
    let sharks = Sharks(*threshold);

    // Create shares using blahaj
    let dealer = sharks.dealer(&entropy);
    let share_vec: Vec<_> = dealer.take(num_shares as usize).collect();

    // Encode each share as a shamir39 mnemonic
    let mut share_mnemonics = Vec::new();
    for (idx, share) in share_vec.iter().enumerate() {
        // Convert share to bytes
        let share_bytes = Zeroizing::new(Vec::from(share));

        // Create shamir39 mnemonic with embedded metadata
        // Safe: idx < num_shares (which is u8), so idx always fits in u8
        let idx_u8 =
            u8::try_from(idx).unwrap_or_else(|_| unreachable!("idx < num_shares fits in u8"));
        let share_mnemonic =
            codec::create_share(&share_bytes, threshold, ShareIndex::new(idx_u8)?)?;

        share_mnemonics.push(share_mnemonic.to_string());
    }

    Ok(share_mnemonics)
}

/// Combine Shamir Secret Shares to reconstruct the original mnemonic
///
/// Returns the reconstructed BIP39 mnemonic as a string.
///
/// # Errors
/// Returns an error if share decoding fails, share combination fails, or mnemonic reconstruction fails
pub fn combine_shares(share_strings: &[String]) -> Result<String> {
    if share_strings.is_empty() {
        bail!("No shares provided");
    }

    let mut parsed_shares = Vec::new();
    let mut threshold_from_shares = None;

    for (idx, share_str) in share_strings.iter().enumerate() {
        // Parse shamir39 mnemonic
        let (threshold, _share_index, share_data) = codec::parse_share(share_str)
            .with_context(|| format!("Failed to parse share #{}", idx + 1))?;

        // Validate threshold consistency
        match threshold_from_shares {
            None => {
                threshold_from_shares = Some(threshold);
            }
            Some(t) if t != threshold => {
                bail!(
                    "Share #{} has inconsistent threshold: expected {}, got {}",
                    idx + 1,
                    *t,
                    *threshold
                );
            }
            _ => {}
        }

        // Convert to blahaj Share
        let share = blahaj::Share::try_from(share_data.as_slice())
            .map_err(|e| anyhow!("Failed to create share from data: {e:?}"))?;

        parsed_shares.push(share);
    }

    let threshold = threshold_from_shares.ok_or_else(|| anyhow!("No valid shares found"))?;

    // Check if we have enough shares
    let threshold_val = *threshold;
    if parsed_shares.len() < threshold_val as usize {
        bail!(
            "Insufficient shares: need at least {}, but only {} provided",
            threshold_val,
            parsed_shares.len()
        );
    }

    // Combine shares using blahaj
    let sharks = Sharks(threshold_val);
    let recovered = Zeroizing::new(
        sharks
            .recover(&parsed_shares)
            .map_err(|e| anyhow!("Failed to recover secret: {e:?}"))?,
    );

    // Convert back to mnemonic
    let mnemonic = Mnemonic::from_entropy(&recovered)
        .context("Failed to create mnemonic from recovered entropy")?;

    Ok(mnemonic.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_mnemonic_invalid_input() {
        use crate::domain::{ShareCount, Threshold};
        let config =
            SplitConfig::new(Threshold::new(2).unwrap(), ShareCount::new(3).unwrap()).unwrap();
        let result = split_mnemonic("invalid mnemonic words here", config);

        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to parse input mnemonic")
        );
    }

    #[test]
    fn test_split_mnemonic_threshold_too_low() {
        use crate::domain::Threshold;
        // Threshold::new(1) will fail, so we test the constructor
        let result = Threshold::new(1);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Threshold must be at least 2"));
    }

    #[test]
    fn test_split_mnemonic_threshold_zero() {
        use crate::domain::Threshold;
        // Threshold::new(0) will fail, so we test the constructor
        let result = Threshold::new(0);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Threshold must be at least 2"));
    }

    #[test]
    fn test_split_mnemonic_12_word() {
        use crate::domain::{ShareCount, Threshold};
        let mnemonic_str =
            "army van defense carry jealous true garbage claim echo media make crunch";
        let config =
            SplitConfig::new(Threshold::new(2).unwrap(), ShareCount::new(3).unwrap()).unwrap();
        let result = split_mnemonic(mnemonic_str, config);
        assert!(result.is_ok());
        let shares = result.unwrap();
        assert_eq!(shares.len(), 3);
    }

    #[test]
    fn test_split_mnemonic_24_word() {
        use crate::domain::{ShareCount, Threshold};
        let mnemonic_str = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold";
        let config =
            SplitConfig::new(Threshold::new(3).unwrap(), ShareCount::new(5).unwrap()).unwrap();
        let result = split_mnemonic(mnemonic_str, config);
        assert!(result.is_ok());
        let shares = result.unwrap();
        assert_eq!(shares.len(), 5);
    }

    #[test]
    fn test_full_split_and_combine_round_trip() {
        use crate::domain::{ShareCount, Threshold};
        // This tests the full flow through the command functions
        let mnemonic_str =
            "army van defense carry jealous true garbage claim echo media make crunch";

        // Use the split_mnemonic function directly
        let threshold = Threshold::new(2).unwrap();
        let share_count = ShareCount::new(3).unwrap();
        let config = SplitConfig::new(threshold, share_count).unwrap();

        let share_strings = split_mnemonic(mnemonic_str, config).unwrap();
        assert_eq!(share_strings.len(), 3);

        // Take 2 shares (threshold is 2)
        let selected_shares = vec![share_strings[0].clone(), share_strings[1].clone()];

        // Use the combine_shares function directly
        let recovered_mnemonic = combine_shares(&selected_shares).unwrap();

        assert_eq!(mnemonic_str, recovered_mnemonic);
    }

    #[test]
    fn test_split_mnemonic_insufficient_shares() {
        use crate::domain::{ShareCount, Threshold};
        let mnemonic_str =
            "army van defense carry jealous true garbage claim echo media make crunch";

        // Create shares with threshold 3
        let threshold = Threshold::new(3).unwrap();
        let share_count = ShareCount::new(5).unwrap();
        let config = SplitConfig::new(threshold, share_count).unwrap();

        let share_strings = split_mnemonic(mnemonic_str, config).unwrap();
        assert_eq!(share_strings.len(), 5);

        // Try to combine with only 2 shares (threshold is 3)
        let insufficient_shares = vec![share_strings[0].clone(), share_strings[1].clone()];
        let result = combine_shares(&insufficient_shares);

        // Should error with insufficient shares
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Insufficient shares")
        );
    }

    #[test]
    fn test_combine_shares_empty_input() {
        let empty_shares: Vec<String> = vec![];
        let result = combine_shares(&empty_shares);
        assert!(result.is_err());
    }

    #[test]
    fn test_combine_shares_invalid_shamir39() {
        // Invalid version word
        let invalid_shares = vec!["invalid word word word".to_string()];
        let result = combine_shares(&invalid_shares);
        assert!(result.is_err());
    }

    #[test]
    fn test_combine_shares_inconsistent_threshold() {
        use crate::domain::Threshold;
        // Create two shares with different thresholds
        let share_data = vec![0u8; 20];
        let share1 = codec::create_share(
            &share_data,
            Threshold::new(2).unwrap(),
            ShareIndex::new(0).unwrap(),
        )
        .unwrap()
        .to_string();
        let share2 = codec::create_share(
            &share_data,
            Threshold::new(3).unwrap(),
            ShareIndex::new(1).unwrap(),
        )
        .unwrap()
        .to_string();

        let result = combine_shares(&[share1, share2]);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("inconsistent threshold")
        );
    }
}
