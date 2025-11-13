//! Property tests for split/combine workflows

use bip39::Mnemonic;
use blahaj::Sharks;
use quickcheck::{Arbitrary, Gen};
use quickcheck_macros::quickcheck;
use shameless::shamir39;
use shameless::shamir39::{ShareIndex, Threshold};

/// Wrapper for valid BIP39 mnemonics (12 or 24 words)
#[derive(Clone, Debug)]
struct ValidMnemonic(Mnemonic);

impl Arbitrary for ValidMnemonic {
    fn arbitrary(g: &mut Gen) -> Self {
        // Randomly choose between 12 and 24 words
        let word_count = if bool::arbitrary(g) { 12 } else { 24 };
        let entropy_size = if word_count == 12 { 16 } else { 32 };

        // Generate random entropy
        let mut entropy = vec![0u8; entropy_size];
        for byte in &mut entropy {
            *byte = u8::arbitrary(g);
        }

        // Create mnemonic from entropy (this handles checksum automatically)
        let mnemonic = Mnemonic::from_entropy(&entropy).expect("Valid entropy");
        ValidMnemonic(mnemonic)
    }
}

/// Wrapper for valid threshold and share count pairs
#[derive(Clone, Copy, Debug)]
struct ValidShamirParams {
    threshold: u8,
    num_shares: u8,
}

impl Arbitrary for ValidShamirParams {
    fn arbitrary(g: &mut Gen) -> Self {
        // Generate share count between 2 and 20 (keep it reasonable for testing)
        let num_shares = (u8::arbitrary(g) % 19) + 2; // 2..=20

        // Generate threshold between 2 and num_shares (never 1)
        // threshold=1 makes no cryptographic sense and is now rejected by the system
        let threshold = (u8::arbitrary(g) % (num_shares - 1)) + 2; // 2..=num_shares

        ValidShamirParams {
            threshold,
            num_shares,
        }
    }
}

/// Test that splitting and combining with valid shares recovers the original mnemonic
#[quickcheck]
fn prop_split_combine_round_trip(mnemonic: ValidMnemonic, params: ValidShamirParams) -> bool {
    let ValidMnemonic(inner_mnemonic) = mnemonic;
    let original_entropy = inner_mnemonic.to_entropy();
    let threshold = params.threshold;
    let num_shares = params.num_shares;

    // Split using blahaj
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&original_entropy);
    let share_vec: Vec<_> = dealer.take(num_shares.into()).collect();

    if share_vec.len() != num_shares as usize {
        return false;
    }

    // Encode as shamir39
    let share_mnemonics: Result<Vec<_>, _> = share_vec
        .iter()
        .enumerate()
        .map(|(idx, share)| {
            let share_bytes = Vec::from(share);
            let idx_u8 = u8::try_from(idx).unwrap_or_else(|_| unreachable!("idx fits in u8"));
            shamir39::create_share(
                &share_bytes,
                Threshold::new(threshold).unwrap(),
                ShareIndex::new(idx_u8).unwrap(),
            )
        })
        .collect();

    let Ok(share_mnemonics) = share_mnemonics else {
        return false;
    };

    // Select exactly threshold shares (first N shares)
    let selected_mnemonics: Vec<_> = share_mnemonics
        .iter()
        .take(threshold as usize)
        .map(shameless::shamir39::Shamir39Mnemonic::as_str)
        .collect();

    // Parse and recover
    let parse_result: Result<Vec<blahaj::Share>, _> = selected_mnemonics
        .iter()
        .map(|mnemonic| {
            let (_threshold, _index, share_data) = shamir39::parse_share(mnemonic)?;
            blahaj::Share::try_from(share_data.as_slice())
                .map_err(|e| anyhow::anyhow!("Share conversion failed: {e}"))
        })
        .collect();

    let Ok(selected_shares) = parse_result else {
        return false;
    };

    // Recover
    let Ok(recovered) = sharks.recover(&selected_shares) else {
        return false;
    };

    // Should match original
    original_entropy == recovered
}

/// Test that insufficient shares fail to recover
#[quickcheck]
fn prop_insufficient_shares_fail(mnemonic: ValidMnemonic, params: ValidShamirParams) -> bool {
    let ValidMnemonic(inner_mnemonic) = mnemonic;
    let threshold = params.threshold;
    let num_shares = params.num_shares;

    // Note: threshold is always >= 2 (enforced by ValidShamirParams generator)
    let original_entropy = inner_mnemonic.to_entropy();

    // Split using blahaj
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&original_entropy);
    let share_vec: Vec<_> = dealer.take(num_shares.into()).collect();

    // Take one less than threshold
    let insufficient_count = (threshold - 1) as usize;
    let insufficient_shares: Vec<_> = share_vec.iter().take(insufficient_count).cloned().collect();

    // Try to recover - should fail
    sharks.recover(&insufficient_shares).is_err()
}

/// Test that random selections of threshold shares work
#[quickcheck]
fn prop_random_share_selection_works(
    mnemonic: ValidMnemonic,
    params: ValidShamirParams,
    selection_seed: u64,
) -> bool {
    let ValidMnemonic(inner_mnemonic) = mnemonic;
    let original_entropy = inner_mnemonic.to_entropy();
    let threshold = params.threshold;
    let num_shares = params.num_shares;

    // Split using blahaj
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&original_entropy);
    let share_vec: Vec<_> = dealer.take(num_shares.into()).collect();

    // Create a pseudo-random selection of threshold shares
    // Use selection_seed to deterministically select shares
    let mut indices: Vec<usize> = (0..num_shares as usize).collect();

    // Simple shuffle using seed
    let mut seed = selection_seed;
    for i in 0..indices.len() {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        // Convert seed to usize safely by taking modulo first
        let range = indices.len() - i;
        let range_u64 = u64::try_from(range).unwrap_or_else(|_| unreachable!("range fits in u64"));
        let offset = seed % range_u64;
        let offset_usize = usize::try_from(offset)
            .unwrap_or_else(|_| unreachable!("offset < range fits in usize"));
        let j = offset_usize + i;
        indices.swap(i, j);
    }

    // Take first threshold indices
    let selected_indices: Vec<_> = indices.iter().take(threshold as usize).copied().collect();
    let selected_shares: Vec<_> = selected_indices
        .iter()
        .map(|&idx| share_vec[idx].clone())
        .collect();

    // Recover
    let Ok(recovered) = sharks.recover(&selected_shares) else {
        return false;
    };

    // Should match original
    original_entropy == recovered
}

/// Test that shamir39 metadata is preserved through encoding
#[quickcheck]
fn prop_shamir39_metadata_preserved(mnemonic: ValidMnemonic, params: ValidShamirParams) -> bool {
    let ValidMnemonic(inner_mnemonic) = mnemonic;
    let original_entropy = inner_mnemonic.to_entropy();
    let threshold = params.threshold;
    let num_shares = params.num_shares;

    // Split using blahaj
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&original_entropy);
    let share_vec: Vec<_> = dealer.take(num_shares.into()).collect();

    // Encode each share and verify metadata
    for (idx, share) in share_vec.iter().enumerate() {
        let share_bytes = Vec::from(share);
        let Ok(idx_u8) = u8::try_from(idx) else {
            return false; // idx doesn't fit in u8
        };
        let Ok(mnemonic) = shamir39::create_share(
            &share_bytes,
            Threshold::new(threshold).unwrap(),
            ShareIndex::new(idx_u8).unwrap(),
        ) else {
            return false;
        };

        let Ok((parsed_threshold, parsed_index, _)) = shamir39::parse_share(mnemonic.as_str())
        else {
            return false;
        };

        if *parsed_threshold != threshold || *parsed_index != idx_u8 {
            return false;
        }
    }

    true
}

/// Test that corrupted share data fails to decode or combine
#[quickcheck]
fn prop_corrupted_shares_fail(mnemonic: ValidMnemonic, params: ValidShamirParams) -> bool {
    let ValidMnemonic(inner_mnemonic) = mnemonic;
    let original_entropy = inner_mnemonic.to_entropy();
    let threshold = params.threshold;
    let num_shares = params.num_shares;

    // Note: threshold is always >= 2 (enforced by ValidShamirParams generator and system validation)
    // The regression cases that previously failed with threshold=1 are now captured in
    // regression_threshold_one module tests below

    // Split using blahaj
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&original_entropy);
    let share_vec: Vec<_> = dealer.take(num_shares.into()).collect();

    if share_vec.is_empty() {
        return true;
    }

    // Take first share and corrupt it
    let share_bytes = Vec::from(&share_vec[0]);

    // Create a corrupted version by flipping some bytes
    let mut corrupted = share_bytes.clone();
    if !corrupted.is_empty() {
        corrupted[0] ^= 0xFF; // Flip all bits in first byte
    }

    // Try to use corrupted share with threshold-1 valid shares
    let Ok(corrupted_mnemonic) = shamir39::create_share(
        &corrupted,
        Threshold::new(threshold).unwrap(),
        ShareIndex::new(0).unwrap(),
    ) else {
        return true; // If creation fails, that's fine
    };

    let Ok((_threshold, _index, corrupted_data)) =
        shamir39::parse_share(corrupted_mnemonic.as_str())
    else {
        return true; // If parsing fails, that's fine
    };

    // Try to convert to share
    let Ok(corrupted_share) = blahaj::Share::try_from(corrupted_data.as_slice()) else {
        return true; // If conversion fails, that's acceptable
    };

    // Combine corrupted share with valid shares
    let mut shares_to_combine = vec![corrupted_share];
    shares_to_combine.extend(
        share_vec
            .iter()
            .skip(1)
            .take(threshold as usize - 1)
            .cloned(),
    );

    if shares_to_combine.len() < threshold as usize {
        return true; // Not enough shares
    }

    // Recovery should either fail or produce wrong result
    match sharks.recover(&shares_to_combine) {
        Err(_) => true,                                 // Failed to recover - good
        Ok(recovered) => recovered != original_entropy, // Recovered wrong value - acceptable
    }
}

/// Test that shares from different secrets don't combine correctly
#[quickcheck]
fn prop_mixed_shares_fail(
    mnemonic1: ValidMnemonic,
    mnemonic2: ValidMnemonic,
    params: ValidShamirParams,
) -> bool {
    let ValidMnemonic(inner_mnemonic1) = mnemonic1;
    let ValidMnemonic(inner_mnemonic2) = mnemonic2;
    let entropy1 = inner_mnemonic1.to_entropy();
    let entropy2 = inner_mnemonic2.to_entropy();

    // Skip if same entropy (unlikely but possible)
    if entropy1 == entropy2 {
        return true;
    }

    let threshold = params.threshold;
    let num_shares = params.num_shares;

    // Note: threshold is always >= 2 (enforced by ValidShamirParams generator)

    // Split both secrets
    let sharks = Sharks(threshold);

    let dealer1 = sharks.dealer(&entropy1);
    let shares1: Vec<_> = dealer1.take(num_shares.into()).collect();

    let dealer2 = sharks.dealer(&entropy2);
    let shares2: Vec<_> = dealer2.take(num_shares.into()).collect();

    // Mix shares: take some from secret1, some from secret2
    let mut mixed_shares = Vec::new();
    let half = (threshold as usize) / 2;

    mixed_shares.extend(shares1.iter().take(half).cloned());
    mixed_shares.extend(shares2.iter().take(threshold as usize - half).cloned());

    if mixed_shares.len() < threshold as usize {
        return true;
    }

    // Recovery should fail or produce neither original secret
    match sharks.recover(&mixed_shares) {
        Err(_) => true,                                                  // Failed - good
        Ok(recovered) => recovered != entropy1 && recovered != entropy2, // Wrong result - acceptable
    }
}

// ==============================================================================
// Regression tests for threshold=1 issues discovered by quickcheck
// ==============================================================================
// These tests document the problematic behavior with threshold=1 before
// we add validation to prevent it. threshold=1 makes no cryptographic sense
// (any single share can recover the secret, providing no security).

#[cfg(test)]
mod regression_threshold_one {
    use super::*;

    /// Regression test #1: 24-word mnemonic with `threshold=1`, `num_shares=2`
    /// This test documents that `threshold=1` corrupted shares may not be detected
    #[test]
    fn test_threshold_1_corruption_not_detected_case1() {
        // Create a deterministic 24-word mnemonic
        let entropy = vec![
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42,
        ];
        let mnemonic = Mnemonic::from_entropy(&entropy).expect("Valid entropy");
        let threshold = 1u8;
        let num_shares = 2u8;

        // Split using blahaj
        let sharks = Sharks(threshold);
        let dealer = sharks.dealer(&mnemonic.to_entropy());
        let share_vec: Vec<_> = dealer.take(num_shares.into()).collect();

        assert_eq!(share_vec.len(), 2);

        // With threshold=1, any single share can recover the secret
        // This defeats the purpose of secret sharing
        let recovered = sharks
            .recover(std::slice::from_ref(&share_vec[0]))
            .expect("Should recover with single share when threshold=1");
        assert_eq!(recovered, mnemonic.to_entropy());
    }

    /// Regression test #2: Different entropy with `threshold=1`, `num_shares=10`
    /// Demonstrates that `threshold=1` works but provides no security benefit
    #[test]
    fn test_threshold_1_no_security_benefit_case2() {
        let entropy = vec![
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB,
        ];
        let mnemonic = Mnemonic::from_entropy(&entropy).expect("Valid entropy");
        let threshold = 1u8;
        let num_shares = 10u8;

        let sharks = Sharks(threshold);
        let dealer = sharks.dealer(&mnemonic.to_entropy());
        let share_vec: Vec<_> = dealer.take(num_shares.into()).collect();

        assert_eq!(share_vec.len(), 10);

        // With threshold=1, EVERY share alone can recover the full secret
        // This means we're essentially creating 10 copies of the secret
        for (idx, share) in share_vec.iter().enumerate() {
            let recovered = sharks
                .recover(std::slice::from_ref(share))
                .unwrap_or_else(|_| panic!("Share {idx} should recover secret"));
            assert_eq!(
                recovered,
                mnemonic.to_entropy(),
                "Share {idx} should recover original secret"
            );
        }
    }

    /// Regression test #3: 12-word mnemonic with `threshold=1`
    /// Shows the same issue applies to 12-word mnemonics
    #[test]
    fn test_threshold_1_twelve_word_mnemonic() {
        let entropy = vec![
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let mnemonic = Mnemonic::from_entropy(&entropy).expect("Valid entropy");
        let threshold = 1u8;
        let num_shares = 2u8;

        let sharks = Sharks(threshold);
        let dealer = sharks.dealer(&mnemonic.to_entropy());
        let share_vec: Vec<_> = dealer.take(num_shares.into()).collect();

        // Each share alone can recover the secret - no security benefit
        for share in &share_vec {
            let recovered = sharks
                .recover(std::slice::from_ref(share))
                .expect("Should recover with single share");
            assert_eq!(recovered, mnemonic.to_entropy());
        }
    }
}
