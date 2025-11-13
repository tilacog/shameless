//! Property tests for shamir39 encoding/decoding

use quickcheck::{Arbitrary, Gen};
use quickcheck_macros::quickcheck;
use shameless::shamir39;
use shameless::shamir39::{ShareIndex, Threshold};

/// Wrapper for arbitrary byte vectors
#[derive(Clone, Debug)]
struct ByteVec(Vec<u8>);

impl Arbitrary for ByteVec {
    fn arbitrary(g: &mut Gen) -> Self {
        ByteVec(Vec::arbitrary(g))
    }
}

/// Test that complete share creation and parsing round trips correctly
/// This test verifies that the share data length is exactly preserved through encode/decode cycles.
/// With the new format (length prefix + CRC32 checksum), there should be no padding issues.
#[quickcheck]
fn prop_complete_share_round_trip(data: ByteVec, threshold: u8, index: u8) -> bool {
    let ByteVec(bytes) = data;
    if bytes.is_empty() {
        return true; // Skip empty data
    }

    // Skip invalid threshold values (< 2)
    let Ok(threshold_newtype) = Threshold::new(threshold) else {
        return true;
    };
    let Ok(index_newtype) = ShareIndex::new(index) else {
        return true; // Skip invalid indices
    };

    // Create share
    let Ok(mnemonic) = shamir39::create_share(&bytes, threshold_newtype, index_newtype) else {
        return true; // Skip if creation fails
    };

    // Verify it starts with version word
    if !mnemonic.as_str().starts_with("shameless ") {
        return false;
    }

    // Parse back
    let Ok((parsed_threshold, parsed_index, parsed_data)) =
        shamir39::parse_share(mnemonic.as_str())
    else {
        return false;
    };

    // Metadata should match exactly
    if threshold != *parsed_threshold || index != *parsed_index {
        return false;
    }

    // CRITICAL: With length encoding and CRC32 checksum, the share data must be
    // exactly preserved - no padding issues
    bytes == *parsed_data
}

/// Test that invalid version words are rejected
#[quickcheck]
fn prop_invalid_version_word_rejected(words: Vec<String>) -> bool {
    if words.is_empty() {
        return true;
    }

    // Create a mnemonic that doesn't start with "shameless"
    let mut invalid_words = words;
    invalid_words[0] = "invalid".to_string();
    let invalid_mnemonic = invalid_words.join(" ");

    // Parsing should fail
    shamir39::parse_share(&invalid_mnemonic).is_err()
}

/// Test that corrupted share data is detected via checksum
#[quickcheck]
fn prop_checksum_detects_corruption(data: ByteVec, threshold: u8, index: u8) -> bool {
    let ByteVec(bytes) = data;
    if bytes.is_empty() {
        return true;
    }

    let Ok(threshold_newtype) = Threshold::new(threshold) else {
        return true;
    };
    let Ok(index_newtype) = ShareIndex::new(index) else {
        return true;
    };

    // Create a valid share
    let Ok(mnemonic) = shamir39::create_share(&bytes, threshold_newtype, index_newtype) else {
        return true;
    };

    // Corrupt the mnemonic by replacing a word (skip version and parameter words)
    let words: Vec<&str> = mnemonic.as_str().split_whitespace().collect();
    if words.len() < 4 {
        return true; // Not enough words to corrupt meaningfully
    }

    // Try corrupting the last word (share data)
    let mut corrupted_words = words.clone();
    let last_word_idx = corrupted_words.len() - 1;

    // Choose a replacement word that's different from the current word
    let replacement_word = if corrupted_words[last_word_idx] == "abandon" {
        "zoo" // Use a different word if it's already "abandon"
    } else {
        "abandon"
    };

    corrupted_words[last_word_idx] = replacement_word;

    let corrupted_mnemonic = corrupted_words.join(" ");

    // Parsing should fail due to checksum mismatch
    // (unless by extreme coincidence the corruption still produces a valid checksum)
    let result = shamir39::parse_share(&corrupted_mnemonic);

    // We expect either a checksum error or some other parsing error
    // A successful parse would indicate the checksum didn't catch the corruption
    result.is_err()
}
