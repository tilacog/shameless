//! Shamir Secret Sharing encoding using shamir39 specification
//!
//! This module implements the [shamir39 specification] for encoding Shamir secret shares
//! as BIP39 mnemonics with embedded metadata (threshold and share index).
//!
//! # Overview
//!
//! The shamir39 format encodes binary share data as a single BIP39 mnemonic phrase with
//! embedded metadata. Each share contains:
//! - A version word (`"shameless"`) to identify the format
//! - Parameter words encoding the threshold (M) and share index (O)
//! - Data words encoding the binary share with length prefix and CRC32 checksum
//!
//! # Examples
//!
//! ## Creating and parsing a share
//!
//! ```rust
//! use shameless::shamir39::{create_share, parse_share, Threshold, ShareIndex};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a share from binary data
//! let share_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
//! let threshold = Threshold::new(3)?;
//! let index = ShareIndex::new(0)?;
//!
//! let mnemonic = create_share(&share_data, threshold, index)?;
//!
//! // The mnemonic starts with "shameless"
//! assert!(mnemonic.as_str().starts_with("shameless "));
//!
//! // Parse it back to recover the components
//! let (parsed_threshold, parsed_index, parsed_data) = parse_share(mnemonic.as_str())?;
//!
//! assert_eq!(threshold, parsed_threshold);
//! assert_eq!(index, parsed_index);
//! assert_eq!(share_data, *parsed_data);
//! # Ok(())
//! # }
//! ```
//!
//! ## Working with validated types
//!
//! ```rust
//! use shameless::shamir39::{Threshold, ShareIndex, ShareCount, SplitConfig};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Types enforce invariants at construction
//! let threshold = Threshold::new(3)?;
//! let share_count = ShareCount::new(5)?;
//! let index = ShareIndex::new(0)?;
//!
//! // SplitConfig validates threshold <= share_count
//! let config = SplitConfig::new(threshold, share_count)?;
//!
//! // This would fail: threshold cannot be less than 2
//! assert!(Threshold::new(1).is_err());
//!
//! // This would fail: index 255 is reserved
//! assert!(ShareIndex::new(255).is_err());
//!
//! // This would fail: threshold > share_count
//! assert!(SplitConfig::new(Threshold::new(5)?, ShareCount::new(3)?).is_err());
//! # Ok(())
//! # }
//! ```
//!
//! [shamir39 specification]: https://github.com/iancoleman/shamir39/blob/master/specification.md

use anyhow::{Context, Result, anyhow, bail};
use bip39::Language;
use crc::{CRC_32_ISO_HDLC, Crc};
use std::collections::HashMap;
use std::sync::LazyLock;
use zeroize::Zeroizing;

use crate::domain::{ShareIndex, Threshold};

/// CRC32 algorithm for share integrity checking
const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

/// Version word that identifies shameless format
pub const VERSION_WORD: &str = "shameless";

/// A validated shameless mnemonic string
///
/// Wraps the mnemonic in `Zeroizing` to ensure secure memory cleanup.
#[derive(Debug, Clone, PartialEq)]
pub struct Shamir39Mnemonic(Zeroizing<String>);

impl Shamir39Mnemonic {
    /// Creates a new `Shamir39Mnemonic` from a string without validation
    ///
    /// This is used internally when creating shares. Use `parse` to validate existing mnemonics.
    pub(crate) fn new_unchecked(s: String) -> Self {
        Self(Zeroizing::new(s))
    }

    /// Gets the mnemonic as a string slice
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Shamir39Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &*self.0)
    }
}

/// Static `HashMap` for O(1) word-to-index lookups
static WORD_TO_INDEX_MAP: LazyLock<HashMap<&'static str, usize>> = LazyLock::new(|| {
    Language::English
        .word_list()
        .iter()
        .enumerate()
        .map(|(idx, &word)| (word, idx))
        .collect()
});

/// Encodes threshold (M) and share index (O) into BIP39 words
///
/// Uses 11-bit word encoding: [`continuation_bit` (1)][M bits (5)][O bits (5)]
/// - `continuation_bit` = 1: more words follow
/// - `continuation_bit` = 0: final word
///
/// # Arguments
/// * `threshold` - Minimum shares required (M)
/// * `index` - Share index/order (O), 0-based
///
/// # Returns
/// Vector of BIP39 words encoding the parameters
///
/// # Errors
/// Returns an error if word index conversion fails
fn encode_parameters(threshold: Threshold, index: ShareIndex) -> Result<Vec<String>> {
    let m = *threshold as usize;
    let o = *index as usize;

    // Determine how many words we need
    // We need continuation if either M or O requires more than 5 bits
    let needs_continuation = m >= 32 || o >= 32;

    let mut words = Vec::new();

    if needs_continuation {
        // First word: continuation=1, M high bits (bits 5-9), O high bits (bits 5-9)
        let m_high = (m >> 5) & 0b11111;
        let o_high = (o >> 5) & 0b11111;
        let word_index = (1 << 10) | (m_high << 5) | o_high;
        words.push(word_from_index(word_index)?);

        // Second word: continuation=0, M low bits (bits 0-4), O low bits (bits 0-4)
        let m_low = m & 0b11111;
        let o_low = o & 0b11111;
        let word_index = (m_low << 5) | o_low;
        words.push(word_from_index(word_index)?);
    } else {
        // Single word: continuation=0, M low bits, O low bits
        let word_index = (m << 5) | o;
        words.push(word_from_index(word_index)?);
    }

    Ok(words)
}

/// Decodes threshold and share index from BIP39 parameter words
///
/// # Arguments
/// * `words` - Parameter words from shameless share
///
/// # Returns
/// Tuple of (threshold, index)
///
/// # Errors
/// Returns an error if word index lookup fails or parameter format is invalid
fn decode_parameters(words: &[String]) -> Result<(Threshold, ShareIndex)> {
    if words.is_empty() {
        bail!("No parameter words provided");
    }

    let first_index = word_to_index(&words[0])?;
    let continuation = (first_index >> 10) & 1;

    if continuation == 1 {
        // Two-word encoding
        if words.len() < 2 {
            bail!("Continuation bit set but only one parameter word provided");
        }

        let second_index = word_to_index(&words[1])?;
        let second_continuation = (second_index >> 10) & 1;

        if second_continuation != 0 {
            bail!("Second parameter word has continuation bit set");
        }

        // Extract bits from both words
        let m_high = (first_index >> 5) & 0b11111;
        let o_high = first_index & 0b11111;
        let m_low = (second_index >> 5) & 0b11111;
        let o_low = second_index & 0b11111;

        // Combine into full values (10 bits each)
        let threshold_value = (m_high << 5) | m_low;
        let index_value = (o_high << 5) | o_low;

        // Convert to u8 with validation
        let threshold_u8 =
            u8::try_from(threshold_value).context("Threshold value exceeds u8::MAX (255)")?;
        let index_u8 = u8::try_from(index_value).context("Share index exceeds u8::MAX (255)")?;

        Ok((Threshold::new(threshold_u8)?, ShareIndex::new(index_u8)?))
    } else {
        // Single-word encoding (5 bits each, always fits in u8)
        #[allow(
            clippy::cast_possible_truncation,
            reason = "5-bit masked values (0-31) are guaranteed to fit in u8 (0-255)"
        )]
        let m = ((first_index >> 5) & 0b11111) as u8;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "5-bit masked values (0-31) are guaranteed to fit in u8 (0-255)"
        )]
        let o = (first_index & 0b11111) as u8;

        Ok((Threshold::new(m)?, ShareIndex::new(o)?))
    }
}

/// Encodes binary share data as BIP39 words
///
/// Each word encodes 11 bits. Data is left-padded to align with 11-bit boundaries.
/// Uses direct bit manipulation for efficiency, avoiding string allocations.
///
/// # Arguments
/// * `data` - Binary share data
///
/// # Returns
/// Vector of BIP39 words encoding the data
///
/// # Errors
/// Returns an error if word index conversion fails
fn encode_share_data(data: &[u8]) -> Result<Vec<String>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let bit_count = data.len() * 8;
    let padding = (11 - (bit_count % 11)) % 11;
    let total_bits = bit_count + padding;
    let word_count = total_bits / 11;

    let mut words = Vec::with_capacity(word_count);
    let mut bit_buffer: u16 = 0;
    let mut bits_in_buffer = 0;

    // Add padding bits first (left-padding with zeros)
    for _ in 0..padding {
        bit_buffer <<= 1;
        bits_in_buffer += 1;

        if bits_in_buffer == 11 {
            words.push(word_from_index(bit_buffer as usize)?);
            bit_buffer = 0;
            bits_in_buffer = 0;
        }
    }

    // Process data bytes
    for &byte in data {
        for bit_pos in (0..8).rev() {
            let bit = (byte >> bit_pos) & 1;
            bit_buffer = (bit_buffer << 1) | u16::from(bit);
            bits_in_buffer += 1;

            if bits_in_buffer == 11 {
                words.push(word_from_index(bit_buffer as usize)?);
                bit_buffer = 0;
                bits_in_buffer = 0;
            }
        }
    }

    Ok(words)
}

/// Decodes BIP39 words back to binary share data
///
/// Reverses the encoding process, removing left padding.
/// Uses direct bit manipulation for efficiency, avoiding string allocations.
///
/// # Arguments
/// * `words` - BIP39 words encoding share data
/// * `expected_bytes` - Expected number of bytes in output
///
/// # Returns
/// Binary share data wrapped in `Zeroizing` for automatic memory cleanup
///
/// # Errors
/// Returns an error if words cannot be decoded or insufficient data provided
fn decode_share_data(words: &[String], expected_bytes: usize) -> Result<Zeroizing<Vec<u8>>> {
    if words.is_empty() {
        return Ok(Zeroizing::new(Vec::new()));
    }

    let expected_bits = expected_bytes * 8;
    let total_bits = words.len() * 11;

    if total_bits < expected_bits {
        bail!("Not enough bits: got {total_bits}, expected at least {expected_bits}");
    }

    // Calculate padding to skip
    let padding = total_bits - expected_bits;

    let mut result = Zeroizing::new(Vec::with_capacity(expected_bytes));
    let mut bit_buffer: u16 = 0;
    let mut bits_in_buffer = 0;
    let mut bits_processed = 0;

    // Process each word as 11 bits
    for word in words {
        let index = word_to_index(word)?;

        // Add 11 bits to buffer
        for bit_pos in (0..11).rev() {
            let bit = (index >> bit_pos) & 1;

            // Skip padding bits
            if bits_processed < padding {
                bits_processed += 1;
                continue;
            }

            #[allow(
                clippy::cast_possible_truncation,
                reason = "bit is guaranteed to be 0 or 1 from masking"
            )]
            let bit_u16 = bit as u16;
            bit_buffer = (bit_buffer << 1) | bit_u16;
            bits_in_buffer += 1;

            if bits_in_buffer == 8 {
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "bit_buffer only contains 8 bits at this point"
                )]
                let byte = bit_buffer as u8;
                result.push(byte);
                bit_buffer = 0;
                bits_in_buffer = 0;
            }

            bits_processed += 1;
        }
    }

    Ok(result)
}

/// Creates a complete shameless mnemonic from components
///
/// Format: "shameless <parameter words> <share data words>"
///
/// The encoded data format is: length (2 bytes) || `share_data` || checksum (4 bytes)
/// This ensures exact length preservation through encode/decode cycles and data integrity.
///
/// # Arguments
/// * `share_data` - Binary share data
/// * `threshold` - Minimum shares required
/// * `index` - Share index (0-based)
///
/// # Returns
/// Complete shameless mnemonic as a single string wrapped in `Zeroizing` for automatic memory cleanup
///
/// # Errors
/// Returns an error if parameter or share data encoding fails, or if share data is too large (>65535 bytes)
///
/// # Examples
///
/// ```rust
/// use shameless::shamir39::{create_share, Threshold, ShareIndex};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let share_data = vec![0x01, 0x02, 0x03, 0x04];
/// let threshold = Threshold::new(3)?;
/// let index = ShareIndex::new(0)?;
///
/// let mnemonic = create_share(&share_data, threshold, index)?;
///
/// // Verify the mnemonic format
/// assert!(mnemonic.as_str().starts_with("shameless "));
/// # Ok(())
/// # }
/// ```
pub fn create_share(
    share_data: &[u8],
    threshold: Threshold,
    index: ShareIndex,
) -> Result<Shamir39Mnemonic> {
    // Check share data size fits in u16
    if share_data.len() > u16::MAX as usize {
        bail!(
            "Share data too large: {} bytes (max 65535)",
            share_data.len()
        );
    }

    // Calculate CRC32 checksum of the share data
    let checksum = CRC32.checksum(share_data);

    // Build: length (2 bytes) || share_data || checksum (4 bytes)
    let mut encoded_data = Vec::with_capacity(2 + share_data.len() + 4);
    #[allow(
        clippy::cast_possible_truncation,
        reason = "share_data.len() already validated to be <= u16::MAX above"
    )]
    let length = share_data.len() as u16;
    encoded_data.extend_from_slice(&length.to_be_bytes());
    encoded_data.extend_from_slice(share_data);
    encoded_data.extend_from_slice(&checksum.to_be_bytes());

    let mut words = vec![VERSION_WORD.to_string()];
    words.extend(encode_parameters(threshold, index)?);
    words.extend(encode_share_data(&encoded_data)?);

    Ok(Shamir39Mnemonic::new_unchecked(words.join(" ")))
}

/// Parses a shameless mnemonic into components
///
/// # Arguments
/// * `mnemonic` - Complete shameless mnemonic string
///
/// # Returns
/// Tuple of (threshold, index, `share_data`) where `share_data` is wrapped in `Zeroizing` for automatic memory cleanup
///
/// # Errors
/// Returns an error if the mnemonic format is invalid, version word is incorrect,
/// share data cannot be decoded, or checksum verification fails
///
/// # Examples
///
/// ```rust
/// use shameless::shamir39::{create_share, parse_share, Threshold, ShareIndex};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a share
/// let original_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
/// let threshold = Threshold::new(2)?;
/// let index = ShareIndex::new(0)?;
/// let mnemonic = create_share(&original_data, threshold, index)?;
///
/// // Parse it back
/// let (parsed_threshold, parsed_index, parsed_data) = parse_share(mnemonic.as_str())?;
///
/// assert_eq!(threshold, parsed_threshold);
/// assert_eq!(index, parsed_index);
/// assert_eq!(original_data, *parsed_data);
/// # Ok(())
/// # }
/// ```
pub fn parse_share(mnemonic: &str) -> Result<(Threshold, ShareIndex, Zeroizing<Vec<u8>>)> {
    let words: Vec<String> = mnemonic.split_whitespace().map(str::to_lowercase).collect();

    if words.is_empty() {
        bail!("Empty mnemonic");
    }

    // Check version word
    if words[0] != VERSION_WORD {
        bail!(
            "Invalid version word: expected '{}', got '{}'",
            VERSION_WORD,
            words[0]
        );
    }

    if words.len() < 2 {
        bail!("Mnemonic too short: need at least version + parameters");
    }

    // Decode parameters (could be 1 or 2 words)
    let first_param_index = word_to_index(&words[1])?;
    let continuation = (first_param_index >> 10) & 1;

    let param_word_count = if continuation == 1 { 2 } else { 1 };

    if words.len() < 1 + param_word_count {
        bail!("Mnemonic too short for parameter words");
    }

    let param_words = &words[1..=param_word_count];
    let (threshold, index) = decode_parameters(param_words)?;

    // Remaining words are share data
    let data_words = &words[1 + param_word_count..];

    if data_words.is_empty() {
        bail!("No share data words found");
    }

    // Calculate maximum possible bytes from word count
    let total_data_bits = data_words.len() * 11;
    let max_bytes = total_data_bits / 8;

    let mut encoded_data = decode_share_data(data_words, max_bytes)?;

    // Handle potential leading zero padding bytes from bit alignment issues
    // The length field (first 2 bytes) should be non-zero for valid shares
    while encoded_data.len() >= 6 && encoded_data[0] == 0 && encoded_data[1] == 0 {
        // Remove leading zero byte
        encoded_data.remove(0);
    }

    // Verify minimum size (2 bytes for length + 4 bytes for checksum)
    if encoded_data.len() < 6 {
        bail!(
            "Encoded data too short: need at least 6 bytes (length + checksum), got {}",
            encoded_data.len()
        );
    }

    // Extract length (first 2 bytes)
    let share_data_len = u16::from_be_bytes([encoded_data[0], encoded_data[1]]) as usize;

    // Verify total size matches: 2 (length) + share_data_len + 4 (checksum)
    let expected_total_len = 2 + share_data_len + 4;
    if encoded_data.len() < expected_total_len {
        bail!(
            "Encoded data size mismatch: expected at least {} bytes (2 + {} + 4), got {}",
            expected_total_len,
            share_data_len,
            encoded_data.len()
        );
    }

    // Extract share data and checksum
    let share_data = &encoded_data[2..2 + share_data_len];
    let checksum_start = 2 + share_data_len;

    // Check we have enough bytes for checksum
    if checksum_start + 4 > encoded_data.len() {
        bail!(
            "Not enough bytes for checksum: need {} bytes, got {}",
            checksum_start + 4,
            encoded_data.len()
        );
    }

    let checksum_bytes = &encoded_data[checksum_start..checksum_start + 4];

    // Verify checksum
    let expected_checksum = CRC32.checksum(share_data);
    let actual_checksum = u32::from_be_bytes([
        checksum_bytes[0],
        checksum_bytes[1],
        checksum_bytes[2],
        checksum_bytes[3],
    ]);

    if expected_checksum != actual_checksum {
        bail!(
            "Checksum verification failed: expected 0x{expected_checksum:08x}, got 0x{actual_checksum:08x}"
        );
    }

    Ok((threshold, index, Zeroizing::new(share_data.to_vec())))
}

/// Converts a BIP39 word to its index (0-2047)
fn word_to_index(word: &str) -> Result<usize> {
    let word_lower = word.to_lowercase();

    WORD_TO_INDEX_MAP
        .get(word_lower.as_str())
        .copied()
        .ok_or_else(|| anyhow!("Word '{word}' not found in BIP39 wordlist"))
}

/// Converts an index (0-2047) to its BIP39 word
fn word_from_index(index: usize) -> Result<String> {
    if index > 2047 {
        bail!("Word index {index} out of range (must be 0-2047)");
    }

    let wordlist = Language::English.word_list();
    Ok(wordlist[index].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_word_conversion() {
        // Test round trip
        let index = 65;
        let word = word_from_index(index).unwrap();
        let back = word_to_index(&word).unwrap();
        assert_eq!(index, back);
    }

    #[test]
    fn test_single_word_parameters() {
        // M=2, O=1 should fit in single word
        let words =
            encode_parameters(Threshold::new(2).unwrap(), ShareIndex::new(1).unwrap()).unwrap();
        assert_eq!(words.len(), 1);

        let (m, o) = decode_parameters(&words).unwrap();
        assert_eq!(*m, 2);
        assert_eq!(*o, 1);
    }

    #[test]
    fn test_two_word_parameters() {
        // M=35, O=10 requires two words
        let words =
            encode_parameters(Threshold::new(35).unwrap(), ShareIndex::new(10).unwrap()).unwrap();
        assert_eq!(words.len(), 2);

        let (m, o) = decode_parameters(&words).unwrap();
        assert_eq!(*m, 35);
        assert_eq!(*o, 10);
    }

    #[test]
    fn test_share_data_encoding() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let words = encode_share_data(&data).unwrap();
        assert!(!words.is_empty());

        let decoded = decode_share_data(&words, data.len()).unwrap();
        assert_eq!(data, *decoded);
    }

    #[test]
    fn test_complete_share_round_trip() {
        let share_data = vec![0xAB, 0xCD, 0xEF, 0x12, 0x34];
        let threshold = Threshold::new(3).unwrap();
        let index = ShareIndex::new(0).unwrap();

        let mnemonic = create_share(&share_data, threshold, index).unwrap();

        // Should start with "shameless"
        assert!(mnemonic.as_str().starts_with("shameless "));

        let (decoded_threshold, decoded_index, decoded_data) =
            parse_share(mnemonic.as_str()).unwrap();

        assert_eq!(threshold, decoded_threshold);
        assert_eq!(index, decoded_index);
        assert_eq!(share_data, *decoded_data);
    }

    #[test]
    fn test_invalid_version_word() {
        let result = parse_share("invalid word word word");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid version word")
        );
    }

    #[test]
    fn test_empty_mnemonic() {
        let result = parse_share("");
        assert!(result.is_err());
    }

    #[test]
    fn test_checksum_validation_detects_corruption() {
        // Create a valid share
        let share_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let threshold = Threshold::new(2).unwrap();
        let index = ShareIndex::new(0).unwrap();

        let mnemonic = create_share(&share_data, threshold, index).unwrap();

        // Corrupt the mnemonic by changing the last word (which is part of the data)
        let words: Vec<&str> = mnemonic.as_str().split_whitespace().collect();
        let mut corrupted_words = words.clone();
        let last_idx = corrupted_words.len() - 1;

        corrupted_words[last_idx] = "abandon"; // Replace with different word

        let corrupted_mnemonic = corrupted_words.join(" ");

        // Parsing should fail due to checksum mismatch
        let result = parse_share(&corrupted_mnemonic);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Checksum verification failed")
        );
    }

    #[test]
    fn test_checksum_validation_accepts_valid_share() {
        // Create a valid share
        let share_data = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB];
        let threshold = Threshold::new(3).unwrap();
        let index = ShareIndex::new(1).unwrap();

        let mnemonic = create_share(&share_data, threshold, index).unwrap();

        // Parse it back - should succeed with matching checksum
        let result = parse_share(mnemonic.as_str());
        assert!(result.is_ok());

        let (parsed_threshold, parsed_index, parsed_data) = result.unwrap();
        assert_eq!(threshold, parsed_threshold);
        assert_eq!(index, parsed_index);
        assert_eq!(share_data, *parsed_data);
    }

    #[test]
    fn test_checksum_validation_with_multiple_shares() {
        // Test that different shares have different checksums
        let share_data_1 = vec![0x11, 0x22, 0x33];
        let share_data_2 = vec![0x44, 0x55, 0x66];

        let mnemonic_1 = create_share(
            &share_data_1,
            Threshold::new(2).unwrap(),
            ShareIndex::new(0).unwrap(),
        )
        .unwrap();
        let mnemonic_2 = create_share(
            &share_data_2,
            Threshold::new(2).unwrap(),
            ShareIndex::new(1).unwrap(),
        )
        .unwrap();

        // Both should parse successfully
        let result_1 = parse_share(mnemonic_1.as_str());
        let result_2 = parse_share(mnemonic_2.as_str());

        assert!(result_1.is_ok());
        assert!(result_2.is_ok());

        // And return the correct data
        assert_eq!(*result_1.unwrap().2, share_data_1);
        assert_eq!(*result_2.unwrap().2, share_data_2);
    }

    #[test]
    fn test_checksum_regression_single_byte_255() {
        // Regression test for property test failure case: ByteVec([255])
        // This specific case generated a mnemonic where the last word was "abandon",
        // which exposed an issue in the corruption detection test logic.
        // Note: Changed threshold from 1 to 2 (minimum valid threshold)
        let share_data = vec![0xFF]; // 255 in hex
        let threshold = Threshold::new(2).unwrap();
        let index = ShareIndex::new(0).unwrap();

        // Create the share
        let mnemonic = create_share(&share_data, threshold, index).unwrap();

        // Verify it's valid
        let (parsed_threshold, parsed_index, parsed_data) = parse_share(mnemonic.as_str()).unwrap();
        assert_eq!(threshold, parsed_threshold);
        assert_eq!(index, parsed_index);
        assert_eq!(share_data, *parsed_data);

        // Now corrupt it - ensure we change a word to actually corrupt it
        let words: Vec<&str> = mnemonic.as_str().split_whitespace().collect();
        let mut corrupted_words = words.clone();
        let last_idx = corrupted_words.len() - 1;
        corrupted_words[last_idx] = "zoo";

        let corrupted_mnemonic = corrupted_words.join(" ");

        // Verify corruption is detected
        let result = parse_share(&corrupted_mnemonic);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Checksum verification failed")
        );
    }
}
