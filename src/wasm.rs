//! WASM bindings for shameless
//!
//! This module provides JavaScript-friendly bindings for the core split/combine functionality.

use bip39::{Language, Mnemonic};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::commands;
use crate::domain::{ShareCount, SplitConfig, Threshold};

/// Initialize panic hook for better error messages in the browser console
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Use wee_alloc as the global allocator for smaller WASM binary size
#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// Result of a split operation (for JSON serialization)
#[derive(Serialize, Deserialize)]
pub struct SplitResult {
    /// The generated shares as shamir39 mnemonics
    pub shares: Vec<String>,
    /// Number of shares generated
    pub share_count: u8,
    /// Threshold required to reconstruct
    pub threshold: u8,
}

/// Split a BIP39 mnemonic into Shamir Secret Shares
///
/// # Arguments
/// * `mnemonic` - The BIP39 mnemonic to split (12 or 24 words)
/// * `shares` - Total number of shares to create (2-255)
/// * `threshold` - Minimum number of shares needed to reconstruct (2-shares)
///
/// # Returns
/// JSON string containing the shares and metadata, or an error message
///
/// # Example (JavaScript)
/// ```javascript
/// const result = wasm_split(
///     "army van defense carry jealous true garbage claim echo media make crunch",
///     5,
///     3
/// );
/// const data = JSON.parse(result);
/// console.log(`Created ${data.share_count} shares with threshold ${data.threshold}`);
/// for (let i = 0; i < data.shares.length; i++) {
///     console.log(`Share ${i+1}: ${data.shares[i]}`);
/// }
/// ```
#[wasm_bindgen]
pub fn wasm_split(mnemonic: &str, shares: u8, threshold: u8) -> Result<String, JsValue> {
    // Validate inputs
    let threshold_obj = Threshold::new(threshold)
        .map_err(|e| JsValue::from_str(&format!("Invalid threshold: {}", e)))?;

    let share_count = ShareCount::new(shares)
        .map_err(|e| JsValue::from_str(&format!("Invalid share count: {}", e)))?;

    let config = SplitConfig::new(threshold_obj, share_count)
        .map_err(|e| JsValue::from_str(&format!("Invalid configuration: {}", e)))?;

    // Perform the split
    let share_mnemonics = commands::split_mnemonic(mnemonic, config)
        .map_err(|e| JsValue::from_str(&format!("Split failed: {}", e)))?;

    // Build result
    let result = SplitResult {
        shares: share_mnemonics,
        share_count: shares,
        threshold,
    };

    // Serialize to JSON
    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Serialization failed: {}", e)))
}

/// Combine Shamir Secret Shares to reconstruct the original mnemonic
///
/// # Arguments
/// * `shares` - Array of shamir39-encoded share mnemonics
///
/// # Returns
/// The reconstructed BIP39 mnemonic, or an error message
///
/// # Example (JavaScript)
/// ```javascript
/// const shares = [
///     "shameless word1 word2 ...",
///     "shameless word1 word2 ...",
///     "shameless word1 word2 ..."
/// ];
/// const mnemonic = wasm_combine(shares);
/// console.log(`Recovered mnemonic: ${mnemonic}`);
/// ```
#[wasm_bindgen]
pub fn wasm_combine(shares: Vec<String>) -> Result<String, JsValue> {
    // Perform the combine
    commands::combine_shares(&shares)
        .map_err(|e| JsValue::from_str(&format!("Combine failed: {}", e)))
}

/// Parse a shamir39 share to extract metadata (threshold and index)
///
/// # Arguments
/// * `share` - A shamir39-encoded share mnemonic
///
/// # Returns
/// JSON string containing threshold and share_index, or an error message
///
/// # Example (JavaScript)
/// ```javascript
/// const metadata = wasm_parse_share("shameless word1 word2 ...");
/// const data = JSON.parse(metadata);
/// console.log(`Threshold: ${data.threshold}, Index: ${data.share_index}`);
/// ```
#[wasm_bindgen]
pub fn wasm_parse_share(share: &str) -> Result<String, JsValue> {
    use crate::codec;

    let (threshold, share_index, _data) = codec::parse_share(share)
        .map_err(|e| JsValue::from_str(&format!("Parse failed: {}", e)))?;

    #[derive(Serialize)]
    struct ShareMetadata {
        threshold: u8,
        share_index: u8,
    }

    let metadata = ShareMetadata {
        threshold: *threshold,
        share_index: *share_index,
    };

    serde_json::to_string(&metadata)
        .map_err(|e| JsValue::from_str(&format!("Serialization failed: {}", e)))
}

/// Generate a random BIP39 mnemonic
///
/// # Arguments
/// * `word_count` - Number of words (12 or 24)
///
/// # Returns
/// A randomly generated BIP39 mnemonic string, or an error message
///
/// # Example (JavaScript)
/// ```javascript
/// const mnemonic12 = wasm_generate_mnemonic(12);
/// const mnemonic24 = wasm_generate_mnemonic(24);
/// console.log(`Random 12-word: ${mnemonic12}`);
/// ```
#[wasm_bindgen]
pub fn wasm_generate_mnemonic(word_count: u8) -> Result<String, JsValue> {
    // Validate word count
    if word_count != 12 && word_count != 24 {
        return Err(JsValue::from_str("Invalid word count: must be 12 or 24"));
    }

    // Generate random entropy
    // The getrandom crate (with "js" feature) will use browser's crypto.getRandomValues()
    let entropy_size = if word_count == 12 { 16 } else { 32 }; // 128 or 256 bits
    let mut entropy = vec![0u8; entropy_size];

    getrandom::getrandom(&mut entropy)
        .map_err(|e| JsValue::from_str(&format!("Failed to generate random entropy: {}", e)))?;

    // Create mnemonic from entropy
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| JsValue::from_str(&format!("Failed to create mnemonic: {}", e)))?;

    Ok(mnemonic.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_split_basic() {
        let mnemonic = "army van defense carry jealous true garbage claim echo media make crunch";
        let result = wasm_split(mnemonic, 5, 3);
        assert!(result.is_ok());

        let json = result.unwrap();
        let data: SplitResult = serde_json::from_str(&json).unwrap();
        assert_eq!(data.shares.len(), 5);
        assert_eq!(data.share_count, 5);
        assert_eq!(data.threshold, 3);
    }

    #[test]
    fn test_wasm_split_invalid_threshold() {
        let mnemonic = "army van defense carry jealous true garbage claim echo media make crunch";
        let result = wasm_split(mnemonic, 5, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_wasm_split_invalid_mnemonic() {
        let result = wasm_split("invalid mnemonic words", 5, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_wasm_combine_basic() {
        let mnemonic = "army van defense carry jealous true garbage claim echo media make crunch";

        // First split
        let split_result = wasm_split(mnemonic, 5, 3).unwrap();
        let data: SplitResult = serde_json::from_str(&split_result).unwrap();

        // Take 3 shares (threshold)
        let selected_shares = data.shares[0..3].to_vec();

        // Combine
        let recovered = wasm_combine(selected_shares);
        assert!(recovered.is_ok());
        assert_eq!(recovered.unwrap(), mnemonic);
    }

    #[test]
    fn test_wasm_combine_insufficient_shares() {
        let mnemonic = "army van defense carry jealous true garbage claim echo media make crunch";

        // Split with threshold 3
        let split_result = wasm_split(mnemonic, 5, 3).unwrap();
        let data: SplitResult = serde_json::from_str(&split_result).unwrap();

        // Take only 2 shares (insufficient)
        let selected_shares = data.shares[0..2].to_vec();

        // Should fail
        let result = wasm_combine(selected_shares);
        assert!(result.is_err());
    }

    #[test]
    fn test_wasm_parse_share() {
        let mnemonic = "army van defense carry jealous true garbage claim echo media make crunch";
        let split_result = wasm_split(mnemonic, 5, 3).unwrap();
        let data: SplitResult = serde_json::from_str(&split_result).unwrap();

        // Parse first share
        let parse_result = wasm_parse_share(&data.shares[0]);
        assert!(parse_result.is_ok());

        #[derive(Deserialize)]
        struct ShareMetadata {
            threshold: u8,
            share_index: u8,
        }

        let metadata: ShareMetadata = serde_json::from_str(&parse_result.unwrap()).unwrap();
        assert_eq!(metadata.threshold, 3);
        assert_eq!(metadata.share_index, 0);
    }

    #[test]
    fn test_wasm_generate_mnemonic_12_words() {
        let result = wasm_generate_mnemonic(12);
        assert!(result.is_ok());
        let mnemonic = result.unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 12);
    }

    #[test]
    fn test_wasm_generate_mnemonic_24_words() {
        let result = wasm_generate_mnemonic(24);
        assert!(result.is_ok());
        let mnemonic = result.unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 24);
    }

    #[test]
    fn test_wasm_generate_mnemonic_invalid_count() {
        let result = wasm_generate_mnemonic(15);
        assert!(result.is_err());
    }

    #[test]
    fn test_wasm_generate_and_split() {
        // Generate a random 12-word mnemonic
        let mnemonic = wasm_generate_mnemonic(12).unwrap();

        // Split it
        let split_result = wasm_split(&mnemonic, 3, 2).unwrap();
        let data: SplitResult = serde_json::from_str(&split_result).unwrap();

        // Should produce 3 shares
        assert_eq!(data.shares.len(), 3);

        // Combine them back
        let recovered = wasm_combine(data.shares[0..2].to_vec()).unwrap();

        // Should match original
        assert_eq!(mnemonic, recovered);
    }
}
