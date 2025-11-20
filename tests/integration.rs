use bip39::{Language, Mnemonic};
use blahaj::Sharks;

use shameless::shamir39;
use shameless::shamir39::{ShareIndex, Threshold};

#[test]
fn test_split_and_combine_12_word_mnemonic() {
    let mnemonic_str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str).unwrap();
    let original_entropy = mnemonic.to_entropy();

    // Split using blahaj
    let threshold = 2;
    let num_shares = 3;
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&original_entropy);
    let share_vec: Vec<_> = dealer.take(num_shares).collect();

    assert_eq!(share_vec.len(), 3);

    // Take any 2 shares (threshold is 2)
    let selected_shares = vec![share_vec[0].clone(), share_vec[2].clone()];

    // Combine
    let recovered = sharks.recover(&selected_shares).unwrap();

    assert_eq!(original_entropy, recovered);

    // Verify mnemonic reconstructs correctly
    let recovered_mnemonic = Mnemonic::from_entropy(&recovered).unwrap();
    assert_eq!(mnemonic.to_string(), recovered_mnemonic.to_string());
}

#[test]
fn test_split_and_combine_24_word_mnemonic() {
    let mnemonic_str = "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless";
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str).unwrap();
    let original_entropy = mnemonic.to_entropy();

    // Split using blahaj
    let threshold = 3;
    let num_shares = 5;
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&original_entropy);
    let share_vec: Vec<_> = dealer.take(num_shares).collect();

    assert_eq!(share_vec.len(), 5);

    // Take any 3 shares (threshold is 3)
    let selected_shares = vec![
        share_vec[0].clone(),
        share_vec[2].clone(),
        share_vec[4].clone(),
    ];

    // Combine
    let recovered = sharks.recover(&selected_shares).unwrap();

    assert_eq!(original_entropy, recovered);

    let recovered_mnemonic = Mnemonic::from_entropy(&recovered).unwrap();
    assert_eq!(mnemonic.to_string(), recovered_mnemonic.to_string());
}

#[test]
fn test_full_shamir39_encoding_round_trip() {
    // Test the complete flow with shamir39 encoded shares
    let mnemonic_str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str).unwrap();
    let original_entropy = mnemonic.to_entropy();

    // Split using blahaj
    let threshold = 2;
    let num_shares = 3;
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&original_entropy);
    let share_vec: Vec<_> = dealer.take(num_shares).collect();

    // Encode each share using shamir39 encoding
    let encoded_shares = share_vec
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
            .unwrap()
        })
        .collect::<Vec<_>>();

    // Verify each encoded share starts with "shameless"
    for share_mnemonic in &encoded_shares {
        assert!(share_mnemonic.as_str().starts_with("shameless "));
    }

    // Decode shares back
    let decoded_shares: Vec<blahaj::Share> = encoded_shares
        .iter()
        .map(|mnemonic| {
            let (_threshold, _index, share_data) =
                shamir39::parse_share(mnemonic.as_str()).unwrap();
            blahaj::Share::try_from(share_data.as_slice()).unwrap()
        })
        .collect();

    // Take 2 shares and combine (threshold is 2)
    let selected = vec![decoded_shares[0].clone(), decoded_shares[1].clone()];
    let recovered = sharks.recover(&selected).unwrap();

    // Verify
    assert_eq!(original_entropy, recovered);
    let recovered_mnemonic = Mnemonic::from_entropy(&recovered).unwrap();
    assert_eq!(mnemonic.to_string(), recovered_mnemonic.to_string());
}

#[test]
fn test_insufficient_shares() {
    let mnemonic_str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str).unwrap();
    let original_entropy = mnemonic.to_entropy();

    // Create shares with threshold 3
    let threshold = 3;
    let num_shares = 5;
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&original_entropy);
    let share_vec: Vec<_> = dealer.take(num_shares).collect();

    // Try to combine with only 2 shares (threshold is 3)
    let insufficient = vec![share_vec[0].clone(), share_vec[1].clone()];
    let result = sharks.recover(&insufficient);

    // Should error when insufficient shares
    assert!(result.is_err());
}

#[test]
fn test_shamir39_metadata_extraction() {
    // Test that shamir39 encoding properly embeds and extracts metadata
    let share_data = vec![0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A];
    let threshold = 3;
    let index = 1;

    let mnemonic = shamir39::create_share(
        &share_data,
        Threshold::new(threshold).unwrap(),
        ShareIndex::new(index).unwrap(),
    )
    .unwrap();

    // Parse it back
    let (parsed_threshold, parsed_index, parsed_data) =
        shamir39::parse_share(mnemonic.as_str()).unwrap();

    assert_eq!(threshold, *parsed_threshold);
    assert_eq!(index, *parsed_index);
    assert_eq!(share_data, *parsed_data);
}

#[test]
fn test_shamir39_version_validation() {
    // Test that invalid version word is rejected
    let invalid_mnemonic = "invalid army achieve visa couch actress sand";
    let result = shamir39::parse_share(invalid_mnemonic);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Invalid version word")
    );
}

#[test]
fn test_12_word_complete_workflow() {
    // Complete end-to-end test for 12-word mnemonic
    let mnemonic_str =
        "fine cloth tackle vintage ribbon spike supreme patient change ice fade trigger";
    let original_mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str).unwrap();
    let entropy = original_mnemonic.to_entropy();

    // Split into 5 shares, threshold 3
    let threshold = 3;
    let num_shares = 5;
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&entropy);
    let share_vec: Vec<_> = dealer.take(num_shares).collect();

    // Encode as shamir39
    let share_mnemonics = share_vec
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
            .unwrap()
        })
        .collect::<Vec<_>>();

    // Select shares 0, 2, 4 (any 3 of 5)
    let selected_mnemonics = [
        share_mnemonics[0].clone(),
        share_mnemonics[2].clone(),
        share_mnemonics[4].clone(),
    ];

    // Parse and recover
    let selected_shares: Vec<blahaj::Share> = selected_mnemonics
        .iter()
        .map(|mnemonic| {
            let (_threshold, _index, share_data) =
                shamir39::parse_share(mnemonic.as_str()).unwrap();
            blahaj::Share::try_from(share_data.as_slice()).unwrap()
        })
        .collect();

    let recovered = sharks.recover(&selected_shares).unwrap();
    let recovered_mnemonic = Mnemonic::from_entropy(&recovered).unwrap();

    assert_eq!(
        original_mnemonic.to_string(),
        recovered_mnemonic.to_string()
    );
}

#[test]
fn test_24_word_complete_workflow() {
    // Complete end-to-end test for 24-word mnemonic
    let mnemonic_str = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold";
    let original_mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str).unwrap();
    let entropy = original_mnemonic.to_entropy();

    // Split into 3 shares, threshold 2
    let threshold = 2;
    let num_shares = 3;
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&entropy);
    let share_vec: Vec<_> = dealer.take(num_shares).collect();

    // Encode as shamir39
    let share_mnemonics = share_vec
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
            .unwrap()
        })
        .collect::<Vec<_>>();

    // Select shares 0 and 2
    let selected_mnemonics = [share_mnemonics[0].clone(), share_mnemonics[2].clone()];

    // Parse and recover
    let selected_shares: Vec<blahaj::Share> = selected_mnemonics
        .iter()
        .map(|mnemonic| {
            let (_threshold, _index, share_data) =
                shamir39::parse_share(mnemonic.as_str()).unwrap();
            blahaj::Share::try_from(share_data.as_slice()).unwrap()
        })
        .collect();

    let recovered = sharks.recover(&selected_shares).unwrap();
    let recovered_mnemonic = Mnemonic::from_entropy(&recovered).unwrap();

    assert_eq!(
        original_mnemonic.to_string(),
        recovered_mnemonic.to_string()
    );
}
