#!/usr/bin/env bash
#
# Example usage script for shameless
# Demonstrates how to split and combine BIP39 mnemonics using Shamir Secret Sharing
#
# WARNING: This is for demonstration purposes only.
# Never use this script with real wallet mnemonics in an insecure environment.

set -euo pipefail

# Build the tool if not already built
if [ ! -f "./target/release/shameless" ]; then
    echo "Building shameless..."
    cargo build --release
fi

SHAMELESS="./target/release/shameless"

echo "============================================"
echo "Shameless - Example Usage"
echo "============================================"
echo

# Example 1: Split a 12-word mnemonic
echo "Example 1: Splitting a 12-word test mnemonic"
echo "---------------------------------------------"

# Test mnemonic (DO NOT use real mnemonics!)
TEST_MNEMONIC="shock work cute shuffle random thank before identify employ security during leisure"

echo "Original mnemonic:"
echo "  $TEST_MNEMONIC"
echo

# Split into 5 shares with threshold of 3
echo "Splitting into 5 shares (threshold: 3)..."
echo

# Capture output - mnemonic is passed via stdin for security
SPLIT_OUTPUT=$(echo "$TEST_MNEMONIC" | $SHAMELESS split -s 5 -t 3)

echo "$SPLIT_OUTPUT"
echo

# Extract individual shares from output
SHARE_1=$(echo "$SPLIT_OUTPUT" | grep -A 1 "Share #1:" | tail -1)
SHARE_2=$(echo "$SPLIT_OUTPUT" | grep -A 1 "Share #2:" | tail -1)
SHARE_3=$(echo "$SPLIT_OUTPUT" | grep -A 1 "Share #3:" | tail -1)
SHARE_4=$(echo "$SPLIT_OUTPUT" | grep -A 1 "Share #4:" | tail -1)
SHARE_5=$(echo "$SPLIT_OUTPUT" | grep -A 1 "Share #5:" | tail -1)

echo "============================================"
echo

# Example 2: Combine shares
echo "Example 2: Combining shares to recover mnemonic"
echo "------------------------------------------------"
echo "Using shares 1, 3, and 5 (any 3 of 5 will work)..."
echo

# Combine using shares 1, 3, and 5 - shares passed via stdin for security
# Empty line signals end of input
COMBINE_OUTPUT=$(printf "%s\n%s\n%s\n\n" "$SHARE_1" "$SHARE_3" "$SHARE_5" | $SHAMELESS combine)

echo "$COMBINE_OUTPUT"
echo

# Example 3: Insufficient shares
echo "============================================"
echo
echo "Example 3: Attempting with insufficient shares"
echo "-----------------------------------------------"
echo "Trying to combine with only 2 shares (threshold is 3)..."
echo

# This should fail
set +e
INSUFFICIENT_OUTPUT=$(printf "%s\n%s\n\n" "$SHARE_1" "$SHARE_2" | $SHAMELESS combine 2>&1)
INSUFFICIENT_EXIT_CODE=$?
set -e

if [ $INSUFFICIENT_EXIT_CODE -ne 0 ]; then
    echo "Failed as expected:"
    echo "$INSUFFICIENT_OUTPUT" | grep "Insufficient shares" || echo "$INSUFFICIENT_OUTPUT"
else
    echo "WARNING: Unexpected - should have failed with insufficient shares"
fi

echo

# Example 4: 24-word mnemonic
echo "============================================"
echo
echo "Example 4: Splitting a 24-word test mnemonic"
echo "---------------------------------------------"

TEST_MNEMONIC_24="void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"

echo "Original 24-word mnemonic:"
echo "  $TEST_MNEMONIC_24"
echo

# Split into 3 shares with threshold of 2
echo "Splitting into 3 shares (threshold: 2)..."
echo

# Mnemonic passed via stdin for security
SPLIT_OUTPUT_24=$(echo "$TEST_MNEMONIC_24" | $SHAMELESS split -s 3 -t 2)

echo "$SPLIT_OUTPUT_24"
echo

# Extract shares
SHARE_24_1=$(echo "$SPLIT_OUTPUT_24" | grep -A 1 "Share #1:" | tail -1)
SHARE_24_2=$(echo "$SPLIT_OUTPUT_24" | grep -A 1 "Share #2:" | tail -1)
SHARE_24_3=$(echo "$SPLIT_OUTPUT_24" | grep -A 1 "Share #3:" | tail -1)

echo "Combining with shares 1 and 3..."
echo

# Shares passed via stdin for security
COMBINE_OUTPUT_24=$(printf "%s\n%s\n\n" "$SHARE_24_1" "$SHARE_24_3" | $SHAMELESS combine)

echo "$COMBINE_OUTPUT_24"
echo

echo "============================================"
echo "All examples completed successfully!"
echo
echo "Production Usage Notes:"
echo "-----------------------"
echo "1. Store each share in a separate, secure location"
echo "2. Never store threshold or more shares together"
echo "3. Consider using different storage methods:"
echo "   - Paper backup (printed or handwritten)"
echo "   - Encrypted USB drives"
echo "   - Password manager vaults"
echo "   - Safety deposit boxes"
echo "4. Test recovery process before trusting the shares"
echo "5. Each share is self-describing (contains threshold info)"
echo "6. You only need threshold number of shares to recover"
echo
echo "Example secure storage plan (3-of-5):"
echo "  Share 1: Paper backup in home safe"
echo "  Share 2: Password manager"
echo "  Share 3: Trusted family member"
echo "  Share 4: Safety deposit box"
echo "  Share 5: Encrypted cloud backup"
echo
echo "With this setup, you can lose any 2 shares and still recover!"
echo "============================================"
