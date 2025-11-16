# Shameless

Split Ethereum BIP39 mnemonics into Shamir Secret Shares using shameless encoding (directly based on the [shamir39](https://github.com/iancoleman/shamir39) specification).

## Features

- Split 12 or 24-word BIP39 mnemonics into threshold-based shares
- Each share is a single BIP39 mnemonic with embedded metadata prefixed with the `shameless` identifier
- Shares are self-describing (embed threshold and index)

## Installation

```bash
cargo build --release
```

Binary: `./target/release/shameless`

## Usage

### Split

```bash
shameless split -m "legal winner thank year wave sausage worth useful legal winner thank yellow" -s 5 -t 3
```

Output:
```
Original mnemonic entropy: 16 bytes

Created 5 shares (threshold: 3)
You need at least 3 shares to reconstruct the secret.

Share #1:
shameless amount abandon boring keep ill alert liberty weird elevator escape word doll verb garment

Share #2:
shameless amused abandon claw diary need detect organ bind useful patient cart execute trash arrange

Share #3:
shameless analyst abandon cross will burst stick glue behind jelly base civil rabbit trend rough
...
```

### Combine

```bash
shameless combine --shares "shameless amount abandon boring...","shameless amused abandon claw...","shameless analyst abandon cross..."
```

Output:
```
Successfully reconstructed mnemonic:
legal winner thank year wave sausage worth useful legal winner thank yellow
```

## How It Works

1. Mnemonic → entropy bytes (16 bytes for 12 words, 32 bytes for 24 words)
2. Entropy → Shamir shares using [blahaj](https://github.com/c0dearm/blahaj)
3. Each share → shameless mnemonic (single BIP39 phrase with embedded metadata)

Each share is self-describing:
- Format: `shameless <params> <data>`
- Embeds threshold and share index
- Variable length based on secret size

## Security

- **Information-theoretically secure**: Individual shares reveal nothing about the secret
- **Threshold security**: Requires exactly `threshold` shares to reconstruct
- **Minimum threshold**: Threshold must be at least 2 (threshold of 1 provides no security benefit as any single share can recover the entire secret)


## Technical Details

**Dependencies:**
- `blahaj` - Secure Shamir Secret Sharing (GF256)
- `bip39` - BIP39 mnemonic handling
- `clap` - CLI argument parsing

**Encoding:**
- [shamir39 specification](https://github.com/iancoleman/shamir39/blob/master/specification.md)
- 11-bit word encoding with metadata
- Standard BIP39 English wordlist

## Testing

```bash
just test      # Run all tests
just ci        # Run full CI checks (fmt + clippy + test)
```

Test suite includes:
- Unit tests for encoding/decoding
- Integration tests for split/combine workflows
- Property-based tests (quickcheck) for randomized validation
- Documentation tests for API examples

## Credits

This project is directly based on the [`shamir39` specification](https://github.com/iancoleman/shamir39) by Ian Coleman, which provides a compact, self-describing format for encoding Shamir Secret Shares as BIP39 mnemonics. Shameless uses the "shameless" version identifier instead of "shamir39" to distinguish its output format.

## Warning

**Use at your own risk!**
- This is a prototype.
- This tool should only be used for experiments.
- This tool handles sensitive cryptographic key material.
- There are no alternative implementations, meaning you are totally dependent on this tool if you use it. That is a dangerous situation to be in.

**Consider using a multisig wallet instead:**
- For most use cases requiring distributed control or threshold security, you probably want a multisig wallet rather than this tool
- Multisig wallets like [Safe](https://safe.global/) (formerly Gnosis Safe) provide on-chain threshold security with much better tooling, recovery options, and ecosystem support
- Shamir Secret Sharing is primarily useful for offline backup scenarios, not ongoing wallet management

**Before using with real funds:**
- Test with dummy mnemonics first
- Verify reconstruction works correctly
- Store shares in separate secure locations
- Understand the risks of threshold cryptography
