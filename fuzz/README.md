# VERITAS Protocol Fuzz Testing

This directory contains fuzz testing infrastructure for the VERITAS protocol.

## Prerequisites

Install `cargo-fuzz`:

```bash
cargo install cargo-fuzz
```

**Note**: Fuzzing requires nightly Rust:

```bash
rustup install nightly
```

## Available Fuzz Targets

| Target | Description |
|--------|-------------|
| `fuzz_symmetric_decrypt` | Tests symmetric decryption with arbitrary ciphertext |
| `fuzz_hash_from_bytes` | Tests Hash256 parsing from arbitrary bytes |
| `fuzz_encrypted_data_parse` | Tests EncryptedData deserialization |
| `fuzz_identity_hash_from_hex` | Tests IdentityHash hex parsing |
| `fuzz_username_validation` | Tests Username validation with arbitrary strings |
| `fuzz_padding` | Tests message padding/unpadding |
| `fuzz_message_chunking` | Tests message chunking and reassembly |
| `fuzz_x25519_public_key` | Tests X25519 public key parsing |

## Running Fuzz Tests

### Run a specific target

```bash
cd fuzz
cargo +nightly fuzz run fuzz_symmetric_decrypt
```

### Run with limited time

```bash
cargo +nightly fuzz run fuzz_username_validation -- -max_total_time=60
```

### List all targets

```bash
cargo +nightly fuzz list
```

### View coverage

After running fuzz tests, view coverage:

```bash
cargo +nightly fuzz coverage fuzz_symmetric_decrypt
```

### Minimize a crash

If a crash is found:

```bash
cargo +nightly fuzz tmin fuzz_symmetric_decrypt artifacts/fuzz_symmetric_decrypt/crash-XXX
```

## Corpus Management

Fuzz corpora are stored in `corpus/<target>/`. To seed the corpus:

```bash
mkdir -p corpus/fuzz_username_validation
echo "validuser" > corpus/fuzz_username_validation/seed1
echo "test_user" > corpus/fuzz_username_validation/seed2
```

## CI Integration

For CI, run fuzz tests for a limited time:

```bash
# Run each target for 30 seconds
for target in $(cargo +nightly fuzz list); do
    cargo +nightly fuzz run $target -- -max_total_time=30
done
```

## Security Notes

- Fuzz targets focus on parsing untrusted input
- All targets should never panic - only return errors
- Any crash indicates a potential security issue
- Crashes are saved in `artifacts/<target>/`

## Adding New Targets

1. Create a new file in `fuzz_targets/`
2. Add a `[[bin]]` entry in `Cargo.toml`
3. Use the `fuzz_target!` macro

Example:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Your fuzzing code here
    // Should handle all input gracefully
});
```
