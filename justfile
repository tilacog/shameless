# Default recipe to display available commands
default:
    @just --list

# Check code formatting without making changes
fmt:
    cargo fmt --all -- --check

# Auto-fix clippy warnings and format code
fix:
    cargo clippy --all-targets --all-features --fix --allow-dirty -- -W clippy::pedantic
    cargo fmt --all

# Run all tests
test:
    cargo test

# Run documentation tests
doctest:
    cargo test --doc

# Run property-based tests only
proptest $QUICKCHECK_TESTS="100000":
    cargo test --release -- --nocapture quickcheck prop_

# Run clippy with pedantic lints
clippy:
    cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic

# Run all CI checks (fmt, clippy, test, doctest)
ci: fmt clippy test doctest
    @echo "All CI checks passed!"

# Build WASM module for web (requires wasm-pack)
wasm-build:
    wasm-pack build --target web --out-dir docs/pkg

# Serve the web demo locally for testing
wasm-serve:
    @echo "Serving on http://localhost:8000"
    @echo "Press Ctrl+C to stop"
    python3 -m http.server 8000 --directory docs

# Build WASM and serve locally
wasm-dev: wasm-build wasm-serve

# Clean WASM build artifacts
wasm-clean:
    rm -rf docs/pkg target/wasm32-unknown-unknown

# Check that WASM builds without errors
wasm-check:
    cargo check --lib --target wasm32-unknown-unknown --no-default-features
