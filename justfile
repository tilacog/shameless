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
