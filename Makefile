# Makefile for c2pa-cbor development

.PHONY: fmt test test-all test-compact check help

fmt-check:
	cargo +nightly-2026-01-16 fmt --all -- --check

# Format code with specific nightly toolchain
fmt:
	cargo +nightly-2026-01-16 fmt

# Run standard tests
test: fmt-check
	cargo test

# Run all tests with all features
test-all:
	cargo test --all-features

# Run tests with compact_floats feature
test-compact:
	cargo test --features compact_floats

# Run RFC 8949 compliance tests
test-rfc:
	cargo test --features compact_floats --test rfc8949_compliance

# Check code without building
check:
	cargo check --all-targets --all-features

# Run clippy linter
clippy:
	cargo clippy --all-targets --all-features

# Build documentation
docs:
	cargo doc --no-deps --all-features

# Show this help message
help:
	@echo "Available targets:"
	@echo "  fmt          - Format code with nightly-2026-01-16"
	@echo "  test         - Run standard tests"
	@echo "  test-all     - Run tests with all features"
	@echo "  test-compact - Run tests with compact_floats feature"
	@echo "  test-rfc     - Run RFC 8949 compliance tests"
	@echo "  check        - Check code without building"
	@echo "  clippy       - Run clippy linter"
	@echo "  docs         - Build documentation"
	@echo "  help         - Show this help message"
