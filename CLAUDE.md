# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust client library for the Bugcrowd Vulnerability Rating Taxonomy (VRT). The VRT is a standardized taxonomy for security vulnerabilities used by Bugcrowd's bug bounty platform. The library provides a client (`BugcrowdVrtClient`) to fetch VRT data from Bugcrowd's API and type-safe representations of the taxonomy.

## Development Commands

### Building and Testing
```bash
# Build the project
cargo build

# Build in release mode
cargo build --release

# Run tests
cargo test

# Run a specific test
cargo test <test_name>

# Run tests with output
cargo test -- --nocapture
```

### Code Quality
```bash
# Format code
cargo fmt

# Check formatting without modifying files
cargo fmt -- --check

# Run linter
cargo clippy

# Run clippy with all features
cargo clippy --all-features
```

### Documentation
```bash
# Generate and open documentation
cargo doc --open

# Build documentation without opening
cargo doc
```

### Running Examples
```bash
# Run the fetch example to test VRT API integration
cargo run --example fetch
```

## Architecture Notes

The library is structured as an async HTTP client that interacts with Bugcrowd's VRT API:

- **Client**: `BugcrowdVrtClient` - Main entry point for interacting with the VRT API
- **Dependencies**: Uses `reqwest` for async HTTP requests, `serde` for JSON serialization, and `thiserror` for error handling
- **Async Runtime**: All API calls are async and require a tokio runtime (see `example/fetch.rs` for usage)

The Bugcrowd VRT is a hierarchical taxonomy, so the type system should reflect this structure while maintaining type safety and ergonomic API design.
