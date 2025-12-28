# bugcrowd-vrt

A comprehensive Rust library for working with the [Bugcrowd Vulnerability Rating Taxonomy (VRT)](https://bugcrowd.com/vulnerability-rating-taxonomy), including CWE mappings and CVSS v3 scoring.

[![Crates.io](https://img.shields.io/crates/v/bugcrowd-vrt.svg)](https://crates.io/crates/bugcrowd-vrt)
[![Documentation](https://docs.rs/bugcrowd-vrt/badge.svg)](https://docs.rs/bugcrowd-vrt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **VRT Taxonomy** - Type-safe deserialization of Bugcrowd's vulnerability taxonomy
- **CWE Mapping** - Map VRT categories to Common Weakness Enumeration (CWE) identifiers
- **CVSS v3** - Get CVSS v3 vectors and scores for vulnerabilities
- **Smart Categorization** - Automatically categorize vulnerability findings
- **Zero Dependencies** (core) - Minimal footprint with optional features
- **Well Tested** - 50+ tests covering edge cases and integrations

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
bugcrowd-vrt = "1.17"
```

### Basic Usage

```rust
use bugcrowd_vrt::{load_vrt_from_file, VulnerabilityCategorizer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load the VRT taxonomy
    let vrt = load_vrt_from_file("vrt.json")?;

    println!("Loaded {} vulnerability categories", vrt.len());

    // Find a specific vulnerability
    if let Some(node) = vrt[0].find_by_id("sql_injection") {
        println!("Found: {} (Priority: P{})",
            node.name,
            node.priority.unwrap_or(5)
        );
    }

    Ok(())
}
```

### Scanner Integration

Perfect for vulnerability scanners - automatically categorize findings:

```rust
use bugcrowd_vrt::{
    VulnerabilityCategorizer,
    load_vrt_from_file,
    load_cwe_mapping_from_file,
    load_cvss_v3_mapping_from_file,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load all mappings
    let vrt = load_vrt_from_file("vrt.json")?;
    let cwe = load_cwe_mapping_from_file("cwe.mappings.json")?;
    let cvss = load_cvss_v3_mapping_from_file("cvss_v3.json")?;

    let categorizer = VulnerabilityCategorizer::with_all_mappings(
        vrt, cwe, cvss
    );

    // Automatically categorize a finding
    let finding = categorizer
        .categorize_by_description("SQL injection in login form")
        .expect("Should categorize");

    println!("VRT: {}", finding.vrt_name);
    println!("Priority: P{}", finding.priority.unwrap_or(5));
    println!("CWEs: {:?}", finding.cwes);
    println!("CVSS: {:?}", finding.cvss_vector);

    Ok(())
}
```

**Output:**
```
VRT: SQL Injection
Priority: P1
CWEs: ["CWE-89"]
CVSS: Some("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N")
```

## Use Cases

### 1. Vulnerability Scanners

Categorize security findings with industry-standard taxonomies:

```rust
// Your scanner finds a vulnerability
let scanner_output = "Reflected XSS in search parameter";

// Automatically categorize it
if let Some(finding) = categorizer.categorize_by_description(scanner_output) {
    report_vulnerability(
        finding.vrt_name,
        finding.priority.unwrap_or(5),
        finding.cwes,
        finding.cvss_vector,
    );
}
```

### 2. Security Reporting

Generate standardized vulnerability reports:

```rust
// Export to JSON
let report = serde_json::json!({
    "vulnerability": finding.vrt_name,
    "vrt_id": finding.vrt_id,
    "priority": finding.priority,
    "category_path": finding.category_path,
    "cwe": finding.cwes,
    "cvss_v3": finding.cvss_vector,
});
```

### 3. Bug Bounty Platforms

Validate and categorize bug bounty submissions:

```rust
// Search for matching categories
let matches = categorizer.search_by_name("injection");
println!("Found {} injection-related categories", matches.len());

// Get details for each
for vrt_id in matches {
    if let Some(cat) = categorizer.categorize_by_id(&vrt_id) {
        println!("  - {} (P{})", cat.vrt_name, cat.priority.unwrap_or(5));
    }
}
```

## API Overview

### VRT Taxonomy

```rust
use bugcrowd_vrt::{load_vrt_from_file, VrtNode};

let taxonomy = load_vrt_from_file("vrt.json")?;

// Navigate the hierarchy
for category in &taxonomy {
    println!("Category: {}", category.name);

    for subcategory in &category.children {
        println!("  Subcategory: {}", subcategory.name);

        // Get all variants (leaf nodes)
        let variants = subcategory.variants();
        println!("    {} variants", variants.len());
    }
}

// Find by ID
if let Some(node) = taxonomy[0].find_by_id("sql_injection") {
    println!("Priority: P{}", node.priority.unwrap_or(5));
}
```

### CWE Mapping

```rust
use bugcrowd_vrt::load_cwe_mapping_from_file;

let cwe_mapping = load_cwe_mapping_from_file("cwe.mappings.json")?;

// Lookup CWE IDs for a VRT entry
if let Some(cwes) = cwe_mapping.lookup_cwe("sql_injection") {
    for cwe in cwes {
        println!("CWE: {}", cwe); // "CWE-89"
    }
}

// Get statistics
let stats = cwe_mapping.statistics();
println!("Coverage: {}/{} nodes mapped",
    stats.nodes_with_mappings,
    stats.total_nodes
);
```

### CVSS v3 Vectors

```rust
use bugcrowd_vrt::{load_cvss_v3_mapping_from_file, CvssV3Vector};
use std::str::FromStr;

let cvss_mapping = load_cvss_v3_mapping_from_file("cvss_v3.json")?;

// Get CVSS vector for a vulnerability
if let Some(vector) = cvss_mapping.lookup_cvss("sql_injection") {
    println!("CVSS: {}", vector);
    println!("Attack Vector: {:?}", vector.attack_vector);
    println!("Confidentiality: {:?}", vector.confidentiality);

    if vector.is_critical() {
        println!("⚠️  CRITICAL severity!");
    }
}

// Parse CVSS vectors
let vector = CvssV3Vector::from_str(
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
)?;
assert!(vector.is_critical());
```

### Vulnerability Categorization

```rust
use bugcrowd_vrt::VulnerabilityCategorizer;

let categorizer = VulnerabilityCategorizer::with_all_mappings(vrt, cwe, cvss);

// Method 1: Automatic categorization by description
let finding = categorizer.categorize_by_description(
    "Server-Side Request Forgery in API endpoint"
)?;

// Method 2: Direct lookup by VRT ID
let finding = categorizer.categorize_by_id("ssrf")?;

// Method 3: Search and select
let matches = categorizer.search_by_name("request forgery");
let finding = categorizer.categorize_by_id(&matches[0])?;

// Access all data
println!("VRT ID: {}", finding.vrt_id);
println!("Name: {}", finding.vrt_name);
println!("Path: {}", finding.category_path.join(" > "));
println!("Priority: P{}", finding.priority.unwrap_or(5));
println!("CWEs: {}", finding.cwes.join(", "));
println!("CVSS: {}", finding.cvss_vector.unwrap_or_default());
```

## Examples

Run the included examples:

```bash
# Load and explore VRT taxonomy
cargo run --example load_vrt

# Explore CWE mappings
cargo run --example cwe_mapping

# Explore CVSS v3 mappings
cargo run --example cvss_v3_mapping

# Complete scanner integration example
cargo run --example scanner_integration
```

## Data Files

You'll need the VRT data files (included in the repo):

- `vrt.json` - Bugcrowd VRT taxonomy (287 vulnerability variants)
- `cwe.mappings.json` - VRT to CWE mappings (117 unique CWEs)
- `cvss_v3.json` - VRT to CVSS v3 mappings (252 entries)

Download the latest from [Bugcrowd's VRT repository](https://github.com/bugcrowd/vulnerability-rating-taxonomy).

## Documentation

- **[Scanner Integration Guide](SCANNER_INTEGRATION.md)** - Complete guide for vulnerability scanner integration
- **[API Documentation](https://docs.rs/bugcrowd-vrt)** - Full API reference
- **[Examples Directory](examples/)** - Working code examples

## Type Safety

All types are fully documented and use Rust's type system for safety:

```rust
pub struct VrtNode {
    pub id: String,
    pub name: String,
    pub node_type: VrtNodeType,  // Category | Subcategory | Variant
    pub children: Vec<VrtNode>,
    pub priority: Option<u8>,     // 1-5 for variants
}

pub struct CategorizedFinding {
    pub vrt_id: String,
    pub vrt_name: String,
    pub priority: Option<u8>,
    pub category_path: Vec<String>,
    pub cwes: Vec<String>,
    pub cvss_vector: Option<String>,
}

pub struct CvssV3Vector {
    pub attack_vector: AttackVector,
    pub attack_complexity: AttackComplexity,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: UserInteraction,
    pub scope: Scope,
    pub confidentiality: Impact,
    pub integrity: Impact,
    pub availability: Impact,
}
```

## Performance

- **Loading VRT data**: ~50ms (one-time at startup)
- **Categorization by ID**: O(1) - instant lookup
- **Categorization by description**: ~1ms (keyword matching)
- **Search operations**: ~5ms (full taxonomy scan)

Suitable for high-throughput scanners processing thousands of findings.

## Testing

Comprehensive test coverage with 50+ tests:

```bash
# Run all tests
cargo test

# Run specific test suites
cargo test vrt_tests
cargo test cwe_mapping_tests
cargo test cvss_v3_tests
cargo test edge_cases_tests
cargo test categorization

# Run with output
cargo test -- --nocapture
```

Test categories:
- ✅ VRT taxonomy parsing and navigation
- ✅ CWE mapping and lookups
- ✅ CVSS v3 parsing and validation
- ✅ Edge cases (empty data, invalid formats, deep nesting)
- ✅ Categorization accuracy
- ✅ Integration examples

## Project Structure

```
bugcrowd-vrt/
├── src/
│   ├── lib.rs              # Main library exports
│   ├── types.rs            # VRT taxonomy types
│   ├── cwe_mapping.rs      # CWE mapping types
│   ├── cvss_v3.rs          # CVSS v3 types and parsing
│   └── categorization.rs   # Vulnerability categorization
├── tests/
│   ├── vrt_tests.rs
│   ├── types_tests.rs
│   ├── cwe_mapping_tests.rs
│   ├── cvss_v3_tests.rs
│   └── edge_cases_tests.rs
├── examples/
│   ├── load_vrt.rs
│   ├── cwe_mapping.rs
│   ├── cvss_v3_mapping.rs
│   └── scanner_integration.rs
├── vrt.json                # VRT taxonomy data
├── cwe.mappings.json       # CWE mappings
├── cvss_v3.json            # CVSS v3 mappings
└── SCANNER_INTEGRATION.md  # Integration guide
```

## Contributing

Contributions welcome! Please:

1. Add tests for new features
2. Update documentation
3. Follow existing code style
4. Run `cargo fmt` and `cargo clippy`

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Bugcrowd](https://bugcrowd.com) for the VRT taxonomy
- [MITRE](https://cwe.mitre.org) for CWE
- [FIRST](https://www.first.org/cvss/) for CVSS

## Related Projects

- [Bugcrowd VRT](https://github.com/bugcrowd/vulnerability-rating-taxonomy) - Official VRT repository
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1) - Official CVSS v3.1 calculator

## Support

- 📖 [Documentation](https://docs.rs/bugcrowd-vrt)
- 💬 [Issues](https://github.com/akses0/bugcrowd-vrt/issues)
- 📧 Contact: [trapdoorsec.com](https://trapdoorsec.com)

---

Made with ❤️ for the security community
