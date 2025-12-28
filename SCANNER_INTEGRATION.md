# Integrating Bugcrowd VRT into Your Vulnerability Scanner

This guide shows how to use the `bugcrowd-vrt` library to categorize vulnerability findings from your web scanner using the Bugcrowd Vulnerability Rating Taxonomy (VRT).

## Quick Start

### 1. Add to Your Project

```toml
[dependencies]
bugcrowd-vrt = "1.17"
```

### 2. Basic Usage

```rust
use bugcrowd_vrt::{
    VulnerabilityCategorizer,
    load_vrt_from_file,
    load_cwe_mapping_from_file,
    load_cvss_v3_mapping_from_file,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load the VRT taxonomy and mappings
    let vrt = load_vrt_from_file("vrt.json")?;
    let cwe_mapping = load_cwe_mapping_from_file("cwe.mappings.json")?;
    let cvss_mapping = load_cvss_v3_mapping_from_file("cvss_v3.json")?;

    // Create the categorizer
    let categorizer = VulnerabilityCategorizer::with_all_mappings(
        vrt,
        cwe_mapping,
        cvss_mapping,
    );

    // Categorize a finding by description
    if let Some(finding) = categorizer.categorize_by_description(
        "SQL injection detected in login form"
    ) {
        println!("VRT: {}", finding.vrt_name);
        println!("Priority: P{}", finding.priority.unwrap_or(5));
        println!("CWEs: {:?}", finding.cwes);
        println!("CVSS: {:?}", finding.cvss_vector);
    }

    Ok(())
}
```

## Use Cases

### Method 1: Automatic Categorization by Description

Best for: Scanner output with descriptive finding names

```rust
// Your scanner finds a vulnerability
let scanner_output = "Cross-Site Scripting (XSS) detected in search parameter";

// Automatically categorize it
if let Some(finding) = categorizer.categorize_by_description(scanner_output) {
    println!("Categorized as: {} ({})", finding.vrt_name, finding.vrt_id);
    println!("Priority: P{}", finding.priority.unwrap_or(5));
    println!("CWE IDs: {}", finding.cwes.join(", "));
}
```

**Supported Keywords:**
- SQL injection, SQLi, SQL
- XSS, Cross-Site Scripting
- SSRF, Server-Side Request Forgery
- RCE, Remote Code Execution
- IDOR, Insecure Direct Object Reference
- CSRF, Cross-Site Request Forgery
- Path traversal, Directory traversal
- And many more (see `build_keyword_mappings()` in categorization.rs)

### Method 2: Direct VRT ID Lookup

Best for: When you know the exact VRT identifier

```rust
// If you maintain a mapping of scanner checks to VRT IDs
let scanner_check_id = "SQL_001";
let vrt_id = match scanner_check_id {
    "SQL_001" => "sql_injection",
    "XSS_001" => "cross_site_scripting_xss",
    "IDOR_001" => "idor",
    _ => return None,
};

if let Some(finding) = categorizer.categorize_by_id(vrt_id) {
    // Get full VRT metadata
    println!("Category Path: {}", finding.category_path.join(" > "));
}
```

### Method 3: Search for VRT Categories

Best for: Building UI selection or manual categorization

```rust
// Search for relevant VRT categories
let matches = categorizer.search_by_name("injection");

println!("Found {} matching categories:", matches.len());
for vrt_id in matches {
    if let Some(finding) = categorizer.categorize_by_id(&vrt_id) {
        println!("  - {} (P{})", finding.vrt_name, finding.priority.unwrap_or(5));
    }
}
```

## Complete Scanner Integration Example

```rust
use bugcrowd_vrt::{VulnerabilityCategorizer, CategorizedFinding};

// Your scanner's finding structure
struct ScannerFinding {
    url: String,
    check_name: String,
    description: String,
    severity: String, // Your scanner's severity
}

// Enriched finding with VRT data
struct EnrichedFinding {
    original: ScannerFinding,
    vrt: Option<CategorizedFinding>,
}

fn categorize_scanner_findings(
    findings: Vec<ScannerFinding>,
    categorizer: &VulnerabilityCategorizer,
) -> Vec<EnrichedFinding> {
    findings
        .into_iter()
        .map(|finding| {
            // Try automatic categorization
            let vrt = categorizer
                .categorize_by_description(&finding.description)
                .or_else(|| {
                    // Fallback: try check name
                    categorizer.categorize_by_description(&finding.check_name)
                });

            EnrichedFinding {
                original: finding,
                vrt,
            }
        })
        .collect()
}

// Generate a report
fn generate_report(findings: Vec<EnrichedFinding>) {
    // Group by VRT priority
    let mut by_priority: std::collections::HashMap<u8, Vec<_>> =
        std::collections::HashMap::new();

    for finding in findings {
        if let Some(ref vrt) = finding.vrt {
            let priority = vrt.priority.unwrap_or(5);
            by_priority.entry(priority).or_default().push(finding);
        }
    }

    // Print report
    for priority in 1..=5 {
        if let Some(findings) = by_priority.get(&priority) {
            println!("\n=== Priority {} ({} findings) ===", priority, findings.len());
            for finding in findings {
                let vrt = finding.vrt.as_ref().unwrap();
                println!("  • {} - {}", vrt.vrt_name, finding.original.url);
                println!("    CWEs: {}", vrt.cwes.join(", "));
                if let Some(cvss) = &vrt.cvss_vector {
                    println!("    CVSS: {}", cvss);
                }
            }
        }
    }
}
```

## Export Formats

### JSON Export

```rust
use serde_json::json;

fn export_to_json(finding: &EnrichedFinding) -> serde_json::Value {
    let vrt = finding.vrt.as_ref().unwrap();

    json!({
        "url": finding.original.url,
        "vulnerability": {
            "scanner_name": finding.original.check_name,
            "description": finding.original.description,
        },
        "vrt": {
            "id": vrt.vrt_id,
            "name": vrt.vrt_name,
            "category_path": vrt.category_path,
            "priority": vrt.priority,
        },
        "standards": {
            "cwe": vrt.cwes,
            "cvss_v3": vrt.cvss_vector,
        }
    })
}
```

### CSV Export

```rust
fn export_to_csv(findings: Vec<EnrichedFinding>) -> String {
    let mut csv = String::from("URL,Vulnerability,VRT ID,VRT Name,Priority,CWE,CVSS\n");

    for finding in findings {
        if let Some(vrt) = finding.vrt {
            csv.push_str(&format!(
                "{},{},{},{},P{},{},{}\n",
                finding.original.url,
                finding.original.check_name,
                vrt.vrt_id,
                vrt.vrt_name,
                vrt.priority.unwrap_or(5),
                vrt.cwes.join(";"),
                vrt.cvss_vector.unwrap_or_default()
            ));
        }
    }

    csv
}
```

## Available VRT Data

For each categorized finding, you get:

- **`vrt_id`**: Machine-readable identifier (e.g., `"sql_injection"`)
- **`vrt_name`**: Human-readable name (e.g., `"SQL Injection"`)
- **`priority`**: Bugcrowd priority rating (1-5, where 1 is most severe)
- **`category_path`**: Full taxonomy path (e.g., `["Server-Side Injection", "SQL Injection"]`)
- **`cwes`**: List of CWE IDs (e.g., `["CWE-89"]`)
- **`cvss_vector`**: CVSS v3.x vector string (e.g., `"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"`)

## Utility Functions

### Get All Available Categories

```rust
// List all VRT variant IDs (287 total)
let all_variants = categorizer.list_all_variants();
println!("Total VRT variants: {}", all_variants.len());
```

### Get All Categorizations

```rust
// Get complete categorization data for all variants
let all_findings = categorizer.get_all_categorizations();

// Use for pre-populating dropdowns, building indices, etc.
for finding in all_findings {
    println!("{}: P{}", finding.vrt_name, finding.priority.unwrap_or(5));
}
```

## Best Practices

1. **Load Once**: Load VRT data once at startup and reuse the categorizer
2. **Cache Mappings**: Create a lookup table from your scanner's check IDs to VRT IDs
3. **Handle Misses**: Have a fallback for findings that don't auto-categorize
4. **Validate Results**: Review automatic categorizations periodically
5. **Update VRT Data**: Regularly update vrt.json, cwe.mappings.json, and cvss_v3.json

## Performance Considerations

- Loading VRT data: ~50ms (one-time)
- Categorization by ID: O(1) - instant
- Categorization by description: O(n) where n = number of keywords (~1ms)
- Search by name: O(n) where n = total VRT entries (~5ms)

For high-throughput scanners, consider:
1. Pre-computing VRT mappings for known check types
2. Using direct ID lookups instead of description matching
3. Caching categorization results

## Example: Complete Scanner

See `examples/scanner_integration.rs` for a complete working example.

```bash
cargo run --example scanner_integration
```

## Need Help?

- Check examples directory for working code
- Review tests for API usage patterns
- Open an issue for bugs or feature requests
