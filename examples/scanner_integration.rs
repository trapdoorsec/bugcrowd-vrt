/// Example: Integrating VRT categorization into a web vulnerability scanner
///
/// This example demonstrates how to categorize vulnerability findings from
/// a web scanner using the Bugcrowd VRT taxonomy, CWE mappings, and CVSS scores.

use bugcrowd_vrt::{
    load_cwe_mapping_from_file, load_cvss_v3_mapping_from_file, load_vrt_from_file,
    VulnerabilityCategorizer,
};

// Simulated finding from your vulnerability scanner
#[derive(Debug)]
struct ScannerFinding {
    url: String,
    vulnerability_type: String,
    description: String,
    evidence: String,
}

// Enriched finding with VRT categorization
#[derive(Debug)]
struct CategorizedScannerFinding {
    // Original scanner data
    url: String,
    vulnerability_type: String,
    description: String,
    evidence: String,

    // VRT categorization
    vrt_id: String,
    vrt_name: String,
    vrt_category_path: String,
    priority: u8,
    cwes: Vec<String>,
    cvss_vector: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Vulnerability Scanner VRT Integration Example ===\n");

    // Step 1: Load VRT taxonomy and mappings
    println!("Loading VRT taxonomy and mappings...");
    let vrt = load_vrt_from_file("vrt.json")?;
    let cwe_mapping = load_cwe_mapping_from_file("cwe.mappings.json")?;
    let cvss_mapping = load_cvss_v3_mapping_from_file("cvss_v3.json")?;

    // Step 2: Create the categorizer
    let categorizer =
        VulnerabilityCategorizer::with_all_mappings(vrt, cwe_mapping, cvss_mapping);

    println!("Categorizer initialized with {} variants\n", categorizer.list_all_variants().len());

    // Step 3: Simulate findings from your scanner
    let scanner_findings = vec![
        ScannerFinding {
            url: "https://example.com/login".to_string(),
            vulnerability_type: "SQL Injection".to_string(),
            description: "SQL injection vulnerability detected in login form".to_string(),
            evidence: "Parameter 'username' is vulnerable to UNION-based SQL injection".to_string(),
        },
        ScannerFinding {
            url: "https://example.com/search".to_string(),
            vulnerability_type: "XSS".to_string(),
            description: "Reflected Cross-Site Scripting found".to_string(),
            evidence: "Parameter 'q' reflects user input without sanitization".to_string(),
        },
        ScannerFinding {
            url: "https://example.com/profile".to_string(),
            vulnerability_type: "IDOR".to_string(),
            description: "Insecure Direct Object Reference in user profiles".to_string(),
            evidence: "Can access other users' profiles by changing 'user_id' parameter".to_string(),
        },
        ScannerFinding {
            url: "https://example.com/api/internal".to_string(),
            vulnerability_type: "SSRF".to_string(),
            description: "Server-Side Request Forgery detected".to_string(),
            evidence: "API endpoint allows requests to internal network resources".to_string(),
        },
    ];

    // Step 4: Categorize each finding
    println!("=== Categorizing {} Findings ===\n", scanner_findings.len());

    let mut categorized_findings = Vec::new();

    for finding in scanner_findings {
        println!("Original Finding:");
        println!("  URL: {}", finding.url);
        println!("  Type: {}", finding.vulnerability_type);
        println!("  Description: {}", finding.description);

        // Try to categorize by description (automatic mapping)
        if let Some(vrt_finding) = categorizer.categorize_by_description(&finding.description) {
            println!("\nVRT Categorization:");
            println!("  VRT ID: {}", vrt_finding.vrt_id);
            println!("  VRT Name: {}", vrt_finding.vrt_name);
            println!("  Category Path: {}", vrt_finding.category_path.join(" > "));
            println!("  Priority: P{}", vrt_finding.priority.unwrap_or(5));

            if !vrt_finding.cwes.is_empty() {
                println!("  CWEs: {}", vrt_finding.cwes.join(", "));
            }

            if let Some(cvss) = &vrt_finding.cvss_vector {
                println!("  CVSS v3: {}", cvss);
            }

            categorized_findings.push(CategorizedScannerFinding {
                url: finding.url.clone(),
                vulnerability_type: finding.vulnerability_type.clone(),
                description: finding.description.clone(),
                evidence: finding.evidence.clone(),
                vrt_id: vrt_finding.vrt_id.clone(),
                vrt_name: vrt_finding.vrt_name.clone(),
                vrt_category_path: vrt_finding.category_path.join(" > "),
                priority: vrt_finding.priority.unwrap_or(5),
                cwes: vrt_finding.cwes.clone(),
                cvss_vector: vrt_finding.cvss_vector.clone(),
            });
        } else {
            println!("\nVRT Categorization: Not found (manual categorization needed)");
        }

        println!("\n{}", "=".repeat(80));
        println!();
    }

    // Step 5: Generate summary report
    println!("\n=== Summary Report ===\n");

    categorized_findings.sort_by_key(|f| f.priority);

    println!("Findings by Priority:");
    for priority in 1..=5 {
        let count = categorized_findings.iter().filter(|f| f.priority == priority).count();
        if count > 0 {
            println!("  P{}: {} finding(s)", priority, count);
        }
    }

    println!("\nCritical Findings (P1-P2):");
    for finding in categorized_findings.iter().filter(|f| f.priority <= 2) {
        println!("  • {} - {} ({})", finding.vrt_name, finding.url, finding.vrt_id);
    }

    // Step 6: Example of direct VRT ID lookup (if you know the VRT ID)
    println!("\n=== Example: Direct VRT ID Lookup ===\n");

    let direct_lookup_ids = vec!["sql_injection", "cross_site_scripting_xss", "idor"];

    for vrt_id in direct_lookup_ids {
        if let Some(finding) = categorizer.categorize_by_id(vrt_id) {
            println!("VRT ID: {}", finding.vrt_id);
            println!("  Name: {}", finding.vrt_name);
            println!("  Priority: P{}", finding.priority.unwrap_or(5));
            println!("  CWEs: {:?}", finding.cwes);
            println!();
        }
    }

    // Step 7: Search for VRT entries
    println!("=== Example: Searching VRT ===\n");

    let search_terms = vec!["injection", "disclosure", "bypass"];

    for term in search_terms {
        let results = categorizer.search_by_name(term);
        println!("Search '{}': {} results", term, results.len());
        for id in results.iter().take(3) {
            println!("  - {}", id);
        }
        if results.len() > 3 {
            println!("  ... and {} more", results.len() - 3);
        }
        println!();
    }

    // Step 8: Export findings as JSON (for reporting)
    println!("=== Example: JSON Export ===\n");

    if let Some(finding) = categorized_findings.first() {
        let json = serde_json::json!({
            "url": finding.url,
            "vulnerability": {
                "scanner_type": finding.vulnerability_type,
                "description": finding.description,
                "evidence": finding.evidence
            },
            "vrt": {
                "id": finding.vrt_id,
                "name": finding.vrt_name,
                "category_path": finding.vrt_category_path,
                "priority": finding.priority
            },
            "standards": {
                "cwe": finding.cwes,
                "cvss_v3": finding.cvss_vector
            }
        });

        println!("{}", serde_json::to_string_pretty(&json)?);
    }

    Ok(())
}
