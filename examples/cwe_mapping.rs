use bugcrowd_vrt::{load_cwe_mapping_from_file, load_vrt_from_file};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Loading VRT taxonomy and CWE mappings...\n");

    // Load both the VRT taxonomy and CWE mappings
    let vrt = load_vrt_from_file("vrt.json")?;
    let cwe_mapping = load_cwe_mapping_from_file("cwe.mappings.json")?;

    // Display statistics
    let stats = cwe_mapping.statistics();
    println!("=== CWE Mapping Statistics ===");
    println!("Total VRT nodes: {}", stats.total_nodes);
    println!("Nodes with CWE mappings: {}", stats.nodes_with_mappings);
    println!("Nodes without mappings: {}", stats.nodes_without_mappings);
    println!(
        "Coverage: {:.1}%",
        (stats.nodes_with_mappings as f64 / stats.total_nodes as f64) * 100.0
    );

    // Get all unique CWE IDs
    let all_cwes = cwe_mapping.all_cwe_ids();
    println!("\nUnique CWE IDs in mapping: {}", all_cwes.len());

    // Show some example mappings
    println!("\n=== Example VRT to CWE Mappings ===");

    let examples = [
        ("cross_site_scripting_xss", "Cross-Site Scripting (XSS)"),
        ("sql_injection", "SQL Injection"),
        ("broken_access_control", "Broken Access Control"),
        ("server_side_request_forgery_ssrf", "Server-Side Request Forgery"),
        ("idor", "Insecure Direct Object References"),
    ];

    for (vrt_id, description) in &examples {
        if let Some(cwes) = cwe_mapping.lookup_cwe(vrt_id) {
            print!("{} ({}): ", description, vrt_id);
            for (i, cwe) in cwes.iter().enumerate() {
                if i > 0 {
                    print!(", ");
                }
                print!("{}", cwe);
            }
            println!();
        } else {
            println!("{} ({}): No CWE mapping", description, vrt_id);
        }
    }

    // Find VRT categories without CWE mappings
    println!("\n=== Categories Without CWE Mappings ===");
    let mut no_mapping_count = 0;
    for node in &cwe_mapping.content {
        if !node.has_cwe_mapping() {
            println!("  - {} ({})", node.id, if node.has_children() { "has children" } else { "no children" });
            no_mapping_count += 1;
            if no_mapping_count >= 10 {
                println!("  ... and {} more", cwe_mapping.content.iter().filter(|n| !n.has_cwe_mapping()).count() - 10);
                break;
            }
        }
    }

    // Cross-reference with VRT taxonomy
    println!("\n=== VRT Category Coverage ===");
    let mut mapped = 0;

    for category in &vrt {
        if let Some(mapping_node) = cwe_mapping.find_by_vrt_id(&category.id) {
            if mapping_node.has_cwe_mapping() || mapping_node.children.iter().any(|c| c.has_cwe_mapping()) {
                mapped += 1;
            }
        }
    }

    println!("VRT categories with CWE data: {}/{}", mapped, vrt.len());
    println!(
        "Coverage: {:.1}%",
        (mapped as f64 / vrt.len() as f64) * 100.0
    );

    // Show CWE distribution
    println!("\n=== Most Common CWEs (Top 10) ===");
    let mut cwe_counts = std::collections::HashMap::new();
    for node in &cwe_mapping.content {
        count_cwes(node, &mut cwe_counts);
    }

    let mut cwe_vec: Vec<_> = cwe_counts.iter().collect();
    cwe_vec.sort_by(|a, b| b.1.cmp(a.1));

    for (i, (cwe, count)) in cwe_vec.iter().take(10).enumerate() {
        println!("{}. {} - {} occurrences", i + 1, cwe, count);
    }

    Ok(())
}

fn count_cwes(node: &bugcrowd_vrt::CweMappingNode, counts: &mut std::collections::HashMap<String, usize>) {
    if let Some(cwes) = &node.cwe {
        for cwe in cwes {
            *counts.entry(cwe.as_str().to_string()).or_insert(0) += 1;
        }
    }

    for child in &node.children {
        count_cwes(child, counts);
    }
}
