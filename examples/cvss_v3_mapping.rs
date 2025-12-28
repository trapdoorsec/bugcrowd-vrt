use bugcrowd_vrt::{load_cvss_v3_mapping_from_file, load_vrt_from_file, Impact};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Loading VRT taxonomy and CVSS v3 mappings...\n");

    // Load both the VRT taxonomy and CVSS v3 mappings
    let vrt = load_vrt_from_file("vrt.json")?;
    let cvss_mapping = load_cvss_v3_mapping_from_file("cvss_v3.json")?;

    // Display statistics
    let stats = cvss_mapping.statistics();
    println!("=== CVSS v3 Mapping Statistics ===");
    println!("Total VRT nodes: {}", stats.total_nodes);
    println!("Nodes with CVSS mappings: {}", stats.nodes_with_mappings);
    println!("Nodes without mappings: {}", stats.nodes_without_mappings);
    println!(
        "Coverage: {:.1}%",
        (stats.nodes_with_mappings as f64 / stats.total_nodes as f64) * 100.0
    );

    // Show default CVSS vector
    println!("\n=== Default CVSS Vector ===");
    println!("{}", cvss_mapping.metadata.default);

    // Show some example mappings
    println!("\n=== Example VRT to CVSS v3 Mappings ===");

    let examples = [
        ("cross_site_scripting_xss", "Cross-Site Scripting (XSS)"),
        ("full_system_compromise", "Full System Compromise (RCE)"),
        ("idor", "Insecure Direct Object References"),
        ("sql_injection", "SQL Injection"),
        ("clickjacking", "Clickjacking"),
    ];

    for (vrt_id, description) in &examples {
        if let Some(vector) = cvss_mapping.lookup_cvss(vrt_id) {
            println!("\n{} ({}):", description, vrt_id);
            println!("  Vector: {}", vector);
            println!("  Attack Vector: {:?}", vector.attack_vector);
            println!("  Attack Complexity: {:?}", vector.attack_complexity);
            println!("  Privileges Required: {:?}", vector.privileges_required);
            println!("  User Interaction: {:?}", vector.user_interaction);
            println!("  Scope: {:?}", vector.scope);
            println!(
                "  Impact (CIA): {:?}/{:?}/{:?}",
                vector.confidentiality, vector.integrity, vector.availability
            );
        } else {
            println!("{} ({}): No CVSS mapping", description, vrt_id);
        }
    }

    // Find all critical severity vulnerabilities
    println!("\n=== Critical Severity Vulnerabilities (C:H/I:H/A:H) ===");
    let mut critical_count = 0;
    for node in &cvss_mapping.content {
        find_critical(node, &mut critical_count);
    }
    println!("Total critical vulnerabilities: {}", critical_count);

    // Impact analysis
    println!("\n=== Impact Analysis ===");
    let mut high_confidentiality = 0;
    let mut high_integrity = 0;
    let mut high_availability = 0;
    let mut no_impact = 0;

    for node in &cvss_mapping.content {
        analyze_impact(
            node,
            &mut high_confidentiality,
            &mut high_integrity,
            &mut high_availability,
            &mut no_impact,
        );
    }

    println!("High Confidentiality Impact: {}", high_confidentiality);
    println!("High Integrity Impact: {}", high_integrity);
    println!("High Availability Impact: {}", high_availability);
    println!("No Impact: {}", no_impact);

    // Scope analysis
    println!("\n=== Scope Analysis ===");
    let mut scope_changed = 0;
    let mut scope_unchanged = 0;

    for node in &cvss_mapping.content {
        count_scope(node, &mut scope_changed, &mut scope_unchanged);
    }

    println!("Scope Changed: {}", scope_changed);
    println!("Scope Unchanged: {}", scope_unchanged);

    // User interaction analysis
    println!("\n=== User Interaction Analysis ===");
    let mut requires_interaction = 0;
    let mut no_interaction = 0;

    for node in &cvss_mapping.content {
        count_user_interaction(node, &mut requires_interaction, &mut no_interaction);
    }

    println!("Requires User Interaction: {}", requires_interaction);
    println!("No User Interaction Required: {}", no_interaction);

    // Cross-reference with VRT taxonomy
    println!("\n=== VRT Category Coverage ===");
    let mut mapped = 0;

    for category in &vrt {
        if let Some(mapping_node) = cvss_mapping.find_by_vrt_id(&category.id) {
            if mapping_node.has_cvss_mapping()
                || mapping_node
                    .children
                    .iter()
                    .any(|c| c.has_cvss_mapping())
            {
                mapped += 1;
            }
        }
    }

    println!("VRT categories with CVSS v3 data: {}/{}", mapped, vrt.len());
    println!(
        "Coverage: {:.1}%",
        (mapped as f64 / vrt.len() as f64) * 100.0
    );

    Ok(())
}

fn find_critical(node: &bugcrowd_vrt::CvssV3MappingNode, count: &mut usize) {
    if let Some(vector) = &node.cvss_v3 {
        if vector.is_critical() {
            *count += 1;
            println!("  - {} ({})", node.id, vector);
        }
    }

    for child in &node.children {
        find_critical(child, count);
    }
}

fn analyze_impact(
    node: &bugcrowd_vrt::CvssV3MappingNode,
    high_c: &mut usize,
    high_i: &mut usize,
    high_a: &mut usize,
    no_impact: &mut usize,
) {
    if let Some(vector) = &node.cvss_v3 {
        if vector.is_no_impact() {
            *no_impact += 1;
        }
        if matches!(vector.confidentiality, Impact::High) {
            *high_c += 1;
        }
        if matches!(vector.integrity, Impact::High) {
            *high_i += 1;
        }
        if matches!(vector.availability, Impact::High) {
            *high_a += 1;
        }
    }

    for child in &node.children {
        analyze_impact(child, high_c, high_i, high_a, no_impact);
    }
}

fn count_scope(
    node: &bugcrowd_vrt::CvssV3MappingNode,
    changed: &mut usize,
    unchanged: &mut usize,
) {
    if let Some(vector) = &node.cvss_v3 {
        match vector.scope {
            bugcrowd_vrt::Scope::Changed => *changed += 1,
            bugcrowd_vrt::Scope::Unchanged => *unchanged += 1,
        }
    }

    for child in &node.children {
        count_scope(child, changed, unchanged);
    }
}

fn count_user_interaction(
    node: &bugcrowd_vrt::CvssV3MappingNode,
    required: &mut usize,
    not_required: &mut usize,
) {
    if let Some(vector) = &node.cvss_v3 {
        match vector.user_interaction {
            bugcrowd_vrt::UserInteraction::Required => *required += 1,
            bugcrowd_vrt::UserInteraction::None => *not_required += 1,
        }
    }

    for child in &node.children {
        count_user_interaction(child, required, not_required);
    }
}
