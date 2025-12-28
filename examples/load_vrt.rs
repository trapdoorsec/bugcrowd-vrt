use bugcrowd_vrt::load_vrt_from_file;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Loading VRT taxonomy from vrt.json...");

    let taxonomy = load_vrt_from_file("vrt.json")?;

    println!("\n=== VRT Taxonomy Summary ===");
    println!("Total categories: {}", taxonomy.len());

    let mut total_subcategories = 0;
    let mut total_variants = 0;

    for category in &taxonomy {
        println!("\n📁 {} ({})", category.name, category.id);
        println!("   Subcategories: {}", category.children.len());

        total_subcategories += category.children.len();

        for subcategory in &category.children {
            let variant_count = subcategory.children.len();
            total_variants += variant_count;

            println!(
                "   └─ {} ({}) - {} variants",
                subcategory.name, subcategory.id, variant_count
            );

            // Show first 3 variants as examples
            for (i, variant) in subcategory.children.iter().take(3).enumerate() {
                let priority = variant.priority.unwrap_or(0);
                println!(
                    "      {}─ {} (P{})",
                    if i < 2 && variant_count > 1 { "├" } else { "└" },
                    variant.name,
                    priority
                );
            }

            if variant_count > 3 {
                println!("      ... and {} more", variant_count - 3);
            }
        }
    }

    println!("\n=== Statistics ===");
    println!("Total categories: {}", taxonomy.len());
    println!("Total subcategories: {}", total_subcategories);
    println!("Total variants: {}", total_variants);

    // Priority distribution
    let all_variants: Vec<_> = taxonomy
        .iter()
        .flat_map(|c| c.variants())
        .collect();

    println!("\n=== Priority Distribution ===");
    for priority in 1..=5 {
        let count = all_variants
            .iter()
            .filter(|v| v.priority == Some(priority))
            .count();
        println!("Priority {}: {} variants", priority, count);
    }

    // Test find_by_id functionality
    println!("\n=== Testing find_by_id ===");
    if let Some(category) = taxonomy.first() {
        if let Some(found) = category.find_by_id("prompt_injection") {
            println!("Found: {} ({})", found.name, found.id);
            println!("Type: {:?}", found.node_type);
        }
    }

    Ok(())
}
