use bugcrowd_vrt::{
    load_cwe_mapping_from_str, load_cvss_v3_mapping_from_str, load_vrt_from_str,
    AttackComplexity, AttackVector, CweId, CweMappingNode, CvssV3Vector, Impact,
    PrivilegesRequired, Scope, UserInteraction, VrtNode, VrtNodeType,
};
use std::str::FromStr;

// ============================================================================
// VRT Edge Cases (5 tests)
// ============================================================================

#[test]
fn test_empty_vrt_taxonomy() {
    let json = r#"[]"#;
    let taxonomy = load_vrt_from_str(json).expect("Failed to parse empty taxonomy");
    assert_eq!(taxonomy.len(), 0);
}

#[test]
fn test_deeply_nested_vrt() {
    let json = r#"[
        {
            "id": "level1",
            "name": "Level 1",
            "type": "category",
            "children": [
                {
                    "id": "level2",
                    "name": "Level 2",
                    "type": "subcategory",
                    "children": [
                        {
                            "id": "level3",
                            "name": "Level 3",
                            "type": "variant",
                            "priority": 1
                        }
                    ]
                }
            ]
        }
    ]"#;

    let taxonomy = load_vrt_from_str(json).expect("Failed to parse");
    assert_eq!(taxonomy.len(), 1);

    let level3 = taxonomy[0]
        .find_by_id("level3")
        .expect("Should find deeply nested node");
    assert_eq!(level3.id, "level3");
    assert!(level3.is_variant());
}

#[test]
fn test_vrt_node_with_no_children_field() {
    let json = r#"{
        "id": "simple_variant",
        "name": "Simple Variant",
        "type": "variant",
        "priority": 3
    }"#;

    let node: VrtNode = serde_json::from_str(json).expect("Failed to parse");
    assert_eq!(node.children.len(), 0);
    assert!(!node.has_children());
}

#[test]
fn test_vrt_variant_collection() {
    let node = VrtNode {
        id: "root".to_string(),
        name: "Root".to_string(),
        node_type: VrtNodeType::Category,
        children: vec![
            VrtNode {
                id: "cat1".to_string(),
                name: "Category 1".to_string(),
                node_type: VrtNodeType::Subcategory,
                children: vec![
                    VrtNode {
                        id: "var1".to_string(),
                        name: "Variant 1".to_string(),
                        node_type: VrtNodeType::Variant,
                        children: vec![],
                        priority: Some(1),
                    },
                    VrtNode {
                        id: "var2".to_string(),
                        name: "Variant 2".to_string(),
                        node_type: VrtNodeType::Variant,
                        children: vec![],
                        priority: Some(2),
                    },
                ],
                priority: None,
            },
            VrtNode {
                id: "cat2".to_string(),
                name: "Category 2".to_string(),
                node_type: VrtNodeType::Subcategory,
                children: vec![
                    VrtNode {
                        id: "var3".to_string(),
                        name: "Variant 3".to_string(),
                        node_type: VrtNodeType::Variant,
                        children: vec![],
                        priority: Some(3),
                    },
                ],
                priority: None,
            },
        ],
        priority: None,
    };

    let variants = node.variants();
    assert_eq!(variants.len(), 3);
    assert!(variants.iter().all(|v| v.is_variant()));

    let ids: Vec<_> = variants.iter().map(|v| v.id.as_str()).collect();
    assert!(ids.contains(&"var1"));
    assert!(ids.contains(&"var2"));
    assert!(ids.contains(&"var3"));
}

#[test]
fn test_vrt_find_nonexistent_deeply() {
    let node = VrtNode {
        id: "root".to_string(),
        name: "Root".to_string(),
        node_type: VrtNodeType::Category,
        children: vec![
            VrtNode {
                id: "child".to_string(),
                name: "Child".to_string(),
                node_type: VrtNodeType::Subcategory,
                children: vec![],
                priority: None,
            },
        ],
        priority: None,
    };

    assert!(node.find_by_id("root").is_some());
    assert!(node.find_by_id("child").is_some());
    assert!(node.find_by_id("nonexistent").is_none());
    assert!(node.find_by_id("").is_none());
}

// ============================================================================
// CWE Mapping Edge Cases (8 tests)
// ============================================================================

#[test]
fn test_cwe_id_edge_cases() {
    // Valid CWE
    let cwe1 = CweId::new("CWE-79");
    assert!(cwe1.is_valid());
    assert_eq!(cwe1.number(), Some(79));

    // Large CWE number
    let cwe2 = CweId::new("CWE-99999");
    assert!(cwe2.is_valid());
    assert_eq!(cwe2.number(), Some(99999));

    // Invalid formats
    let invalid1 = CweId::new("cwe-79");
    assert!(!invalid1.is_valid());

    let invalid2 = CweId::new("CWE79");
    assert!(!invalid2.is_valid());

    let invalid3 = CweId::new("CWE-");
    assert!(!invalid3.is_valid());

    let invalid4 = CweId::new("CWE-ABC");
    assert!(!invalid4.is_valid());
}

#[test]
fn test_cwe_mapping_empty_content() {
    let json = r#"{
        "metadata": {"default": null},
        "content": []
    }"#;

    let mapping = load_cwe_mapping_from_str(json).expect("Failed to parse");
    assert_eq!(mapping.content.len(), 0);
    assert!(mapping.lookup_cwe("anything").is_none());
}

#[test]
fn test_cwe_mapping_null_vs_empty_array() {
    let json_null = r#"{
        "id": "test",
        "cwe": null
    }"#;
    let node_null: CweMappingNode = serde_json::from_str(json_null).expect("Failed to parse");
    assert!(!node_null.has_cwe_mapping());
    assert_eq!(node_null.cwe_ids().len(), 0);

    // Empty array - accepted by deserializer but treated as "no mapping"
    let json_empty = r#"{
        "id": "test",
        "cwe": []
    }"#;
    let node_empty: CweMappingNode = serde_json::from_str(json_empty).expect("Failed to parse");

    // Empty array is semantically equivalent to null - both mean "no CWE mappings"
    assert!(!node_empty.has_cwe_mapping());
    assert_eq!(node_empty.cwe_ids().len(), 0);

    // Both null and [] result in the same behavior
}

#[test]
fn test_cwe_mapping_multiple_cwes() {
    let node = CweMappingNode {
        id: "test".to_string(),
        cwe: Some(vec![
            CweId::new("CWE-79"),
            CweId::new("CWE-80"),
            CweId::new("CWE-81"),
        ]),
        children: vec![],
    };

    assert!(node.has_cwe_mapping());
    assert_eq!(node.cwe_ids().len(), 3);
}

#[test]
fn test_cwe_mapping_deep_hierarchy_lookup() {
    let json = r#"{
        "metadata": {"default": null},
        "content": [
            {
                "id": "root",
                "cwe": null,
                "children": [
                    {
                        "id": "level1",
                        "cwe": null,
                        "children": [
                            {
                                "id": "level2",
                                "cwe": null,
                                "children": [
                                    {
                                        "id": "level3",
                                        "cwe": ["CWE-999"]
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }"#;

    let mapping = load_cwe_mapping_from_str(json).expect("Failed to parse");

    let cwes = mapping.lookup_cwe("level3").expect("Should find deeply nested node");
    assert_eq!(cwes.len(), 1);
    assert_eq!(cwes[0].as_str(), "CWE-999");
}

#[test]
fn test_cwe_all_ids_deduplication() {
    let mapping = load_cwe_mapping_from_str(r#"{
        "metadata": {"default": null},
        "content": [
            {
                "id": "node1",
                "cwe": ["CWE-79", "CWE-80"]
            },
            {
                "id": "node2",
                "cwe": ["CWE-79", "CWE-89"]
            }
        ]
    }"#).expect("Failed to parse");

    let all_cwes = mapping.all_cwe_ids();

    // Should have CWE-79, CWE-80, CWE-89 (3 unique)
    assert_eq!(all_cwes.len(), 3);

    let cwe_strings: Vec<String> = all_cwes.iter().map(|c| c.as_str().to_string()).collect();
    assert!(cwe_strings.contains(&"CWE-79".to_string()));
    assert!(cwe_strings.contains(&"CWE-80".to_string()));
    assert!(cwe_strings.contains(&"CWE-89".to_string()));
}

#[test]
fn test_cwe_leaf_nodes_filtering() {
    let root = CweMappingNode {
        id: "root".to_string(),
        cwe: Some(vec![CweId::new("CWE-1")]),
        children: vec![
            CweMappingNode {
                id: "child1".to_string(),
                cwe: Some(vec![CweId::new("CWE-2")]),
                children: vec![],
            },
        ],
    };

    let leaves = root.leaf_nodes();
    // Only child1 is a leaf (has CWE but no children)
    // root has children, so it's not a leaf
    assert_eq!(leaves.len(), 1);
    assert_eq!(leaves[0].id, "child1");
}

#[test]
fn test_cwe_mapping_statistics() {
    let json = r#"{
        "metadata": {"default": null},
        "content": [
            {
                "id": "node1",
                "cwe": ["CWE-79"]
            },
            {
                "id": "parent",
                "cwe": null,
                "children": [
                    {
                        "id": "child1",
                        "cwe": ["CWE-89"]
                    },
                    {
                        "id": "child2",
                        "cwe": null
                    }
                ]
            }
        ]
    }"#;

    let mapping = load_cwe_mapping_from_str(json).expect("Failed to parse");
    let stats = mapping.statistics();

    assert_eq!(stats.total_nodes, 4); // node1, parent, child1, child2
    assert_eq!(stats.nodes_with_mappings, 2); // node1, child1
    assert_eq!(stats.nodes_without_mappings, 2); // parent, child2
}

// ============================================================================
// CVSS v3 Edge Cases (7 tests)
// ============================================================================

#[test]
fn test_cvss_vector_invalid_formats() {
    // Too few parts
    let result1 = CvssV3Vector::from_str("AV:N/AC:L");
    assert!(result1.is_err());

    // Too many parts
    let result2 = CvssV3Vector::from_str("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/EXTRA:X");
    assert!(result2.is_err());

    // Invalid separator
    let result3 = CvssV3Vector::from_str("AV:N,AC:L,PR:N,UI:N,S:U,C:H,I:H,A:H");
    assert!(result3.is_err());

    // Missing colon
    let result4 = CvssV3Vector::from_str("AVN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    assert!(result4.is_err());
}

#[test]
fn test_cvss_vector_invalid_values() {
    // Invalid AV value
    let result1 = CvssV3Vector::from_str("AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    assert!(result1.is_err());

    // Invalid AC value
    let result2 = CvssV3Vector::from_str("AV:N/AC:M/PR:N/UI:N/S:U/C:H/I:H/A:H");
    assert!(result2.is_err());

    // Invalid PR value
    let result3 = CvssV3Vector::from_str("AV:N/AC:L/PR:M/UI:N/S:U/C:H/I:H/A:H");
    assert!(result3.is_err());

    // Invalid impact value
    let result4 = CvssV3Vector::from_str("AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:H/A:H");
    assert!(result4.is_err());
}

#[test]
fn test_cvss_vector_out_of_order_metrics() {
    // Metrics in wrong order - parser accepts any order and extracts by name
    let result = CvssV3Vector::from_str("AC:L/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H");
    // Our parser is lenient and accepts metrics in any order
    assert!(result.is_ok());

    let vector = result.unwrap();
    assert_eq!(vector.attack_vector, AttackVector::Network);
    assert_eq!(vector.attack_complexity, AttackComplexity::Low);

    // However, the display format uses canonical order
    assert_eq!(vector.to_string(), "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
}

#[test]
fn test_cvss_vector_all_combinations() {
    // Test various valid combinations
    let vectors = vec![
        "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L",
        "AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "AV:P/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:L",
    ];

    for vector_str in vectors {
        let vector = CvssV3Vector::from_str(vector_str).expect(&format!("Failed to parse: {}", vector_str));
        assert_eq!(vector.to_string(), vector_str);
    }
}

#[test]
fn test_cvss_vector_impact_checks() {
    let no_impact = CvssV3Vector::new(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Unchanged,
        Impact::None,
        Impact::None,
        Impact::None,
    );
    assert!(no_impact.is_no_impact());
    assert!(!no_impact.is_critical());

    let critical = CvssV3Vector::new(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Changed,
        Impact::High,
        Impact::High,
        Impact::High,
    );
    assert!(critical.is_critical());
    assert!(!critical.is_no_impact());

    let partial = CvssV3Vector::new(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Unchanged,
        Impact::High,
        Impact::Low,
        Impact::None,
    );
    assert!(!partial.is_critical());
    assert!(!partial.is_no_impact());
}

#[test]
fn test_cvss_mapping_empty_content() {
    let json = r#"{
        "metadata": {"default": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
        "content": []
    }"#;

    let mapping = load_cvss_v3_mapping_from_str(json).expect("Failed to parse");
    assert_eq!(mapping.content.len(), 0);
    assert!(mapping.lookup_cvss("anything").is_none());
}

#[test]
fn test_cvss_mapping_deep_hierarchy() {
    let json = r#"{
        "metadata": {"default": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
        "content": [
            {
                "id": "root",
                "children": [
                    {
                        "id": "level1",
                        "children": [
                            {
                                "id": "level2",
                                "cvss_v3": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            }
                        ]
                    }
                ]
            }
        ]
    }"#;

    let mapping = load_cvss_v3_mapping_from_str(json).expect("Failed to parse");

    let vector = mapping.lookup_cvss("level2").expect("Should find deeply nested node");
    assert!(vector.is_critical());
}
