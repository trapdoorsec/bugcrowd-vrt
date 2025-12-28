use bugcrowd_vrt::{CweId, CweMapping, CweMappingNode};

#[test]
fn test_cwe_id_creation() {
    let cwe = CweId::new("CWE-79");
    assert_eq!(cwe.as_str(), "CWE-79");
    assert_eq!(cwe.number(), Some(79));
    assert!(cwe.is_valid());
}

#[test]
fn test_cwe_id_invalid() {
    let cwe = CweId::new("INVALID-79");
    assert!(!cwe.is_valid());
    assert_eq!(cwe.number(), None);
}

#[test]
fn test_deserialize_mapping_node() {
    let json = r#"{
        "id": "xss",
        "cwe": ["CWE-79", "CWE-80"]
    }"#;

    let node: CweMappingNode = serde_json::from_str(json).unwrap();
    assert_eq!(node.id, "xss");
    assert!(node.has_cwe_mapping());
    assert_eq!(node.cwe_ids().len(), 2);
}

#[test]
fn test_deserialize_mapping_with_children() {
    let json = r#"{
        "id": "parent",
        "cwe": null,
        "children": [
            {
                "id": "child1",
                "cwe": ["CWE-100"]
            },
            {
                "id": "child2",
                "cwe": ["CWE-200"]
            }
        ]
    }"#;

    let node: CweMappingNode = serde_json::from_str(json).unwrap();
    assert_eq!(node.id, "parent");
    assert!(!node.has_cwe_mapping());
    assert_eq!(node.children.len(), 2);
    assert_eq!(node.all_cwe_ids().len(), 2);
}

#[test]
fn test_find_by_id() {
    let node = CweMappingNode {
        id: "parent".to_string(),
        cwe: None,
        children: vec![
            CweMappingNode {
                id: "child1".to_string(),
                cwe: Some(vec![CweId::new("CWE-100")]),
                children: vec![],
            },
            CweMappingNode {
                id: "child2".to_string(),
                cwe: Some(vec![CweId::new("CWE-200")]),
                children: vec![],
            },
        ],
    };

    assert!(node.find_by_id("parent").is_some());
    assert!(node.find_by_id("child1").is_some());
    assert!(node.find_by_id("child2").is_some());
    assert!(node.find_by_id("nonexistent").is_none());
}

#[test]
fn test_leaf_nodes() {
    let node = CweMappingNode {
        id: "parent".to_string(),
        cwe: None,
        children: vec![
            CweMappingNode {
                id: "child1".to_string(),
                cwe: Some(vec![CweId::new("CWE-100")]),
                children: vec![],
            },
            CweMappingNode {
                id: "parent2".to_string(),
                cwe: None,
                children: vec![CweMappingNode {
                    id: "child2".to_string(),
                    cwe: Some(vec![CweId::new("CWE-200")]),
                    children: vec![],
                }],
            },
        ],
    };

    let leaves = node.leaf_nodes();
    assert_eq!(leaves.len(), 2);
    assert_eq!(leaves[0].id, "child1");
    assert_eq!(leaves[1].id, "child2");
}

#[test]
fn test_cwe_mapping() {
    let json = r#"{
        "metadata": {
            "default": null
        },
        "content": [
            {
                "id": "xss",
                "cwe": ["CWE-79"]
            },
            {
                "id": "sqli",
                "cwe": ["CWE-89"]
            }
        ]
    }"#;

    let mapping: CweMapping = serde_json::from_str(json).unwrap();
    assert_eq!(mapping.content.len(), 2);

    let cwes = mapping.lookup_cwe("xss").unwrap();
    assert_eq!(cwes.len(), 1);
    assert_eq!(cwes[0].as_str(), "CWE-79");
}
