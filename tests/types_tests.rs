use bugcrowd_vrt::{VrtNode, VrtNodeType};

#[test]
fn test_deserialize_category() {
    let json = r#"{
        "id": "test_category",
        "name": "Test Category",
        "type": "category",
        "children": []
    }"#;

    let node: VrtNode = serde_json::from_str(json).unwrap();
    assert_eq!(node.id, "test_category");
    assert_eq!(node.name, "Test Category");
    assert!(node.is_category());
    assert_eq!(node.priority, None);
}

#[test]
fn test_deserialize_variant() {
    let json = r#"{
        "id": "test_variant",
        "name": "Test Variant",
        "type": "variant",
        "priority": 3
    }"#;

    let node: VrtNode = serde_json::from_str(json).unwrap();
    assert_eq!(node.id, "test_variant");
    assert_eq!(node.name, "Test Variant");
    assert!(node.is_variant());
    assert_eq!(node.priority, Some(3));
}

#[test]
fn test_find_by_id() {
    let node = VrtNode {
        id: "parent".to_string(),
        name: "Parent".to_string(),
        node_type: VrtNodeType::Category,
        children: vec![
            VrtNode {
                id: "child1".to_string(),
                name: "Child 1".to_string(),
                node_type: VrtNodeType::Subcategory,
                children: vec![],
                priority: None,
            },
            VrtNode {
                id: "child2".to_string(),
                name: "Child 2".to_string(),
                node_type: VrtNodeType::Variant,
                children: vec![],
                priority: Some(2),
            },
        ],
        priority: None,
    };

    assert!(node.find_by_id("parent").is_some());
    assert!(node.find_by_id("child1").is_some());
    assert!(node.find_by_id("child2").is_some());
    assert!(node.find_by_id("nonexistent").is_none());
}

#[test]
fn test_variants() {
    let node = VrtNode {
        id: "category".to_string(),
        name: "Category".to_string(),
        node_type: VrtNodeType::Category,
        children: vec![VrtNode {
            id: "subcategory".to_string(),
            name: "Subcategory".to_string(),
            node_type: VrtNodeType::Subcategory,
            children: vec![
                VrtNode {
                    id: "variant1".to_string(),
                    name: "Variant 1".to_string(),
                    node_type: VrtNodeType::Variant,
                    children: vec![],
                    priority: Some(1),
                },
                VrtNode {
                    id: "variant2".to_string(),
                    name: "Variant 2".to_string(),
                    node_type: VrtNodeType::Variant,
                    children: vec![],
                    priority: Some(3),
                },
            ],
            priority: None,
        }],
        priority: None,
    };

    let variants = node.variants();
    assert_eq!(variants.len(), 2);
    assert!(variants.iter().all(|v| v.is_variant()));
}
