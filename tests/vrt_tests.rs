use bugcrowd_vrt::{load_vrt_from_reader, load_vrt_from_str};

#[test]
fn test_load_vrt_from_str() {
    let json = r#"[
        {
            "id": "test_category",
            "name": "Test Category",
            "type": "category",
            "children": [
                {
                    "id": "test_subcategory",
                    "name": "Test Subcategory",
                    "type": "subcategory",
                    "children": [
                        {
                            "id": "test_variant",
                            "name": "Test Variant",
                            "type": "variant",
                            "priority": 2
                        }
                    ]
                }
            ]
        }
    ]"#;

    let taxonomy = load_vrt_from_str(json).expect("Failed to parse");
    assert_eq!(taxonomy.len(), 1);
    assert_eq!(taxonomy[0].id, "test_category");
    assert_eq!(taxonomy[0].children.len(), 1);
    assert_eq!(taxonomy[0].children[0].children.len(), 1);
    assert_eq!(taxonomy[0].children[0].children[0].priority, Some(2));
}

#[test]
fn test_load_vrt_from_reader() {
    let json = r#"[{"id": "test", "name": "Test", "type": "category", "children": []}]"#;
    let reader = json.as_bytes();

    let taxonomy = load_vrt_from_reader(reader).expect("Failed to parse");
    assert_eq!(taxonomy.len(), 1);
}
