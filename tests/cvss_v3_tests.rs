use bugcrowd_vrt::{
    AttackComplexity, AttackVector, CvssV3MappingNode, CvssV3Vector, Impact, PrivilegesRequired,
    Scope, UserInteraction,
};
use std::str::FromStr;

#[test]
fn test_cvss_vector_parsing() {
    let vector =
        CvssV3Vector::from_str("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").expect("Failed to parse");

    assert_eq!(vector.attack_vector, AttackVector::Network);
    assert_eq!(vector.attack_complexity, AttackComplexity::Low);
    assert_eq!(vector.privileges_required, PrivilegesRequired::None);
    assert_eq!(vector.user_interaction, UserInteraction::None);
    assert_eq!(vector.scope, Scope::Unchanged);
    assert_eq!(vector.confidentiality, Impact::High);
    assert_eq!(vector.integrity, Impact::High);
    assert_eq!(vector.availability, Impact::High);
    assert!(vector.is_critical());
}

#[test]
fn test_cvss_vector_display() {
    let vector = CvssV3Vector::new(
        AttackVector::Network,
        AttackComplexity::Low,
        PrivilegesRequired::None,
        UserInteraction::None,
        Scope::Unchanged,
        Impact::High,
        Impact::High,
        Impact::High,
    );

    assert_eq!(vector.to_string(), "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
}

#[test]
fn test_cvss_vector_no_impact() {
    let vector =
        CvssV3Vector::from_str("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N").expect("Failed to parse");
    assert!(vector.is_no_impact());
    assert!(!vector.is_critical());
}

#[test]
fn test_deserialize_mapping_node() {
    let json = r#"{
        "id": "xss",
        "cvss_v3": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    }"#;

    let node: CvssV3MappingNode = serde_json::from_str(json).unwrap();
    assert_eq!(node.id, "xss");
    assert!(node.has_cvss_mapping());
}

#[test]
fn test_deserialize_mapping_with_children() {
    let json = r#"{
        "id": "parent",
        "children": [
            {
                "id": "child1",
                "cvss_v3": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }
        ]
    }"#;

    let node: CvssV3MappingNode = serde_json::from_str(json).unwrap();
    assert_eq!(node.id, "parent");
    assert!(!node.has_cvss_mapping());
    assert_eq!(node.children.len(), 1);
}

#[test]
fn test_find_by_id() {
    let node = CvssV3MappingNode {
        id: "parent".to_string(),
        cvss_v3: None,
        children: vec![CvssV3MappingNode {
            id: "child".to_string(),
            cvss_v3: Some(
                CvssV3Vector::from_str("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap(),
            ),
            children: vec![],
        }],
    };

    assert!(node.find_by_id("parent").is_some());
    assert!(node.find_by_id("child").is_some());
    assert!(node.find_by_id("nonexistent").is_none());
}
