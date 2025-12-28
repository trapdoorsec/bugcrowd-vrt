use serde::{Deserialize, Serialize};

/// Represents the type of a VRT node in the taxonomy hierarchy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VrtNodeType {
    /// Top-level category (e.g., "AI Application Security")
    Category,
    /// Subcategory within a category (e.g., "Prompt Injection")
    Subcategory,
    /// Specific vulnerability variant (e.g., "System Prompt Leakage")
    Variant,
}

/// A node in the VRT taxonomy tree
///
/// The VRT is hierarchical with three levels:
/// - Category (top level)
/// - Subcategory (children of categories)
/// - Variant (children of subcategories, leaf nodes with priority ratings)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VrtNode {
    /// Unique identifier for this node (e.g., "prompt_injection")
    pub id: String,

    /// Human-readable name (e.g., "Prompt Injection")
    pub name: String,

    /// The type of this node in the hierarchy
    #[serde(rename = "type")]
    pub node_type: VrtNodeType,

    /// Child nodes (categories have subcategories, subcategories have variants)
    /// Only present for category and subcategory nodes
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<VrtNode>,

    /// Priority/severity rating (1-5, where 1 is most severe)
    /// Only present for variant nodes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,
}

impl VrtNode {
    /// Returns true if this node is a category
    pub fn is_category(&self) -> bool {
        self.node_type == VrtNodeType::Category
    }

    /// Returns true if this node is a subcategory
    pub fn is_subcategory(&self) -> bool {
        self.node_type == VrtNodeType::Subcategory
    }

    /// Returns true if this node is a variant
    pub fn is_variant(&self) -> bool {
        self.node_type == VrtNodeType::Variant
    }

    /// Returns true if this node has children
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }

    /// Recursively finds a node by ID in the tree
    pub fn find_by_id(&self, id: &str) -> Option<&VrtNode> {
        if self.id == id {
            return Some(self);
        }

        for child in &self.children {
            if let Some(found) = child.find_by_id(id) {
                return Some(found);
            }
        }

        None
    }

    /// Returns all variant nodes (leaf nodes with priority ratings) under this node
    pub fn variants(&self) -> Vec<&VrtNode> {
        let mut variants = Vec::new();

        if self.is_variant() {
            variants.push(self);
        }

        for child in &self.children {
            variants.extend(child.variants());
        }

        variants
    }
}

/// The complete VRT taxonomy
///
/// This is the root structure that represents the entire Bugcrowd VRT.
/// It's a vector of top-level categories.
pub type VrtTaxonomy = Vec<VrtNode>;
