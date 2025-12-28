use serde::{Deserialize, Serialize};

/// A CWE (Common Weakness Enumeration) identifier
///
/// CWE IDs follow the format "CWE-{number}" (e.g., "CWE-79" for Cross-Site Scripting)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CweId(pub String);

impl CweId {
    /// Creates a new CWE ID
    ///
    /// # Example
    /// ```
    /// use bugcrowd_vrt::CweId;
    ///
    /// let cwe = CweId::new("CWE-79");
    /// assert_eq!(cwe.as_str(), "CWE-79");
    /// ```
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Returns the CWE ID as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Extracts the numeric portion of the CWE ID
    ///
    /// # Example
    /// ```
    /// use bugcrowd_vrt::CweId;
    ///
    /// let cwe = CweId::new("CWE-79");
    /// assert_eq!(cwe.number(), Some(79));
    /// ```
    pub fn number(&self) -> Option<u32> {
        self.0.strip_prefix("CWE-")?.parse().ok()
    }

    /// Validates that the CWE ID follows the correct format
    pub fn is_valid(&self) -> bool {
        self.0.starts_with("CWE-") && self.number().is_some()
    }
}

impl std::fmt::Display for CweId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for CweId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for CweId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Metadata for the CWE mapping
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingMetadata {
    /// Default CWE mapping (typically null)
    pub default: Option<String>,
}

/// A node in the VRT to CWE mapping tree
///
/// This represents either a leaf mapping or a parent node with children.
/// Each node maps a VRT ID to zero or more CWE IDs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CweMappingNode {
    /// VRT identifier (e.g., "cross_site_scripting_xss")
    pub id: String,

    /// Associated CWE identifiers (e.g., ["CWE-79"])
    /// Can be null if no CWE mapping exists for this VRT ID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe: Option<Vec<CweId>>,

    /// Child mappings (for hierarchical structure)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<CweMappingNode>,
}

impl CweMappingNode {
    /// Returns true if this node has CWE mappings
    pub fn has_cwe_mapping(&self) -> bool {
        self.cwe.as_ref().map_or(false, |cwes| !cwes.is_empty())
    }

    /// Returns true if this node has children
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }

    /// Recursively finds a mapping node by VRT ID
    pub fn find_by_id(&self, vrt_id: &str) -> Option<&CweMappingNode> {
        if self.id == vrt_id {
            return Some(self);
        }

        for child in &self.children {
            if let Some(found) = child.find_by_id(vrt_id) {
                return Some(found);
            }
        }

        None
    }

    /// Returns all CWE IDs associated with this node (non-recursive)
    pub fn cwe_ids(&self) -> Vec<&CweId> {
        self.cwe
            .as_ref()
            .map(|cwes| cwes.iter().collect())
            .unwrap_or_default()
    }

    /// Returns all CWE IDs in the subtree rooted at this node (recursive)
    pub fn all_cwe_ids(&self) -> Vec<&CweId> {
        let mut ids = self.cwe_ids();

        for child in &self.children {
            ids.extend(child.all_cwe_ids());
        }

        ids
    }

    /// Returns all leaf nodes (nodes with CWE mappings but no children)
    pub fn leaf_nodes(&self) -> Vec<&CweMappingNode> {
        let mut leaves = Vec::new();

        if self.has_cwe_mapping() && !self.has_children() {
            leaves.push(self);
        }

        for child in &self.children {
            leaves.extend(child.leaf_nodes());
        }

        leaves
    }
}

/// The complete VRT to CWE mapping document
///
/// This represents the root structure of a CWE mapping file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CweMapping {
    /// Metadata about the mapping
    pub metadata: MappingMetadata,

    /// The mapping content (root nodes)
    pub content: Vec<CweMappingNode>,
}

impl CweMapping {
    /// Finds a mapping node by VRT ID across all root nodes
    pub fn find_by_vrt_id(&self, vrt_id: &str) -> Option<&CweMappingNode> {
        for node in &self.content {
            if let Some(found) = node.find_by_id(vrt_id) {
                return Some(found);
            }
        }
        None
    }

    /// Looks up CWE IDs for a given VRT ID
    ///
    /// # Example
    /// ```no_run
    /// use bugcrowd_vrt::load_cwe_mapping_from_file;
    ///
    /// let mapping = load_cwe_mapping_from_file("cwe.mappings.json")
    ///     .expect("Failed to load mapping");
    ///
    /// if let Some(cwes) = mapping.lookup_cwe("cross_site_scripting_xss") {
    ///     for cwe in cwes {
    ///         println!("CWE: {}", cwe);
    ///     }
    /// }
    /// ```
    pub fn lookup_cwe(&self, vrt_id: &str) -> Option<Vec<&CweId>> {
        self.find_by_vrt_id(vrt_id)
            .and_then(|node| node.cwe.as_ref())
            .map(|cwes| cwes.iter().collect())
    }

    /// Returns all unique CWE IDs present in the mapping
    pub fn all_cwe_ids(&self) -> Vec<&CweId> {
        let mut ids = Vec::new();
        for node in &self.content {
            ids.extend(node.all_cwe_ids());
        }

        // Remove duplicates while preserving order
        let mut seen = std::collections::HashSet::new();
        ids.into_iter()
            .filter(|id| seen.insert(id.as_str()))
            .collect()
    }

    /// Returns statistics about the mapping
    pub fn statistics(&self) -> MappingStatistics {
        let mut stats = MappingStatistics::default();

        for node in &self.content {
            collect_stats(node, &mut stats);
        }

        stats
    }
}

/// Statistics about a CWE mapping
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MappingStatistics {
    /// Total number of VRT nodes
    pub total_nodes: usize,
    /// Number of nodes with CWE mappings
    pub nodes_with_mappings: usize,
    /// Number of nodes without CWE mappings
    pub nodes_without_mappings: usize,
    /// Total number of unique CWE IDs
    pub unique_cwe_ids: usize,
}

fn collect_stats(node: &CweMappingNode, stats: &mut MappingStatistics) {
    stats.total_nodes += 1;

    if node.has_cwe_mapping() {
        stats.nodes_with_mappings += 1;
    } else {
        stats.nodes_without_mappings += 1;
    }

    for child in &node.children {
        collect_stats(child, stats);
    }
}
