use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// CVSS v3.x Attack Vector
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackVector {
    /// Network (N) - Exploitable remotely
    #[serde(rename = "N")]
    Network,
    /// Adjacent (A) - Requires local network access
    #[serde(rename = "A")]
    Adjacent,
    /// Local (L) - Requires local access
    #[serde(rename = "L")]
    Local,
    /// Physical (P) - Requires physical access
    #[serde(rename = "P")]
    Physical,
}

/// CVSS v3.x Attack Complexity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackComplexity {
    /// Low (L) - No special conditions
    #[serde(rename = "L")]
    Low,
    /// High (H) - Requires special conditions
    #[serde(rename = "H")]
    High,
}

/// CVSS v3.x Privileges Required
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegesRequired {
    /// None (N) - No privileges required
    #[serde(rename = "N")]
    None,
    /// Low (L) - Basic user privileges
    #[serde(rename = "L")]
    Low,
    /// High (H) - Admin/elevated privileges
    #[serde(rename = "H")]
    High,
}

/// CVSS v3.x User Interaction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserInteraction {
    /// None (N) - No user interaction required
    #[serde(rename = "N")]
    None,
    /// Required (R) - User interaction required
    #[serde(rename = "R")]
    Required,
}

/// CVSS v3.x Scope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    /// Unchanged (U) - Scope doesn't change
    #[serde(rename = "U")]
    Unchanged,
    /// Changed (C) - Scope changes
    #[serde(rename = "C")]
    Changed,
}

/// CVSS v3.x Impact level (for C, I, A)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Impact {
    /// None (N) - No impact
    #[serde(rename = "N")]
    None,
    /// Low (L) - Low impact
    #[serde(rename = "L")]
    Low,
    /// High (H) - High impact
    #[serde(rename = "H")]
    High,
}

/// A parsed CVSS v3.x vector string
///
/// CVSS v3 vectors follow the format:
/// `AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]`
///
/// # Example
/// ```
/// use bugcrowd_vrt::CvssV3Vector;
/// use std::str::FromStr;
///
/// let vector = CvssV3Vector::from_str("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
///     .expect("Invalid CVSS vector");
///
/// assert_eq!(vector.to_string(), "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CvssV3Vector {
    /// Attack Vector
    pub attack_vector: AttackVector,
    /// Attack Complexity
    pub attack_complexity: AttackComplexity,
    /// Privileges Required
    pub privileges_required: PrivilegesRequired,
    /// User Interaction
    pub user_interaction: UserInteraction,
    /// Scope
    pub scope: Scope,
    /// Confidentiality Impact
    pub confidentiality: Impact,
    /// Integrity Impact
    pub integrity: Impact,
    /// Availability Impact
    pub availability: Impact,
}

impl CvssV3Vector {
    /// Creates a new CVSS v3 vector with all fields
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        attack_vector: AttackVector,
        attack_complexity: AttackComplexity,
        privileges_required: PrivilegesRequired,
        user_interaction: UserInteraction,
        scope: Scope,
        confidentiality: Impact,
        integrity: Impact,
        availability: Impact,
    ) -> Self {
        Self {
            attack_vector,
            attack_complexity,
            privileges_required,
            user_interaction,
            scope,
            confidentiality,
            integrity,
            availability,
        }
    }

    /// Returns true if this vector represents no impact (all CIA are None)
    pub fn is_no_impact(&self) -> bool {
        matches!(self.confidentiality, Impact::None)
            && matches!(self.integrity, Impact::None)
            && matches!(self.availability, Impact::None)
    }

    /// Returns true if this is a critical severity vector (all CIA are High)
    pub fn is_critical(&self) -> bool {
        matches!(self.confidentiality, Impact::High)
            && matches!(self.integrity, Impact::High)
            && matches!(self.availability, Impact::High)
    }
}

impl FromStr for CvssV3Vector {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 8 {
            return Err(format!("Expected 8 parts, got {}", parts.len()));
        }

        let mut av = None;
        let mut ac = None;
        let mut pr = None;
        let mut ui = None;
        let mut s_scope = None;
        let mut c = None;
        let mut i = None;
        let mut a = None;

        for part in parts {
            let kv: Vec<&str> = part.split(':').collect();
            if kv.len() != 2 {
                return Err(format!("Invalid part: {}", part));
            }

            match kv[0] {
                "AV" => av = Some(parse_av(kv[1])?),
                "AC" => ac = Some(parse_ac(kv[1])?),
                "PR" => pr = Some(parse_pr(kv[1])?),
                "UI" => ui = Some(parse_ui(kv[1])?),
                "S" => s_scope = Some(parse_scope(kv[1])?),
                "C" => c = Some(parse_impact(kv[1])?),
                "I" => i = Some(parse_impact(kv[1])?),
                "A" => a = Some(parse_impact(kv[1])?),
                _ => return Err(format!("Unknown metric: {}", kv[0])),
            }
        }

        Ok(CvssV3Vector {
            attack_vector: av.ok_or("Missing AV")?,
            attack_complexity: ac.ok_or("Missing AC")?,
            privileges_required: pr.ok_or("Missing PR")?,
            user_interaction: ui.ok_or("Missing UI")?,
            scope: s_scope.ok_or("Missing S")?,
            confidentiality: c.ok_or("Missing C")?,
            integrity: i.ok_or("Missing I")?,
            availability: a.ok_or("Missing A")?,
        })
    }
}

impl fmt::Display for CvssV3Vector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
            av_to_str(self.attack_vector),
            ac_to_str(self.attack_complexity),
            pr_to_str(self.privileges_required),
            ui_to_str(self.user_interaction),
            scope_to_str(self.scope),
            impact_to_str(self.confidentiality),
            impact_to_str(self.integrity),
            impact_to_str(self.availability),
        )
    }
}

impl From<CvssV3Vector> for String {
    fn from(vector: CvssV3Vector) -> String {
        vector.to_string()
    }
}

impl TryFrom<String> for CvssV3Vector {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        CvssV3Vector::from_str(&s)
    }
}

// Helper parsing functions
fn parse_av(s: &str) -> Result<AttackVector, String> {
    match s {
        "N" => Ok(AttackVector::Network),
        "A" => Ok(AttackVector::Adjacent),
        "L" => Ok(AttackVector::Local),
        "P" => Ok(AttackVector::Physical),
        _ => Err(format!("Invalid AV value: {}", s)),
    }
}

fn parse_ac(s: &str) -> Result<AttackComplexity, String> {
    match s {
        "L" => Ok(AttackComplexity::Low),
        "H" => Ok(AttackComplexity::High),
        _ => Err(format!("Invalid AC value: {}", s)),
    }
}

fn parse_pr(s: &str) -> Result<PrivilegesRequired, String> {
    match s {
        "N" => Ok(PrivilegesRequired::None),
        "L" => Ok(PrivilegesRequired::Low),
        "H" => Ok(PrivilegesRequired::High),
        _ => Err(format!("Invalid PR value: {}", s)),
    }
}

fn parse_ui(s: &str) -> Result<UserInteraction, String> {
    match s {
        "N" => Ok(UserInteraction::None),
        "R" => Ok(UserInteraction::Required),
        _ => Err(format!("Invalid UI value: {}", s)),
    }
}

fn parse_scope(s: &str) -> Result<Scope, String> {
    match s {
        "U" => Ok(Scope::Unchanged),
        "C" => Ok(Scope::Changed),
        _ => Err(format!("Invalid S value: {}", s)),
    }
}

fn parse_impact(s: &str) -> Result<Impact, String> {
    match s {
        "N" => Ok(Impact::None),
        "L" => Ok(Impact::Low),
        "H" => Ok(Impact::High),
        _ => Err(format!("Invalid impact value: {}", s)),
    }
}

// Helper display functions
fn av_to_str(av: AttackVector) -> &'static str {
    match av {
        AttackVector::Network => "N",
        AttackVector::Adjacent => "A",
        AttackVector::Local => "L",
        AttackVector::Physical => "P",
    }
}

fn ac_to_str(ac: AttackComplexity) -> &'static str {
    match ac {
        AttackComplexity::Low => "L",
        AttackComplexity::High => "H",
    }
}

fn pr_to_str(pr: PrivilegesRequired) -> &'static str {
    match pr {
        PrivilegesRequired::None => "N",
        PrivilegesRequired::Low => "L",
        PrivilegesRequired::High => "H",
    }
}

fn ui_to_str(ui: UserInteraction) -> &'static str {
    match ui {
        UserInteraction::None => "N",
        UserInteraction::Required => "R",
    }
}

fn scope_to_str(s: Scope) -> &'static str {
    match s {
        Scope::Unchanged => "U",
        Scope::Changed => "C",
    }
}

fn impact_to_str(i: Impact) -> &'static str {
    match i {
        Impact::None => "N",
        Impact::Low => "L",
        Impact::High => "H",
    }
}

/// Metadata for the CVSS v3 mapping
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CvssV3MappingMetadata {
    /// Default CVSS v3 vector
    pub default: CvssV3Vector,
}

/// A node in the VRT to CVSS v3 mapping tree
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CvssV3MappingNode {
    /// VRT identifier (e.g., "cross_site_scripting_xss")
    pub id: String,

    /// Associated CVSS v3 vector
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_v3: Option<CvssV3Vector>,

    /// Child mappings (for hierarchical structure)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<CvssV3MappingNode>,
}

impl CvssV3MappingNode {
    /// Returns true if this node has a CVSS v3 mapping
    pub fn has_cvss_mapping(&self) -> bool {
        self.cvss_v3.is_some()
    }

    /// Returns true if this node has children
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }

    /// Recursively finds a mapping node by VRT ID
    pub fn find_by_id(&self, vrt_id: &str) -> Option<&CvssV3MappingNode> {
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

    /// Returns all leaf nodes (nodes with CVSS mappings but no children)
    pub fn leaf_nodes(&self) -> Vec<&CvssV3MappingNode> {
        let mut leaves = Vec::new();

        if self.has_cvss_mapping() && !self.has_children() {
            leaves.push(self);
        }

        for child in &self.children {
            leaves.extend(child.leaf_nodes());
        }

        leaves
    }
}

/// The complete VRT to CVSS v3 mapping document
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CvssV3Mapping {
    /// Metadata about the mapping
    pub metadata: CvssV3MappingMetadata,

    /// The mapping content (root nodes)
    pub content: Vec<CvssV3MappingNode>,
}

impl CvssV3Mapping {
    /// Finds a mapping node by VRT ID across all root nodes
    pub fn find_by_vrt_id(&self, vrt_id: &str) -> Option<&CvssV3MappingNode> {
        for node in &self.content {
            if let Some(found) = node.find_by_id(vrt_id) {
                return Some(found);
            }
        }
        None
    }

    /// Looks up the CVSS v3 vector for a given VRT ID
    ///
    /// # Example
    /// ```no_run
    /// use bugcrowd_vrt::load_cvss_v3_mapping_from_file;
    ///
    /// let mapping = load_cvss_v3_mapping_from_file("cvss_v3.json")
    ///     .expect("Failed to load mapping");
    ///
    /// if let Some(vector) = mapping.lookup_cvss("cross_site_scripting_xss") {
    ///     println!("CVSS Vector: {}", vector);
    /// }
    /// ```
    pub fn lookup_cvss(&self, vrt_id: &str) -> Option<&CvssV3Vector> {
        self.find_by_vrt_id(vrt_id)
            .and_then(|node| node.cvss_v3.as_ref())
    }

    /// Returns statistics about the mapping
    pub fn statistics(&self) -> CvssV3Statistics {
        let mut stats = CvssV3Statistics::default();

        for node in &self.content {
            collect_stats(node, &mut stats);
        }

        stats
    }
}

/// Statistics about a CVSS v3 mapping
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CvssV3Statistics {
    /// Total number of VRT nodes
    pub total_nodes: usize,
    /// Number of nodes with CVSS mappings
    pub nodes_with_mappings: usize,
    /// Number of nodes without CVSS mappings
    pub nodes_without_mappings: usize,
}

fn collect_stats(node: &CvssV3MappingNode, stats: &mut CvssV3Statistics) {
    stats.total_nodes += 1;

    if node.has_cvss_mapping() {
        stats.nodes_with_mappings += 1;
    } else {
        stats.nodes_without_mappings += 1;
    }

    for child in &node.children {
        collect_stats(child, stats);
    }
}
