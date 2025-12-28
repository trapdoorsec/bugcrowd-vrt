use crate::{CweMapping, CvssV3Mapping, VrtNode, VrtTaxonomy};

/// A categorized vulnerability finding with all relevant metadata
#[derive(Debug, Clone)]
pub struct CategorizedFinding {
    /// VRT identifier (e.g., "cross_site_scripting_xss")
    pub vrt_id: String,
    /// VRT display name (e.g., "Cross-Site Scripting (XSS)")
    pub vrt_name: String,
    /// VRT priority (1-5, where 1 is most severe)
    pub priority: Option<u8>,
    /// Category path (e.g., ["Server-Side Injection", "XSS"])
    pub category_path: Vec<String>,
    /// Associated CWE identifiers
    pub cwes: Vec<String>,
    /// CVSS v3 vector string
    pub cvss_vector: Option<String>,
}

/// Helper for categorizing vulnerability findings
pub struct VulnerabilityCategorizer {
    vrt: VrtTaxonomy,
    cwe_mapping: Option<CweMapping>,
    cvss_mapping: Option<CvssV3Mapping>,
}

impl VulnerabilityCategorizer {
    /// Creates a new categorizer with VRT taxonomy only
    pub fn new(vrt: VrtTaxonomy) -> Self {
        Self {
            vrt,
            cwe_mapping: None,
            cvss_mapping: None,
        }
    }

    /// Creates a categorizer with all mappings (VRT, CWE, CVSS)
    pub fn with_all_mappings(
        vrt: VrtTaxonomy,
        cwe_mapping: CweMapping,
        cvss_mapping: CvssV3Mapping,
    ) -> Self {
        Self {
            vrt,
            cwe_mapping: Some(cwe_mapping),
            cvss_mapping: Some(cvss_mapping),
        }
    }

    /// Adds CWE mapping
    pub fn with_cwe_mapping(mut self, cwe_mapping: CweMapping) -> Self {
        self.cwe_mapping = Some(cwe_mapping);
        self
    }

    /// Adds CVSS v3 mapping
    pub fn with_cvss_mapping(mut self, cvss_mapping: CvssV3Mapping) -> Self {
        self.cvss_mapping = Some(cvss_mapping);
        self
    }

    /// Categorizes a finding by VRT ID
    ///
    /// # Example
    /// ```no_run
    /// use bugcrowd_vrt::{VulnerabilityCategorizer, load_vrt_from_file};
    ///
    /// let vrt = load_vrt_from_file("vrt.json").expect("Failed to load VRT");
    /// let categorizer = VulnerabilityCategorizer::new(vrt);
    ///
    /// if let Some(finding) = categorizer.categorize_by_id("sql_injection") {
    ///     println!("VRT: {} (P{})", finding.vrt_name, finding.priority.unwrap_or(0));
    /// }
    /// ```
    pub fn categorize_by_id(&self, vrt_id: &str) -> Option<CategorizedFinding> {
        // Find the VRT node
        let (node, path) = self.find_node_with_path(vrt_id)?;

        // Get CWE mappings
        let cwes = self
            .cwe_mapping
            .as_ref()
            .and_then(|m| m.lookup_cwe(vrt_id))
            .map(|cwes| cwes.iter().map(|c| c.as_str().to_string()).collect())
            .unwrap_or_default();

        // Get CVSS vector
        let cvss_vector = self
            .cvss_mapping
            .as_ref()
            .and_then(|m| m.lookup_cvss(vrt_id))
            .map(|v| v.to_string());

        Some(CategorizedFinding {
            vrt_id: node.id.clone(),
            vrt_name: node.name.clone(),
            priority: node.priority,
            category_path: path,
            cwes,
            cvss_vector,
        })
    }

    /// Searches for VRT IDs by name (case-insensitive substring match)
    ///
    /// Returns a list of matching VRT IDs
    ///
    /// # Example
    /// ```no_run
    /// use bugcrowd_vrt::{VulnerabilityCategorizer, load_vrt_from_file};
    ///
    /// let vrt = load_vrt_from_file("vrt.json").expect("Failed to load VRT");
    /// let categorizer = VulnerabilityCategorizer::new(vrt);
    ///
    /// let matches = categorizer.search_by_name("sql");
    /// for id in matches {
    ///     println!("Found: {}", id);
    /// }
    /// ```
    pub fn search_by_name(&self, query: &str) -> Vec<String> {
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();

        for category in &self.vrt {
            self.search_node_by_name(&query_lower, category, &mut results);
        }

        results
    }

    /// Finds the best matching VRT ID for a vulnerability name/description
    ///
    /// Uses keyword matching to find the most relevant VRT category
    ///
    /// # Example
    /// ```no_run
    /// use bugcrowd_vrt::{VulnerabilityCategorizer, load_vrt_from_file};
    ///
    /// let vrt = load_vrt_from_file("vrt.json").expect("Failed to load VRT");
    /// let categorizer = VulnerabilityCategorizer::new(vrt);
    ///
    /// let finding_name = "SQL Injection detected in login form";
    /// if let Some(finding) = categorizer.categorize_by_description(finding_name) {
    ///     println!("Categorized as: {} (P{})", finding.vrt_name, finding.priority.unwrap_or(0));
    /// }
    /// ```
    pub fn categorize_by_description(&self, description: &str) -> Option<CategorizedFinding> {
        let description_lower = description.to_lowercase();

        // Common vulnerability keywords mapped to VRT IDs
        let keyword_mappings = self.build_keyword_mappings();

        // Find best match
        let mut best_match: Option<(&str, usize)> = None;

        for (vrt_id, keywords) in &keyword_mappings {
            let mut score = 0;
            for keyword in keywords {
                if description_lower.contains(keyword) {
                    score += keyword.len(); // Longer keywords = more specific = higher score
                }
            }

            if score > 0 {
                if let Some((_, best_score)) = best_match {
                    if score > best_score {
                        best_match = Some((vrt_id, score));
                    }
                } else {
                    best_match = Some((vrt_id, score));
                }
            }
        }

        best_match.and_then(|(vrt_id, _)| self.categorize_by_id(vrt_id))
    }

    /// Lists all available VRT variant IDs (leaf nodes)
    pub fn list_all_variants(&self) -> Vec<String> {
        let mut variants = Vec::new();
        for category in &self.vrt {
            self.collect_variant_ids(category, &mut variants);
        }
        variants
    }

    /// Gets all categorized findings for all variants
    pub fn get_all_categorizations(&self) -> Vec<CategorizedFinding> {
        let mut findings = Vec::new();
        for variant_id in self.list_all_variants() {
            if let Some(finding) = self.categorize_by_id(&variant_id) {
                findings.push(finding);
            }
        }
        findings
    }

    // Helper methods

    fn find_node_with_path(&self, vrt_id: &str) -> Option<(&VrtNode, Vec<String>)> {
        for category in &self.vrt {
            let mut path = vec![category.name.clone()];
            if let Some((node, mut node_path)) =
                self.find_node_recursive(vrt_id, category, &path)
            {
                path.append(&mut node_path);
                return Some((node, path));
            }
        }
        None
    }

    fn find_node_recursive<'a>(
        &self,
        vrt_id: &str,
        node: &'a VrtNode,
        current_path: &[String],
    ) -> Option<(&'a VrtNode, Vec<String>)> {
        if node.id == vrt_id {
            return Some((node, vec![]));
        }

        for child in &node.children {
            let mut path = current_path.to_vec();
            path.push(child.name.clone());

            if child.id == vrt_id {
                return Some((child, vec![child.name.clone()]));
            }

            if let Some((found, mut subpath)) = self.find_node_recursive(vrt_id, child, &path) {
                let mut result_path = vec![child.name.clone()];
                result_path.append(&mut subpath);
                return Some((found, result_path));
            }
        }

        None
    }

    fn search_node_by_name(&self, query: &str, node: &VrtNode, results: &mut Vec<String>) {
        if node.name.to_lowercase().contains(query) || node.id.contains(query) {
            results.push(node.id.clone());
        }

        for child in &node.children {
            self.search_node_by_name(query, child, results);
        }
    }

    fn collect_variant_ids(&self, node: &VrtNode, variants: &mut Vec<String>) {
        if node.is_variant() {
            variants.push(node.id.clone());
        }

        for child in &node.children {
            self.collect_variant_ids(child, variants);
        }
    }

    fn build_keyword_mappings(&self) -> Vec<(&str, Vec<&str>)> {
        vec![
            // Injection vulnerabilities
            ("sql_injection", vec!["sql injection", "sqli", "sql"]),
            (
                "cross_site_scripting_xss",
                vec!["xss", "cross-site scripting", "cross site scripting"],
            ),
            (
                "server_side_request_forgery_ssrf",
                vec!["ssrf", "server-side request forgery", "server side request forgery"],
            ),
            ("remote_code_execution_rce", vec!["rce", "remote code execution", "code execution"]),
            ("command_injection", vec!["command injection", "os command"]),
            ("ldap_injection", vec!["ldap injection", "ldap"]),
            ("xml_external_entity_injection_xxe", vec!["xxe", "xml external entity"]),
            // Access control
            ("idor", vec!["idor", "insecure direct object", "object reference"]),
            ("broken_access_control", vec!["access control", "authorization"]),
            ("privilege_escalation", vec!["privilege escalation", "privesc"]),
            // CSRF
            ("csrf", vec!["csrf", "cross-site request forgery", "cross site request"]),
            // Authentication
            ("authentication_bypass", vec!["auth bypass", "authentication bypass"]),
            ("session_fixation", vec!["session fixation"]),
            ("weak_login_function", vec!["weak login", "plaintext password"]),
            // Crypto
            ("weak_hash", vec!["weak hash", "md5", "sha1"]),
            ("insecure_ssl", vec!["weak ssl", "weak tls", "insecure ssl"]),
            // Information disclosure
            ("disclosure_of_secrets", vec!["secret disclosure", "credential leak", "api key"]),
            ("visible_detailed_error_page", vec!["stack trace", "error page", "debug"]),
            // File vulnerabilities
            ("path_traversal", vec!["path traversal", "directory traversal", "../"]),
            ("unsafe_file_upload", vec!["file upload", "upload"]),
            // Clickjacking
            ("clickjacking", vec!["clickjacking", "iframe", "x-frame-options"]),
            // Open redirect
            ("open_redirect", vec!["open redirect", "unvalidated redirect"]),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{load_vrt_from_str, VrtNodeType};

    fn create_test_taxonomy() -> VrtTaxonomy {
        vec![VrtNode {
            id: "server_side_injection".to_string(),
            name: "Server-Side Injection".to_string(),
            node_type: VrtNodeType::Category,
            children: vec![VrtNode {
                id: "sql_injection".to_string(),
                name: "SQL Injection".to_string(),
                node_type: VrtNodeType::Variant,
                children: vec![],
                priority: Some(1),
            }],
            priority: None,
        }]
    }

    #[test]
    fn test_categorize_by_id() {
        let vrt = create_test_taxonomy();
        let categorizer = VulnerabilityCategorizer::new(vrt);

        let finding = categorizer
            .categorize_by_id("sql_injection")
            .expect("Should find SQL injection");

        assert_eq!(finding.vrt_id, "sql_injection");
        assert_eq!(finding.vrt_name, "SQL Injection");
        assert_eq!(finding.priority, Some(1));
    }

    #[test]
    fn test_search_by_name() {
        let vrt = create_test_taxonomy();
        let categorizer = VulnerabilityCategorizer::new(vrt);

        let results = categorizer.search_by_name("sql");
        assert!(results.contains(&"sql_injection".to_string()));
    }

    #[test]
    fn test_categorize_by_description() {
        let vrt = create_test_taxonomy();
        let categorizer = VulnerabilityCategorizer::new(vrt);

        let finding = categorizer
            .categorize_by_description("SQL Injection detected in login form")
            .expect("Should categorize");

        assert_eq!(finding.vrt_id, "sql_injection");
    }
}
