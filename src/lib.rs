pub mod types;
pub mod cwe_mapping;
pub mod cvss_v3;
pub mod categorization;

pub use types::{VrtNode, VrtNodeType, VrtTaxonomy};
pub use cwe_mapping::{
    CweId, CweMapping, CweMappingNode, MappingMetadata, MappingStatistics,
};
pub use cvss_v3::{
    AttackComplexity, AttackVector, CvssV3Mapping, CvssV3MappingMetadata,
    CvssV3MappingNode, CvssV3Statistics, CvssV3Vector, Impact,
    PrivilegesRequired, Scope, UserInteraction,
};
pub use categorization::{CategorizedFinding, VulnerabilityCategorizer};

use std::fs;
use std::io;
use std::path::Path;

/// Loads and deserializes a VRT taxonomy from a JSON file
///
/// # Arguments
/// * `path` - Path to the VRT JSON file
///
/// # Errors
/// Returns an error if the file cannot be read or the JSON is invalid
///
/// # Example
/// ```no_run
/// use bugcrowd_vrt::load_vrt_from_file;
///
/// let taxonomy = load_vrt_from_file("vrt.json").expect("Failed to load VRT");
/// println!("Loaded {} categories", taxonomy.len());
/// ```
pub fn load_vrt_from_file<P: AsRef<Path>>(path: P) -> Result<VrtTaxonomy, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let taxonomy = serde_json::from_str(&content)?;
    Ok(taxonomy)
}

/// Deserializes a VRT taxonomy from a JSON string
///
/// # Arguments
/// * `json` - JSON string containing the VRT data
///
/// # Errors
/// Returns an error if the JSON is invalid
///
/// # Example
/// ```
/// use bugcrowd_vrt::load_vrt_from_str;
///
/// let json = r#"[{"id": "test", "name": "Test", "type": "category", "children": []}]"#;
/// let taxonomy = load_vrt_from_str(json).expect("Failed to parse VRT");
/// assert_eq!(taxonomy.len(), 1);
/// ```
pub fn load_vrt_from_str(json: &str) -> Result<VrtTaxonomy, serde_json::Error> {
    serde_json::from_str(json)
}

/// Deserializes a VRT taxonomy from a reader
///
/// # Arguments
/// * `reader` - Any type implementing `io::Read` containing JSON data
///
/// # Errors
/// Returns an error if reading fails or the JSON is invalid
pub fn load_vrt_from_reader<R: io::Read>(reader: R) -> Result<VrtTaxonomy, serde_json::Error> {
    serde_json::from_reader(reader)
}

/// Loads and deserializes a CWE mapping from a JSON file
///
/// # Arguments
/// * `path` - Path to the CWE mapping JSON file
///
/// # Errors
/// Returns an error if the file cannot be read or the JSON is invalid
///
/// # Example
/// ```no_run
/// use bugcrowd_vrt::load_cwe_mapping_from_file;
///
/// let mapping = load_cwe_mapping_from_file("cwe.mappings.json")
///     .expect("Failed to load CWE mapping");
/// println!("Loaded {} root nodes", mapping.content.len());
/// ```
pub fn load_cwe_mapping_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<CweMapping, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let mapping = serde_json::from_str(&content)?;
    Ok(mapping)
}

/// Deserializes a CWE mapping from a JSON string
///
/// # Arguments
/// * `json` - JSON string containing the CWE mapping data
///
/// # Errors
/// Returns an error if the JSON is invalid
///
/// # Example
/// ```
/// use bugcrowd_vrt::load_cwe_mapping_from_str;
///
/// let json = r#"{
///   "metadata": {"default": null},
///   "content": [
///     {"id": "xss", "cwe": ["CWE-79"]}
///   ]
/// }"#;
/// let mapping = load_cwe_mapping_from_str(json).expect("Failed to parse");
/// assert_eq!(mapping.content.len(), 1);
/// ```
pub fn load_cwe_mapping_from_str(json: &str) -> Result<CweMapping, serde_json::Error> {
    serde_json::from_str(json)
}

/// Deserializes a CWE mapping from a reader
///
/// # Arguments
/// * `reader` - Any type implementing `io::Read` containing JSON data
///
/// # Errors
/// Returns an error if reading fails or the JSON is invalid
pub fn load_cwe_mapping_from_reader<R: io::Read>(reader: R) -> Result<CweMapping, serde_json::Error> {
    serde_json::from_reader(reader)
}

/// Loads and deserializes a CVSS v3 mapping from a JSON file
///
/// # Arguments
/// * `path` - Path to the CVSS v3 mapping JSON file
///
/// # Errors
/// Returns an error if the file cannot be read or the JSON is invalid
///
/// # Example
/// ```no_run
/// use bugcrowd_vrt::load_cvss_v3_mapping_from_file;
///
/// let mapping = load_cvss_v3_mapping_from_file("cvss_v3.json")
///     .expect("Failed to load CVSS v3 mapping");
/// println!("Loaded {} root nodes", mapping.content.len());
/// ```
pub fn load_cvss_v3_mapping_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<CvssV3Mapping, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let mapping = serde_json::from_str(&content)?;
    Ok(mapping)
}

/// Deserializes a CVSS v3 mapping from a JSON string
///
/// # Arguments
/// * `json` - JSON string containing the CVSS v3 mapping data
///
/// # Errors
/// Returns an error if the JSON is invalid
///
/// # Example
/// ```
/// use bugcrowd_vrt::load_cvss_v3_mapping_from_str;
///
/// let json = r#"{
///   "metadata": {"default": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
///   "content": [
///     {"id": "xss", "cvss_v3": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}
///   ]
/// }"#;
/// let mapping = load_cvss_v3_mapping_from_str(json).expect("Failed to parse");
/// assert_eq!(mapping.content.len(), 1);
/// ```
pub fn load_cvss_v3_mapping_from_str(json: &str) -> Result<CvssV3Mapping, serde_json::Error> {
    serde_json::from_str(json)
}

/// Deserializes a CVSS v3 mapping from a reader
///
/// # Arguments
/// * `reader` - Any type implementing `io::Read` containing JSON data
///
/// # Errors
/// Returns an error if reading fails or the JSON is invalid
pub fn load_cvss_v3_mapping_from_reader<R: io::Read>(
    reader: R,
) -> Result<CvssV3Mapping, serde_json::Error> {
    serde_json::from_reader(reader)
}
