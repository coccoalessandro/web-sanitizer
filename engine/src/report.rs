//! Structured telemetry and auditing reports for sanitization runs.

use serde::{Serialize, Deserialize};

/// Comprehensive audit report generated for a single processed input.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SanitizationReport {
    /// Identifier or path/URL of the processed resource.
    pub file_name: String,

    /// Total processing time in milliseconds.
    pub time_elapsed: u64,

    /// Whether the file was rejected/blocked completely due to security policies.
    pub file_blocked: bool,

    /// Ordered list of sanitization modifications and security actions performed.
    pub actions: Vec<SanitizationAction>,

    /// Extracted URLs of sub-resources (images, scripts, frames) eligible for fetching.
    pub resources_to_fetch: Vec<String>,
}

/// An individual sanitization action describing a specific modification made to the document.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SanitizationAction {
    /// The specific policy rule that triggered this action (e.g., `"Tag not allowed"`).
    pub rule_fired: String,

    /// Line and column location `(row, col)` in the source document, if available.
    pub location: (usize, usize),

    /// The original malicious or disallowed fragment that was matched.
    pub original_fragment: String,

    /// The replacement text or description of the action taken (e.g., `"Tag removed"`).
    pub replaced_fragment: String,
}