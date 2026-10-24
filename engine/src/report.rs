//! Structured telemetry and auditing reports for sanitization runs.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Where in the input a sanitisation action applies.
///
/// `lol_html` 1.x does not expose source byte positions to element handlers, so HTML
/// actions are located structurally: the ordinal of the element among those visited by
/// the rewriter in document order (1-based) and, for attribute-level actions, the ordinal
/// of the attribute inside that element (1-based, original order). Actions on binary
/// documents (PDF) carry the byte offset of the matched marker. Whole-input checks
/// (image headers, entity bombs, ...) use `Document`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Location {
    /// The action concerns the input as a whole.
    #[default]
    Document,
    /// The `index`-th element in document order and, optionally, its `attribute`-th attribute.
    Element {
        index: usize,
        attribute: Option<usize>,
    },
    /// Absolute byte offset in the original input.
    Byte { offset: usize },
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Location::Document => write!(f, "document"),
            Location::Element { index, attribute: None } => write!(f, "element #{index}"),
            Location::Element { index, attribute: Some(attr) } => {
                write!(f, "element #{index}, attr #{attr}")
            }
            Location::Byte { offset } => write!(f, "byte {offset}"),
        }
    }
}

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

    /// Position of the matched construct in the original input (see [`Location`]).
    pub location: Location,

    /// The original malicious or disallowed fragment that was matched.
    pub original_fragment: String,

    /// The replacement text or description of the action taken (e.g., `"Tag removed"`).
    pub replaced_fragment: String,
}
