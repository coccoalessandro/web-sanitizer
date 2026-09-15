//! # Web Sanitizer Engine
//!
//! A modular, defensive HTML and resource sanitization engine written in Rust.
//! It neutralizes malicious content (XSS, SSRF, MIME confusion, IDN homographs, DoS payloads)
//! using streaming zero-copy HTML rewriting and configurable security policies.
//!
//! ## Core Modules
//! - [`policy`]: Declarative configuration defining allow-lists and security rules.
//! - [`parser`]: Streaming HTML inspection and sanitization using `lol_html`.
//! - [`network`]: Safe HTTP sub-resource fetching with SSRF and MIME sniffing defenses.
//! - [`pipeline`]: Concurrent worker pool processing local files and remote URLs.
//! - [`report`]: Structured, machine-readable audit reports of all sanitization actions.

pub mod policy;
pub mod report;
pub mod parser;
pub mod network;
pub mod pipeline;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;
    use parser::*;

    // 1. Base XSS Test
    #[test]
    fn test_remove_unallowed_tags() {
        let policy = Policy::balanced();
        let html_input = b"<div>Testo sicuro</div><script>alert('XSS!');</script>";

        let (output_bytes, report) = sanitize_html(html_input, &policy).unwrap();
        let output_string = String::from_utf8(output_bytes).unwrap();

        assert!(output_string.contains("<div>Testo sicuro</div>"));
        assert!(!output_string.contains("<script>"));

        assert!(report.actions.iter().any(|a| a.original_fragment == "script"))
    }

    // 2. Advanced XSS Test
    #[test]
    fn test_block_javascript_urls() {
        let policy = Policy::balanced();
        let html_input = b"<a href=\"javascript:alert('XSS')\">Cliccami</a>";

        let (output_bytes, _) = sanitize_html(html_input, &policy).unwrap();
        let output_string = String::from_utf8(output_bytes).unwrap();

        assert!(output_string.contains("<a>Cliccami</a>"));
        assert!(!output_string.contains("javascript"));
    }

    // 3. Meta Refresh Test
    #[test]
    fn test_block_meta_refresh() {
        let policy = Policy::balanced();
        let html_input = b"<head><meta http-equiv=\"refresh\" content=\"0; url=http://evil.com\"></head>";

        let (output_bytes, _) = sanitize_html(html_input, &policy).unwrap();
        let output_string = String::from_utf8(output_bytes).unwrap();

        assert!(!output_string.contains("refresh"));
    }

    // 4. Iframe Sandboxing Test
    #[test]
    fn test_iframe_sandboxing() {
        let mut policy = Policy::balanced();

        policy.html.allowed_tags.insert("iframe".to_string());
        policy.html.allowed_attributes.insert("iframe".to_string(), std::collections::HashSet::from(["src".to_string(), "sandbox".to_string()]));

        let html_input = b"<iframe src=\"https://youtube.com\"></iframe>";

        let (output_bytes, _) = sanitize_html(html_input, &policy).unwrap();
        let output_string = String::from_utf8(output_bytes).unwrap();

        assert!(output_string.contains("sandbox"));
    }

    // 5. IDN Homograph Test
        #[test]
        fn test_idn_homograph_blocking() {
            let policy = Policy::balanced();
            let html_input = b"<a href=\"https://xn--pple-43d.com\">Finta Apple</a>";

            let (output_bytes, _) = sanitize_html(html_input, &policy).unwrap();
            let output_string = String::from_utf8(output_bytes).unwrap();

            assert!(output_string.contains("<a>Finta Apple</a>"));
            assert!(!output_string.contains("xn--"))
        }
}