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

pub mod active_content;
pub mod css;
pub mod network;
pub mod parser;
pub mod pipeline;
pub mod policy;
pub mod report;
pub mod url_sanitizer;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;
    use crate::report::Location;
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

        assert!(
            report
                .actions
                .iter()
                .any(|a| a.original_fragment == "script")
        )
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
        let html_input =
            b"<head><meta http-equiv=\"refresh\" content=\"0; url=http://evil.com\"></head>";

        let (output_bytes, _) = sanitize_html(html_input, &policy).unwrap();
        let output_string = String::from_utf8(output_bytes).unwrap();

        assert!(!output_string.contains("refresh"));
    }

    // 4. Iframe Sandboxing Test
    #[test]
    fn test_iframe_sandboxing() {
        let mut policy = Policy::balanced();

        policy.html.allowed_tags.insert("iframe".to_string());
        policy.html.allowed_attributes.insert(
            "iframe".to_string(),
            std::collections::HashSet::from(["src".to_string(), "sandbox".to_string()]),
        );

        let html_input = b"<iframe src=\"https://youtube.com\"></iframe>";

        let (output_bytes, _) = sanitize_html(html_input, &policy).unwrap();
        let output_string = String::from_utf8(output_bytes).unwrap();

        assert!(output_string.contains("sandbox"));
    }

    // 5. IDN Homograph Test
    #[test]
    fn test_idn_homograph_blocking() {
        let policy_strict = Policy::strict();
        let html_input = b"<a href=\"https://xn--pple-43d.com\">Finta Apple</a>";

        let (output_bytes, _) = sanitize_html(html_input, &policy_strict).unwrap();
        let output_string = String::from_utf8(output_bytes).unwrap();

        assert!(output_string.contains("<a>Finta Apple</a>"));
        assert!(!output_string.contains("xn--"));

        // Balanced profile replaces with warning
        let policy_balanced = Policy::balanced();
        let (output_bytes_b, _) = sanitize_html(html_input, &policy_balanced).unwrap();
        let output_string_b = String::from_utf8(output_bytes_b).unwrap();
        assert!(output_string_b.contains("[REMOVED SUSPICIOUS LINK]"));
        assert!(!output_string_b.contains("xn--"));
    }

    // 6. Inline Event Handlers Test
    #[test]
    fn test_inline_event_handler_stripping() {
        let policy = Policy::balanced();
        let html_input = b"<div onclick=\"alert('pwned')\" onmouseover=\"bad()\">Safe Text</div>";

        let (output_bytes, report) = sanitize_html(html_input, &policy).unwrap();
        let output_string = String::from_utf8(output_bytes).unwrap();

        assert!(!output_string.contains("onclick"));
        assert!(!output_string.contains("onmouseover"));
        assert!(output_string.contains("Safe Text"));
        assert!(
            report
                .actions
                .iter()
                .any(|a| a.rule_fired.contains("Inline event handler"))
        );
    }

    // 7. Inline Style CSS Sanitization Test
    #[test]
    fn test_inline_style_css_sanitization() {
        let policy = Policy::balanced();
        let html_input = b"<div style=\"color: blue; width: expression(alert(1)); background: url(javascript:evil())\">Styled Text</div>";

        let (output_bytes, report) = sanitize_html(html_input, &policy).unwrap();
        let output_string = String::from_utf8(output_bytes).unwrap();

        assert!(output_string.contains("color: blue"));
        assert!(!output_string.contains("expression"));
        assert!(!output_string.contains("javascript:"));
        assert!(report.actions.iter().any(|a| a.rule_fired.contains("CSS")));
    }

    // 8. Style Tag Content Sanitization Test
    #[test]
    fn test_style_tag_css_sanitization() {
        let policy = Policy::balanced();
        let html_input =
            b"<style>body { -moz-binding: url('xbl'); color: red; }</style><p>Text</p>";

        let (output_bytes, report) = sanitize_html(html_input, &policy).unwrap();
        let output_string = String::from_utf8(output_bytes).unwrap();

        assert!(!output_string.contains("-moz-binding"));
        assert!(output_string.contains("color: red"));
        assert!(
            report
                .actions
                .iter()
                .any(|a| a.rule_fired.contains("-moz-binding"))
        );
    }

    // 9. Host-Split Unicode Normalization Confusion Test
    #[test]
    fn test_host_split_unicode_mitigation() {
        let policy = Policy::balanced();
        let html_input =
            "<a href=\"https://legit.com\u{FF0F}evil.com\">Deceptive Link</a>".as_bytes();

        let (output_bytes, report) = sanitize_html(html_input, &policy).unwrap();
        let output_string = String::from_utf8(output_bytes).unwrap();

        assert!(!output_string.contains("\u{FF0F}"));
        assert!(output_string.contains("[REMOVED SUSPICIOUS LINK]"));
        assert!(
            report
                .actions
                .iter()
                .any(|a| a.rule_fired.contains("Host-Split"))
        );
    }

    // 12. Disallowed wrappers are unwrapped, dangerous elements dropped with their content
    #[test]
    fn test_disallowed_wrapper_keeps_content() {
        let policy = Policy::balanced();
        let html_input = b"<!doctype html><html><body><section><p>Visible text</p></section>\
<script>alert(1)</script></body></html>";

        let (output_bytes, report) = sanitize_html(html_input, &policy).unwrap();
        let output = String::from_utf8(output_bytes).unwrap();

        assert!(output.contains("<p>Visible text</p>"), "content of a disallowed wrapper must survive");
        assert!(!output.contains("<section"));
        assert!(!output.contains("alert(1)"), "script content must be dropped");
        assert!(output.contains("<body>"));
        assert!(report.actions.iter().any(|a| a.original_fragment == "section"
            && a.replaced_fragment.contains("content kept")));
    }

    // 11. Structural location of actions
    #[test]
    fn test_actions_report_structural_location() {
        let policy = Policy::balanced();
        // element #1 <div>, #2 <script>, #3 <a> whose 2nd attribute is an event handler
        let html_input = b"<div>ok</div><script>x()</script>\
<a href=\"https://example.org\" onclick=\"y()\">l</a>";

        let (_, report) = sanitize_html(html_input, &policy).unwrap();

        let script = report
            .actions
            .iter()
            .find(|a| a.original_fragment == "script")
            .expect("script removal must be reported");
        assert_eq!(
            script.location,
            Location::Element {
                index: 2,
                attribute: None
            }
        );

        let handler = report
            .actions
            .iter()
            .find(|a| a.rule_fired.contains("Inline event handler"))
            .expect("event handler stripping must be reported");
        assert_eq!(
            handler.location,
            Location::Element {
                index: 3,
                attribute: Some(2)
            }
        );
        assert_eq!(handler.location.to_string(), "element #3, attr #2");
    }

    // 10. Data URI Disallowed Test
    #[test]
    fn test_disallow_data_uri() {
        let policy = Policy::balanced();
        let html_input =
            b"<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">Data link</a>";

        let (output_bytes, report) = sanitize_html(html_input, &policy).unwrap();
        let output_string = String::from_utf8(output_bytes).unwrap();

        assert!(!output_string.contains("data:text/html"));
        assert!(
            report
                .actions
                .iter()
                .any(|a| a.rule_fired.contains("data: URI"))
        );
    }
}
