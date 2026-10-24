//! CSS sanitization module.
//!
//! Neutralizes dangerous CSS constructs:
//! - `expression(...)` dynamic evaluation
//! - `javascript:`, `vbscript:`, and unsafe `data:` URI schemes in `url(...)`
//! - Proprietary active vectors: `-moz-binding`, `behavior:`
//! - Untrusted `@import` directives targeting blocked or suspicious origins

use crate::policy::Policy;
use crate::report::{Location, SanitizationAction};

/// Sanitizes a CSS stylesheet or inline `style` attribute value.
///
/// Returns the cleaned CSS string and a list of actions taken.
pub fn sanitize_css(css_input: &str, policy: &Policy) -> (String, Vec<SanitizationAction>) {
    let mut actions = Vec::new();
    let mut cleaned_lines = Vec::new();

    // Check for comment obfuscation / decode escapes for threat detection
    for line in css_input.lines() {
        let mut current_line = line.to_string();
        let normalized = normalize_css_for_detection(&current_line);

        // 1. Check for expression(...)
        if normalized.contains("expression(") || normalized.contains("expression (") {
            actions.push(SanitizationAction {
                rule_fired: "CSS expression blocked".to_string(),
                location: Location::Document,
                original_fragment: "expression(...)".to_string(),
                replaced_fragment: "Property stripped".to_string(),
            });
            // Strip any property containing expression
            current_line = strip_css_property(&current_line, "expression");
        }

        // 2. Check for -moz-binding
        if normalized.contains("-moz-binding") {
            actions.push(SanitizationAction {
                rule_fired: "CSS -moz-binding blocked".to_string(),
                location: Location::Document,
                original_fragment: "-moz-binding".to_string(),
                replaced_fragment: "Property stripped".to_string(),
            });
            current_line = strip_css_property(&current_line, "-moz-binding");
        }

        // 3. Check for behavior:
        if normalized.contains("behavior:") || normalized.contains("behavior :") {
            actions.push(SanitizationAction {
                rule_fired: "CSS behavior property blocked".to_string(),
                location: Location::Document,
                original_fragment: "behavior".to_string(),
                replaced_fragment: "Property stripped".to_string(),
            });
            current_line = strip_css_property(&current_line, "behavior");
        }

        // 4. Check for @import directives
        if normalized.trim_start().starts_with("@import") {
            let (sanitized_import, import_actions) = sanitize_css_import(&current_line, policy);
            actions.extend(import_actions);
            current_line = sanitized_import;
        }

        // 5. Check for dangerous url schemes (javascript:, vbscript:, data:text/html)
        if normalized.contains("url(") {
            let (sanitized_url_line, url_actions) = sanitize_css_urls(&current_line, policy);
            actions.extend(url_actions);
            current_line = sanitized_url_line;
        }

        cleaned_lines.push(current_line);
    }

    (cleaned_lines.join("\n"), actions)
}

/// Normalizes CSS by lowercasing, stripping comments `/* ... */`, and backslash escapes
/// to detect obfuscated patterns like `exp/* */ression` or `\6a avascript:`.
fn normalize_css_for_detection(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut in_comment = false;
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if !in_comment && i + 1 < chars.len() && chars[i] == '/' && chars[i + 1] == '*' {
            in_comment = true;
            i += 2;
            continue;
        }
        if in_comment && i + 1 < chars.len() && chars[i] == '*' && chars[i + 1] == '/' {
            in_comment = false;
            i += 2;
            continue;
        }
        if in_comment {
            i += 1;
            continue;
        }

        // Remove backslash escapes in identifiers: e.g. \65xpression -> expression
        if chars[i] == '\\' && i + 1 < chars.len() {
            i += 1;
            // if hex escape, skip hex digits and optional space
            if chars[i].is_ascii_hexdigit() {
                let mut hex_val = 0u32;
                let mut digits = 0;
                while i < chars.len() && chars[i].is_ascii_hexdigit() && digits < 6 {
                    hex_val = hex_val * 16 + chars[i].to_digit(16).unwrap_or(0);
                    digits += 1;
                    i += 1;
                }
                if i < chars.len() && chars[i] == ' ' {
                    i += 1;
                }
                if let Some(c) = char::from_u32(hex_val) {
                    result.push(c.to_ascii_lowercase());
                }
                continue;
            } else {
                result.push(chars[i].to_ascii_lowercase());
                i += 1;
                continue;
            }
        }

        result.push(chars[i].to_ascii_lowercase());
        i += 1;
    }

    result
}

/// Strips any CSS declaration containing a specific keyword.
fn strip_css_property(line: &str, keyword: &str) -> String {
    let parts: Vec<&str> = line.split(';').collect();
    let mut retained = Vec::new();

    for part in parts {
        let norm = normalize_css_for_detection(part);
        if norm.contains(keyword) {
            // Drop this declaration
            continue;
        }
        retained.push(part);
    }

    retained.join(";")
}

/// Sanitizes `url(...)` occurrences in a CSS line.
fn sanitize_css_urls(line: &str, policy: &Policy) -> (String, Vec<SanitizationAction>) {
    let mut actions = Vec::new();
    let mut output = String::new();
    let mut remaining = line;

    while let Some(start_idx) = remaining.to_ascii_lowercase().find("url(") {
        output.push_str(&remaining[..start_idx]);
        let url_part = &remaining[start_idx..];

        if let Some(end_idx) = url_part.find(')') {
            let inner_content = &url_part[4..end_idx];
            let clean_inner = inner_content
                .trim()
                .trim_matches('\'')
                .trim_matches('"')
                .trim();
            let norm_inner = clean_inner.to_ascii_lowercase();

            let is_js = norm_inner.starts_with("javascript:");
            let is_vb = norm_inner.starts_with("vbscript:");
            let is_data_html = norm_inner.starts_with("data:text/html")
                || (policy.html.block_data_uris && norm_inner.starts_with("data:"));

            let is_blocked_host = url::Url::parse(clean_inner)
                .ok()
                .and_then(|u| {
                    u.host_str().map(|h| {
                        policy.urls.blocked_domains.contains(h)
                            || policy.urls.tracker_domains.contains(h)
                            || (policy.urls.check_idn_homographs && h.starts_with("xn--"))
                    })
                })
                .unwrap_or(false);

            if is_js || is_vb || is_data_html || is_blocked_host {
                actions.push(SanitizationAction {
                    rule_fired: "CSS dangerous url() removed".to_string(),
                    location: Location::Document,
                    original_fragment: clean_inner.to_string(),
                    replaced_fragment: "url(about:blank)".to_string(),
                });
                output.push_str("url(\"about:blank\")");
            } else {
                output.push_str(&url_part[..=end_idx]);
            }

            remaining = &url_part[end_idx + 1..];
        } else {
            // Unclosed url(
            output.push_str(url_part);
            remaining = "";
            break;
        }
    }

    output.push_str(remaining);
    (output, actions)
}

/// Sanitizes an `@import` statement.
fn sanitize_css_import(line: &str, policy: &Policy) -> (String, Vec<SanitizationAction>) {
    let mut actions = Vec::new();
    let norm = normalize_css_for_detection(line);

    // If @import targets a dangerous scheme or blocked domain
    let has_danger =
        norm.contains("javascript:") || norm.contains("data:") || norm.contains("vbscript:");

    if has_danger {
        actions.push(SanitizationAction {
            rule_fired: "Malicious CSS @import stripped".to_string(),
            location: Location::Document,
            original_fragment: line.trim().to_string(),
            replaced_fragment: "/* @import removed */".to_string(),
        });
        return ("/* @import removed */".to_string(), actions);
    }

    // Check if url inside @import is blocked
    for blocked in &policy.urls.blocked_domains {
        if norm.contains(blocked) {
            actions.push(SanitizationAction {
                rule_fired: "Blocked domain in CSS @import".to_string(),
                location: Location::Document,
                original_fragment: line.trim().to_string(),
                replaced_fragment: "/* @import removed */".to_string(),
            });
            return ("/* @import removed */".to_string(), actions);
        }
    }

    (line.to_string(), actions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_expression() {
        let policy = Policy::balanced();
        let css = "body { color: red; width: expression(alert('XSS')); height: 100px; }";
        let (sanitized, actions) = sanitize_css(css, &policy);
        assert!(!sanitized.contains("expression"));
        assert!(sanitized.contains("color: red"));
        assert!(sanitized.contains("height: 100px"));
        assert!(!actions.is_empty());
    }

    #[test]
    fn test_strip_obfuscated_expression() {
        let policy = Policy::balanced();
        let css = "div { background: exp/* comment */ression(alert(1)); }";
        let (sanitized, actions) = sanitize_css(css, &policy);
        assert!(!sanitized.contains("expression"));
        assert!(!actions.is_empty());
    }

    #[test]
    fn test_strip_javascript_url() {
        let policy = Policy::balanced();
        let css = "body { background-image: url('javascript:alert(1)'); }";
        let (sanitized, actions) = sanitize_css(css, &policy);
        assert!(!sanitized.contains("javascript:"));
        assert!(sanitized.contains("about:blank"));
        assert!(!actions.is_empty());
    }

    #[test]
    fn test_strip_moz_binding() {
        let policy = Policy::balanced();
        let css = "p { -moz-binding: url('http://evil.com/xbl'); font-size: 14px; }";
        let (sanitized, actions) = sanitize_css(css, &policy);
        assert!(!sanitized.contains("-moz-binding"));
        assert!(sanitized.contains("font-size: 14px"));
        assert!(!actions.is_empty());
    }

    #[test]
    fn test_blocked_import() {
        let mut policy = Policy::balanced();
        policy
            .urls
            .blocked_domains
            .insert("malware.com".to_string());
        let css = "@import url('https://malware.com/evil.css');\nbody { color: blue; }";
        let (sanitized, actions) = sanitize_css(css, &policy);
        assert!(!sanitized.contains("malware.com"));
        assert!(sanitized.contains("body { color: blue; }"));
        assert!(!actions.is_empty());
    }
}
