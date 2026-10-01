//! URL sanitization, anti-spoofing, and Host-Split / Unicode normalization defense.
//!
//! Mitigates:
//! - Dangerous pseudo-protocols: `javascript:`, `vbscript:`, and unauthorized `data:` URIs.
//! - Unicode normalization confusion and Host-Split attacks (e.g., fullwidth `／`, `＠`, `：`, `。`).
//! - IDN homograph / Punycode spoofing (`xn--...`).
//! - Blocked domain and tracking beacon matching.

use crate::policy::{LinkAction, Policy};
use crate::report::SanitizationAction;
use url::Url;

/// Outcome of inspecting and validating a URL against policy rules.
#[derive(Debug, Clone)]
pub enum UrlCheckOutcome {
    /// The URL is safe as-is.
    Safe(String),
    /// The URL was rewritten according to policy.
    Rewritten(String, SanitizationAction),
    /// The URL is deemed malicious or disallowed and must be stripped/removed.
    Remove(SanitizationAction),
}

/// Inspects a raw URL string against security policies.
pub fn inspect_url(raw_url: &str, _is_src_attribute: bool, policy: &Policy) -> UrlCheckOutcome {
    // 0. Decode HTML numeric entities (e.g. &#x09;, &#10;) which browsers decode before protocol dispatch
    let decoded_entities = decode_html_numeric_entities(raw_url);

    // 1. Strip ASCII whitespace and control characters (which browsers ignore during protocol dispatch)
    let clean_str: String = decoded_entities
        .chars()
        .filter(|c| !c.is_ascii_control() && *c != ' ' && *c != '\t' && *c != '\n' && *c != '\r')
        .collect();

    let lower_clean = clean_str.to_ascii_lowercase();

    // 2. Check for javascript: and vbscript: pseudo-protocols
    if policy.html.block_javascript_uris
        && (lower_clean.starts_with("javascript:") || lower_clean.starts_with("vbscript:"))
    {
        return UrlCheckOutcome::Remove(SanitizationAction {
            rule_fired: "Malicious URI scheme blocked".to_string(),
            location: (0, 0),
            original_fragment: raw_url.to_string(),
            replaced_fragment: "Attribute stripped".to_string(),
        });
    }

    // 3. Check for data: URI scheme
    if policy.html.block_data_uris && lower_clean.starts_with("data:") {
        return UrlCheckOutcome::Remove(SanitizationAction {
            rule_fired: "data: URI scheme disallowed by policy".to_string(),
            location: (0, 0),
            original_fragment: raw_url.to_string(),
            replaced_fragment: "Attribute stripped".to_string(),
        });
    }

    // 4. Unicode Host-Split & Normalization Confusion Check
    if policy.urls.check_unicode_host_split
        && let Some(bad_char) = find_host_split_character(raw_url)
    {
        let action = SanitizationAction {
            rule_fired: format!(
                "Unicode normalization confusion / Host-Split detected (character U+{:04X})",
                bad_char as u32
            ),
            location: (0, 0),
            original_fragment: raw_url.to_string(),
            replaced_fragment: "Suspicious link mitigated".to_string(),
        };

        return apply_suspicious_link_action(raw_url, action, policy);
    }

    // 5. Parse URL using standard URL parser with a base fallback for relative URLs
    let base_addr = Url::parse("http://internal.base").unwrap();
    let parsed = match base_addr.join(&clean_str) {
        Ok(u) => u,
        Err(_) => {
            return UrlCheckOutcome::Remove(SanitizationAction {
                rule_fired: "Malformed URL parsing failure".to_string(),
                location: (0, 0),
                original_fragment: raw_url.to_string(),
                replaced_fragment: "Attribute stripped".to_string(),
            });
        }
    };

    // Scheme re-check on parsed URL
    let scheme = parsed.scheme();
    if (policy.html.block_javascript_uris && (scheme == "javascript" || scheme == "vbscript"))
        || (policy.html.block_data_uris && scheme == "data")
    {
        return UrlCheckOutcome::Remove(SanitizationAction {
            rule_fired: "Dangerous parsed URL scheme".to_string(),
            location: (0, 0),
            original_fragment: raw_url.to_string(),
            replaced_fragment: "Attribute stripped".to_string(),
        });
    }

    // If the URL has an external host
    if parsed.host_str() != Some("internal.base")
        && let Some(host) = parsed.host_str()
    {
        let is_punycode = host.starts_with("xn--") || host.contains(".xn--");
        let is_malware = is_domain_in_set(host, &policy.urls.blocked_domains);
        let is_tracker = is_domain_in_set(host, &policy.urls.tracker_domains);

        if (is_punycode && policy.urls.check_idn_homographs) || is_malware || is_tracker {
            let reason = if is_malware {
                "Known malware domain"
            } else if is_tracker {
                "Tracking beacon domain"
            } else {
                "IDN homograph Punycode domain"
            };

            let action = SanitizationAction {
                rule_fired: format!("Suspicious URL mitigated: {}", reason),
                location: (0, 0),
                original_fragment: raw_url.to_string(),
                replaced_fragment: "Rewritten or stripped by policy".to_string(),
            };

            return apply_suspicious_link_action(raw_url, action, policy);
        }
    }

    // URL is safe
    UrlCheckOutcome::Safe(clean_str)
}

/// Applies the configured [`LinkAction`] when a link is flagged as suspicious.
fn apply_suspicious_link_action(
    raw_url: &str,
    action: SanitizationAction,
    policy: &Policy,
) -> UrlCheckOutcome {
    match &policy.urls.suspicious_link_action {
        LinkAction::Remove => UrlCheckOutcome::Remove(action),
        LinkAction::ReplaceWithWarning(warning) => {
            UrlCheckOutcome::Rewritten(warning.clone(), action)
        }
        LinkAction::Rewrite(prefix) => {
            let encoded =
                url::form_urlencoded::byte_serialize(raw_url.as_bytes()).collect::<String>();
            let rewritten = format!("{}{}", prefix, encoded);
            UrlCheckOutcome::Rewritten(rewritten, action)
        }
    }
}

/// Checks if a domain or its parent matches any entry in `set`.
fn is_domain_in_set(domain: &str, set: &std::collections::HashSet<String>) -> bool {
    if set.contains(domain) {
        return true;
    }
    // Check wildcard or parent domain matches
    let parts: Vec<&str> = domain.split('.').collect();
    for i in 1..parts.len() {
        let parent = parts[i..].join(".");
        if set.contains(&parent) || set.contains(&format!("*.{}", parent)) {
            return true;
        }
    }
    false
}

/// Detects Unicode characters known to cause Host-Split attacks or URL confusion
/// under Unicode NFKC normalization.
fn find_host_split_character(input: &str) -> Option<char> {
    let lower = input.to_ascii_lowercase();
    if lower.contains("&#x200b") || lower.contains("&#8203") || lower.contains("&zerowidthspace;") {
        return Some('\u{200B}');
    }

    for c in input.chars() {
        match c {
            // Fullwidth slash / solidus ／ and reverse solidus ＼
            '\u{FF0F}' | '\u{FF3C}' => return Some(c),
            // Fullwidth question mark ？ and fullwidth hash ＃
            '\u{FF1F}' | '\u{FF03}' => return Some(c),
            // Fullwidth colon ： and fullwidth commercial at ＠
            '\u{FF1A}' | '\u{FF20}' => return Some(c),
            // Ideographic full stop 。 and fullwidth full stop ．
            '\u{3002}' | '\u{FF0E}' | '\u{FF61}' => return Some(c),
            // Zero-width spaces and control formatting
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{202E}' | '\u{00AD}' => return Some(c),
            _ => {}
        }
    }
    None
}

/// Decodes decimal and hexadecimal HTML numeric character references (e.g. `&#x09;`, `&#10;`).
fn decode_html_numeric_entities(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '&' && chars.peek() == Some(&'#') {
            chars.next(); // consume '#'
            let is_hex = chars.peek() == Some(&'x') || chars.peek() == Some(&'X');
            if is_hex {
                chars.next(); // consume 'x'
            }
            let mut num_str = String::new();
            while let Some(&nc) = chars.peek() {
                if (is_hex && nc.is_ascii_hexdigit()) || (!is_hex && nc.is_ascii_digit()) {
                    num_str.push(nc);
                    chars.next();
                } else {
                    break;
                }
            }
            if chars.peek() == Some(&';') {
                chars.next(); // consume ';'
            }
            let codepoint = if is_hex {
                u32::from_str_radix(&num_str, 16).ok()
            } else {
                num_str.parse::<u32>().ok()
            };
            if let Some(cp) = codepoint
                && let Some(decoded_char) = char::from_u32(cp)
            {
                result.push(decoded_char);
            }
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfuscated_javascript_scheme() {
        let policy = Policy::balanced();
        // Leading spaces, tabs, and newlines
        let bad_url = " \t\n javascript:alert('pwned')";
        let outcome = inspect_url(bad_url, false, &policy);
        assert!(matches!(outcome, UrlCheckOutcome::Remove(_)));
    }

    #[test]
    fn test_unicode_host_split() {
        let policy = Policy::balanced();
        // Fullwidth solidus U+FF0F: evil.com／target.com
        let evil_url = "https://evil.com\u{FF0F}target.com";
        let outcome = inspect_url(evil_url, false, &policy);
        assert!(matches!(outcome, UrlCheckOutcome::Rewritten(_, _)));
    }

    #[test]
    fn test_idn_punycode_blocking() {
        let policy = Policy::strict();
        let idn_url = "https://xn--apple-43d.com/login";
        let outcome = inspect_url(idn_url, false, &policy);
        assert!(matches!(outcome, UrlCheckOutcome::Remove(_)));
    }

    #[test]
    fn test_blocked_domain_check() {
        let mut policy = Policy::balanced();
        policy
            .urls
            .blocked_domains
            .insert("tracker.net".to_string());
        let url = "https://sub.tracker.net/pixel.gif";
        let outcome = inspect_url(url, true, &policy);
        assert!(matches!(outcome, UrlCheckOutcome::Rewritten(_, _)));
    }
}
