//! Security policies and configuration profiles for the sanitization engine.

use serde::{Serialize, Deserialize};
use std::collections::{HashSet, HashMap};

/// Top-level configuration aggregating all security policy rules.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    /// Rules governing HTML structure, elements, and attributes.
    pub html: HtmlPolicy,
    /// Rules governing URL validation, link rewriting, and domain filtering.
    pub urls: UrlPolicy,
    /// Rules governing external sub-resource fetching and size limits.
    pub resources: ResourcePolicy,
}

/// Action to perform when a suspicious link (e.g., untrusted domain or IDN homograph) is detected.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LinkAction {
    /// Completely strip the link attribute/element.
    Remove,
    /// Replace the link target with a warning placeholder string.
    ReplaceWithWarning(String),
    /// Rewrite the target URL (e.g., prepend a safe proxy prefix).
    Rewrite(String),
}

/// Policy governing HTML element filtering, attribute allow-lists, and active content handling.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HtmlPolicy {
    /// Allowed HTML tag names (e.g., `"p"`, `"a"`, `"div"`). All other tags are removed.
    pub allowed_tags: HashSet<String>,
    /// Allowed attributes mapped per tag name (e.g., `"a" => {"href", "title"}`).
    pub allowed_attributes: HashMap<String, HashSet<String>>,
    /// Whether to rewrite active content (e.g., sandboxing iframes) instead of removing outright.
    pub rewrite_active_content: bool,
    /// Disallow `javascript:` pseudo-protocol URIs in `href` and `src` attributes.
    pub block_javascript_uris: bool,
    /// Disallow `data:` inline payload URIs in `href` and `src` attributes.
    pub block_data_uris: bool,
    /// Disallow `<meta http-equiv="refresh">` client-side redirect tags.
    pub block_meta_refresh: bool,
    /// Whitelist of trusted origins allowed inside `<iframe>` and `<object>` elements.
    pub trusted_iframe_origins: HashSet<String>,
}

/// Policy governing link inspection, domain block-lists, and anti-spoofing checks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UrlPolicy {
    /// Hostnames known for malware or phishing; references are dropped or rewritten.
    pub blocked_domains: HashSet<String>,
    /// Hostnames associated with tracking or analytics beacons.
    pub tracker_domains: HashSet<String>,
    /// Enable detection of IDN homograph attacks (e.g., `xn--` punycode spoofing).
    pub check_idn_homographs: bool,
    /// Action executed when a suspicious or blocked link is encountered.
    pub suspicious_link_action: LinkAction,
}

/// Policy governing remote sub-resource fetching, resource limits, and anti-SSRF protections.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourcePolicy {
    /// Maximum recursive depth for downloading linked sub-resources (0 disables fetching).
    pub max_fetch_depth: u8,
    /// Maximum total HTTP requests permitted per input job.
    pub max_requests_per_job: usize,
    /// Maximum byte size permitted for a single downloaded resource (DoS prevention).
    pub max_resource_size_bytes: usize,
    /// Maximum decompressed payload size permitted (compression/XML bomb defense).
    pub max_decompressed_size_bytes: usize,
    /// Network request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Block requests targeting private, link-local, or loopback IPs (SSRF prevention).
    pub block_internal_ips: bool,
    /// Sniff real content bytes using magic numbers to prevent MIME-confusion exploits.
    pub enforce_mime_sniffing: bool,
}

impl Policy {
    /// Creates a balanced default profile suitable for general-purpose web content.
    ///
    /// Permits common formatting tags and links, blocks active scripts/redirects,
    /// checks IDN homographs, and enforces moderate resource download limits.
    pub fn balanced() -> Self {
        let allowed_tags = HashSet::from([
            "p".to_string(), "a".to_string(), "div".to_string(), "span".to_string(),
            "h1".to_string(), "h2".to_string(), "b".to_string(), "i".to_string(),
        ]);

        let mut allowed_attributes = HashMap::new();
        allowed_attributes.insert("a".to_string(), HashSet::from(["href".to_string(), "title".to_string()]));
        allowed_attributes.insert("img".to_string(), HashSet::from(["src".to_string(), "alt".to_string()]));

        Self {
            html: HtmlPolicy {
                allowed_tags,
                allowed_attributes,
                rewrite_active_content: true,
                block_javascript_uris: true,
                block_data_uris: true,
                block_meta_refresh: true,
                trusted_iframe_origins: HashSet::new(),
            },
            urls: UrlPolicy {
                blocked_domains: HashSet::new(),
                tracker_domains: HashSet::new(),
                check_idn_homographs: true,
                suspicious_link_action: LinkAction::ReplaceWithWarning("[REMOVED SUSPICIOUS LINK]".to_string()),
            },
            resources: ResourcePolicy {
                max_fetch_depth: 3,
                max_requests_per_job: 50,
                max_resource_size_bytes: 2 * 1024 * 1024,
                max_decompressed_size_bytes: 10 * 1024 * 1024,
                timeout_ms: 5000,
                block_internal_ips: true,
                enforce_mime_sniffing: true,
            }
        }
    }

    /// Creates a strict profile for highly untrusted inputs (e.g., user comments, emails).
    ///
    /// Restricts HTML to minimal formatting tags, disables external resource fetching entirely,
    /// and drops any suspicious links outright.
    pub fn strict() -> Self {
        let allowed_tags = HashSet::from([
            "p".to_string(), "a".to_string(), "b".to_string(), "i".to_string(), "em".to_string(), "strong".to_string()
        ]);

        let mut allowed_attributes = HashMap::new();
        allowed_attributes.insert("a".to_string(), HashSet::from(["href".to_string()]));

        Self {
            html: HtmlPolicy {
                allowed_tags,
                allowed_attributes,
                rewrite_active_content: false, // directly removes instead of attempting to rewrite
                block_javascript_uris: true,
                block_data_uris: true,
                block_meta_refresh: true,
                trusted_iframe_origins: HashSet::new(), // no iframes
            },
            urls: UrlPolicy {
                blocked_domains: HashSet::new(),
                tracker_domains: HashSet::new(),
                check_idn_homographs: true,
                suspicious_link_action: LinkAction::Remove, // completely removes suspicious links
            },
            resources: ResourcePolicy {
                max_fetch_depth: 0, // no external resource downloads
                max_requests_per_job: 0,
                max_resource_size_bytes: 0,
                max_decompressed_size_bytes: 0,
                timeout_ms: 2000,
                block_internal_ips: true,
                enforce_mime_sniffing: true,
            }
        }
    }

    /// Creates a relaxed profile for semi-trusted inputs (e.g., internal CMS/dashboards).
    ///
    /// Allows rich layout tags (tables, iframes, images), higher resource budgets,
    /// and proxy rewriting for suspicious links.
    pub fn relaxed() -> Self {
        let allowed_tags = HashSet::from([
            "p".to_string(), "a".to_string(), "div".to_string(), "span".to_string(),
            "h1".to_string(), "h2".to_string(), "b".to_string(), "i".to_string(),
            "img".to_string(), "table".to_string(), "tr".to_string(), "td".to_string(), "iframe".to_string()
        ]);

        let mut allowed_attributes = HashMap::new();
        allowed_attributes.insert("a".to_string(), HashSet::from(["href".to_string(), "title".to_string(), "target".to_string()]));
        allowed_attributes.insert("img".to_string(), HashSet::from(["src".to_string(), "alt".to_string(), "width".to_string(), "height".to_string()]));
        allowed_attributes.insert("iframe".to_string(), HashSet::from(["src".to_string(), "width".to_string(), "height".to_string(), "allowfullscreen".to_string()]));

        Self {
            html: HtmlPolicy {
                allowed_tags,
                allowed_attributes,
                rewrite_active_content: true,
                block_javascript_uris: true, // This should always be blocked!
                block_data_uris: false, // Allows data: URIs (e.g. for inline images)
                block_meta_refresh: false, // Allows harmless redirects
                trusted_iframe_origins: HashSet::from(["https://www.youtube.com".to_string(), "https://vimeo.com".to_string()]),
            },
            urls: UrlPolicy {
                blocked_domains: HashSet::new(),
                tracker_domains: HashSet::new(),
                check_idn_homographs: false, // More tolerant with international characters
                suspicious_link_action: LinkAction::Rewrite("https://internal.safelink.proxy?url=".to_string()),
            },
            resources: ResourcePolicy {
                max_fetch_depth: 10,
                max_requests_per_job: 200,
                max_resource_size_bytes: 15 * 1024 * 1024, // 15 MB
                max_decompressed_size_bytes: 50 * 1024 * 1024, // 50 MB
                timeout_ms: 15000,
                block_internal_ips: false, // Might need to fetch resources from the intranet
                enforce_mime_sniffing: false,
            }
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::balanced()
    }
}