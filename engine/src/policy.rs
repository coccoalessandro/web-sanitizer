//! Security policies and configuration profiles for the sanitization engine.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

fn default_true() -> bool {
    true
}

fn default_max_image_pixels() -> usize {
    50_000_000 // 50 Megapixels
}

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
    /// Sanitize inline `style="..."` attributes (stripping `expression`, dangerous `url()`, etc.)
    #[serde(default = "default_true")]
    pub sanitize_inline_styles: bool,
    /// Sanitize `<style>` tag contents
    #[serde(default = "default_true")]
    pub sanitize_style_tags: bool,
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
    /// Detect Unicode normalization Host-Split characters (e.g. fullwidth slash, commercial at, etc.)
    #[serde(default = "default_true")]
    pub check_unicode_host_split: bool,
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
    /// Maximum pixel count for images before rejecting as decompression pixel bombs.
    #[serde(default = "default_max_image_pixels")]
    pub max_image_pixels: usize,
    /// Block documents with active content (e.g. JavaScript in PDF/SVG).
    #[serde(default = "default_true")]
    pub block_active_documents: bool,
    /// Resolve domain names to verify they do not point to internal/private IPs.
    #[serde(default = "default_true")]
    pub resolve_dns_for_ssrf: bool,
    /// Network request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Block requests targeting private, link-local, or loopback IPs (SSRF prevention).
    pub block_internal_ips: bool,
    /// Internal hosts explicitly trusted despite the SSRF guard (e.g. a local test origin
    /// such as `localhost`). Matched case-insensitively against the URL host, without port.
    /// Every other internal address stays blocked.
    #[serde(default)]
    pub trusted_internal_hosts: HashSet<String>,
    /// Sniff real content bytes using magic numbers to prevent MIME-confusion exploits.
    pub enforce_mime_sniffing: bool,
}

impl Policy {
    /// Creates a balanced default profile suitable for general-purpose web content.
    pub fn balanced() -> Self {
        let allowed_tags = HashSet::from([
            // Document structure carries no active behaviour; its attributes are still
            // filtered (none are allowed), e.g. <body onload> loses the handler.
            "html".to_string(),
            "head".to_string(),
            "body".to_string(),
            "p".to_string(),
            "a".to_string(),
            "div".to_string(),
            "span".to_string(),
            "h1".to_string(),
            "h2".to_string(),
            "h3".to_string(),
            "b".to_string(),
            "i".to_string(),
            "em".to_string(),
            "strong".to_string(),
            "code".to_string(),
            "pre".to_string(),
            "blockquote".to_string(),
            "ul".to_string(),
            "ol".to_string(),
            "li".to_string(),
            "img".to_string(),
            "style".to_string(),
        ]);

        let mut allowed_attributes = HashMap::new();
        allowed_attributes.insert(
            "a".to_string(),
            HashSet::from(["href".to_string(), "title".to_string()]),
        );
        allowed_attributes.insert(
            "img".to_string(),
            HashSet::from(["src".to_string(), "alt".to_string()]),
        );
        allowed_attributes.insert(
            "div".to_string(),
            HashSet::from(["class".to_string(), "style".to_string()]),
        );
        allowed_attributes.insert(
            "span".to_string(),
            HashSet::from(["class".to_string(), "style".to_string()]),
        );
        allowed_attributes.insert(
            "p".to_string(),
            HashSet::from(["class".to_string(), "style".to_string()]),
        );
        allowed_attributes.insert(
            "h1".to_string(),
            HashSet::from(["class".to_string(), "style".to_string()]),
        );
        allowed_attributes.insert(
            "h2".to_string(),
            HashSet::from(["class".to_string(), "style".to_string()]),
        );
        allowed_attributes.insert(
            "h3".to_string(),
            HashSet::from(["class".to_string(), "style".to_string()]),
        );

        Self {
            html: HtmlPolicy {
                allowed_tags,
                allowed_attributes,
                rewrite_active_content: true,
                block_javascript_uris: true,
                block_data_uris: true,
                block_meta_refresh: true,
                trusted_iframe_origins: HashSet::new(),
                sanitize_inline_styles: true,
                sanitize_style_tags: true,
            },
            urls: UrlPolicy {
                blocked_domains: HashSet::from([
                    "malware.com".to_string(),
                    "malware-test.com".to_string(),
                ]),
                tracker_domains: HashSet::from([
                    "tracking-beacon.com".to_string(),
                    "tracker.com".to_string(),
                ]),
                check_idn_homographs: true,
                check_unicode_host_split: true,
                suspicious_link_action: LinkAction::ReplaceWithWarning(
                    "[REMOVED SUSPICIOUS LINK]".to_string(),
                ),
            },
            resources: ResourcePolicy {
                max_fetch_depth: 3,
                max_requests_per_job: 50,
                max_resource_size_bytes: 2 * 1024 * 1024,
                max_decompressed_size_bytes: 10 * 1024 * 1024,
                max_image_pixels: 50_000_000,
                block_active_documents: true,
                resolve_dns_for_ssrf: true,
                timeout_ms: 5000,
                block_internal_ips: true,
                trusted_internal_hosts: HashSet::new(),
                enforce_mime_sniffing: true,
            },
        }
    }

    /// Creates a strict profile for highly untrusted inputs (e.g., user comments, emails).
    pub fn strict() -> Self {
        let allowed_tags = HashSet::from([
            // Document structure carries no active behaviour; its attributes are still
            // filtered (none are allowed), e.g. <body onload> loses the handler.
            "html".to_string(),
            "head".to_string(),
            "body".to_string(),
            "p".to_string(),
            "a".to_string(),
            "b".to_string(),
            "i".to_string(),
            "em".to_string(),
            "strong".to_string(),
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
                sanitize_inline_styles: true,
                sanitize_style_tags: true,
            },
            urls: UrlPolicy {
                blocked_domains: HashSet::from([
                    "malware.com".to_string(),
                    "malware-test.com".to_string(),
                ]),
                tracker_domains: HashSet::from([
                    "tracking-beacon.com".to_string(),
                    "tracker.com".to_string(),
                ]),
                check_idn_homographs: true,
                check_unicode_host_split: true,
                suspicious_link_action: LinkAction::Remove, // completely removes suspicious links
            },
            resources: ResourcePolicy {
                max_fetch_depth: 0, // no external resource downloads
                max_requests_per_job: 0,
                max_resource_size_bytes: 0,
                max_decompressed_size_bytes: 0,
                max_image_pixels: 10_000_000,
                block_active_documents: true,
                resolve_dns_for_ssrf: true,
                timeout_ms: 2000,
                block_internal_ips: true,
                trusted_internal_hosts: HashSet::new(),
                enforce_mime_sniffing: true,
            },
        }
    }

    /// Creates a relaxed profile for semi-trusted inputs (e.g., internal CMS/dashboards).
    pub fn relaxed() -> Self {
        let allowed_tags = HashSet::from([
            // Document structure carries no active behaviour; its attributes are still
            // filtered (none are allowed), e.g. <body onload> loses the handler.
            "html".to_string(),
            "head".to_string(),
            "body".to_string(),
            "p".to_string(),
            "a".to_string(),
            "div".to_string(),
            "span".to_string(),
            "h1".to_string(),
            "h2".to_string(),
            "b".to_string(),
            "i".to_string(),
            "img".to_string(),
            "table".to_string(),
            "tr".to_string(),
            "td".to_string(),
            "iframe".to_string(),
            "style".to_string(),
        ]);

        let mut allowed_attributes = HashMap::new();
        allowed_attributes.insert(
            "a".to_string(),
            HashSet::from([
                "href".to_string(),
                "title".to_string(),
                "target".to_string(),
            ]),
        );
        allowed_attributes.insert(
            "img".to_string(),
            HashSet::from([
                "src".to_string(),
                "alt".to_string(),
                "width".to_string(),
                "height".to_string(),
            ]),
        );
        allowed_attributes.insert(
            "iframe".to_string(),
            HashSet::from([
                "src".to_string(),
                "width".to_string(),
                "height".to_string(),
                "allowfullscreen".to_string(),
            ]),
        );
        allowed_attributes.insert(
            "div".to_string(),
            HashSet::from(["class".to_string(), "style".to_string()]),
        );
        allowed_attributes.insert(
            "span".to_string(),
            HashSet::from(["class".to_string(), "style".to_string()]),
        );

        Self {
            html: HtmlPolicy {
                allowed_tags,
                allowed_attributes,
                rewrite_active_content: true,
                block_javascript_uris: true,
                block_data_uris: false, // Allows data: URIs (e.g. for inline images)
                block_meta_refresh: false, // Allows harmless redirects
                trusted_iframe_origins: HashSet::from([
                    "https://www.youtube.com".to_string(),
                    "https://vimeo.com".to_string(),
                ]),
                sanitize_inline_styles: true,
                sanitize_style_tags: true,
            },
            urls: UrlPolicy {
                blocked_domains: HashSet::new(),
                tracker_domains: HashSet::new(),
                check_idn_homographs: false,
                check_unicode_host_split: true,
                suspicious_link_action: LinkAction::Rewrite(
                    "https://internal.safelink.proxy?url=".to_string(),
                ),
            },
            resources: ResourcePolicy {
                max_fetch_depth: 10,
                max_requests_per_job: 200,
                max_resource_size_bytes: 15 * 1024 * 1024,
                max_decompressed_size_bytes: 50 * 1024 * 1024,
                max_image_pixels: 100_000_000,
                block_active_documents: false,
                resolve_dns_for_ssrf: false, // Intranet fetching allowed in relaxed
                timeout_ms: 15000,
                block_internal_ips: false,
                trusted_internal_hosts: HashSet::new(),
                enforce_mime_sniffing: false,
            },
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::balanced()
    }
}
