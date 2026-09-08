use serde::{Serialize, Deserialize};
use std::collections::{HashSet, HashMap};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    pub html: HtmlPolicy,
    pub urls: UrlPolicy,
    pub resources: ResourcePolicy
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LinkAction {
    Remove,
    ReplaceWithWarning(String),
    Rewrite(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HtmlPolicy {
    // allowed tags
    pub allowed_tags: HashSet<String>,
    // allowed attributes for each tag
    pub allowed_attributes: HashMap<String, HashSet<String>>,
    // if true, rewrites active content
    pub rewrite_active_content: bool,
    // prevents javascript: in href/src attributes
    pub block_javascript_uris: bool,
    // prevents data: in href/src attributes (often used for malicious payloads)
    pub block_data_uris: bool,
    // blocks meta-refresh redirects
    pub block_meta_refresh: bool,
    // allowed origins for iframe and object
    pub trusted_iframe_origins: HashSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UrlPolicy {
    // domains known for malware
    pub blocked_domains: HashSet<String>,
    // tracking domains
    pub tracker_domains: HashSet<String>,
    // apply checks for IDN homograph attacks (Unicode normalization confusion)
    pub check_idn_homographs: bool,
    // action to take when a suspicious link is encountered
    pub suspicious_link_action: LinkAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourcePolicy {
    // maximum depth to download nested resources
    pub max_fetch_depth: u8,
    // maximum number of requests per single input
    pub max_requests_per_job: usize,
    // maximum byte limit to download a single resource (DoS protection)
    pub max_resource_size_bytes: usize,
    // decompression limit to avoid compression/XML bombs (DoS protection)
    pub max_decompressed_size_bytes: usize,
    pub timeout_ms: u64,
    // prevents SSRF (Server-Side Request Forgery) by blocking local IPs
    pub block_internal_ips: bool,
    // verify real content type (sniffing) to avoid MIME confusion
    pub enforce_mime_sniffing: bool,
}

impl Policy {
    /// Balanced profile (Standard) - useful for most cases
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

    /// Strict profile (Strict) - for highly untrusted inputs (e.g. public comments)
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

    /// Relaxed profile (Relaxed) - for semi-trusted inputs (e.g. internal dashboards)
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