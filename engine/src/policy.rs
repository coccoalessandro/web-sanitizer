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
    // tag consentiti
    pub allowed_tags: HashSet<String>,
    // attributi consentiti per ogni tag
    pub allowed_attributes: HashMap<String, HashSet<String>>,
    // se true, riscrive i contenuti attivi
    pub rewrite_active_content: bool,
    // previene javascript: negli attributi href/src
    pub block_javascript_uris: bool,
    // previene data: negli attributi href/src (spesso usati per payload maligni)
    pub block_data_uris: bool,
    // blocca redirect meta-refresh
    pub block_meta_refresh: bool,
    // origini consentite per iframe e object
    pub trusted_iframe_origins: HashSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UrlPolicy {
    // domini noti per malware
    pub blocked_domains: HashSet<String>,
    // domini di tracciamento
    pub tracker_domains: HashSet<String>,
    // applica controlli per attacchi IDN homograph (Unicode normalization confusion)
    pub check_idn_homographs: bool,
    // azione da eseguire quando si incontra un link sospetto
    pub suspicious_link_action: LinkAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourcePolicy {
    // profondità massima per scaricare risorse annidate
    pub max_fetch_depth: u8,
    // numero massimo di richieste per singolo input
    pub max_requests_per_job: usize,
    // limite massimo in bytes per scaricare una singola risorsa (DoS protection)
    pub max_resource_size_bytes: usize,
    // limite di decompressione per evitare compression/XML bombs (DoS protection)
    pub max_decompressed_size_bytes: usize,
    pub timeout_ms: u64,
    // previene SSRF (Server-Side Request Forgery) bloccando IP locali
    pub block_internal_ips: bool,
    // verifica il tipo di contenuto reale (sniffing) per evitare MIME confusion
    pub enforce_mime_sniffing: bool,
}

impl Policy {
    /// Profilo bilanciato (Standard) - utile per la maggior parte dei casi
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

    /// Profilo restrittivo (Strict) - per input altamente non attendibili (es. commenti pubblici)
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
                rewrite_active_content: false, // rimuove direttamente invece di tentare di riscrivere
                block_javascript_uris: true,
                block_data_uris: true,
                block_meta_refresh: true,
                trusted_iframe_origins: HashSet::new(), // nessun iframe
            },
            urls: UrlPolicy {
                blocked_domains: HashSet::new(),
                tracker_domains: HashSet::new(),
                check_idn_homographs: true,
                suspicious_link_action: LinkAction::Remove, // Rimuove i link sospetti del tutto
            },
            resources: ResourcePolicy {
                max_fetch_depth: 0, // Nessun download di risorse esterne
                max_requests_per_job: 0,
                max_resource_size_bytes: 0,
                max_decompressed_size_bytes: 0,
                timeout_ms: 2000,
                block_internal_ips: true,
                enforce_mime_sniffing: true,
            }
        }
    }

    /// Profilo rilassato (Relaxed) - per input semi-attendibili (es. dashboard interne)
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
                block_javascript_uris: true, // Questo va bloccato sempre!
                block_data_uris: false, // Permette data: URIs (es. per immagini inline)
                block_meta_refresh: false, // Permette i redirect innocui
                trusted_iframe_origins: HashSet::from(["https://www.youtube.com".to_string(), "https://vimeo.com".to_string()]),
            },
            urls: UrlPolicy {
                blocked_domains: HashSet::new(),
                tracker_domains: HashSet::new(),
                check_idn_homographs: false, // Più tollerante con i caratteri internazionali
                suspicious_link_action: LinkAction::Rewrite("https://internal.safelink.proxy?url=".to_string()),
            },
            resources: ResourcePolicy {
                max_fetch_depth: 10,
                max_requests_per_job: 200,
                max_resource_size_bytes: 15 * 1024 * 1024, // 15 MB
                max_decompressed_size_bytes: 50 * 1024 * 1024, // 50 MB
                timeout_ms: 15000,
                block_internal_ips: false, // Potrebbe dover fetchare risorse dalla intranet
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