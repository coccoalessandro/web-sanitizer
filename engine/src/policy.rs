use std::collections::{HashSet, HashMap};

pub struct Policy {
    pub html: HtmlPolicy,
    pub urls: UrlPolicy,
    pub resources: ResourcePolicy
}

pub struct HtmlPolicy {
    
    // lista dei tag consentiti
    pub allowed_tags: HashSet<String>,

    // mappa che definisce per ogni tag quali sono gli attributi consentiti
    pub allowed_attributes: HashMap<String, HashSet<String>>,

    // se true, converte <script> e gli elementi sospetti
    pub rewrite_active_content: bool
}

pub struct UrlPolicy {
    
    // domini noti per malware o tracking
    pub blocked_domains: HashSet<String>,

    // se true, applica controlli per evitare attacchi IDN homograph
    pub check_idn_homographs: bool
}

pub struct ResourcePolicy {
    
    // profondità massima per scaricare risorse annidate
    pub max_fetch_depth: u8,

    // limite massimo in bytes per scaricare una singola risorsa
    pub max_resource_size_bytes: usize,

    pub timeout_ms: u64
}


impl Default for Policy {
    fn default() -> Self {

        let allowed_tags = HashSet::from([
                "p".to_string(),
                "a".to_string()
            ]);

        let mut allowed_attributes: HashMap<String, HashSet<String>> = HashMap::new();
            allowed_attributes.insert(
                "a".to_string(),
                HashSet::from(["href".to_string()])
            );

        let html = HtmlPolicy {
            allowed_tags: allowed_tags,
            allowed_attributes: allowed_attributes,
            rewrite_active_content: true
        };

        let urls = UrlPolicy {
            blocked_domains: HashSet::new(),
            check_idn_homographs: true
        };

        let resources = ResourcePolicy {
            max_fetch_depth: 10,
            max_resource_size_bytes: 2 * 1024 * 1024, // 2 MB
            timeout_ms: 5000
        };

        Self {
            html, urls, resources
        }
        
    }
}