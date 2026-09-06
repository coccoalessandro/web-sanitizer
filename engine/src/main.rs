use std::collections::{HashMap, HashSet};

use engine::policy::{HtmlPolicy, Policy, ResourcePolicy, UrlPolicy};
use engine::parser::sanitize_html;

fn main() {
    let mut allowed_tags: HashSet<String> = HashSet::new();
    allowed_tags.insert("a".to_string());
    allowed_tags.insert("p".to_string());
    allowed_tags.insert("div".to_string());

    let mut allowed_attributes = HashMap::new();
    let mut a_attrs = HashSet::new();

    a_attrs.insert("href".to_string());
    allowed_attributes.insert("a".to_string(), a_attrs);
    
    let mut blocked_domains: HashSet<String> = HashSet::new();
    blocked_domains.insert("malware.com".to_string());


    let mut policy = Policy::default();
    policy.html.allowed_tags = allowed_tags;
    policy.html.allowed_attributes = allowed_attributes;
    policy.html.rewrite_active_content = false;
    policy.urls.blocked_domains = blocked_domains;
    policy.urls.check_idn_homographs = false;
    policy.resources.max_fetch_depth = 10;
    policy.resources.max_resource_size_bytes = 2 * 1024 * 1024;
    policy.resources.timeout_ms = 5000;

    let html_sporco = r#"
        <div>
            <p>Questo è un testo sicuro.</p>
            
            <!-- Questo tag dovrebbe essere rimosso -->
            <script>alert('Hacked!');</script>
            
            <!-- Questo link è sicuro e dovrebbe passare intatto -->
            <a href="https://google.com">Link Google</a>
            
            <!-- Questo link ha un attributo non permesso (class) che dovrebbe sparire -->
            <a class="btn-pericoloso" href="https://rust-lang.org">Link Rust</a>
            
            <!-- Questo link punta a un dominio bloccato, l'href dovrebbe sparire -->
            <a href="http://malware.com/virus.exe">Scarica Virus</a>
        </div>
    "#;

    println!("Inizio sanitizzazione...");

    match sanitize_html(html_sporco.as_bytes(), &policy) {
        Ok((html_pulito, report)) => {
            println!("HTML PULITO");
            println!("{:?}", String::from_utf8_lossy(&html_pulito));

            println!("REPORT SANITIZZAZIONE");
            println!("{:?}", report);
        },
        Err(e) => {
            println!("Il parser ha restituito un errore: {}", e);
        }
    }
}