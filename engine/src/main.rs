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

    let dirty_html = r#"
        <div>
            <p>This is a safe text.</p>
            
            <!-- This tag should be removed -->
            <script>alert('Hacked!');</script>
            
            <!-- This link is safe and should pass intact -->
            <a href="https://google.com">Google Link</a>
            
            <!-- This link has an unpermitted attribute (class) that should disappear -->
            <a class="btn-dangerous" href="https://rust-lang.org">Rust Link</a>
            
            <!-- This link points to a blocked domain, the href should disappear -->
            <a href="http://malware.com/virus.exe">Download Virus</a>
        </div>
    "#;

    println!("Starting sanitization...");

    match sanitize_html(dirty_html.as_bytes(), &policy) {
        Ok((clean_html, report)) => {
            println!("CLEAN HTML");
            println!("{:?}", String::from_utf8_lossy(&clean_html));

            println!("SANITIZATION REPORT");
            println!("{:?}", report);
        },
        Err(e) => {
            println!("The parser returned an error: {}", e);
        }
    }
}