use std::collections::HashMap;
use std::time::Duration;
use std::io::Read;
use ureq;

use crate::policy::ResourcePolicy;

pub fn fetch_resources(urls: &[String], resource_policy: &ResourcePolicy) -> Result<HashMap<String, Vec<u8>>, String> {

    let mut downloaded_files: HashMap<String, Vec<u8>> = HashMap::new();

    // agente http con ureq
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_millis(resource_policy.timeout_ms)).build();
    
    for url in urls {

        let parsed_url = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => continue
        };

        // SSRF check: block the requests to private/local IPs
        if let Some(host) = parsed_url.host() {
            match host {
                url::Host::Ipv4(ip) => {
                    if ip.is_loopback() || ip.is_private() || ip.is_link_local() {
                        continue; // skip this URL because private/local/loopback
                    }
                }
                url::Host::Ipv6(ip) => {
                    if ip.is_loopback() {
                        continue;
                    }
                }
                url::Host::Domain(domain) => {
                    if domain == "localhost" {
                        continue;
                    }
                }
            }
        }

        let response = agent.get(url).call();

        match response {
            Ok(r) => {
                // controllo del campo Content-Length nell'header
                if let Some(content_length) = r.header("Content-Length") {
                    if let Ok(parsed_content_length) = content_length.parse::<usize>() {
                        if parsed_content_length > resource_policy.max_resource_size_bytes {
                            continue;
                        }
                    }   
                }
                let mut reader = r.into_reader().take(resource_policy.max_resource_size_bytes as u64);

                // scarico i bytes
                let mut vec_bytes: Vec<u8> = Vec::new();

                let _ = reader.read_to_end(&mut vec_bytes);

                downloaded_files.insert(url.to_string(), vec_bytes);

            },
            Err(_) => {
                continue;
            } 
        }
    }

    Ok(downloaded_files)

}