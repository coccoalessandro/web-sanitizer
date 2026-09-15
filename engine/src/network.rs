//! Safe embedded resource fetcher with SSRF prevention and content sniffing defenses.
//!
//! Features:
//! - SSRF prevention: blocks private, loopback, link-local IPs and localhost.
//! - MIME confusion defense: sniffs payload bytes with [`infer`] to detect executable binaries.
//! - Resource limits: enforces timeout, content-length limits, streaming byte caps, and recursion depth.

use std::collections::{HashMap, HashSet};
use std::time::Duration;
use std::io::Read;
use ureq;

use crate::policy::Policy;

/// Recursively downloads and sanitizes embedded web resources up to `policy.resources.max_fetch_depth`.
///
/// Applies SSRF filtering on hosts, enforces maximum byte downloads, validates actual MIME types
/// against executable payloads, and recursively sanitizes nested HTML resources.
///
/// Returns a map of `(URL -> sanitized or raw bytes)`.
pub fn fetch_resources(
    urls: &[String], 
    policy: &Policy,
    current_depth: u8,
    visited: &mut HashSet<String>
) -> Result<HashMap<String, Vec<u8>>, String> {

    if current_depth > policy.resources.max_fetch_depth {
        return Ok(HashMap::new());
    }

    let mut downloaded_files: HashMap<String, Vec<u8>> = HashMap::new();

    // http agent with ureq
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_millis(policy.resources.timeout_ms)).build();
    
    for url in urls {
        if visited.contains(url) {
            continue;
        }

        if visited.len() >= policy.resources.max_requests_per_job {
            break;
        }

        visited.insert(url.clone());

        let parsed_url = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => continue
        };

        // SSRF check: block the requests to private/local IPs
        if policy.resources.block_internal_ips {
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
        }

        let response = agent.get(url).call();

        match response {
            Ok(r) => {
                // check Content-Length field in the header
                if let Some(content_length) = r.header("Content-Length") {
                    if let Ok(parsed_content_length) = content_length.parse::<usize>() {
                        if parsed_content_length > policy.resources.max_resource_size_bytes {
                            continue;
                        }
                    }   
                }
                let mut reader = r.into_reader().take(policy.resources.max_resource_size_bytes as u64);

                // download bytes
                let mut vec_bytes: Vec<u8> = Vec::new();

                let _ = reader.read_to_end(&mut vec_bytes);

                // MIME confusion
                let mut should_block = false;
                if let Some(kind) = infer::get(&vec_bytes) {
                    let real_mime = kind.mime_type();

                    if real_mime.starts_with("application/x-dosexec") // .exe Windows
                    || real_mime.starts_with("application/x-executable") // Linux/Mac
                    || real_mime.starts_with("applicatio/x-sh") // shell script
                    { 
                        should_block = true;
                    }
                }

                if should_block {
                    continue;
                }

                let mut is_html = false;
                if let Some(kind) = infer::get(&vec_bytes) {
                    if kind.mime_type() == "text/html" {
                        is_html = true;
                    }
                } else if url.ends_with(".html") || url.ends_with(".htm") {
                    is_html = true;
                }

                if is_html {
                    if let Ok((sanitized, report)) = crate::parser::sanitize_html(&vec_bytes, policy) {
                        downloaded_files.insert(url.to_string(), sanitized);
                        
                        let sub_resources = fetch_resources(&report.resources_to_fetch, policy, current_depth + 1, visited).unwrap_or_default();
                        downloaded_files.extend(sub_resources);
                    } else {
                        downloaded_files.insert(url.to_string(), vec_bytes);
                    }
                } else {
                    downloaded_files.insert(url.to_string(), vec_bytes);
                }
            },
            Err(_) => {
                continue;
            } 
        }
    }

    Ok(downloaded_files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::TcpListener;
    use std::io::Write;

    fn setup_network_policy() -> Policy {
        let mut policy = Policy::balanced();
        policy.resources.max_requests_per_job = 10;
        policy.resources.max_fetch_depth = 1;
        policy.resources.max_resource_size_bytes = 1024;
        policy
    }

    // 1. SSRF Test
    #[test]
    fn test_ssrf_prevention_blocks() {
        let policy = setup_network_policy();

        let malicious_urls = vec![
            "http://127.0.0.1/admin-panel".to_string(), // Loopback
            "http://localhost:8080/secret".to_string(), // Localhost string
            "http://10.0.0.1/db".to_string(),           // Private Class A
            "http://192.168.1.254/router".to_string(),  // Private Class C
        ];

        let mut visited = HashSet::new();
        let results = fetch_resources(&malicious_urls, &policy, 0, &mut visited).unwrap();

        assert!(results.is_empty());
    }

    // 2. DoS Test
    #[test]
    fn test_dos_prevention_content_length() {
        let mut policy = setup_network_policy();
        policy.resources.block_internal_ips = false; 
        policy.resources.max_resource_size_bytes = 50; 

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let malicious_response = b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\nEcco il file";
                let _ = stream.write_all(malicious_response);
            }
        });

        let target_url = format!("http://127.0.0.1:{}/huge_file.zip", port);
        
        let mut visited = HashSet::new();
        let results = fetch_resources(&[target_url], &policy, 0, &mut visited).unwrap();

        assert!(results.is_empty());
    }


    // 3. MIME Sniffing Test
    #[test]
    fn test_mime_sniffing_blocks() {
        let mut policy = setup_network_policy();
        policy.resources.block_internal_ips = false;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                
                let mut fake_payload = vec![0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01];
                fake_payload.extend(vec![0; 50]); 

                let headers = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", fake_payload.len());
                let mut response = headers.into_bytes();
                response.extend(fake_payload);

                let _ = stream.write_all(&response);
            }
        });

        let target_url = format!("http://127.0.0.1:{}/malware", port);
        
        let mut visited = HashSet::new();
        let results = fetch_resources(&[target_url], &policy, 0, &mut visited).unwrap();

        
        assert!(results.is_empty());
    }
}