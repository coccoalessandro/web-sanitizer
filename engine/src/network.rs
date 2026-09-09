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