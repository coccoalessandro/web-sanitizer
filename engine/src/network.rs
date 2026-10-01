//! Safe embedded resource fetcher with SSRF prevention and content sniffing defenses.
//!
//! Features:
//! - SSRF prevention: blocks private, loopback, link-local, broadcast, unspecified IPs, and resolves domain DNS.
//! - MIME confusion defense: sniffs payload bytes with [`infer`] to detect executable binaries.
//! - Asset-specific sanitization:
//!   - Recursively parses and sanitizes nested HTML.
//!   - Sanitizes fetched CSS stylesheets.
//!   - Inspects and sanitizes SVG images (neutralizing scripts and XML entity bombs).
//!   - Inspects PDF documents for embedded JavaScript.
//!   - Validates image dimensions against pixel-flood decompression bombs.
//! - Resource limits: enforces timeout, content-length limits, streaming byte caps, and recursion depth.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::time::Duration;
use ureq;
use url::Url;

use crate::active_content::{check_image_dimensions, inspect_and_sanitize_svg, inspect_pdf};
use crate::css::sanitize_css;
use crate::policy::Policy;

/// Recursively downloads and sanitizes embedded web resources up to `policy.resources.max_fetch_depth`.
///
/// Applies SSRF filtering on hosts, enforces maximum byte downloads, validates actual MIME types
/// against executable payloads, and recursively sanitizes nested HTML, CSS, SVG, PDF, and image resources.
///
/// Returns a map of `(URL -> sanitized bytes)`.
pub fn fetch_resources(
    urls: &[String],
    policy: &Policy,
    current_depth: u8,
    visited: &mut HashSet<String>,
) -> Result<HashMap<String, Vec<u8>>, String> {
    fetch_resources_with_cache(urls, policy, current_depth, visited, None)
}

/// Recursively downloads and sanitizes embedded web resources with an optional in-memory cache lookup.
pub fn fetch_resources_with_cache(
    urls: &[String],
    policy: &Policy,
    current_depth: u8,
    visited: &mut HashSet<String>,
    cache: Option<&HashMap<String, Vec<u8>>>,
) -> Result<HashMap<String, Vec<u8>>, String> {
    if current_depth > policy.resources.max_fetch_depth {
        return Ok(HashMap::new());
    }

    let mut downloaded_files: HashMap<String, Vec<u8>> = HashMap::new();

    // HTTP agent with timeout
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_millis(policy.resources.timeout_ms))
        .build();

    for url in urls {
        if visited.contains(url) {
            continue;
        }

        if visited.len() >= policy.resources.max_requests_per_job {
            break;
        }

        visited.insert(url.clone());

        // Cache hit check
        if let Some(cached_data) = cache.and_then(|c| c.get(url)) {
            downloaded_files.insert(url.clone(), cached_data.clone());
            continue;
        }

        let parsed_url = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => continue,
        };

        // Scheme check: only allow http and https for sub-resources
        if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
            continue;
        }

        // Domain block-list & IDN homograph checks
        if let Some(host_str) = parsed_url.host_str()
            && (policy.urls.blocked_domains.contains(host_str)
                || policy.urls.tracker_domains.contains(host_str)
                || (policy.urls.check_idn_homographs && host_str.starts_with("xn--")))
        {
            continue;
        }

        // SSRF check: block requests to private, loopback, or local IPs
        if policy.resources.block_internal_ips
            && is_ssrf_host(&parsed_url, policy.resources.resolve_dns_for_ssrf)
        {
            continue;
        }

        let response = agent.get(url).call();

        match response {
            Ok(r) => {
                // Check Content-Length field in the header
                if let Some(content_length) = r.header("Content-Length")
                    && let Ok(parsed_content_length) = content_length.parse::<usize>()
                    && parsed_content_length > policy.resources.max_resource_size_bytes
                {
                    continue;
                }

                // Streaming limit: cap decompressed download stream
                let mut reader = r
                    .into_reader()
                    .take(policy.resources.max_decompressed_size_bytes as u64);
                let mut vec_bytes: Vec<u8> = Vec::new();
                if reader.read_to_end(&mut vec_bytes).is_err() {
                    continue;
                }

                if vec_bytes.len() > policy.resources.max_resource_size_bytes {
                    continue;
                }

                // MIME sniffing & executable payload prevention
                let inferred_mime = infer::get(&vec_bytes).map(|k| k.mime_type());
                if policy.resources.enforce_mime_sniffing
                    && let Some(real_mime) = inferred_mime
                    && (real_mime.starts_with("application/x-dosexec")
                        || real_mime.starts_with("application/x-executable")
                        || real_mime.starts_with("application/x-mach-binary")
                        || real_mime.starts_with("application/x-sh"))
                {
                    continue; // Block executable payload
                }

                // PER-TYPE ASSET SANITIZATION
                let mime_str = inferred_mime.unwrap_or("");
                let url_lower = url.to_ascii_lowercase();

                // 1. HTML Sub-Resource
                let is_html = mime_str == "text/html"
                    || url_lower.ends_with(".html")
                    || url_lower.ends_with(".htm");

                if is_html {
                    if let Ok((sanitized, report)) =
                        crate::parser::sanitize_html(&vec_bytes, policy)
                    {
                        downloaded_files.insert(url.to_string(), sanitized);

                        let sub_resources = fetch_resources_with_cache(
                            &report.resources_to_fetch,
                            policy,
                            current_depth + 1,
                            visited,
                            cache,
                        )
                        .unwrap_or_default();
                        downloaded_files.extend(sub_resources);
                    } else {
                        downloaded_files.insert(url.to_string(), vec_bytes);
                    }
                    continue;
                }

                // 2. CSS Stylesheet Sub-Resource
                let is_css = mime_str == "text/css" || url_lower.ends_with(".css");
                if is_css {
                    let css_text = String::from_utf8_lossy(&vec_bytes);
                    let (sanitized_css, _actions) = sanitize_css(&css_text, policy);
                    downloaded_files.insert(url.to_string(), sanitized_css.into_bytes());
                    continue;
                }

                // 3. SVG Vector Image Sub-Resource
                let is_svg = mime_str == "image/svg+xml"
                    || url_lower.ends_with(".svg")
                    || vec_bytes.starts_with(b"<svg")
                    || (vec_bytes.len() > 10
                        && String::from_utf8_lossy(&vec_bytes[..50.min(vec_bytes.len())])
                            .contains("<svg"));

                if is_svg {
                    let (sanitized_svg, _actions, blocked) =
                        inspect_and_sanitize_svg(&vec_bytes, policy);
                    if !blocked {
                        downloaded_files.insert(url.to_string(), sanitized_svg);
                    }
                    continue;
                }

                // 4. PDF Document Sub-Resource
                let is_pdf = mime_str == "application/pdf" || vec_bytes.starts_with(b"%PDF-");
                if is_pdf {
                    if policy.resources.block_active_documents {
                        let pdf_check = inspect_pdf(&vec_bytes);
                        if pdf_check.is_threat_detected {
                            // Block PDF containing active JavaScript
                            continue;
                        }
                    }
                    downloaded_files.insert(url.to_string(), vec_bytes);
                    continue;
                }

                // 5. Bitmap Images: PNG, GIF, JPEG, WebP - Decompression Bomb Defense
                let is_raster_image = mime_str.starts_with("image/")
                    || url_lower.ends_with(".png")
                    || url_lower.ends_with(".jpg")
                    || url_lower.ends_with(".jpeg")
                    || url_lower.ends_with(".gif")
                    || url_lower.ends_with(".webp");

                if is_raster_image
                    && check_image_dimensions(&vec_bytes, policy.resources.max_image_pixels)
                        .is_err()
                {
                    // Image pixel flood / decompression bomb detected
                    continue;
                }

                // Clean binary asset accepted
                downloaded_files.insert(url.to_string(), vec_bytes);
            }
            Err(_) => {
                continue;
            }
        }
    }

    Ok(downloaded_files)
}

/// Checks if a parsed URL targets internal, private, loopback, or non-routable IPs (SSRF defense).
pub fn is_ssrf_host(url: &Url, resolve_dns: bool) -> bool {
    let host = match url.host() {
        Some(h) => h,
        None => return true,
    };

    match host {
        url::Host::Ipv4(ip) => is_internal_ipv4(&ip),
        url::Host::Ipv6(ip) => is_internal_ipv6(&ip),
        url::Host::Domain(domain) => {
            let d_lower = domain.to_ascii_lowercase();
            if d_lower == "localhost"
                || d_lower.ends_with(".localhost")
                || d_lower.ends_with(".local")
                || d_lower.ends_with(".internal")
            {
                return true;
            }

            if resolve_dns {
                let port = url.port_or_known_default().unwrap_or(80);
                if let Ok(addrs) = (domain, port).to_socket_addrs() {
                    for addr in addrs {
                        match addr.ip() {
                            IpAddr::V4(ip) => {
                                if is_internal_ipv4(&ip) {
                                    return true;
                                }
                            }
                            IpAddr::V6(ip) => {
                                if is_internal_ipv6(&ip) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }

            false
        }
    }
}

/// Identifies internal, private, loopback, broadcast, or non-routable IPv4 addresses.
pub fn is_internal_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();

    ip.is_loopback() // 127.0.0.0/8
        || ip.is_private() // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || ip.is_link_local() // 169.254.0.0/16
        || ip.is_unspecified() // 0.0.0.0
        || ip.is_broadcast() // 255.255.255.255
        || ip.is_documentation() // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        // Carrier-Grade NAT (CGNAT) 100.64.0.0/10
        || (octets[0] == 100 && (octets[1] & 0xC0) == 64)
        // Multicast 224.0.0.0/4
        || ip.is_multicast()
}

/// Identifies internal, private, loopback, or non-routable IPv6 addresses.
pub fn is_internal_ipv6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }

    // Check for IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_internal_ipv4(&ipv4);
    }

    let segments = ip.segments();
    // Unique Local Address fc00::/7
    if (segments[0] & 0xFE00) == 0xFC00 {
        return true;
    }
    // Link-Local Unicast fe80::/10
    if (segments[0] & 0xFFC0) == 0xFE80 {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::io::Write;
    use std::net::TcpListener;

    fn setup_network_policy() -> Policy {
        let mut policy = Policy::balanced();
        policy.resources.max_requests_per_job = 10;
        policy.resources.max_fetch_depth = 1;
        policy.resources.max_resource_size_bytes = 1024;
        policy
    }

    #[test]
    fn test_ssrf_prevention_blocks() {
        let policy = setup_network_policy();

        let malicious_urls = vec![
            "http://127.0.0.1/admin-panel".to_string(),
            "http://localhost:8080/secret".to_string(),
            "http://10.0.0.1/db".to_string(),
            "http://192.168.1.254/router".to_string(),
            "http://169.254.169.254/latest/meta-data".to_string(), // AWS IMDS
            "http://0.0.0.0/root".to_string(),
            "http://[::1]/secret".to_string(),
        ];

        let mut visited = HashSet::new();
        let results = fetch_resources(&malicious_urls, &policy, 0, &mut visited).unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn test_dos_prevention_content_length() {
        let mut policy = setup_network_policy();
        policy.resources.block_internal_ips = false;
        policy.resources.max_resource_size_bytes = 50;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let malicious_response =
                    b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\nLarge payload";
                let _ = stream.write_all(malicious_response);
            }
        });

        let target_url = format!("http://127.0.0.1:{}/huge_file.zip", port);

        let mut visited = HashSet::new();
        let results = fetch_resources(&[target_url], &policy, 0, &mut visited).unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn test_mime_sniffing_blocks() {
        let mut policy = setup_network_policy();
        policy.resources.block_internal_ips = false;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut fake_payload = vec![0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01]; // ELF binary
                fake_payload.extend(vec![0; 50]);

                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    fake_payload.len()
                );
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

    #[test]
    fn test_internal_ip_detection() {
        assert!(is_internal_ipv4(&"127.0.0.1".parse().unwrap()));
        assert!(is_internal_ipv4(&"10.200.1.5".parse().unwrap()));
        assert!(is_internal_ipv4(&"172.16.0.1".parse().unwrap()));
        assert!(is_internal_ipv4(&"192.168.1.1".parse().unwrap()));
        assert!(is_internal_ipv4(&"169.254.169.254".parse().unwrap()));
        assert!(is_internal_ipv4(&"0.0.0.0".parse().unwrap()));
        assert!(is_internal_ipv4(&"100.64.0.1".parse().unwrap())); // CGNAT

        assert!(!is_internal_ipv4(&"8.8.8.8".parse().unwrap()));
        assert!(!is_internal_ipv4(&"1.1.1.1".parse().unwrap()));
    }
}
