//! Streaming HTML parsing and zero-copy sanitization engine.
//!
//! Uses [`lol_html`] to inspect and rewrite HTML elements on the fly according to policy rules:
//! - Strips disallowed tags and unauthorized attributes.
//! - Sandboxes active containers (`<iframe>`, `<object>`).
//! - Blocks meta-refresh redirects.
//! - Validates and sanitizes link targets (filtering `javascript:`, `data:`, IDN homographs, and blocked domains).

use std::cell::RefCell;
use std::rc::Rc;
use lol_html::{element, HtmlRewriter, Settings};
use url::Url;

use crate::policy::{Policy, LinkAction};
use crate::report::{SanitizationAction, SanitizationReport};

/// Sanitizes raw HTML input bytes according to the provided [`Policy`].
///
/// Returns a tuple containing:
/// - `Vec<u8>`: The sanitized output HTML bytes.
/// - [`SanitizationReport`]: Detailed log of actions taken and extracted sub-resource URLs.
///
/// # Errors
/// Returns an error string if the underlying HTML rewriter fails or if report extraction fails.
pub fn sanitize_html(html_input: &[u8], policy: &Policy) -> Result<(Vec<u8>, SanitizationReport), String> {

    let mut vector: Vec<u8> = Vec::new();
    
    let report = Rc::new(RefCell::new(SanitizationReport {
        file_name: "to_be_defined".to_string(),
        time_elapsed: 0,
        file_blocked: false,
        actions: Vec::new(),
        resources_to_fetch: Vec::new()
    }));

    let report_closure = Rc::clone(&report);
    let policy_clone = policy.clone();
    
    let mut rewriter = HtmlRewriter::new(
        Settings {
            element_content_handlers: vec![
                element!("*", move |el| {
                    let tag_name = el.tag_name();

                    // TAG CHECK
                    if !policy_clone.html.allowed_tags.contains(&tag_name) {
                        let action = SanitizationAction {
                            rule_fired: "Tag not allowed".to_string(),
                            location: (0, 0),
                            original_fragment: format!("{}", tag_name),
                            replaced_fragment: "Tag removed".to_string()
                        };

                        report_closure.borrow_mut().actions.push(action);
                        el.remove();

                        return Ok(())
                    }

                    // META REFRESH
                    if tag_name == "meta" && policy_clone.html.block_meta_refresh {
                        if let Some(http_equiv) = el.get_attribute("http-equiv") {
                            if http_equiv.to_lowercase() == "refresh" {
                                let action = SanitizationAction {
                                    rule_fired: "Meta refresh block".to_string(),
                                    location: (0, 0),
                                    original_fragment: "<meta http-equiv=\"refresh\">".to_string(),
                                    replaced_fragment: "Tag removed".to_string()
                                };

                                report_closure.borrow_mut().actions.push(action);
                                el.remove();

                                return Ok(())
                            }
                        }
                    }

                    // iframe and object handling
                    if tag_name == "iframe" || tag_name == "object" {
                        let mut is_trusted = false;

                        if let Some(src) = el.get_attribute("src") {
                            if let Ok(parsed) = Url::parse(&src) {
                                let origin = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
                                if policy_clone.html.trusted_iframe_origins.contains(&origin) {
                                    is_trusted = true;
                                }
                            }
                        }

                        if !is_trusted {
                            if policy_clone.html.rewrite_active_content {
                                el.set_attribute("sandbox", "").unwrap_or(());
                                report_closure.borrow_mut().actions.push(SanitizationAction {
                                    rule_fired: "Untrusted active content sanboxed".to_string(),
                                    location: (0,0),
                                    original_fragment: format!("<{}>", tag_name),
                                    replaced_fragment: "Added sandbox attribute".to_string()
                                });
                            } else {
                                el.remove();
                                report_closure.borrow_mut().actions.push(SanitizationAction {
                                    rule_fired: "Untrusted active content removed".to_string(),
                                    location: (0, 0),
                                    original_fragment: format!("<{}>", tag_name),
                                    replaced_fragment: "Tag removed".to_string()
                                });
                                return Ok(());
                            }
                        }
                    }

                    // ATTRIBUTE CHECK
                    let allowed_attributes = policy_clone.html.allowed_attributes.get(&tag_name);

                    let mut attributes_to_remove: Vec<String> = Vec::new();
                    let mut attributes_to_modify: Vec<(String, String)> = Vec::new();

                    let base_addr = Url::parse("http://internal.base").unwrap();

                    for attr in el.attributes() {
                        let attr_name = attr.name();

                        let is_allowed = allowed_attributes.map_or(false, |set| set.contains(&attr_name));

                        if !is_allowed {
                            // attribute not allowed
                            attributes_to_remove.push(attr_name);
                            continue;   
                        } 
                        
                        if attr_name == "href" || attr_name == "src" {
                            let url_value = attr.value();

                            match base_addr.join(&url_value) {
                                Ok(parsed_url) => {
                                    // URI scheme
                                    let scheme = parsed_url.scheme();
                                    if scheme == "javascript" || scheme == "data" {
                                        attributes_to_remove.push(attr_name);
                                        continue;
                                    }

                                    if parsed_url.host_str() != Some("internal.base") {
                                        if let Some(host) = parsed_url.host_str() {
                                            let is_idn = host.starts_with("xn--");
                                            let is_malware = policy_clone.urls.blocked_domains.contains(host);
                                            let is_tracker = policy_clone.urls.tracker_domains.contains(host);

                                            if (is_idn && policy_clone.urls.check_idn_homographs) || is_malware || is_tracker {
                                                match &policy_clone.urls.suspicious_link_action {
                                                    LinkAction::Remove => {
                                                        attributes_to_remove.push(attr_name.clone());
                                                    },
                                                    LinkAction::ReplaceWithWarning(warning) => {
                                                        attributes_to_modify.push((attr_name.clone(), warning.clone()))
                                                    },
                                                    LinkAction::Rewrite(proxy_prefix) => {
                                                        let encoded = url::form_urlencoded::byte_serialize(url_value.as_bytes()).collect::<String>();
                                                        let new_url = format!("{}{}", proxy_prefix, encoded);
                                                        attributes_to_modify.push((attr_name.clone(), new_url));
                                                    }
                                                }
                                            } else if attr_name == "src" {
                                                // Secure link
                                                report_closure.borrow_mut().resources_to_fetch.push(url_value.clone());
                                            }
                                        }
                                    } else if attr_name == "src" {
                                        report_closure.borrow_mut().resources_to_fetch.push(url_value.clone());
                                    }
                                }, 
                                Err(_) => {
                                    attributes_to_remove.push(attr_name);
                                }
                            }
                        }
                    }

                    for attr_name in attributes_to_remove {
                        let action = SanitizationAction {
                            rule_fired: "Attribute not allowed".to_string(),
                            location: (0, 0),
                            original_fragment: format!("{}", attr_name),
                            replaced_fragment: "Attribute removed".to_string()
                        };

                        report_closure.borrow_mut().actions.push(action);
                        el.remove_attribute(&attr_name);
                    }

                    for (attr_name, new_val) in attributes_to_modify {
                        let action = SanitizationAction {
                            rule_fired: "Suspicious link mitigated".to_string(),
                            location: (0, 0),
                            original_fragment: format!("{} attribute", attr_name),
                            replaced_fragment: "Value rewritten by policy".to_string()
                        };

                        report_closure.borrow_mut().actions.push(action);
                        el.set_attribute(&attr_name, &new_val).unwrap_or(());
                    }

                    Ok(())
                }) 
            ],
            ..Settings::default()
        },
        |c: &[u8]| vector.extend_from_slice(c)
    );
    
    if let Err(e) = rewriter.write(html_input) {
        return Err(format!("Error during sanitization: {}", e));
    }

    let _ = rewriter.end();
    
    let final_report = Rc::try_unwrap(report)
        .map_err(|_| "Error during report extraction")?
        .into_inner();

    Ok((vector, final_report))
}