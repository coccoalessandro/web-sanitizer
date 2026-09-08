use std::cell::RefCell;
use std::rc::Rc;
use lol_html::{element, HtmlRewriter, Settings};

use crate::policy::Policy;
use crate::report::{SanitizationAction, SanitizationReport};

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
    
    let mut rewriter = HtmlRewriter::new(
        Settings {
            element_content_handlers: vec![
                element!("*", move |el| {
                    let tag_name = el.tag_name();

                    // TAG CHECK
                    if !policy.html.allowed_tags.contains(&tag_name) {
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
                    if tag_name == "meta" {
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
                        el.set_attribute("sandbox", "").unwrap_or(());
                    }

                    // ATTRIBUTE CHECK
                    let allowed_attributes = policy.html.allowed_attributes.get(&tag_name);

                    let mut attributes_to_remove: Vec<String> = Vec::new();

                    for attr in el.attributes() {
                        let attr_name = attr.name();

                        let is_allowed = match allowed_attributes {
                            Some(set) => set.contains(&attr_name),
                            None => false,
                        };

                        if !is_allowed {
                            // attribute not allowed
                            attributes_to_remove.push(attr_name);
                            
                        } else if attr_name == "href" || attr_name == "src" {
                            let url_value = attr.value();

                            if let Ok(parsed_url) = url::Url::parse(&url_value) {

                                // URI scheme
                                let scheme = parsed_url.scheme();
                                if scheme == "javascript" || scheme == "data" {
                                    attributes_to_remove.push(attr_name);
                                    continue;
                                }

                                if let Some(host) = parsed_url.host_str() {
                                    // IDN HOMOGRAPH PATTERN CHECK
                                    if host.starts_with("xn--") || policy.urls.blocked_domains.contains(host) {
                                        // domain known for malware or tracking or suspicious homograph attack
                                        attributes_to_remove.push(attr_name);
                                    } else if attr_name == "src" {
                                        report_closure.borrow_mut().resources_to_fetch.push(parsed_url.to_string());
                                    }
                                }
                            } else {
                                attributes_to_remove.push(attr_name);
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