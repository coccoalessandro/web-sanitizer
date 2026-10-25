//! Streaming HTML parsing and zero-copy sanitization engine.
//!
//! Uses [`lol_html`] to inspect and rewrite HTML elements on the fly according to policy rules:
//! - Strips disallowed tags and unauthorized attributes.
//! - Sandboxes active containers (`<iframe>`, `<object>`, `<embed>`).
//! - Blocks meta-refresh redirects.
//! - Validates and sanitizes link targets (filtering `javascript:`, `data:`, IDN homographs, Unicode Host-Split, and blocked domains).
//! - Sanitizes inline `style="..."` attributes and `<style>` blocks to strip dynamic evaluation and dangerous expressions.

use lol_html::{HtmlRewriter, Settings, element, html_content::ContentType, text};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use url::Url;

use crate::css::sanitize_css;
use crate::policy::Policy;
use crate::report::{Location, SanitizationAction, SanitizationReport};
use crate::url_sanitizer::{UrlCheckOutcome, inspect_url};

/// Disallowed elements whose *content* is dangerous or never meant to be rendered: they are
/// removed together with everything inside them. Any other disallowed element is unwrapped
/// (tag removed, content kept), so that a disallowed wrapper such as `<html>` or `<section>`
/// does not erase the text it contains. Elements nested inside an unwrapped element are
/// still visited and filtered individually.
const DROP_WITH_CONTENT: &[&str] = &[
    "script", "style", "iframe", "frame", "frameset", "object", "embed", "applet", "noscript",
    "noembed", "noframes", "template", "head", "title",
];

/// Sanitizes raw HTML input bytes according to the provided [`Policy`].
///
/// Returns a tuple containing:
/// - `Vec<u8>`: The sanitized output HTML bytes.
/// - [`SanitizationReport`]: Detailed log of actions taken and extracted sub-resource URLs.
///
/// # Errors
/// Returns an error string if the underlying HTML rewriter fails or if report extraction fails.
pub fn sanitize_html(
    html_input: &[u8],
    policy: &Policy,
) -> Result<(Vec<u8>, SanitizationReport), String> {
    let mut vector: Vec<u8> = Vec::new();

    let report = Rc::new(RefCell::new(SanitizationReport {
        file_name: "to_be_defined".to_string(),
        time_elapsed: 0,
        file_blocked: false,
        actions: Vec::new(),
        resources_to_fetch: Vec::new(),
    }));

    let report_closure = Rc::clone(&report);
    let policy_clone = policy.clone();

    // Ordinal (1-based, document order) of the element currently visited. Shared with the
    // <style> text handler, which runs right after its own start tag (raw text, no children).
    let element_counter = Rc::new(Cell::new(0usize));
    let counter_el = Rc::clone(&element_counter);

    let mut handlers = vec![element!("*", move |el| {
        let tag_name = el.tag_name();
        let element_index = counter_el.get() + 1;
        counter_el.set(element_index);
        let element_loc = Location::Element {
            index: element_index,
            attribute: None,
        };

        // 1. ACTIVE CONTAINERS: iframe, object, embed
        if tag_name == "iframe" || tag_name == "object" || tag_name == "embed" {
            let is_trusted = el
                .get_attribute("src")
                .and_then(|src| Url::parse(&src).ok())
                .is_some_and(|parsed| {
                    let origin =
                        format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
                    policy_clone.html.trusted_iframe_origins.contains(&origin)
                });

            if !is_trusted {
                if policy_clone.html.rewrite_active_content
                    && policy_clone.html.allowed_tags.contains(&tag_name)
                {
                    el.set_attribute("sandbox", "").unwrap_or(());
                    report_closure
                        .borrow_mut()
                        .actions
                        .push(SanitizationAction {
                            rule_fired: "Untrusted active content sandboxed".to_string(),
                            location: element_loc,
                            original_fragment: tag_name.clone(),
                            replaced_fragment: "Added sandbox attribute".to_string(),
                        });
                } else {
                    el.remove();
                    report_closure.borrow_mut().file_blocked = true;
                    report_closure
                        .borrow_mut()
                        .actions
                        .push(SanitizationAction {
                            rule_fired: "Untrusted active content removed".to_string(),
                            location: element_loc,
                            original_fragment: tag_name.clone(),
                            replaced_fragment: "Tag removed".to_string(),
                        });
                    return Ok(());
                }
            }
        }

        // 2. META REFRESH CHECK: Disallow client-side redirects
        if tag_name == "meta"
            && policy_clone.html.block_meta_refresh
            && el
                .get_attribute("http-equiv")
                .is_some_and(|h| h.eq_ignore_ascii_case("refresh"))
        {
            let action = SanitizationAction {
                rule_fired: "Meta refresh block".to_string(),
                location: element_loc,
                original_fragment: "<meta http-equiv=\"refresh\">".to_string(),
                replaced_fragment: "Tag removed".to_string(),
            };

            report_closure.borrow_mut().actions.push(action);
            el.remove();
            return Ok(());
        }

        // 3. TAG CHECK: Verify allow-list
        if !policy_clone.html.allowed_tags.contains(&tag_name) {
            let drop_content = DROP_WITH_CONTENT.contains(&tag_name.as_str());
            let action = SanitizationAction {
                rule_fired: "Tag not allowed".to_string(),
                location: element_loc,
                original_fragment: tag_name.clone(),
                replaced_fragment: if drop_content {
                    "Tag and content removed".to_string()
                } else {
                    "Tag removed, content kept".to_string()
                },
            };

            report_closure.borrow_mut().actions.push(action);
            if drop_content {
                el.remove();
            } else {
                el.remove_and_keep_content();
            }
            return Ok(());
        }

        // 4. ATTRIBUTE CHECKS
        let allowed_attributes = policy_clone.html.allowed_attributes.get(&tag_name);

        let mut attributes_to_remove: Vec<String> = Vec::new();
        let mut attributes_to_modify: Vec<(String, String)> = Vec::new();

        for (attr_pos, attr) in el.attributes().iter().enumerate() {
            let attr_name = attr.name();
            let attr_value = attr.value();
            let attr_loc = Location::Element {
                index: element_index,
                attribute: Some(attr_pos + 1),
            };

            // High-priority check: Inline Event Handlers (onclick, onload, onerror, etc.)
            if attr_name.starts_with("on") && attr_name.len() > 2 {
                report_closure
                    .borrow_mut()
                    .actions
                    .push(SanitizationAction {
                        rule_fired: "Inline event handler stripped".to_string(),
                        location: attr_loc,
                        original_fragment: format!("{}=\"{}\"", attr_name, attr_value),
                        replaced_fragment: "Attribute stripped".to_string(),
                    });
                attributes_to_remove.push(attr_name);
                continue;
            }

            let is_allowed = allowed_attributes.is_some_and(|set| set.contains(&attr_name));

            if !is_allowed {
                report_closure
                    .borrow_mut()
                    .actions
                    .push(SanitizationAction {
                        rule_fired: "Attribute not allowed".to_string(),
                        location: attr_loc,
                        original_fragment: attr_name.clone(),
                        replaced_fragment: "Attribute removed".to_string(),
                    });
                attributes_to_remove.push(attr_name);
                continue;
            }

            // Inline CSS styles sanitization
            if attr_name == "style" && policy_clone.html.sanitize_inline_styles {
                let (sanitized_css, css_actions) = sanitize_css(&attr_value, &policy_clone);
                if !css_actions.is_empty() || sanitized_css != attr_value {
                    for mut action in css_actions {
                        action.location = attr_loc;
                        report_closure.borrow_mut().actions.push(action);
                    }
                    attributes_to_modify.push((attr_name.clone(), sanitized_css));
                }
                continue;
            }

            // URL-bearing attributes
            let is_url_attr = attr_name == "href"
                || attr_name == "src"
                || attr_name == "action"
                || attr_name == "formaction"
                || attr_name == "poster"
                || attr_name == "background";

            if is_url_attr {
                let is_src = attr_name == "src" || (tag_name == "link" && attr_name == "href");
                match inspect_url(&attr_value, is_src, &policy_clone) {
                    UrlCheckOutcome::Remove(mut action) => {
                        action.location = attr_loc;
                        report_closure.borrow_mut().actions.push(action);
                        attributes_to_remove.push(attr_name);
                    }
                    UrlCheckOutcome::Rewritten(new_val, mut action) => {
                        action.location = attr_loc;
                        report_closure.borrow_mut().actions.push(action);
                        attributes_to_modify.push((attr_name, new_val));
                    }
                    UrlCheckOutcome::Safe(clean_val) => {
                        if is_src {
                            report_closure
                                .borrow_mut()
                                .resources_to_fetch
                                .push(clean_val);
                        }
                    }
                }
            }
        }

        for attr_name in attributes_to_remove {
            el.remove_attribute(&attr_name);
        }

        for (attr_name, new_val) in attributes_to_modify {
            el.set_attribute(&attr_name, &new_val).unwrap_or(());
        }

        Ok(())
    })];

    // 5. STYLE TAG CONTENT SANITIZATION
    if policy.html.sanitize_style_tags && policy.html.allowed_tags.contains("style") {
        let report_text_closure = Rc::clone(&report);
        let policy_text_clone = policy.clone();
        let counter_text = Rc::clone(&element_counter);
        handlers.push(text!("style", move |chunk| {
            let original_css = chunk.as_str();
            let (sanitized_css, css_actions) = sanitize_css(original_css, &policy_text_clone);
            if !css_actions.is_empty() || sanitized_css != original_css {
                // The most recently visited element is the <style> element itself.
                let style_loc = Location::Element {
                    index: counter_text.get(),
                    attribute: None,
                };
                for mut action in css_actions {
                    action.location = style_loc;
                    report_text_closure.borrow_mut().actions.push(action);
                }
                chunk.replace(&sanitized_css, ContentType::Text);
            }
            Ok(())
        }));
    }

    let mut rewriter = HtmlRewriter::new(
        Settings {
            element_content_handlers: handlers,
            ..Settings::default()
        },
        |c: &[u8]| vector.extend_from_slice(c),
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
