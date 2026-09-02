use std::cell::RefCell;
use std::rc::Rc;
use lol_html::{element, HtmlRewriter, Settings};

use crate::policy::Policy;
use crate::report::{SanitizationAction, SanitizationReport};

pub fn sanitize_html(html_input: &[u8], policy: &Policy) -> Result<(Vec<u8>, SanitizationReport), String> {

    let mut vettore: Vec<u8> = Vec::new();
    
    let report = Rc::new(RefCell::new(SanitizationReport {
        file_name: "da_definire".to_string(),
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
                    let nome_tag = el.tag_name();

                    // CONTROLLO TAG
                    if !policy.html.allowed_tags.contains(&nome_tag) {
                        let azione = SanitizationAction {
                            rule_fired: "Tag non consentito".to_string(),
                            location: (0, 0),
                            original_fragment: format!("{}", nome_tag),
                            replaced_fragment: "Tag rimosso".to_string()
                        };

                        report_closure.borrow_mut().actions.push(azione);
                        el.remove();

                        return Ok(())
                    }

                    // CONTROLLO ATTRIBUTI
                    let attributi_consentiti = policy.html.allowed_attributes.get(&nome_tag);

                    let mut attributi_da_rimuovere: Vec<String> = Vec::new();

                    for attr in el.attributes() {
                        let attr_name = attr.name();

                        let is_allowed = match attributi_consentiti {
                            Some(set) => set.contains(&attr_name),
                            None => false,
                        };

                        if !is_allowed {
                            // attributo non permesso
                            attributi_da_rimuovere.push(attr_name);
                            
                        } else if attr_name == "href" || attr_name == "src" {
                            let url_value = attr.value();

                            if let Ok(parsed_url) = url::Url::parse(&url_value) {

                                // URI scheme
                                let scheme = parsed_url.scheme();
                                if scheme == "javascript" || scheme == "data" {
                                    attributi_da_rimuovere.push(attr_name);
                                    continue;
                                }

                                if let Some(host) = parsed_url.host_str() {
                                    // IDN HOMOGRAPH PATTERN CHECK
                                    if host.starts_with("xn--") || policy.urls.blocked_domains.contains(host) {
                                        // dominio noto per malware o tracking o sospetto attacco omografo
                                        attributi_da_rimuovere.push(attr_name);
                                    } else if attr_name == "src" {
                                        report_closure.borrow_mut().resources_to_fetch.push(parsed_url.to_string());
                                    }
                                }
                            } else {
                                attributi_da_rimuovere.push(attr_name);
                            }
                        }
                    }

                    for attr_name in attributi_da_rimuovere {
                        let azione = SanitizationAction {
                            rule_fired: "Attributo non consentito".to_string(),
                            location: (0, 0),
                            original_fragment: format!("{}", attr_name),
                            replaced_fragment: "Attributo rimosso".to_string()
                        };

                        report_closure.borrow_mut().actions.push(azione);
                        el.remove_attribute(&attr_name);
                    }

                    Ok(())
                }) 
            ],
            ..Settings::default()
        },
        |c: &[u8]| vettore.extend_from_slice(c)
    );
    
    if let Err(e) = rewriter.write(html_input) {
        return Err(format!("Errore durante la sanitizzazione: {}", e));
    }

    let _ = rewriter.end();
    
    let report_finale = Rc::try_unwrap(report)
        .map_err(|_| "Errore durante l'estrazione del report")?
        .into_inner();

    Ok((vettore, report_finale))
}