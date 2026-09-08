//! # Web Sanitizer Engine
//!
//! A modular, defensive HTML and resource sanitization engine written in Rust.
//! It neutralizes malicious content (XSS, SSRF, MIME confusion, IDN homographs, DoS payloads)
//! using streaming zero-copy HTML rewriting and configurable security policies.
//!
//! ## Core Modules
//! - [`policy`]: Declarative configuration defining allow-lists and security rules.
//! - [`parser`]: Streaming HTML inspection and sanitization using `lol_html`.
//! - [`network`]: Safe HTTP sub-resource fetching with SSRF and MIME sniffing defenses.
//! - [`pipeline`]: Concurrent worker pool processing local files and remote URLs.
//! - [`report`]: Structured, machine-readable audit reports of all sanitization actions.

pub mod policy;
pub mod report;
pub mod parser;
pub mod network;
pub mod pipeline;

