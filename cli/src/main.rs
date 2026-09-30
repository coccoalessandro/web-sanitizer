//! Command-Line Interface (CLI) for Web Sanitizer.
//!
//! Provides batch processing of local HTML files and remote URLs,
//! with selectable security profiles (`Strict`, `Balanced`, `Relaxed`),
//! custom JSON configuration loading, CLI argument overrides,
//! and structured JSON telemetry output.

use clap::{Parser, ValueEnum};
use engine::pipeline::{run_pipeline, Job};
use engine::policy::Policy;
use std::fs;
use std::path::PathBuf;

/// Predefined security profiles for the sanitization engine.
#[derive(ValueEnum, Clone, Debug)]
enum Profile {
    /// Strict profile: minimal HTML formatting, zero sub-resource downloads, aggressive link removal.
    Strict,
    /// Balanced profile (default): standard tag whitelist, sandboxing, and safe network limits.
    Balanced,
    /// Relaxed profile: rich tags (tables, iframes, media), higher resource caps, proxy link rewrites.
    Relaxed,
}

/// Web Sanitizer CLI - defensive HTML and web resource cleaner.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Input files to sanitize
    #[arg(short, long)]
    files: Vec<PathBuf>,

    /// Input URLs to sanitize
    #[arg(short, long)]
    urls: Vec<String>,

    /// Predefined security profile to use (overrides config file if provided)
    #[arg(short, long)]
    profile: Option<Profile>,

    /// Path to a JSON configuration file for custom policies
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Allowed HTML tags (comma-separated, e.g. "p,a,b,i")
    #[arg(long, value_delimiter = ',')]
    allowed_tags: Option<Vec<String>>,

    /// Whether to rewrite active content (e.g. inject sandbox to iframes) instead of removing
    #[arg(long)]
    rewrite_active_content: Option<bool>,

    /// Whether to block javascript: URI schemes
    #[arg(long)]
    block_javascript_uris: Option<bool>,

    /// Whether to block data: URI schemes
    #[arg(long)]
    block_data_uris: Option<bool>,

    /// Whether to block meta-refresh redirects
    #[arg(long)]
    block_meta_refresh: Option<bool>,

    /// Whether to check and block IDN homograph patterns (xn--)
    #[arg(long)]
    check_idn_homographs: Option<bool>,

    /// Maximum fetch recursion depth for embedded resources
    #[arg(long)]
    max_fetch_depth: Option<u8>,

    /// Maximum number of sub-resource requests allowed per job
    #[arg(long)]
    max_requests_per_job: Option<usize>,

    /// Maximum size in bytes for downloaded resources
    #[arg(long)]
    max_resource_size_bytes: Option<usize>,

    /// Maximum size in bytes for decompressed resources (compression bomb protection)
    #[arg(long)]
    max_decompressed_size_bytes: Option<usize>,

    /// Request timeout in milliseconds
    #[arg(long)]
    timeout_ms: Option<u64>,

    /// Whether to block requests to private, loopback, and local IPs (SSRF prevention)
    #[arg(long)]
    block_internal_ips: Option<bool>,

    /// Whether to enforce byte-level MIME sniffing on downloaded payloads
    #[arg(long)]
    enforce_mime_sniffing: Option<bool>,
}

fn main() {
    let args = Args::parse();

    let mut jobs = Vec::new();

    for file in args.files {
        jobs.push(Job::LocalFile(file));
    }

    for url in args.urls {
        jobs.push(Job::RemoteUrl(url));
    }

    if jobs.is_empty() {
        println!("No inputs provided. Use --help for usage.");
        return;
    }

    let mut policy = if let Some(ref config_path) = args.config {
        println!("Loading policy from {:?}", config_path);
        let content = fs::read_to_string(config_path).expect("Failed to read config file");
        serde_json::from_str(&content).expect("Failed to parse config file")
    } else {
        match args.profile {
            Some(Profile::Strict) => {
                println!("Using 'Strict' security profile.");
                Policy::strict()
            }
            Some(Profile::Relaxed) => {
                println!("Using 'Relaxed' security profile.");
                Policy::relaxed()
            }
            Some(Profile::Balanced) => {
                println!("Using 'Balanced' security profile.");
                Policy::balanced()
            }
            None => {
                println!("No profile specified. Using default 'Balanced' configuration.");
                Policy::default()
            }
        }
    };

    if let Some(tags) = args.allowed_tags {
        policy.html.allowed_tags = tags.into_iter().collect();
    }
    if let Some(val) = args.rewrite_active_content {
        policy.html.rewrite_active_content = val;
    }
    if let Some(val) = args.block_javascript_uris {
        policy.html.block_javascript_uris = val;
    }
    if let Some(val) = args.block_data_uris {
        policy.html.block_data_uris = val;
    }
    if let Some(val) = args.block_meta_refresh {
        policy.html.block_meta_refresh = val;
    }
    if let Some(val) = args.check_idn_homographs {
        policy.urls.check_idn_homographs = val;
    }
    if let Some(val) = args.max_fetch_depth {
        policy.resources.max_fetch_depth = val;
    }
    if let Some(val) = args.max_requests_per_job {
        policy.resources.max_requests_per_job = val;
    }
    if let Some(val) = args.max_resource_size_bytes {
        policy.resources.max_resource_size_bytes = val;
    }
    if let Some(val) = args.max_decompressed_size_bytes {
        policy.resources.max_decompressed_size_bytes = val;
    }
    if let Some(val) = args.timeout_ms {
        policy.resources.timeout_ms = val;
    }
    if let Some(val) = args.block_internal_ips {
        policy.resources.block_internal_ips = val;
    }
    if let Some(val) = args.enforce_mime_sniffing {
        policy.resources.enforce_mime_sniffing = val;
    }

    println!("Starting web-sanitizer with {} jobs...", jobs.len());

    let results = run_pipeline(jobs, policy);

    for result in results {
        println!("--------------------------------------------------");
        println!("Source: {}", result.source.name());

        match result.output {
            Ok((content, report)) => {
                println!("Sanitization Successful.");
                println!("Content Size: {} bytes", content.len());
                if let Ok(json) = serde_json::to_string_pretty(&report) {
                    println!("Report:\n{}", json);
                }
            }
            Err(e) => {
                eprintln!("Error processing job: {}", e);
            }
        }
    }
}
