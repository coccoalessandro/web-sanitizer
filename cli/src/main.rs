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
use std::process::exit;

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
    files: Option<Vec<PathBuf>>,

    /// Input URLs to sanitize
    #[arg(short, long)]
    urls: Option<Vec<String>>,

    /// Input directory to walk recursively and sanitize all .html/.htm files
    #[arg(long)]
    dir: Option<PathBuf>,

    /// Output directory to save cleaned files and their .json audit reports
    #[arg(short, long)]
    output_dir: Option<PathBuf>,

    /// Quiet mode (suppress non-error output)
    #[arg(short, long, default_value_t = false)]
    quiet: bool,

    /// Verbose mode
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// JSON-only mode (prints only the JSON report to stdout)
    #[arg(long, default_value_t = false)]
    json_only: bool,

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

fn walk_dir(dir: &std::path::Path, jobs: &mut Vec<Job>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk_dir(&path, jobs);
            } else if path.is_file() {
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();
                    if ext_str == "html" || ext_str == "htm" {
                        jobs.push(Job::LocalFile(path));
                    }
                }
            }
        }
    }
}

fn main() {
    let args = Args::parse();

    let mut jobs = Vec::new();

    for file in args.files.unwrap_or_default() {
        if file.as_os_str() != "" {
            jobs.push(Job::LocalFile(file));
        }
    }

    for url in args.urls.unwrap_or_default() {
        if url != "" {
            jobs.push(Job::RemoteUrl(url));
        }
    }

    if let Some(ref dir) = args.dir {
        walk_dir(dir, &mut jobs);
    }

    if jobs.is_empty() {
        if !args.quiet && !args.json_only {
            println!("No inputs provided. Use --help for usage.");
        }
        return;
    }

    if let Some(ref out_dir) = args.output_dir {
        if !out_dir.exists() {
            fs::create_dir_all(out_dir).expect("Failed to create output directory");
        }
    }

    let mut policy = if let Some(ref config_path) = args.config {
        if args.verbose && !args.quiet && !args.json_only {
            println!("Loading policy from {:?}", config_path);
        }
        let content = fs::read_to_string(config_path).expect("Failed to read config file");
        serde_json::from_str(&content).expect("Failed to parse config file")
    } else {
        match args.profile {
            Some(Profile::Strict) => {
                if args.verbose && !args.quiet && !args.json_only {
                    println!("Using 'Strict' security profile.");
                }
                Policy::strict()
            }
            Some(Profile::Relaxed) => {
                if args.verbose && !args.quiet && !args.json_only {
                    println!("Using 'Relaxed' security profile.");
                }
                Policy::relaxed()
            }
            Some(Profile::Balanced) => {
                if args.verbose && !args.quiet && !args.json_only {
                    println!("Using 'Balanced' security profile.");
                }
                Policy::balanced()
            }
            None => {
                if args.verbose && !args.quiet && !args.json_only {
                    println!("No profile specified. Using default 'Balanced' configuration.");
                }
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

    if !args.quiet && !args.json_only {
        println!("Starting web-sanitizer with {} jobs...", jobs.len());
    }

    let results = run_pipeline(jobs, policy);

    let mut has_threats = false;

    for result in results {
        if !args.quiet && !args.json_only {
            println!("--------------------------------------------------");
            println!("Source: {}", result.source.name());
        }

        match result.output {
            Ok((content, report)) => {
                if !report.actions.is_empty() {
                    has_threats = true;
                }

                if let Some(ref out_dir) = args.output_dir {
                    let safe_name = result.source.name().replace(|c: char| !c.is_alphanumeric(), "_");
                    let html_path = out_dir.join(format!("{}.html", safe_name));
                    let json_path = out_dir.join(format!("{}.json", safe_name));

                    fs::write(&html_path, &content).expect("Failed to write HTML output");
                    let json_str = serde_json::to_string_pretty(&report).unwrap_or_default();
                    fs::write(&json_path, json_str).expect("Failed to write JSON report output");
                    
                    if !args.quiet && !args.json_only {
                        println!("Saved to {:?} and {:?}", html_path, json_path);
                    }
                }

                if args.json_only {
                    if let Ok(json) = serde_json::to_string(&report) {
                        println!("{}", json);
                    }
                } else if !args.quiet {
                    println!("Sanitization Successful.");
                    println!("Content Size: {} bytes", content.len());
                    if let Ok(json) = serde_json::to_string_pretty(&report) {
                        println!("Report:\n{}", json);
                    }
                }
            }
            Err(e) => {
                has_threats = true;
                if !args.quiet {
                    eprintln!("Error processing job: {}", e);
                }
            }
        }
    }

    if has_threats {
        exit(1);
    }
}
