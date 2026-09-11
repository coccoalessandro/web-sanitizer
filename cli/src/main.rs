use clap::{Parser, ValueEnum};
use engine::pipeline::{Job, run_pipeline};
use engine::policy::{HtmlPolicy, LinkAction, Policy, ResourcePolicy, UrlPolicy};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

#[derive(ValueEnum, Clone, Debug)]
enum Profile {
    Strict,
    Balanced,
    Relaxed,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    files: Vec<PathBuf>,

    #[arg(short, long)]
    urls: Vec<String>,

    #[arg(short, long)]
    profile: Option<Profile>,

    #[arg(short, long)]
    config: Option<PathBuf>,

    #[arg(long, value_delimiter = ',')]
    allowed_tags: Option<Vec<String>>,

    #[arg(long)]
    rewrite_active_content: Option<bool>,

    #[arg(long)]
    block_javascript_uris: Option<bool>,

    #[arg(long)]
    block_data_uris: Option<bool>,

    #[arg(long)]
    block_meta_refresh: Option<bool>,

    #[arg(long)]
    check_idn_homographs: Option<bool>,

    #[arg(long)]
    max_fetch_depth: Option<u8>,

    #[arg(long)]
    max_requests_per_job: Option<usize>,

    #[arg(long)]
    max_resource_size_bytes: Option<usize>,

    #[arg(long)]
    max_decompressed_size_bytes: Option<usize>,

    #[arg(long)]
    timeout_ms: Option<u64>,

    #[arg(long)]
    block_internal_ips: Option<bool>,

    #[arg(long)]
    enforce_mime_sniffing: Option<bool>,
}

fn main() {
    let args = Args::parse();

    let mut jobs = Vec::new();
    for file in &args.files {
        jobs.push(Job::LocalFile(file.clone()));
    }
    for url in &args.urls {
        jobs.push(Job::RemoteUrl(url.clone()));
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
            Some(Profile::Strict) => Policy::strict(),
            Some(Profile::Relaxed) => Policy::relaxed(),
            Some(Profile::Balanced) => Policy::balanced(),
            None => Policy::default(),
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
