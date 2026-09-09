//! Command-Line Interface (CLI) for Web Sanitizer.
//!
//! Provides batch processing of local HTML files and remote URLs,
//! with selectable security profiles (`Strict`, `Balanced`, `Relaxed`)
//! and JSON telemetry output.

use clap::{Parser, ValueEnum};
use engine::pipeline::{run_pipeline, Job};
use engine::policy::Policy;
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

    let policy = match args.profile {
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
            // TODO: In the future, attempt to load from config file here before falling back to default
            println!("No profile specified. Using default 'Balanced' configuration.");
            Policy::default()
        }
    };

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
