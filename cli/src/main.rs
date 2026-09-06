use clap::Parser;
use engine::pipeline::{run_pipeline, Job};
use engine::policy::Policy;
use std::path::PathBuf;

/// Web Sanitizer CLI
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Input files to sanitize
    #[arg(short, long)]
    files: Vec<PathBuf>,

    /// Input URLs to sanitize
    #[arg(short, long)]
    urls: Vec<String>,
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

    println!("Starting web-sanitizer with {} jobs...", jobs.len());

    let policy = Policy::default(); // Eventually load this from a config file

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
