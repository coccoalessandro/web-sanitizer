//! Command-Line Interface (CLI) for Web Sanitizer.
//!
//! Provides batch processing of local HTML files, recursive directory trees, and remote URLs,
//! with selectable security profiles (`Strict`, `Balanced`, `Relaxed`),
//! custom JSON configuration loading, CLI argument overrides,
//! file export (`--output-dir`), and structured JSON telemetry output.

use clap::{Parser, ValueEnum};
use engine::pipeline::{Job, PipelineStats, run_pipeline_with_workers};
use engine::policy::Policy;
use engine::report::SanitizationReport;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

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

    /// Directories to scan recursively for HTML and web documents
    #[arg(short, long)]
    dirs: Vec<PathBuf>,

    /// Input URLs to sanitize
    #[arg(short, long)]
    urls: Vec<String>,

    /// Directory to write sanitized output files and per-file audit reports
    #[arg(short, long)]
    output_dir: Option<PathBuf>,

    /// File path to save the full aggregated JSON audit report
    #[arg(long)]
    report_file: Option<PathBuf>,

    /// Predefined security profile to use (overrides config file if provided)
    #[arg(short, long)]
    profile: Option<Profile>,

    /// Path to a JSON configuration file for custom policies
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Number of worker threads for parallel batch processing
    #[arg(short = 'w', long)]
    workers: Option<usize>,

    /// Suppress informative logging and summary banners
    #[arg(short, long, default_value_t = false)]
    quiet: bool,

    /// Print detailed per-action audit information
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Emit only machine-readable JSON output to stdout
    #[arg(long, default_value_t = false)]
    json_only: bool,

    // Policy overrides
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

    /// Whether to detect and block Unicode normalization Host-Split attacks
    #[arg(long)]
    check_unicode_host_split: Option<bool>,

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

    /// Maximum pixel count for images before rejecting as decompression pixel bombs
    #[arg(long)]
    max_image_pixels: Option<usize>,

    /// Whether to block active documents (PDFs/SVGs with active JavaScript)
    #[arg(long)]
    block_active_documents: Option<bool>,

    /// Request timeout in milliseconds
    #[arg(long)]
    timeout_ms: Option<u64>,

    /// Whether to block requests to private, loopback, and local IPs (SSRF prevention)
    #[arg(long)]
    block_internal_ips: Option<bool>,

    /// Whether to resolve DNS to prevent DNS rebinding SSRF
    #[arg(long)]
    resolve_dns_for_ssrf: Option<bool>,

    /// Whether to enforce byte-level MIME sniffing on downloaded payloads
    #[arg(long)]
    enforce_mime_sniffing: Option<bool>,
}

/// JSON payload emitted when `--json-only` or `--report-file` is requested.
#[derive(Serialize)]
struct BatchReportOutput {
    stats: PipelineStats,
    reports: Vec<SanitizationReport>,
    errors: Vec<JobError>,
}

#[derive(Serialize)]
struct JobError {
    target: String,
    error: String,
}

fn main() {
    let args = Args::parse();

    let mut jobs = Vec::new();

    // 1. Collect direct files
    for file in args.files {
        jobs.push(Job::LocalFile(file));
    }

    // 2. Collect directory files recursively
    let supported_extensions = [
        "html", "htm", "xhtml", "svg", "pdf", "png", "gif", "jpeg", "jpg", "webp",
    ];
    for dir in args.dirs {
        if !dir.exists() {
            eprintln!("Error: Specified directory does not exist: {:?}", dir);
            process::exit(1);
        }
        match scan_directory(&dir, &supported_extensions) {
            Ok(found_files) => {
                if !args.quiet && !args.json_only {
                    println!(
                        "Discovered {} files in directory {:?}",
                        found_files.len(),
                        dir
                    );
                }
                for f in found_files {
                    jobs.push(Job::LocalFile(f));
                }
            }
            Err(e) => {
                eprintln!("Error scanning directory {:?}: {}", dir, e);
                process::exit(1);
            }
        }
    }

    // 3. Collect remote URLs
    for url in args.urls {
        jobs.push(Job::RemoteUrl(url));
    }

    if jobs.is_empty() {
        if !args.quiet && !args.json_only {
            println!("No inputs provided. Use --help for usage.");
        }
        process::exit(0);
    }

    // Load base policy
    let mut policy = if let Some(ref config_path) = args.config {
        if !args.quiet && !args.json_only {
            println!("Loading policy from {:?}", config_path);
        }
        let content = fs::read_to_string(config_path).unwrap_or_else(|e| {
            eprintln!("Failed to read config file: {}", e);
            process::exit(1);
        });
        serde_json::from_str(&content).unwrap_or_else(|e| {
            eprintln!("Failed to parse config file: {}", e);
            process::exit(1);
        })
    } else {
        match args.profile {
            Some(Profile::Strict) => {
                if !args.quiet && !args.json_only {
                    println!("Using 'Strict' security profile.");
                }
                Policy::strict()
            }
            Some(Profile::Relaxed) => {
                if !args.quiet && !args.json_only {
                    println!("Using 'Relaxed' security profile.");
                }
                Policy::relaxed()
            }
            Some(Profile::Balanced) => {
                if !args.quiet && !args.json_only {
                    println!("Using 'Balanced' security profile.");
                }
                Policy::balanced()
            }
            None => {
                if !args.quiet && !args.json_only {
                    println!("No profile specified. Using default 'Balanced' configuration.");
                }
                Policy::default()
            }
        }
    };

    // Apply CLI overrides
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
    if let Some(val) = args.check_unicode_host_split {
        policy.urls.check_unicode_host_split = val;
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
    if let Some(val) = args.max_image_pixels {
        policy.resources.max_image_pixels = val;
    }
    if let Some(val) = args.block_active_documents {
        policy.resources.block_active_documents = val;
    }
    if let Some(val) = args.timeout_ms {
        policy.resources.timeout_ms = val;
    }
    if let Some(val) = args.block_internal_ips {
        policy.resources.block_internal_ips = val;
    }
    if let Some(val) = args.resolve_dns_for_ssrf {
        policy.resources.resolve_dns_for_ssrf = val;
    }
    if let Some(val) = args.enforce_mime_sniffing {
        policy.resources.enforce_mime_sniffing = val;
    }

    let num_workers = args.workers.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });

    if !args.quiet && !args.json_only {
        println!(
            "Starting web-sanitizer with {} jobs on {} worker threads...",
            jobs.len(),
            num_workers
        );
    }

    let (results, stats) = run_pipeline_with_workers(jobs, policy, num_workers);

    // Prepare output directory if configured
    if let Some(ref out_dir) = args.output_dir
        && let Err(e) = fs::create_dir_all(out_dir)
    {
        eprintln!("Failed to create output directory {:?}: {}", out_dir, e);
        process::exit(1);
    }

    let mut successful_reports = Vec::new();
    let mut recorded_errors = Vec::new();
    let mut any_blocked = false;

    for (idx, result) in results.iter().enumerate() {
        let source_name = result.source.name();

        match &result.output {
            Ok((content, report)) => {
                successful_reports.push(report.clone());
                if report.file_blocked {
                    any_blocked = true;
                }

                if !args.quiet && !args.json_only {
                    println!("--------------------------------------------------");
                    println!("Source: {}", source_name);
                    println!(
                        "Status: {} ({} actions, {} bytes, {} ms)",
                        if report.file_blocked {
                            "BLOCKED (Refused)"
                        } else {
                            "Cleaned"
                        },
                        report.actions.len(),
                        content.len(),
                        report.time_elapsed
                    );

                    if args.verbose {
                        for action in &report.actions {
                            println!(
                                "  - [{}] {}: {} -> {}",
                                action.location,
                                action.rule_fired,
                                action.original_fragment,
                                action.replaced_fragment
                            );
                        }
                    }
                }

                // Save to output directory if configured
                if let Some(ref out_dir) = args.output_dir {
                    let base_filename = sanitize_filename_for_job(&result.source, idx);
                    let report_path = out_dir.join(format!("{}.report.json", base_filename));

                    // The audit trail is emitted whatever the verdict: a refusal must be
                    // just as auditable as a successful clean-up.
                    if let Ok(json) = serde_json::to_string_pretty(report) {
                        let _ = fs::write(&report_path, json);
                    }

                    if report.file_blocked {
                        // Refused payloads are never materialised. For PDFs and raster
                        // images `content` still holds the original attacker-controlled
                        // bytes (the pipeline returns them verbatim), so writing it would
                        // hand the user the very file we just refused. We write a tombstone
                        // describing the refusal instead.
                        let refused_path = out_dir.join(format!("{}.refused.txt", base_filename));
                        if let Err(e) =
                            fs::write(&refused_path, refusal_notice(&source_name, content, report))
                        {
                            eprintln!("Failed to write refusal notice {:?}: {}", refused_path, e);
                        }
                    } else {
                        let ext = output_extension(content, &result.source);
                        let out_path = out_dir.join(format!("{}.cleaned.{}", base_filename, ext));
                        if let Err(e) = fs::write(&out_path, content) {
                            eprintln!("Failed to write cleaned file {:?}: {}", out_path, e);
                        }
                    }
                }
            }
            Err(e) => {
                recorded_errors.push(JobError {
                    target: source_name.clone(),
                    error: e.clone(),
                });

                if !args.quiet && !args.json_only {
                    eprintln!("--------------------------------------------------");
                    eprintln!("Source: {}", source_name);
                    eprintln!("Error: {}", e);
                }
            }
        }
    }

    // Save aggregated report file if configured
    let full_batch_report = BatchReportOutput {
        stats: stats.clone(),
        reports: successful_reports,
        errors: recorded_errors,
    };

    if let Some(ref r_path) = args.report_file
        && let Ok(json) = serde_json::to_string_pretty(&full_batch_report)
    {
        if let Err(e) = fs::write(r_path, json) {
            eprintln!("Failed to write aggregated report to {:?}: {}", r_path, e);
        } else if !args.quiet && !args.json_only {
            println!("Aggregated report saved to {:?}", r_path);
        }
    }

    // Print stdout summary or json
    if args.json_only {
        if let Ok(json) = serde_json::to_string_pretty(&full_batch_report) {
            println!("{}", json);
        }
    } else if !args.quiet {
        println!("==================================================");
        println!("Batch Execution Summary:");
        println!("  Total Jobs: {}", stats.total_jobs);
        println!("  Successful: {}", stats.successful_jobs);
        println!("  Failed:     {}", stats.failed_jobs);
        println!("  Blocked:    {}", stats.blocked_jobs);
        println!("  Total Actions: {}", stats.total_actions_taken);
        println!("  Bytes Processed: {}", stats.total_bytes_processed);
        println!("  Duration:   {} ms", stats.total_time_ms);
        println!("==================================================");
    }

    // Exit code policy: Return 1 if any failure or outright block occurred
    if stats.failed_jobs > 0 || any_blocked || stats.blocked_jobs > 0 {
        process::exit(1);
    } else {
        process::exit(0);
    }
}

/// Recursively traverses `dir` collecting paths ending in any of `extensions`.
fn scan_directory(dir: &Path, extensions: &[&str]) -> std::io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                files.extend(scan_directory(&path, extensions)?);
            } else if path.is_file()
                && let Some(ext) = path.extension().and_then(|s| s.to_str())
                && extensions.iter().any(|&e| e.eq_ignore_ascii_case(ext))
            {
                files.push(path);
            }
        }
    }
    Ok(files)
}

/// Creates a safe filesystem basename for an output file based on a job.
fn sanitize_filename_for_job(job: &Job, index: usize) -> String {
    match job {
        Job::LocalFile(p) => p
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("document")
            .to_string(),
        Job::RemoteUrl(u) => {
            let safe: String = u
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '_' })
                .collect();
            let truncated = if safe.len() > 40 { &safe[..40] } else { &safe };
            format!("url_{}_{}", index, truncated)
        }
    }
}


/// Builds the human-readable tombstone written in place of a refused payload.
///
/// The refused bytes themselves are deliberately *not* included: the whole point of a
/// refusal is that the payload does not reach the filesystem.
fn refusal_notice(source: &str, withheld: &[u8], report: &SanitizationReport) -> String {
    let mut notice = format!(
        "REFUSED BY WEB-SANITIZER\n\
         ========================\n\
         source:             {}\n\
         withheld payload:   {} bytes (NOT written to disk)\n\
         actions recorded:   {}\n\
         \n\
         Reasons:\n",
        source,
        withheld.len(),
        report.actions.len()
    );

    for action in &report.actions {
        notice.push_str(&format!(
            "  - [{}] {}: {} -> {}\n",
            action.location, action.rule_fired, action.original_fragment, action.replaced_fragment
        ));
    }

    notice.push_str("\nSee the accompanying .report.json for the machine-readable audit trail.\n");
    notice
}

/// Derives the output file extension from the sanitized payload itself.
///
/// Content sniffing comes first (the declared type of the input is never trusted,
/// per the MIME-confusion requirement), then the input's own extension, and finally
/// `html` as the last resort. Without this, every output was labelled `.cleaned.html`
/// regardless of what it actually contained.
fn output_extension(content: &[u8], job: &Job) -> String {
    if content.starts_with(b"%PDF-") {
        return "pdf".to_string();
    }
    if content.starts_with(b"\x89PNG\r\n\x1a\n") {
        return "png".to_string();
    }
    if content.starts_with(b"GIF87a") || content.starts_with(b"GIF89a") {
        return "gif".to_string();
    }
    if content.starts_with(b"\xFF\xD8") {
        return "jpg".to_string();
    }
    if content.starts_with(b"RIFF") && content.len() >= 12 && &content[8..12] == b"WEBP" {
        return "webp".to_string();
    }

    // SVG has no magic number: look for the root element in the leading bytes.
    let head = String::from_utf8_lossy(&content[..content.len().min(256)]);
    if head.contains("<svg") {
        return "svg".to_string();
    }

    if let Job::LocalFile(path) = job
        && let Some(ext) = path.extension().and_then(|s| s.to_str())
    {
        return ext.to_ascii_lowercase();
    }

    "html".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_directory_finds_html() {
        let temp_dir = std::env::temp_dir().join("test_scan_dir");
        let sub_dir = temp_dir.join("sub");
        fs::create_dir_all(&sub_dir).unwrap();

        let file1 = temp_dir.join("index.html");
        let file2 = sub_dir.join("page.htm");
        let file3 = sub_dir.join("image.png");

        fs::write(&file1, "<html></html>").unwrap();
        fs::write(&file2, "<html></html>").unwrap();
        fs::write(&file3, "binary").unwrap();

        let found = scan_directory(&temp_dir, &["html", "htm"]).unwrap();

        let _ = fs::remove_file(file1);
        let _ = fs::remove_file(file2);
        let _ = fs::remove_file(file3);
        let _ = fs::remove_dir_all(temp_dir);

        assert_eq!(found.len(), 2);
    }
}
