//! Concurrent batch execution pipeline using crossbeam channels and a worker thread pool.

use crossbeam_channel::unbounded;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;
use url::Url;

use crate::active_content::{check_image_dimensions, inspect_and_sanitize_svg, inspect_pdf};
use crate::network::{fetch_resources_with_cache, is_ssrf_host};
use crate::parser::sanitize_html;
use crate::policy::Policy;
use crate::report::{SanitizationAction, SanitizationReport};

/// Represents an individual input target to be processed by the pipeline.
#[derive(Clone, Debug)]
pub enum Job {
    /// A local file on the filesystem.
    LocalFile(PathBuf),
    /// A remote URL to fetch and sanitize.
    RemoteUrl(String),
}

impl Job {
    /// Returns a human-readable identifier for the job target.
    pub fn name(&self) -> String {
        match self {
            Job::LocalFile(p) => p.display().to_string(),
            Job::RemoteUrl(u) => u.clone(),
        }
    }
}

/// The outcome of processing a [`Job`].
pub struct JobResult {
    /// The input source associated with this result.
    pub source: Job,
    /// The sanitized output bytes and audit report, or an error description.
    pub output: Result<(Vec<u8>, SanitizationReport), String>,
}

/// Aggregated telemetry and execution metrics for a completed batch pipeline run.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PipelineStats {
    /// Total number of inputs scheduled.
    pub total_jobs: usize,
    /// Number of inputs sanitized without unrecoverable errors.
    pub successful_jobs: usize,
    /// Number of inputs that failed to read, parse, or download.
    pub failed_jobs: usize,
    /// Number of inputs refused outright due to critical policy violations.
    pub blocked_jobs: usize,
    /// Total sanitization actions and mitigations performed across all inputs.
    pub total_actions_taken: usize,
    /// Total raw content bytes processed.
    pub total_bytes_processed: usize,
    /// Total wall-clock processing time in milliseconds.
    pub total_time_ms: u64,
}

/// Thread-safe shared state shared across pipeline worker threads.
pub struct SharedState {
    /// Active security policy configuration.
    pub policy: Policy,
    /// Thread-safe in-memory cache of downloaded sub-resources `(URL -> content)`.
    pub resource_cache: HashMap<String, Vec<u8>>,
}

/// Runs a concurrent batch pipeline over a collection of [`Job`]s using the specified [`Policy`].
pub fn run_pipeline(jobs: Vec<Job>, policy: Policy) -> Vec<JobResult> {
    let (results, _) = run_pipeline_with_stats(jobs, policy);
    results
}

/// Runs a concurrent batch pipeline and computes aggregated [`PipelineStats`].
pub fn run_pipeline_with_stats(jobs: Vec<Job>, policy: Policy) -> (Vec<JobResult>, PipelineStats) {
    let num_workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    run_pipeline_with_workers(jobs, policy, num_workers)
}

/// Runs a concurrent batch pipeline with a configurable number of worker threads.
pub fn run_pipeline_with_workers(
    jobs: Vec<Job>,
    policy: Policy,
    num_workers: usize,
) -> (Vec<JobResult>, PipelineStats) {
    let start_instant = std::time::Instant::now();
    let total_count = jobs.len();

    let (job_tx, job_rx) = unbounded::<Job>();
    let (result_tx, result_rx) = unbounded::<JobResult>();

    let shared_state = Arc::new(RwLock::new(SharedState {
        policy,
        resource_cache: HashMap::new(),
    }));

    let actions_counter = Arc::new(AtomicUsize::new(0));
    let bytes_counter = Arc::new(AtomicUsize::new(0));

    let workers_to_spawn = num_workers.max(1);
    let mut handles = Vec::with_capacity(workers_to_spawn);

    for _ in 0..workers_to_spawn {
        let rx = job_rx.clone();
        let tx = result_tx.clone();
        let state = Arc::clone(&shared_state);
        let a_counter = Arc::clone(&actions_counter);
        let b_counter = Arc::clone(&bytes_counter);

        let handle = thread::spawn(move || {
            while let Ok(job) = rx.recv() {
                let result = process_job(job, &state);

                if let Ok((ref bytes, ref report)) = result.output {
                    b_counter.fetch_add(bytes.len(), Ordering::Relaxed);
                    a_counter.fetch_add(report.actions.len(), Ordering::Relaxed);
                }

                let _ = tx.send(result);
            }
        });
        handles.push(handle);
    }

    drop(job_rx);
    drop(result_tx);

    for job in jobs {
        let _ = job_tx.send(job);
    }
    drop(job_tx);

    let mut final_results = Vec::with_capacity(total_count);
    let mut successful_jobs = 0;
    let mut failed_jobs = 0;
    let mut blocked_jobs = 0;

    while let Ok(result) = result_rx.recv() {
        match &result.output {
            Ok((_, report)) => {
                successful_jobs += 1;
                if report.file_blocked {
                    blocked_jobs += 1;
                }
            }
            Err(_) => {
                failed_jobs += 1;
            }
        }
        final_results.push(result);
    }

    for handle in handles {
        let _ = handle.join();
    }

    let stats = PipelineStats {
        total_jobs: total_count,
        successful_jobs,
        failed_jobs,
        blocked_jobs,
        total_actions_taken: actions_counter.load(Ordering::Relaxed),
        total_bytes_processed: bytes_counter.load(Ordering::Relaxed),
        total_time_ms: start_instant.elapsed().as_millis() as u64,
    };

    (final_results, stats)
}

/// Processes an individual job: reads content (file or remote URL), executes `sanitize_html`,
/// resolves any embedded sub-resources if configured, and builds the `JobResult`.
fn process_job(job: Job, state: &Arc<RwLock<SharedState>>) -> JobResult {
    let start_time = std::time::Instant::now();
    let policy = {
        let state_guard = state.read().unwrap();
        state_guard.policy.clone()
    };

    let raw_bytes = match &job {
        Job::LocalFile(path) => match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) => {
                return JobResult {
                    source: job,
                    output: Err(format!("Failed to read file: {}", e)),
                };
            }
        },
        Job::RemoteUrl(url_str) => {
            let parsed_url = match Url::parse(url_str) {
                Ok(u) => u,
                Err(e) => {
                    return JobResult {
                        source: job,
                        output: Err(format!("Invalid URL syntax: {}", e)),
                    };
                }
            };

            // SSRF check on top-level input URL
            if policy.resources.block_internal_ips
                && is_ssrf_host(&parsed_url, policy.resources.resolve_dns_for_ssrf)
            {
                return JobResult {
                    source: job,
                    output: Err(
                        "Blocked URL request to internal / private IP (SSRF defense)".to_string(),
                    ),
                };
            }

            // Check if already in cache
            let cached_bytes = {
                let state_guard = state.read().unwrap();
                state_guard.resource_cache.get(url_str).cloned()
            };

            if let Some(bytes) = cached_bytes {
                bytes
            } else {
                let agent = ureq::AgentBuilder::new()
                    .timeout(std::time::Duration::from_millis(
                        policy.resources.timeout_ms,
                    ))
                    .build();

                match agent.get(url_str).call() {
                    Ok(response) => {
                        let mut reader = response
                            .into_reader()
                            .take(policy.resources.max_resource_size_bytes as u64);
                        let mut bytes = Vec::new();
                        if let Err(e) = std::io::Read::read_to_end(&mut reader, &mut bytes) {
                            return JobResult {
                                source: job,
                                output: Err(format!("Failed to read URL body: {}", e)),
                            };
                        }
                        bytes
                    }
                    Err(e) => {
                        return JobResult {
                            source: job,
                            output: Err(format!("Failed to fetch URL: {}", e)),
                        };
                    }
                }
            }
        }
    };

    let job_name_lower = job.name().to_ascii_lowercase();

    // 1. PDF Documents: inspect for active content (/JavaScript, /Launch)
    let is_pdf = raw_bytes.starts_with(b"%PDF-") || job_name_lower.ends_with(".pdf");
    if is_pdf {
        let check = inspect_pdf(&raw_bytes);
        let mut report = SanitizationReport {
            file_name: job.name(),
            time_elapsed: start_time.elapsed().as_millis() as u64,
            file_blocked: false,
            actions: Vec::new(),
            resources_to_fetch: Vec::new(),
        };

        if policy.resources.block_active_documents && check.is_threat_detected {
            report.file_blocked = true;
            for threat in check.threats {
                report.actions.push(SanitizationAction {
                    rule_fired: "Active document content detected (PDF JavaScript/Launch)".to_string(),
                    location: (0, 0),
                    original_fragment: threat,
                    replaced_fragment: "Blocked PDF document containing active script/execution vector".to_string(),
                });
            }
        }

        return JobResult {
            source: job,
            output: Ok((raw_bytes, report)),
        };
    }

    // 2. SVG Vector Images: inspect and sanitize SVG scripts and XML entity bombs
    let is_svg = job_name_lower.ends_with(".svg")
        || (raw_bytes.len() > 4
            && String::from_utf8_lossy(&raw_bytes[..100.min(raw_bytes.len())]).contains("<svg"));

    if is_svg {
        let (sanitized_svg, actions, blocked) = inspect_and_sanitize_svg(&raw_bytes, &policy);
        let report = SanitizationReport {
            file_name: job.name(),
            time_elapsed: start_time.elapsed().as_millis() as u64,
            file_blocked: blocked,
            actions,
            resources_to_fetch: Vec::new(),
        };

        return JobResult {
            source: job,
            output: Ok((sanitized_svg, report)),
        };
    }

    // 3. Raster Images: inspect dimensions for decompression pixel bombs (PNG, GIF, JPEG, WebP)
    let is_raster_image = raw_bytes.starts_with(b"\x89PNG")
        || raw_bytes.starts_with(b"GIF8")
        || raw_bytes.starts_with(b"\xFF\xD8")
        || raw_bytes.starts_with(b"RIFF")
        || job_name_lower.ends_with(".png")
        || job_name_lower.ends_with(".gif")
        || job_name_lower.ends_with(".jpg")
        || job_name_lower.ends_with(".jpeg")
        || job_name_lower.ends_with(".webp");

    if is_raster_image {
        let dim_res = check_image_dimensions(&raw_bytes, policy.resources.max_image_pixels);
        let mut report = SanitizationReport {
            file_name: job.name(),
            time_elapsed: start_time.elapsed().as_millis() as u64,
            file_blocked: false,
            actions: Vec::new(),
            resources_to_fetch: Vec::new(),
        };

        match dim_res {
            Ok(_) => {
                return JobResult {
                    source: job,
                    output: Ok((raw_bytes, report)),
                };
            }
            Err(err) => {
                report.file_blocked = true;
                report.actions.push(SanitizationAction {
                    rule_fired: "Image decompression bomb detected".to_string(),
                    location: (0, 0),
                    original_fragment: format!("Image payload ({} bytes)", raw_bytes.len()),
                    replaced_fragment: format!("Blocked image decompression bomb: {}", err),
                });
                return JobResult {
                    source: job,
                    output: Ok((raw_bytes, report)),
                };
            }
        }
    }

    // 4. HTML Documents: streaming HTML parser and sub-resource fetching
    match sanitize_html(&raw_bytes, &policy) {
        Ok((sanitized_content, mut report)) => {
            report.file_name = job.name();
            report.time_elapsed = start_time.elapsed().as_millis() as u64;

            // Mark file as blocked if unallowed active content was encountered without rewriting
            if !policy.html.rewrite_active_content
                && report
                    .actions
                    .iter()
                    .any(|a| a.rule_fired.contains("active content removed"))
            {
                report.file_blocked = true;
            }

            if policy.resources.max_fetch_depth > 0 && !report.resources_to_fetch.is_empty() {
                let mut visited = std::collections::HashSet::new();

                // Read cache snapshot to avoid redundant downloads
                let cache_snapshot = {
                    let state_guard = state.read().unwrap();
                    state_guard.resource_cache.clone()
                };

                if let Ok(resources) = fetch_resources_with_cache(
                    &report.resources_to_fetch,
                    &policy,
                    1,
                    &mut visited,
                    Some(&cache_snapshot),
                ) && !resources.is_empty()
                {
                    let mut state_guard = state.write().unwrap();
                    for (url, bytes) in resources {
                        state_guard.resource_cache.insert(url, bytes);
                    }
                }
            }

            JobResult {
                source: job,
                output: Ok((sanitized_content, report)),
            }
        }
        Err(e) => JobResult {
            source: job,
            output: Err(format!("Parser error: {}", e)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_local_batch() {
        let policy = Policy::balanced();

        let dir = std::env::temp_dir();
        let path1 = dir.join("test_pipe_1.html");
        let path2 = dir.join("test_pipe_2.html");

        fs::write(&path1, "<p>Hello <b>World</b></p><script>bad();</script>").unwrap();
        fs::write(
            &path2,
            "<div>Safe content <a href=\"https://google.com\">Link</a></div>",
        )
        .unwrap();

        let jobs = vec![Job::LocalFile(path1.clone()), Job::LocalFile(path2.clone())];

        let (results, stats) = run_pipeline_with_stats(jobs, policy);

        let _ = fs::remove_file(path1);
        let _ = fs::remove_file(path2);

        assert_eq!(results.len(), 2);
        assert_eq!(stats.total_jobs, 2);
        assert_eq!(stats.successful_jobs, 2);
        assert_eq!(stats.failed_jobs, 0);
        assert!(stats.total_actions_taken >= 1); // <script> tag removed
    }

    #[test]
    fn test_pipeline_ssrf_blocking() {
        let policy = Policy::balanced();
        let jobs = vec![Job::RemoteUrl("http://127.0.0.1:8080/admin".to_string())];

        let (results, stats) = run_pipeline_with_stats(jobs, policy);
        assert_eq!(results.len(), 1);
        assert!(results[0].output.is_err());
        assert_eq!(stats.failed_jobs, 1);
    }
}
