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
use std::time::{Duration, Instant};
use url::Url;

use crate::active_content::{
    check_image_dimensions, check_xml_entities, inspect_and_sanitize_svg, inspect_pdf,
};
use crate::css::sanitize_css;
use crate::network::{fetch_resources_with_cache, is_blocked_internal};
use crate::parser::sanitize_html;
use crate::policy::Policy;
use crate::report::{Location, SanitizationAction, SanitizationReport};

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

/// Processes an individual job: acquires the input (file or remote URL), validates its
/// media type by content sniffing, routes it to the matching per-type sanitiser, and
/// builds the `JobResult`.
fn process_job(job: Job, state: &Arc<RwLock<SharedState>>) -> JobResult {
    let start_time = Instant::now();
    let policy = {
        let state_guard = state.read().unwrap();
        state_guard.policy.clone()
    };
    let output = sanitize_job(&job, &policy, state, start_time);
    JobResult {
        source: job,
        output,
    }
}

/// Bytes acquired for a job, before any sanitisation.
enum Acquired {
    /// Input bytes and the media type declared by the origin (remote inputs only).
    Body {
        bytes: Vec<u8>,
        declared_type: Option<String>,
    },
    /// The input was refused while being acquired (a resource budget was violated).
    Refused(SanitizationAction),
}

/// Reads a local file, or fetches a remote URL under the SSRF guard and the resource budgets.
fn acquire_input(
    job: &Job,
    policy: &Policy,
    state: &Arc<RwLock<SharedState>>,
) -> Result<Acquired, String> {
    match job {
        Job::LocalFile(path) => fs::read(path)
            .map(|bytes| Acquired::Body {
                bytes,
                declared_type: None,
            })
            .map_err(|e| format!("Failed to read file: {}", e)),
        Job::RemoteUrl(url_str) => {
            let parsed_url =
                Url::parse(url_str).map_err(|e| format!("Invalid URL syntax: {}", e))?;

            // SSRF check on top-level input URL (trusted internal hosts excepted)
            if is_blocked_internal(&parsed_url, policy) {
                return Err(
                    "Blocked URL request to internal / private IP (SSRF defense)".to_string(),
                );
            }

            // Check if already in cache
            let cached_bytes = {
                let state_guard = state.read().unwrap();
                state_guard.resource_cache.get(url_str).cloned()
            };
            if let Some(bytes) = cached_bytes {
                return Ok(Acquired::Body {
                    bytes,
                    declared_type: None,
                });
            }

            let agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_millis(policy.resources.timeout_ms))
                .build();
            let response = agent
                .get(url_str)
                .call()
                .map_err(|e| format!("Failed to fetch URL: {}", e))?;

            // Recorded only to be compared with what the content really is: the declared
            // type never decides how the input is parsed (MIME-confusion defence).
            let declared_type = response.header("Content-Type").map(normalise_media_type);

            match read_body_within_budget(
                response,
                policy.resources.max_resource_size_bytes,
                policy.resources.timeout_ms,
            )? {
                BodyRead::Complete(bytes) => Ok(Acquired::Body {
                    bytes,
                    declared_type,
                }),
                BodyRead::Refused(action) => Ok(Acquired::Refused(action)),
            }
        }
    }
}

/// Lower-cased media type without parameters: `"Text/HTML; charset=utf-8"` -> `"text/html"`.
fn normalise_media_type(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// Media type inferred from the content itself (magic numbers or leading markup).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sniffed {
    Pdf,
    Png,
    Gif,
    Jpeg,
    Webp,
    Svg,
    Xml,
    Html,
    Text,
    Binary,
}

impl Sniffed {
    fn mime(self) -> &'static str {
        match self {
            Sniffed::Pdf => "application/pdf",
            Sniffed::Png => "image/png",
            Sniffed::Gif => "image/gif",
            Sniffed::Jpeg => "image/jpeg",
            Sniffed::Webp => "image/webp",
            Sniffed::Svg => "image/svg+xml",
            Sniffed::Xml => "application/xml",
            Sniffed::Html => "text/html",
            Sniffed::Text => "text/plain",
            Sniffed::Binary => "application/octet-stream",
        }
    }
}

/// Classifies the input by its leading bytes. Binary signatures win over everything;
/// markup is recognised from the first non-blank characters of the first KiB.
fn sniff(bytes: &[u8]) -> Sniffed {
    if bytes.starts_with(b"%PDF-") {
        return Sniffed::Pdf;
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Sniffed::Png;
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Sniffed::Gif;
    }
    if bytes.starts_with(b"\xFF\xD8\xFF") {
        return Sniffed::Jpeg;
    }
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        return Sniffed::Webp;
    }

    let head = &bytes[..bytes.len().min(1024)];
    let text = String::from_utf8_lossy(head);
    let lower = text.trim_start_matches('\u{feff}').trim_start().to_ascii_lowercase();
    if lower.contains("<svg") {
        Sniffed::Svg
    } else if lower.starts_with("<?xml") {
        Sniffed::Xml
    } else if lower.starts_with('<') {
        Sniffed::Html
    } else if head.contains(&0) {
        Sniffed::Binary
    } else {
        Sniffed::Text
    }
}

/// Declared types that denote executable content. The declaration alone is enough to
/// refuse: a browser would execute the body as script whatever it contains.
const ACTIVE_SCRIPT_TYPES: &[&str] = &[
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
    "text/x-javascript",
    "text/ecmascript",
    "application/ecmascript",
    "application/x-ecmascript",
    "text/jscript",
    "text/livescript",
    "text/vbscript",
];

/// Whether the declared type contradicts the sniffed content.
fn is_mime_confusion(declared: &str, sniffed: Sniffed) -> bool {
    let declared = match declared {
        "text/xml" => "application/xml",
        "application/xhtml+xml" => "text/html",
        "image/jpg" | "image/pjpeg" => "image/jpeg",
        other => other,
    };
    if declared == sniffed.mime() {
        return false;
    }
    // Plain text carries no signature, so it is consistent with any textual declaration
    // (text/css, text/plain, application/json, ...).
    let textual = declared.starts_with("text/")
        || declared == "application/json"
        || declared.ends_with("+json")
        || declared.ends_with("+xml");
    !(sniffed == Sniffed::Text && textual)
}

/// Report skeleton for a job.
fn new_report(
    job: &Job,
    start_time: Instant,
    actions: Vec<SanitizationAction>,
    blocked: bool,
) -> SanitizationReport {
    SanitizationReport {
        file_name: job.name(),
        time_elapsed: start_time.elapsed().as_millis() as u64,
        file_blocked: blocked,
        actions,
        resources_to_fetch: Vec::new(),
    }
}

/// Acquires, classifies and sanitises one input.
fn sanitize_job(
    job: &Job,
    policy: &Policy,
    state: &Arc<RwLock<SharedState>>,
    start_time: Instant,
) -> Result<(Vec<u8>, SanitizationReport), String> {
    let (raw_bytes, declared_type) = match acquire_input(job, policy, state)? {
        Acquired::Body {
            bytes,
            declared_type,
        } => (bytes, declared_type),
        Acquired::Refused(action) => {
            // A budget violation is a policy decision, not an I/O failure.
            return Ok((Vec::new(), budget_refusal(job, start_time, action)));
        }
    };

    // 0. DECLARED ACTIVE TYPE: refused outright, whatever the body contains.
    if let Some(declared) = declared_type.as_deref()
        && ACTIVE_SCRIPT_TYPES.contains(&declared)
    {
        let action = SanitizationAction {
            rule_fired: "Declared active content type refused".to_string(),
            location: Location::Document,
            original_fragment: format!("Content-Type: {declared}"),
            replaced_fragment: "Input refused: declared as executable script".to_string(),
        };
        return Ok((Vec::new(), new_report(job, start_time, vec![action], true)));
    }

    // 1. MIME CONFUSION: the sniffed type decides how the input is handled; a declaration
    //    that contradicts it is reported, never trusted.
    let sniffed = sniff(&raw_bytes);
    let mut mime_actions = Vec::new();
    if let Some(declared) = declared_type.as_deref()
        && is_mime_confusion(declared, sniffed)
    {
        mime_actions.push(SanitizationAction {
            rule_fired: "MIME confusion: declared type does not match content".to_string(),
            location: Location::Document,
            original_fragment: format!("declared {declared}, sniffed {}", sniffed.mime()),
            replaced_fragment: format!(
                "Handled as {} (content sniffing overrides the declaration)",
                sniffed.mime()
            ),
        });
    }

    let job_name_lower = job.name().to_ascii_lowercase();

    // 2. PDF documents: inspect for active content (/JavaScript, /Launch, ...)
    if sniffed == Sniffed::Pdf || has_extension(&job_name_lower, &[".pdf"]) {
        let check = inspect_pdf(&raw_bytes);
        let mut actions = mime_actions;
        let mut blocked = false;
        if policy.resources.block_active_documents && check.is_threat_detected {
            blocked = true;
            for (threat, offset) in check.threats.into_iter().zip(check.offsets) {
                actions.push(SanitizationAction {
                    rule_fired: "Active document content detected (PDF JavaScript/Launch)"
                        .to_string(),
                    location: Location::Byte { offset },
                    original_fragment: threat,
                    replaced_fragment:
                        "Blocked PDF document containing active script/execution vector"
                            .to_string(),
                });
            }
        }
        return Ok((raw_bytes, new_report(job, start_time, actions, blocked)));
    }

    // 3. SVG images: scripts, event handlers and XML entity bombs
    if sniffed == Sniffed::Svg || has_extension(&job_name_lower, &[".svg"]) {
        let (sanitized_svg, svg_actions, blocked) = inspect_and_sanitize_svg(&raw_bytes, policy);
        let mut actions = mime_actions;
        actions.extend(svg_actions);
        return Ok((sanitized_svg, new_report(job, start_time, actions, blocked)));
    }

    // 4. Raster images: dimension check against decompression pixel bombs
    let is_raster = matches!(
        sniffed,
        Sniffed::Png | Sniffed::Gif | Sniffed::Jpeg | Sniffed::Webp
    ) || has_extension(&job_name_lower, &[".png", ".gif", ".jpg", ".jpeg", ".webp"]);
    if is_raster {
        let mut actions = mime_actions;
        let mut blocked = false;
        if let Err(err) = check_image_dimensions(&raw_bytes, policy.resources.max_image_pixels) {
            blocked = true;
            actions.push(SanitizationAction {
                rule_fired: "Image decompression bomb detected".to_string(),
                location: Location::Document,
                original_fragment: format!("Image payload ({} bytes)", raw_bytes.len()),
                replaced_fragment: format!("Blocked image decompression bomb: {}", err),
            });
        }
        return Ok((raw_bytes, new_report(job, start_time, actions, blocked)));
    }

    // 5. Generic XML: refuse entity-expansion bombs and external entities (XXE) before
    //    any further processing; otherwise fall through to best-effort markup sanitisation.
    if sniffed == Sniffed::Xml || has_extension(&job_name_lower, &[".xml"]) {
        if let Some(reason) = check_xml_entities(&String::from_utf8_lossy(&raw_bytes)) {
            let mut actions = mime_actions;
            actions.push(SanitizationAction {
                rule_fired: "XML Entity Bomb / XXE mitigation".to_string(),
                location: Location::Document,
                original_fragment: reason,
                replaced_fragment: "Input refused: entity expansion is never performed"
                    .to_string(),
            });
            return Ok((Vec::new(), new_report(job, start_time, actions, true)));
        }
    }

    // 6. Stylesheets: CSS has no signature, so a text/css declaration (or a .css name) is
    //    honoured only when the content is plain text, i.e. not markup or binary.
    let declared_css = declared_type.as_deref() == Some("text/css") || has_extension(&job_name_lower, &[".css"]);
    if declared_css && sniffed == Sniffed::Text {
        let (sanitized_css, css_actions) = sanitize_css(&String::from_utf8_lossy(&raw_bytes), policy);
        let mut actions = mime_actions;
        actions.extend(css_actions);
        return Ok((
            sanitized_css.into_bytes(),
            new_report(job, start_time, actions, false),
        ));
    }

    // 7. HTML documents: streaming HTML parser and sub-resource fetching
    let (sanitized_content, mut report) =
        sanitize_html(&raw_bytes, policy).map_err(|e| format!("Parser error: {}", e))?;
    report.file_name = job.name();
    if !mime_actions.is_empty() {
        mime_actions.append(&mut report.actions);
        report.actions = mime_actions;
    }

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
        // The fetcher stops at max_requests_per_job; say so in the report, otherwise the
        // cap is invisible. Counts the document's own references (first level).
        let referenced = report
            .resources_to_fetch
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        if referenced > policy.resources.max_requests_per_job {
            report.actions.push(SanitizationAction {
                rule_fired: "Sub-resource request cap reached".to_string(),
                location: Location::Document,
                original_fragment: format!("{referenced} distinct sub-resources referenced"),
                replaced_fragment: format!(
                    "only the first {} are fetched (max_requests_per_job)",
                    policy.resources.max_requests_per_job
                ),
            });
        }

        let mut visited = std::collections::HashSet::new();

        // Read cache snapshot to avoid redundant downloads
        let cache_snapshot = {
            let state_guard = state.read().unwrap();
            state_guard.resource_cache.clone()
        };

        if let Ok(resources) = fetch_resources_with_cache(
            &report.resources_to_fetch,
            policy,
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

    // Measured last, so that it includes sub-resource fetching.
    report.time_elapsed = start_time.elapsed().as_millis() as u64;
    Ok((sanitized_content, report))
}

/// Whether `name` (already lower-cased) ends with one of `extensions`.
fn has_extension(name: &str, extensions: &[&str]) -> bool {
    extensions.iter().any(|ext| name.ends_with(ext))
}

/// Outcome of reading a remote response body under the policy's budgets.
enum BodyRead {
    /// The whole body was read within every budget.
    Complete(Vec<u8>),
    /// A budget was violated: the input must be refused, never truncated or reported clean.
    Refused(SanitizationAction),
}

/// Reads a remote body while enforcing the size and time budgets.
///
/// Note: `ureq` transparently decompresses `gzip`/`br` bodies and, when it does, removes
/// the `Content-Encoding` and `Content-Length` headers from the response. The budget is
/// therefore enforced on the *decoded* stream, which is what defeats compression bombs,
/// and compression cannot be detected from the headers.
///
/// - Declared `Content-Length` above the limit (identity-encoded bodies only): refused
///   before reading anything.
/// - Decoded body above the limit: refused. Reading stops at `limit + 1` bytes, so memory
///   stays bounded even for compression bombs.
/// - Read timeout (slow-drip / Slowloris-style responses): refused.
/// - Undecodable or truncated body (`InvalidData` / `InvalidInput` / `UnexpectedEof`: corrupt compressed
///   stream, stream cut short, body shorter than declared): refused, since partial content
///   can neither be sanitised reliably nor reported as clean.
///
/// Other I/O errors (connection reset, ...) are genuine failures and are returned as `Err`.
fn read_body_within_budget(
    response: ureq::Response,
    limit: usize,
    timeout_ms: u64,
) -> Result<BodyRead, String> {
    let refuse = |rule: &str, original: String| {
        BodyRead::Refused(SanitizationAction {
            rule_fired: rule.to_string(),
            location: Location::Document,
            original_fragment: original,
            replaced_fragment: "Input refused (budget exceeded; partial content is never reported as clean)"
                .to_string(),
        })
    };

    if let Some(declared) = response
        .header("Content-Length")
        .and_then(|v| v.trim().parse::<u64>().ok())
        && declared > limit as u64
    {
        return Ok(refuse(
            "Input size budget exceeded",
            format!("declared Content-Length {declared} exceeds the {limit}-byte budget"),
        ));
    }

    let mut reader = response.into_reader().take((limit as u64).saturating_add(1));
    let mut bytes = Vec::new();
    match reader.read_to_end(&mut bytes) {
        Ok(_) if bytes.len() > limit => Ok(refuse(
            "Input size budget exceeded",
            format!(
                "decoded body exceeds the {limit}-byte budget (enforced after decompression: covers compression bombs)"
            ),
        )),
        Ok(_) => Ok(BodyRead::Complete(bytes)),
        Err(e) if matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) => {
            Ok(refuse(
                "Read time budget exceeded (slow or stalled response)",
                format!("body not complete within {timeout_ms} ms ({} bytes received): {e}", bytes.len()),
            ))
        }
        // flate2 reports a bad gzip header as InvalidInput, a corrupt stream as InvalidData,
        // and a stream cut short as UnexpectedEof.
        Err(e) if matches!(
            e.kind(),
            std::io::ErrorKind::InvalidData
                | std::io::ErrorKind::InvalidInput
                | std::io::ErrorKind::UnexpectedEof
        ) => {
            Ok(refuse(
                "Malformed or truncated response body",
                format!("{:?} after {} bytes: {e}", e.kind(), bytes.len()),
            ))
        }
        Err(e) => Err(format!("Failed to read URL body: {e}")),
    }
}

/// Report for an input refused before sanitisation because it violated a budget.
fn budget_refusal(
    job: &Job,
    start_time: std::time::Instant,
    action: SanitizationAction,
) -> SanitizationReport {
    SanitizationReport {
        file_name: job.name(),
        time_elapsed: start_time.elapsed().as_millis() as u64,
        file_blocked: true,
        actions: vec![action],
        resources_to_fetch: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One-shot HTTP server on 127.0.0.1: reads the request, writes `head` + `body`,
    /// then optionally keeps the connection open for `stall` without sending more.
    fn serve_once(head: &str, body: Vec<u8>, stall: Option<std::time::Duration>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let head = head.to_string();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0u8; 2048];
                let _ = std::io::Read::read(&mut stream, &mut request);
                let _ = std::io::Write::write_all(&mut stream, head.as_bytes());
                let _ = std::io::Write::write_all(&mut stream, &body);
                if let Some(duration) = stall {
                    std::thread::sleep(duration);
                }
            }
        });
        format!("http://{addr}/page")
    }

    /// Balanced policy pointed at a local test server with small, fast budgets.
    fn budget_policy() -> Policy {
        let mut policy = Policy::balanced();
        policy.resources.block_internal_ips = false; // the test server lives on 127.0.0.1
        policy.resources.max_fetch_depth = 0;
        policy.resources.max_resource_size_bytes = 1024;
        policy.resources.timeout_ms = 500;
        policy
    }

    /// Runs one remote job and returns its report, asserting it was refused (not failed).
    fn refused_report(url: String) -> SanitizationReport {
        let (results, stats) = run_pipeline_with_stats(vec![Job::RemoteUrl(url)], budget_policy());
        let (output, report) = results[0]
            .output
            .as_ref()
            .expect("a budget violation must be a refusal, not an error");
        assert!(report.file_blocked, "input must be refused outright");
        assert!(output.is_empty(), "no partial content may be returned");
        assert_eq!(stats.blocked_jobs, 1);
        assert_eq!(stats.failed_jobs, 0);
        report.clone()
    }

    #[test]
    fn test_oversized_body_is_refused_not_truncated() {
        // No Content-Length: exercises the streaming check, not the header pre-check.
        let url = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n",
            vec![b'a'; 4096],
            None,
        );
        let report = refused_report(url);
        assert!(report.actions[0].rule_fired.contains("Input size budget exceeded"));
    }

    #[test]
    fn test_declared_content_length_over_budget_is_refused() {
        let url = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 999999\r\n\r\n",
            b"<p>tiny</p>".to_vec(),
            None,
        );
        let report = refused_report(url);
        assert!(report.actions[0].original_fragment.contains("Content-Length 999999"));
    }

    #[test]
    fn test_compression_bomb_is_refused() {
        // gzip of 4096 x b'a' (40 bytes on the wire, 4 KiB once decoded; budget is 1 KiB).
        let gzip: Vec<u8> = vec![
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xed, 0xc1, 0x01, 0x0d,
            0x00, 0x00, 0x00, 0xc2, 0xa0, 0xac, 0xef, 0x5f, 0xc2, 0x1e, 0x0e, 0x28, 0x00, 0x00,
            0x00, 0xe0, 0xdd, 0x00, 0x73, 0xdc, 0x99, 0x9c, 0x00, 0x10, 0x00, 0x00,
        ];
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            gzip.len()
        );
        let url = serve_once(&head, gzip, None);
        let report = refused_report(url);
        assert!(report.actions[0].rule_fired.contains("Input size budget exceeded"));
        assert!(report.actions[0].original_fragment.contains("after decompression"));
    }

    #[test]
    fn test_corrupt_compressed_body_is_refused() {
        // Declares gzip but sends bytes that are not a gzip stream.
        let garbage = b"this is definitely not gzip data".to_vec();
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            garbage.len()
        );
        let url = serve_once(&head, garbage, None);
        let report = refused_report(url);
        assert!(report.actions[0].rule_fired.contains("Malformed or truncated response body"));
    }

    #[test]
    fn test_stalled_response_is_refused() {
        // Promises 100 bytes, sends 3, then stalls well past the 500 ms timeout.
        let url = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n",
            b"<p>".to_vec(),
            Some(std::time::Duration::from_secs(3)),
        );
        let report = refused_report(url);
        assert!(report.actions[0].rule_fired.contains("Read time budget exceeded"));
    }

    /// Runs one remote job and returns its output and report, asserting it did not fail.
    fn remote_result(url: String) -> (Vec<u8>, SanitizationReport) {
        let (results, _) = run_pipeline_with_stats(vec![Job::RemoteUrl(url)], budget_policy());
        let (output, report) = results[0].output.as_ref().expect("the job must not fail");
        (output.clone(), report.clone())
    }

    /// HTTP head with the given content type and length.
    fn head_for(content_type: &str, body: &[u8]) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
    }

    #[test]
    fn test_declared_javascript_is_refused() {
        let body = b"This is just plain text, not JavaScript code.".to_vec();
        let url = serve_once(&head_for("text/javascript", &body), body, None);
        let report = refused_report(url);
        assert!(report.actions[0].rule_fired.contains("Declared active content type refused"));
    }

    #[test]
    fn test_html_disguised_as_png_is_sanitised_as_html() {
        let body = b"<!doctype html><html><body><h1>Looks like PNG</h1>\
<script>alert('xss')</script></body></html>"
            .to_vec();
        let url = serve_once(&head_for("image/png", &body), body, None);
        let (output, report) = remote_result(url);
        assert!(!report.file_blocked);
        assert!(report.actions[0].rule_fired.contains("MIME confusion"));
        assert!(report.actions[0]
            .original_fragment
            .contains("declared image/png, sniffed text/html"));
        assert!(!String::from_utf8_lossy(&output).contains("<script"));
    }

    #[test]
    fn test_png_declared_as_octet_stream_is_classified_as_image() {
        // 1x1 PNG: signature + IHDR is all the dimension check needs.
        let mut body = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR".to_vec();
        body.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]);
        let url = serve_once(&head_for("application/octet-stream", &body), body, None);
        let (_, report) = remote_result(url);
        assert!(!report.file_blocked);
        assert!(report.actions[0]
            .original_fragment
            .contains("declared application/octet-stream, sniffed image/png"));
    }

    #[test]
    fn test_xml_bomb_is_refused() {
        let body = b"<?xml version=\"1.0\"?>\n<!DOCTYPE lolz [\n<!ENTITY lol \"lol\">\n\
<!ENTITY lol2 \"&lol;&lol;&lol;\">\n]>\n<lolz>&lol2;</lolz>"
            .to_vec();
        let url = serve_once(&head_for("application/xml", &body), body, None);
        let report = refused_report(url);
        assert!(report
            .actions
            .iter()
            .any(|a| a.rule_fired.contains("XML Entity Bomb")));
    }

    #[test]
    fn test_remote_stylesheet_is_sanitised_as_css() {
        let body = b"body {\n  background-image: url(\"javascript:alert(1)\");\n  color: red;\n}\n\
@import url(\"http://evil.example/exfil.css\");\n"
            .to_vec();
        let url = serve_once(&head_for("text/css", &body), body, None);
        let (output, report) = remote_result(url);
        let css = String::from_utf8_lossy(&output);
        assert!(!report.file_blocked);
        assert!(css.contains("color: red"));
        assert!(!css.contains("javascript:"));
        assert!(!css.contains("evil.example"));
        assert!(report
            .actions
            .iter()
            .any(|a| a.rule_fired.contains("CSS dangerous url()")));
        assert!(report
            .actions
            .iter()
            .any(|a| a.rule_fired.contains("Cross-origin CSS @import")));
        // text/css with plain-text content is consistent: no MIME confusion.
        assert!(!report
            .actions
            .iter()
            .any(|a| a.rule_fired.contains("MIME confusion")));
    }

    #[test]
    fn test_trusted_internal_host_keeps_ssrf_guard_on() {
        // The test origin (127.0.0.1) is trusted; the cloud-metadata address it references
        // is not, so the guard must neutralise it instead of fetching it.
        let body = b"<html><body><p>ok</p><img src=\"http://169.254.169.254/latest/meta-data/\"></body></html>".to_vec();
        let url = serve_once(&head_for("text/html", &body), body, None);
        let mut policy = budget_policy();
        policy.resources.block_internal_ips = true;
        policy.resources.trusted_internal_hosts.insert("127.0.0.1".to_string());
        policy.resources.max_fetch_depth = 3;

        let started = Instant::now();
        let (results, stats) = run_pipeline_with_stats(vec![Job::RemoteUrl(url)], policy);
        let (output, report) = results[0]
            .output
            .as_ref()
            .expect("a trusted origin must be fetched");
        assert_eq!(stats.failed_jobs, 0);

        let html = String::from_utf8_lossy(output);
        assert!(html.contains("<p>ok</p>"), "page content must survive");
        assert!(!html.contains("169.254.169.254"), "internal address must not be served");
        assert!(report
            .actions
            .iter()
            .any(|a| a.rule_fired.contains("Internal network address")));
        // Nothing was fetched from the metadata address (no timeout was waited for).
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn test_sub_resource_request_cap_is_reported() {
        let mut html = String::from("<p>gallery</p>");
        for i in 0..25 {
            // Trusted loopback on a closed port: every fetch fails fast, no external traffic.
            html.push_str(&format!("<img src=\"http://127.0.0.1:9/img{i}.png\">"));
        }
        let path = std::env::temp_dir().join("web_sanitizer_request_cap.html");
        fs::write(&path, html).unwrap();

        let mut policy = Policy::balanced();
        policy
            .resources
            .trusted_internal_hosts
            .insert("127.0.0.1".to_string());
        policy.resources.max_requests_per_job = 20;
        policy.resources.timeout_ms = 500;

        let (results, _) = run_pipeline_with_stats(vec![Job::LocalFile(path.clone())], policy);
        let _ = fs::remove_file(&path);

        let (_, report) = results[0].output.as_ref().expect("a local job must not fail");
        let cap = report
            .actions
            .iter()
            .find(|a| a.rule_fired.contains("request cap"))
            .expect("the cap must be reported");
        assert!(cap.original_fragment.contains("25"));
    }

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
