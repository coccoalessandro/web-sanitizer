use crossbeam_channel::{unbounded};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::thread;

use crate::parser::sanitize_html;
use crate::policy::Policy;
use crate::report::SanitizationReport;

#[derive(Clone, Debug)]
pub enum Job {
    LocalFile(PathBuf),
    RemoteUrl(String),
}

impl Job {
    pub fn name(&self) -> String {
        match self {
            Job::LocalFile(p) => p.display().to_string(),
            Job::RemoteUrl(u) => u.clone(),
        }
    }
}

pub struct JobResult {
    pub source: Job,
    pub output: Result<(Vec<u8>, SanitizationReport), String>,
}

pub struct SharedState {
    pub policy: Policy,
    pub resource_cache: HashMap<String, Vec<u8>>,
}

pub fn run_pipeline(jobs: Vec<Job>, policy: Policy) -> Vec<JobResult> {
    let (job_tx, job_rx) = unbounded::<Job>();
    let (result_tx, result_rx) = unbounded::<JobResult>();

    let shared_state = Arc::new(RwLock::new(SharedState {
        policy,
        resource_cache: HashMap::new(),
    }));

    let num_workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let mut handles = Vec::with_capacity(num_workers);

    for _ in 0..num_workers {
        let rx = job_rx.clone();
        let tx = result_tx.clone();
        let state = Arc::clone(&shared_state);

        let handle = thread::spawn(move || {
            while let Ok(job) = rx.recv() {
                let result = process_job(job, &state);
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

    let mut final_results = Vec::new();
    while let Ok(result) = result_rx.recv() {
        final_results.push(result);
    }

    for handle in handles {
        let _ = handle.join();
    }

    final_results
}

fn process_job(job: Job, state: &Arc<RwLock<SharedState>>) -> JobResult {
    let start_time = std::time::Instant::now();
    let policy = {
        let state_guard = state.read().unwrap();
        state_guard.policy.clone()
    };

    let raw_bytes = match &job {
        Job::LocalFile(path) => match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) => return JobResult {
                source: job,
                output: Err(format!("Failed to read file: {}", e)),
            },
        },
        Job::RemoteUrl(url_str) => {
            let agent = ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_millis(policy.resources.timeout_ms))
                .build();
            
            match agent.get(url_str).call() {
                Ok(response) => {
                    let mut reader = response.into_reader().take(policy.resources.max_resource_size_bytes as u64);
                    let mut bytes = Vec::new();
                    if let Err(e) = std::io::Read::read_to_end(&mut reader, &mut bytes) {
                        return JobResult {
                            source: job,
                            output: Err(format!("Failed to read url body: {}", e)),
                        }
                    }
                    bytes
                },
                Err(e) => return JobResult {
                    source: job,
                    output: Err(format!("Failed to fetch url: {}", e)),
                }
            }
        }
    };

    match sanitize_html(&raw_bytes, &policy) {
        Ok((sanitized_content, mut report)) => {
            report.file_name = job.name();
            report.time_elapsed = start_time.elapsed().as_millis() as u64;

            if policy.resources.max_fetch_depth > 0 && !report.resources_to_fetch.is_empty() {
                let mut visited = std::collections::HashSet::new();
                if let Ok(resources) = crate::network::fetch_resources(&report.resources_to_fetch, &policy, 1, &mut visited) {
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
        },
        Err(e) => JobResult {
            source: job,
            output: Err(format!("Parser error: {}", e)),
        }
    }
}
