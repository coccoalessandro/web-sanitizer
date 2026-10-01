//! Automated evaluation test suite against the curated test corpus.
//!
//! Validates:
//! - Detection rate on malicious samples (True Positives, False Negatives).
//! - False-positive rate on benign pages (True Negatives, False Positives).
//! - Accuracy against documented ground truth (`tests/corpus/ground_truth.json`).
//! - Batch execution via the CLI frontend.

use engine::pipeline::{Job, run_pipeline_with_stats};
use engine::policy::Policy;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GroundTruthManifest {
    version: String,
    description: String,
    samples: Vec<SampleExpectation>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SampleExpectation {
    file: String,
    category: String,
    threat_type: String,
    expected_blocked: bool,
    expected_actions_max: Option<usize>,
    min_expected_actions: Option<usize>,
    expected_rule_patterns: Option<Vec<String>>,
    description: String,
}

fn get_corpus_dir() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().expect("Workspace root");
    workspace_root.join("tests").join("corpus")
}

#[test]
fn test_corpus_ground_truth_correctness() {
    let corpus_dir = get_corpus_dir();
    let ground_truth_path = corpus_dir.join("ground_truth.json");

    assert!(
        ground_truth_path.exists(),
        "Ground truth file missing at {:?}",
        ground_truth_path
    );

    let manifest_content =
        fs::read_to_string(&ground_truth_path).expect("Failed to read ground_truth.json");
    let manifest: GroundTruthManifest =
        serde_json::from_str(&manifest_content).expect("Failed to deserialize ground_truth.json");

    let policy = Policy::balanced();

    let mut tp = 0; // True Positives: malicious properly detected/neutralized
    let mut fp = 0; // False Positives: benign erroneously altered/blocked
    let mut tn = 0; // True Negatives: benign preserved completely intact
    let mut fn_count = 0; // False Negatives: malicious that slipped through undetected

    println!(
        "\n=========================================================================================="
    );
    println!(
        "                           WEB SANITIZER CORPUS EVALUATION                                "
    );
    println!(
        "=========================================================================================="
    );
    println!(
        "{:<32} {:<12} {:<8} {:<9} {:<12}",
        "Sample File", "Category", "Blocked", "Actions", "Evaluation"
    );
    println!(
        "------------------------------------------------------------------------------------------"
    );

    for sample in &manifest.samples {
        let sample_path = corpus_dir.join(&sample.file);
        assert!(
            sample_path.exists(),
            "Corpus sample missing on disk: {:?}",
            sample_path
        );

        let job = Job::LocalFile(sample_path.clone());
        let (results, _) = run_pipeline_with_stats(vec![job], policy.clone());
        assert_eq!(results.len(), 1, "Pipeline should return 1 result");

        let result = &results[0];
        let (_output_bytes, report) = match &result.output {
            Ok((bytes, rep)) => (bytes, rep),
            Err(e) => panic!(
                "Job execution failed unexpectedly on {:?}: {}",
                sample.file, e
            ),
        };

        if sample.category == "benign" {
            let max_allowed_actions = sample.expected_actions_max.unwrap_or(0);
            let is_safe = !report.file_blocked && report.actions.len() <= max_allowed_actions;

            if is_safe {
                tn += 1;
                println!(
                    "{:<32} {:<12} {:<8} {:<9} \x1b[32mPASS (TN)\x1b[0m",
                    sample.file,
                    sample.category,
                    report.file_blocked,
                    report.actions.len()
                );
            } else {
                fp += 1;
                eprintln!(
                    "{:<32} {:<12} {:<8} {:<9} \x1b[31mFAIL (FP)\x1b[0m",
                    sample.file,
                    sample.category,
                    report.file_blocked,
                    report.actions.len()
                );
                for action in &report.actions {
                    eprintln!(
                        "   Spurious Action: {} -> {}",
                        action.rule_fired, action.replaced_fragment
                    );
                }
            }

            assert!(
                !report.file_blocked,
                "Benign sample {:?} was incorrectly blocked!",
                sample.file
            );
            assert!(
                report.actions.len() <= max_allowed_actions,
                "Benign sample {:?} had {} spurious actions (max expected: {})",
                sample.file,
                report.actions.len(),
                max_allowed_actions
            );
        } else if sample.category == "malicious" {
            let min_actions = sample.min_expected_actions.unwrap_or(1);
            let actions_detected = report.actions.len() >= min_actions;
            let blocked_matches = !sample.expected_blocked || report.file_blocked;

            let is_detected = actions_detected && blocked_matches;

            if is_detected {
                tp += 1;
                println!(
                    "{:<32} {:<12} {:<8} {:<9} \x1b[32mPASS (TP)\x1b[0m",
                    sample.file,
                    sample.category,
                    report.file_blocked,
                    report.actions.len()
                );
            } else {
                fn_count += 1;
                eprintln!(
                    "{:<32} {:<12} {:<8} {:<9} \x1b[31mFAIL (FN)\x1b[0m",
                    sample.file,
                    sample.category,
                    report.file_blocked,
                    report.actions.len()
                );
            }

            if sample.expected_blocked {
                assert!(
                    report.file_blocked,
                    "Malicious sample {:?} was expected to be blocked but wasn't!",
                    sample.file
                );
            }

            assert!(
                report.actions.len() >= min_actions,
                "Malicious sample {:?} triggered only {} actions, expected at least {}",
                sample.file,
                report.actions.len(),
                min_actions
            );

            // Verify specific expected rules if declared
            if let Some(ref expected_patterns) = sample.expected_rule_patterns {
                for pattern in expected_patterns {
                    let matched = report
                        .actions
                        .iter()
                        .any(|a| a.rule_fired.contains(pattern));
                    assert!(
                        matched,
                        "Sample {:?} failed to trigger expected rule matching '{}'. Fired rules: {:?}",
                        sample.file,
                        pattern,
                        report
                            .actions
                            .iter()
                            .map(|a| &a.rule_fired)
                            .collect::<Vec<_>>()
                    );
                }
            }
        }
    }

    let total = tp + tn + fp + fn_count;
    let detection_rate = (tp as f64 / (tp + fn_count) as f64) * 100.0;
    let specificity = (tn as f64 / (tn + fp) as f64) * 100.0;
    let precision = (tp as f64 / (tp + fp) as f64) * 100.0;
    let accuracy = ((tp + tn) as f64 / total as f64) * 100.0;

    println!(
        "------------------------------------------------------------------------------------------"
    );
    println!("Evaluation Metrics Summary (Ground Truth Comparison):");
    println!("  Total Samples Evaluated: {}", total);
    println!("  True Positives  (TP):    {}", tp);
    println!("  True Negatives  (TN):    {}", tn);
    println!("  False Positives (FP):    {}", fp);
    println!("  False Negatives (FN):    {}", fn_count);
    println!("  Detection Rate (Recall): {:.2}%", detection_rate);
    println!("  Specificity:             {:.2}%", specificity);
    println!("  Precision:               {:.2}%", precision);
    println!("  Overall Accuracy:        {:.2}%", accuracy);
    println!(
        "==========================================================================================\n"
    );

    assert_eq!(fp, 0, "False Positive rate must be 0% on benign samples!");
    assert_eq!(
        fn_count, 0,
        "False Negative rate must be 0% on malicious samples!"
    );
    assert_eq!(detection_rate, 100.0);
    assert_eq!(accuracy, 100.0);
}

#[test]
fn test_corpus_cli_batch_run() {
    let corpus_dir = get_corpus_dir();
    let temp_out = std::env::temp_dir().join("corpus_cli_eval_output");
    let report_file = temp_out.join("batch_corpus_report.json");

    let _ = fs::remove_dir_all(&temp_out);
    fs::create_dir_all(&temp_out).unwrap();

    let bin_path = env!("CARGO_BIN_EXE_cli");

    // Run CLI recursively across tests/corpus
    let output = Command::new(bin_path)
        .arg("-d")
        .arg(&corpus_dir)
        .arg("-o")
        .arg(&temp_out)
        .arg("--report-file")
        .arg(&report_file)
        .arg("-p")
        .arg("balanced")
        .output()
        .expect("Failed to execute CLI on corpus");

    // Because malicious corpus contains blocked samples (e.g. PDF JavaScript, XML entity bomb, pixel floods),
    // the CLI should return exit code 1 to indicate blocked content
    assert!(
        !output.status.success(),
        "CLI must exit with non-zero code because malicious corpus contains blocked content"
    );
    assert_eq!(output.status.code(), Some(1));

    // Verify report file was generated
    assert!(
        report_file.exists(),
        "Aggregated report file must be written to disk"
    );

    let report_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report_file).unwrap()).unwrap();

    let total_jobs = report_json["stats"]["total_jobs"].as_u64().unwrap();
    let blocked_jobs = report_json["stats"]["blocked_jobs"].as_u64().unwrap();
    let total_actions = report_json["stats"]["total_actions_taken"]
        .as_u64()
        .unwrap();

    assert!(total_jobs >= 20, "Should have processed all corpus files");
    assert!(
        blocked_jobs >= 3,
        "Should have detected and blocked at least 3 bomb/active files"
    );
    assert!(
        total_actions >= 30,
        "Total actions taken should be substantial across malicious files"
    );

    // Clean up
    let _ = fs::remove_dir_all(&temp_out);
}
