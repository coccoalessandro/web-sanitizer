use std::fs;
use std::process::Command;

#[test]
fn test_cli_end_to_end_batch_and_output_dir() {
    let temp_base = std::env::temp_dir().join("web_sanitizer_cli_test_1");
    let input_dir = temp_base.join("inputs");
    let output_dir = temp_base.join("outputs");
    let report_file = temp_base.join("aggregated_report.json");

    let _ = fs::remove_dir_all(&temp_base);
    fs::create_dir_all(&input_dir).unwrap();

    let file1 = input_dir.join("clean.html");
    let file2 = input_dir.join("dirty.html");

    fs::write(
        &file1,
        "<div><p>Clean text</p><a href=\"https://trusted.org\">Link</a></div>",
    )
    .unwrap();
    fs::write(
        &file2,
        "<p>Text</p><script>alert('xss');</script><a href=\"javascript:bad()\">Click</a>",
    )
    .unwrap();

    // Run the compiled CLI binary
    let bin_path = env!("CARGO_BIN_EXE_cli");

    let status = Command::new(bin_path)
        .arg("--dirs")
        .arg(&input_dir)
        .arg("--output-dir")
        .arg(&output_dir)
        .arg("--report-file")
        .arg(&report_file)
        .arg("--verbose")
        .status()
        .expect("Failed to execute cli binary");

    assert!(
        status.success(),
        "CLI process failed with non-zero exit code"
    );

    // Verify output files exist
    let out_clean = output_dir.join("clean.cleaned.html");
    let out_dirty = output_dir.join("dirty.cleaned.html");
    let report_clean = output_dir.join("clean.report.json");
    let report_dirty = output_dir.join("dirty.report.json");

    assert!(out_clean.exists(), "Cleaned clean.html file must exist");
    assert!(out_dirty.exists(), "Cleaned dirty.html file must exist");
    assert!(report_clean.exists(), "Clean report json must exist");
    assert!(report_dirty.exists(), "Dirty report json must exist");
    assert!(report_file.exists(), "Aggregated report file must exist");

    // Check dirty output content was properly sanitized
    let dirty_content = fs::read_to_string(&out_dirty).unwrap();
    assert!(
        !dirty_content.contains("<script>"),
        "<script> must be removed"
    );
    assert!(
        !dirty_content.contains("javascript:"),
        "javascript: scheme must be removed"
    );

    // Check aggregated report JSON parses and contains stats
    let report_json_str = fs::read_to_string(&report_file).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&report_json_str).unwrap();
    assert_eq!(parsed["stats"]["total_jobs"], 2);
    assert_eq!(parsed["stats"]["successful_jobs"], 2);
    assert_eq!(parsed["stats"]["failed_jobs"], 0);
    assert!(parsed["stats"]["total_actions_taken"].as_u64().unwrap() >= 2);

    // Clean up
    let _ = fs::remove_dir_all(&temp_base);
}

#[test]
fn test_cli_json_only_mode() {
    let temp_base = std::env::temp_dir().join("web_sanitizer_cli_test_json");
    let _ = fs::remove_dir_all(&temp_base);
    fs::create_dir_all(&temp_base).unwrap();

    let file = temp_base.join("test.html");
    fs::write(&file, "<div onclick=\"alert(1)\">Hello</div>").unwrap();

    let bin_path = env!("CARGO_BIN_EXE_cli");

    let output = Command::new(bin_path)
        .arg("-f")
        .arg(&file)
        .arg("--json-only")
        .output()
        .expect("Failed to execute cli binary");

    assert!(output.status.success());

    let stdout_str = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout_str).expect("Output must be valid JSON");

    assert_eq!(parsed["stats"]["total_jobs"], 1);
    assert_eq!(parsed["reports"].as_array().unwrap().len(), 1);

    let _ = fs::remove_dir_all(&temp_base);
}

#[test]
fn test_cli_exit_code_on_blocked_content() {
    let temp_base = std::env::temp_dir().join("web_sanitizer_cli_test_blocked");
    let _ = fs::remove_dir_all(&temp_base);
    fs::create_dir_all(&temp_base).unwrap();

    // In strict mode, iframes are disallowed and active content rewrite is false -> file_blocked = true
    let file = temp_base.join("iframe.html");
    fs::write(&file, "<iframe src=\"https://malicious.org\"></iframe>").unwrap();

    let bin_path = env!("CARGO_BIN_EXE_cli");

    let output = Command::new(bin_path)
        .arg("-f")
        .arg(&file)
        .arg("-p")
        .arg("strict")
        .output()
        .expect("Failed to execute cli binary");

    // In strict mode, an untrusted iframe without active content rewrite causes file_blocked = true -> exit code 1
    assert!(
        !output.status.success(),
        "CLI must return non-zero exit code on blocked content"
    );
    assert_eq!(output.status.code(), Some(1));

    let _ = fs::remove_dir_all(&temp_base);
}
