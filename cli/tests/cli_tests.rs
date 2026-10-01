use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_cli_no_args() {
    let mut cmd = Command::cargo_bin("cli").unwrap();
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("No inputs provided"));
}

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("cli").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"));
}

#[test]
fn test_cli_with_invalid_profile() {
    let mut cmd = Command::cargo_bin("cli").unwrap();
    cmd.args(["--urls", "http://example.com", "--profile", "invalid"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value 'invalid' for '--profile <PROFILE>'"));
}

#[test]
fn test_cli_with_valid_profile() {
    let mut cmd = Command::cargo_bin("cli").unwrap();
    cmd.args(["--files", "../README.md", "--profile", "strict", "--max-requests-per-job", "10"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Starting web-sanitizer with 1 jobs"));
}
