use assert_cmd::Command;
use serde_json::Value;

#[test]
fn password_json_mode_wraps_value_and_meta() {
    let output = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["password", "--json"])
        .output()
        .expect("password json output");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid json");

    let value = json
        .get("value")
        .and_then(Value::as_str)
        .expect("value field as string");
    assert_eq!(value.len(), 20, "default password length");

    let meta = json.get("meta").expect("meta field");
    assert_eq!(meta.get("kind").and_then(Value::as_str), Some("password"));
}

#[test]
fn password_quiet_mode_prints_raw_value() {
    let output = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["password", "--quiet"])
        .output()
        .expect("password quiet output");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Single line with no trailing spaces (aside from newline).
    assert_eq!(stdout.lines().count(), 1, "expected a single-line output");
    let line = stdout.trim_end_matches(&['\n', '\r'][..]);
    assert_eq!(line, line.trim(), "line should have no trailing spaces");
}

#[test]
fn entropy_json_mode_wraps_existing_report() {
    let output = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["entropy", "--input", "abc", "--json"])
        .output()
        .expect("entropy json output");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid json");

    let meta = json.get("meta").expect("meta field");
    assert_eq!(meta.get("kind").and_then(Value::as_str), Some("entropy"));

    let report = meta
        .get("report")
        .expect("report field")
        .clone();

    assert_eq!(report.get("length").and_then(Value::as_u64), Some(3));
    // Strength-related fields should still be absent without the feature.
    assert!(report.get("score").is_none());
    assert!(report.get("guesses_log10").is_none());
    assert!(report.get("crack_times_display").is_none());
}

