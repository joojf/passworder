use assert_cmd::Command;
use serde_json::Value;
use std::fs;

#[cfg(target_os = "macos")]
fn expected_default_vault_path(home: &std::path::Path) -> std::path::PathBuf {
    home.join("Library/Application Support")
        .join("passworder")
        .join("vault.pwder")
}

#[test]
#[cfg(target_os = "macos")]
fn vault_path_json_reports_default_path() {
    let home = tempfile::tempdir().expect("temp home");

    let output = Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("HOME", home.path())
        .args(["vault", "path", "--json"])
        .output()
        .expect("vault path output");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid json");
    let value = json
        .get("value")
        .and_then(Value::as_str)
        .expect("value field as string");

    let expected = expected_default_vault_path(home.path());
    assert_eq!(value, expected.display().to_string());
}

#[test]
#[cfg(target_os = "macos")]
fn vault_init_creates_vault_and_status_is_locked() {
    let home = tempfile::tempdir().expect("temp home");
    let expected = expected_default_vault_path(home.path());

    let status_before = Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("HOME", home.path())
        .args(["vault", "status", "--json"])
        .output()
        .expect("vault status output");

    assert!(status_before.status.success());
    let stdout = String::from_utf8_lossy(&status_before.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(
        json.get("value").and_then(Value::as_str),
        Some("missing")
    );

    let init = Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("HOME", home.path())
        .env("PASSWORDER_VAULT_TEST_KDF", "1")
        .args(["vault", "init", "--json"])
        .write_stdin("correct horse battery staple\ncorrect horse battery staple\n")
        .output()
        .expect("vault init output");

    assert!(init.status.success());
    assert!(expected.exists(), "vault file created");

    let bytes = fs::read(&expected).expect("read vault bytes");
    assert!(bytes.starts_with(b"PWDERVLT"));

    let status_after = Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("HOME", home.path())
        .args(["vault", "status", "--json"])
        .output()
        .expect("vault status output");

    assert!(status_after.status.success());
    let stdout = String::from_utf8_lossy(&status_after.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(
        json.get("value").and_then(Value::as_str),
        Some("locked")
    );
}
