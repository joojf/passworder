use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

#[test]
fn password_command_succeeds() {
    Command::cargo_bin("passworder")
        .expect("binary exists")
        .arg("password")
        .assert()
        .success();
}

#[test]
fn password_copy_flag_without_feature_warns() {
    Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["password", "--copy"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "`--copy` requires building with `--features clipboard`",
        ));
}

#[test]
fn entropy_strength_fields_absent_without_feature() {
    let output = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["entropy", "--input", "abc"])
        .output()
        .expect("entropy output");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid json");
    assert!(json.get("score").is_none());
    assert!(json.get("guesses_log10").is_none());
    assert!(json.get("crack_times_display").is_none());
}

#[test]
fn passphrase_missing_wordlist_fails() {
    let path = format!(
        "/tmp/passworder_missing_wordlist_{}.txt",
        std::process::id()
    );

    Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["passphrase", "--wordlist", &path])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error: failed to read word list"));
}

#[test]
fn token_zero_bytes_fails() {
    Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["token", "hex", "--bytes", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Error: byte length must be greater than zero",
        ));
}

#[test]
fn token_invalid_number_fails() {
    Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["token", "hex", "--bytes", "abc"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid digit found in string"));
}

#[test]
fn entropy_stdin_invalid_utf8_fails() {
    Command::cargo_bin("passworder")
        .expect("binary exists")
        .arg("entropy")
        .write_stdin(vec![0xf0, 0x28, 0x8c, 0x28])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Error: STDIN contains invalid UTF-8 data",
        ));
}

#[test]
fn entropy_input_success() {
    Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["entropy", "--input", "abc"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"length\":3"));
}

fn temp_config_path() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    (dir, path)
}

#[test]
fn profile_save_and_list() {
    let (_dir, path) = temp_config_path();

    Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("PASSWORDER_CONFIG", &path)
        .args(["profile", "save", "team", "--length", "24", "--no-digits"])
        .assert()
        .success();

    let output = Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("PASSWORDER_CONFIG", &path)
        .args(["profile", "list"])
        .output()
        .expect("profile list output");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("team"));
    assert!(stdout.contains("length=24"));
    assert!(stdout.contains("digits=false"));
}

#[test]
fn password_uses_profile_settings() {
    let (_dir, path) = temp_config_path();

    Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("PASSWORDER_CONFIG", &path)
        .args([
            "profile",
            "save",
            "uppercase",
            "--length",
            "6",
            "--no-digits",
            "--no-symbols",
            "--lowercase",
            "false",
        ])
        .assert()
        .success();

    let output = Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("PASSWORDER_CONFIG", &path)
        .args(["password", "--profile", "uppercase"])
        .output()
        .expect("password output");

    assert!(output.status.success());
    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(password.len(), 6);
    assert!(password.chars().all(|c| c.is_ascii_uppercase()));
}

#[test]
fn profile_remove_unknown_fails() {
    let (_dir, path) = temp_config_path();

    Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("PASSWORDER_CONFIG", &path)
        .args(["profile", "rm", "missing"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}
