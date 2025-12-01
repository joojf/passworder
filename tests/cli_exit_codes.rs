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

    let output = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["passphrase", "--wordlist", &path])
        .output()
        .expect("passphrase output");

    assert_eq!(output.status.code(), Some(2), "IO errors use code 2");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error: failed to read word list"));
}

#[test]
fn token_zero_bytes_fails() {
    let output = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["token", "hex", "--bytes", "0"])
        .output()
        .expect("token output");

    assert_eq!(output.status.code(), Some(64), "usage errors use code 64");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error: byte length must be greater than zero"));
}

#[test]
fn token_invalid_number_fails() {
    let output = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["token", "hex", "--bytes", "abc"])
        .output()
        .expect("token output");

    assert_eq!(output.status.code(), Some(64), "clap usage errors use code 64");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid digit found in string"));
}

#[test]
fn entropy_stdin_invalid_utf8_fails() {
    let output = Command::cargo_bin("passworder")
        .expect("binary exists")
        .arg("entropy")
        .write_stdin(vec![0xf0, 0x28, 0x8c, 0x28])
        .output()
        .expect("entropy output");

    assert_eq!(
        output.status.code(),
        Some(64),
        "invalid UTF-8 input is treated as usage"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error: STDIN contains invalid UTF-8 data"));
}

#[test]
fn help_and_errors_avoid_ansi_in_pipes() {
    // Non-TTY by default in tests; also force NO_COLOR.
    let output = Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("NO_COLOR", "1")
        .arg("--does-not-exist")
        .output()
        .expect("output");

    assert_eq!(output.status.code(), Some(64));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("\u{1b}["),
        "stderr should not contain ANSI escape sequences"
    );
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

#[test]
#[cfg(any(debug_assertions, feature = "dev-seed"))]
fn dev_seed_password_deterministic() {
    let output1 = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["password", "--dev-seed", "42", "--length", "16"])
        .output()
        .expect("password output");

    let output2 = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["password", "--dev-seed", "42", "--length", "16"])
        .output()
        .expect("password output");

    assert!(output1.status.success());
    assert!(output2.status.success());

    let password1 = String::from_utf8_lossy(&output1.stdout).trim().to_string();
    let password2 = String::from_utf8_lossy(&output2.stdout).trim().to_string();

    // Same seed should produce same password
    assert_eq!(password1, password2);
    assert_eq!(password1.len(), 16);

    // Verify warning is emitted
    let stderr1 = String::from_utf8_lossy(&output1.stderr);
    assert!(stderr1.contains("WARNING: Using dev seed"));
    assert!(stderr1.contains("deterministic"));
}

#[test]
#[cfg(any(debug_assertions, feature = "dev-seed"))]
fn dev_seed_passphrase_deterministic() {
    let output1 = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["passphrase", "--dev-seed", "123", "--words", "5"])
        .output()
        .expect("passphrase output");

    let output2 = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["passphrase", "--dev-seed", "123", "--words", "5"])
        .output()
        .expect("passphrase output");

    assert!(output1.status.success());
    assert!(output2.status.success());

    let phrase1 = String::from_utf8_lossy(&output1.stdout).trim().to_string();
    let phrase2 = String::from_utf8_lossy(&output2.stdout).trim().to_string();

    // Same seed should produce same passphrase
    assert_eq!(phrase1, phrase2);

    // Verify warning is emitted
    let stderr1 = String::from_utf8_lossy(&output1.stderr);
    assert!(stderr1.contains("WARNING: Using dev seed"));
}

#[test]
#[cfg(any(debug_assertions, feature = "dev-seed"))]
fn dev_seed_token_hex_deterministic() {
    let output1 = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["token", "hex", "--dev-seed", "999", "--bytes", "16"])
        .output()
        .expect("token hex output");

    let output2 = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["token", "hex", "--dev-seed", "999", "--bytes", "16"])
        .output()
        .expect("token hex output");

    assert!(output1.status.success());
    assert!(output2.status.success());

    let token1 = String::from_utf8_lossy(&output1.stdout).trim().to_string();
    let token2 = String::from_utf8_lossy(&output2.stdout).trim().to_string();

    // Same seed should produce same token
    assert_eq!(token1, token2);
    assert_eq!(token1.len(), 32); // 16 bytes = 32 hex chars
}

#[test]
#[cfg(any(debug_assertions, feature = "dev-seed"))]
fn dev_seed_token_b64_deterministic() {
    let output1 = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["token", "b64", "--dev-seed", "777", "--bytes", "16"])
        .output()
        .expect("token b64 output");

    let output2 = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["token", "b64", "--dev-seed", "777", "--bytes", "16"])
        .output()
        .expect("token b64 output");

    assert!(output1.status.success());
    assert!(output2.status.success());

    let token1 = String::from_utf8_lossy(&output1.stdout).trim().to_string();
    let token2 = String::from_utf8_lossy(&output2.stdout).trim().to_string();

    // Same seed should produce same token
    assert_eq!(token1, token2);
}

#[test]
#[cfg(any(debug_assertions, feature = "dev-seed"))]
fn dev_seed_uuid_remains_random() {
    // UUID should NOT be deterministic even with dev-seed
    let output1 = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["token", "uuid", "--dev-seed", "555"])
        .output()
        .expect("uuid output");

    let output2 = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["token", "uuid", "--dev-seed", "555"])
        .output()
        .expect("uuid output");

    assert!(output1.status.success());
    assert!(output2.status.success());

    let uuid1 = String::from_utf8_lossy(&output1.stdout).trim().to_string();
    let uuid2 = String::from_utf8_lossy(&output2.stdout).trim().to_string();

    // UUIDs should be different even with same seed
    assert_ne!(uuid1, uuid2);

    // Both should be valid UUIDs
    assert_eq!(uuid1.len(), 36);
    assert_eq!(uuid2.len(), 36);
}

#[test]
#[cfg(any(debug_assertions, feature = "dev-seed"))]
fn dev_seed_different_seeds_different_output() {
    let output1 = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["password", "--dev-seed", "100", "--length", "16"])
        .output()
        .expect("password output");

    let output2 = Command::cargo_bin("passworder")
        .expect("binary exists")
        .args(["password", "--dev-seed", "200", "--length", "16"])
        .output()
        .expect("password output");

    assert!(output1.status.success());
    assert!(output2.status.success());

    let password1 = String::from_utf8_lossy(&output1.stdout).trim().to_string();
    let password2 = String::from_utf8_lossy(&output2.stdout).trim().to_string();

    // Different seeds should produce different passwords
    assert_ne!(password1, password2);
}
