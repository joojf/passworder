use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn password_command_succeeds() {
    Command::cargo_bin("passworder")
        .expect("binary exists")
        .arg("password")
        .assert()
        .success();
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
