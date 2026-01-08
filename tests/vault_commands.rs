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

#[test]
#[cfg(target_os = "macos")]
fn vault_crud_roundtrip_add_get_list_search_edit_rm() {
    let home = tempfile::tempdir().expect("temp home");

    let init = Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("HOME", home.path())
        .env("PASSWORDER_VAULT_TEST_KDF", "1")
        .args(["vault", "init", "--json"])
        .write_stdin("pw\npw\n")
        .output()
        .expect("vault init output");
    assert!(init.status.success());

    let add = Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("HOME", home.path())
        .args([
            "vault",
            "add",
            "--json",
            "--type",
            "login",
            "--name",
            "github",
            "--username",
            "octocat",
            "--secret",
            "s3cr3t",
            "--tag",
            "work",
        ])
        .write_stdin("pw\n")
        .output()
        .expect("vault add output");
    assert!(add.status.success());

    let stdout = String::from_utf8_lossy(&add.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid json");
    let id = json
        .get("meta")
        .and_then(|m| m.get("id"))
        .and_then(Value::as_str)
        .expect("meta.id string");

    let list = Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("HOME", home.path())
        .args(["vault", "list", "--json"])
        .write_stdin("pw\n")
        .output()
        .expect("vault list output");
    assert!(list.status.success());
    let stdout = String::from_utf8_lossy(&list.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid json");
    let items = json
        .get("meta")
        .and_then(|m| m.get("items"))
        .and_then(Value::as_array)
        .expect("meta.items array");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("id").and_then(Value::as_str),
        Some(id)
    );

    let get = Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("HOME", home.path())
        .args(["vault", "get", id, "--json"])
        .write_stdin("pw\n")
        .output()
        .expect("vault get output");
    assert!(get.status.success());
    let stdout = String::from_utf8_lossy(&get.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid json");
    let item = json
        .get("meta")
        .and_then(|m| m.get("item"))
        .expect("meta.item");
    assert_eq!(item.get("secret_redacted").and_then(Value::as_bool), Some(true));

    let reveal = Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("HOME", home.path())
        .args(["vault", "get", id, "--reveal", "--quiet"])
        .write_stdin("pw\n")
        .output()
        .expect("vault get reveal output");
    assert!(reveal.status.success());
    let stdout = String::from_utf8_lossy(&reveal.stdout);
    assert_eq!(stdout.trim_end_matches(&['\n', '\r'][..]), "s3cr3t");

    let search = Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("HOME", home.path())
        .args(["vault", "search", "git", "--json"])
        .write_stdin("pw\n")
        .output()
        .expect("vault search output");
    assert!(search.status.success());
    let stdout = String::from_utf8_lossy(&search.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(
        json.get("meta")
            .and_then(|m| m.get("count"))
            .and_then(Value::as_u64),
        Some(1)
    );

    let edit = Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("HOME", home.path())
        .args(["vault", "edit", id, "--name", "github.com", "--json"])
        .write_stdin("pw\n")
        .output()
        .expect("vault edit output");
    assert!(edit.status.success());

    let get_after = Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("HOME", home.path())
        .args(["vault", "get", id, "--json"])
        .write_stdin("pw\n")
        .output()
        .expect("vault get output");
    assert!(get_after.status.success());
    let stdout = String::from_utf8_lossy(&get_after.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid json");
    let item = json
        .get("meta")
        .and_then(|m| m.get("item"))
        .expect("meta.item");
    assert_eq!(item.get("name").and_then(Value::as_str), Some("github.com"));

    let rm = Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("HOME", home.path())
        .args(["vault", "rm", id, "--json"])
        .write_stdin("pw\n")
        .output()
        .expect("vault rm output");
    assert!(rm.status.success());

    let list_after = Command::cargo_bin("passworder")
        .expect("binary exists")
        .env("HOME", home.path())
        .args(["vault", "list", "--json"])
        .write_stdin("pw\n")
        .output()
        .expect("vault list output");
    assert!(list_after.status.success());
    let stdout = String::from_utf8_lossy(&list_after.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(
        json.get("meta")
            .and_then(|m| m.get("count"))
            .and_then(Value::as_u64),
        Some(0)
    );
}
