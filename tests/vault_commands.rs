#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use passworder::vault::{AddItemInput, UnlockedVault, VaultError, VaultItemType};
use secrecy::SecretString;
use serde_json::Value;
use std::fs;

fn expected_default_vault_path(home: &std::path::Path) -> std::path::PathBuf {
    let config_dir = if cfg!(target_os = "macos") {
        home.join("Library/Application Support")
    } else {
        home.join(".config")
    };
    config_dir.join("passworder").join("vault.pwder")
}

#[test]
fn vault_path_json_reports_default_path() {
    let home = tempfile::tempdir().expect("temp home");

    let output = common::passworder(home.path())
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
fn vault_init_creates_vault_and_status_is_locked() {
    let home = tempfile::tempdir().expect("temp home");
    let expected = expected_default_vault_path(home.path());

    let status_before = common::passworder(home.path())
        .args(["vault", "status", "--json"])
        .output()
        .expect("vault status output");

    assert!(status_before.status.success());
    let stdout = String::from_utf8_lossy(&status_before.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(json.get("value").and_then(Value::as_str), Some("missing"));

    let init = common::passworder(home.path())
        .env("PASSWORDER_VAULT_TEST_KDF", "1")
        .args(["vault", "init", "--json"])
        .write_stdin("correct horse battery staple\ncorrect horse battery staple\n")
        .output()
        .expect("vault init output");

    assert!(init.status.success());
    assert!(expected.exists(), "vault file created");

    let bytes = fs::read(&expected).expect("read vault bytes");
    assert!(bytes.starts_with(b"PWDERVLT"));

    let status_after = common::passworder(home.path())
        .args(["vault", "status", "--json"])
        .output()
        .expect("vault status output");

    assert!(status_after.status.success());
    let stdout = String::from_utf8_lossy(&status_after.stdout);
    let json: Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(json.get("value").and_then(Value::as_str), Some("locked"));
}

#[test]
fn vault_crud_roundtrip_add_get_list_search_edit_rm() {
    let home = tempfile::tempdir().expect("temp home");

    let init = common::passworder(home.path())
        .env("PASSWORDER_VAULT_TEST_KDF", "1")
        .args(["vault", "init", "--json"])
        .write_stdin("pw\npw\n")
        .output()
        .expect("vault init output");
    assert!(init.status.success());

    let add = common::passworder(home.path())
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
            "--tag",
            "work",
        ])
        .write_stdin("pw\ns3cr3t\n")
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

    let list = common::passworder(home.path())
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
    assert_eq!(items[0].get("id").and_then(Value::as_str), Some(id));

    let get = common::passworder(home.path())
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
    assert_eq!(
        item.get("secret_redacted").and_then(Value::as_bool),
        Some(true)
    );

    let reveal = common::passworder(home.path())
        .args(["vault", "get", id, "--reveal", "--quiet"])
        .write_stdin("pw\n")
        .output()
        .expect("vault get reveal output");
    assert!(reveal.status.success());
    let stdout = String::from_utf8_lossy(&reveal.stdout);
    assert_eq!(stdout.trim_end_matches(&['\n', '\r'][..]), "s3cr3t");

    let search = common::passworder(home.path())
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

    let edit = common::passworder(home.path())
        .args(["vault", "edit", id, "--name", "github.com", "--json"])
        .write_stdin("pw\n")
        .output()
        .expect("vault edit output");
    assert!(edit.status.success());

    let get_after = common::passworder(home.path())
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

    let rm = common::passworder(home.path())
        .args(["vault", "rm", id, "--json"])
        .write_stdin("pw\n")
        .output()
        .expect("vault rm output");
    assert!(rm.status.success());

    let list_after = common::passworder(home.path())
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

#[test]
fn vault_search_with_blank_query_returns_nothing_without_opening_the_vault() {
    let home = tempfile::tempdir().expect("temp home");

    let search = common::passworder(home.path())
        .args(["vault", "search", "  ", "--json"])
        .write_stdin("pw\n")
        .output()
        .expect("vault search output");

    assert!(search.status.success());
    let json: Value = serde_json::from_slice(&search.stdout).expect("valid json");
    assert_eq!(json["meta"]["count"], 0);
}

#[test]
fn unlocked_vault_handles_see_each_others_writes() {
    let home = tempfile::tempdir().expect("temp home");
    let path = expected_default_vault_path(home.path());
    let password = SecretString::from("pw");

    let init = common::passworder(home.path())
        .env("PASSWORDER_VAULT_TEST_KDF", "1")
        .args(["vault", "init"])
        .write_stdin("pw\npw\n")
        .output()
        .expect("vault init output");
    assert!(init.status.success());

    let first = UnlockedVault::open(&path, &password).expect("open first handle");
    let second = UnlockedVault::open(&path, &password).expect("open second handle");

    let first_id = first.add_item(token("FIRST")).expect("add through first");
    let second_id = second
        .add_item(token("SECOND"))
        .expect("add through second");
    second
        .get_item(first_id)
        .expect("second sees first's write");
    first
        .get_item(second_id)
        .expect("first sees second's write");

    // A new unlock proves the writes still match the master password.
    let reopened = UnlockedVault::open(&path, &password).expect("reopen with password");
    assert_eq!(reopened.list_items().expect("list items").len(), 2);

    let wrong = SecretString::from("wrong");
    assert!(matches!(
        UnlockedVault::open(&path, &wrong),
        Err(VaultError::AuthFailed)
    ));
}

#[test]
fn vault_edit_rejects_clearing_and_setting_the_same_field() {
    let home = tempfile::tempdir().expect("temp home");
    let id = "00000000-0000-0000-0000-000000000000";

    for flags in [
        &["--clear-path", "--item-path", "value"][..],
        &["--clear-tags", "--tag", "value"],
        &["--clear-username", "--username", "value"],
        &["--clear-urls", "--url", "value"],
        &["--clear-notes", "--new-notes"],
    ] {
        let edit = common::passworder(home.path())
            .args(["vault", "edit", id])
            .args(flags)
            .output()
            .expect("vault edit output");

        assert_eq!(edit.status.code(), Some(64), "{flags:?}");
        let stderr = String::from_utf8_lossy(&edit.stderr);
        assert!(
            stderr.contains("cannot be used with"),
            "{flags:?}: {stderr}"
        );
    }
}

#[test]
fn vault_edit_keeps_sets_and_clears_optional_fields() {
    let home = tempfile::tempdir().expect("temp home");

    let init = common::passworder(home.path())
        .env("PASSWORDER_VAULT_TEST_KDF", "1")
        .args(["vault", "init"])
        .write_stdin("pw\npw\n")
        .output()
        .expect("vault init output");
    assert!(init.status.success());

    let add = common::passworder(home.path())
        .args([
            "vault",
            "add",
            "--json",
            "--type",
            "login",
            "--name",
            "github",
            "--item-path",
            "work",
            "--username",
            "octocat",
            "--with-notes",
            "--tag",
            "dev",
            "--url",
            "https://github.com",
        ])
        .write_stdin("pw\ns3cr3t\nold\n")
        .output()
        .expect("vault add output");
    assert!(add.status.success());
    let json: Value = serde_json::from_slice(&add.stdout).expect("valid json");
    let id = json["meta"]["id"].as_str().expect("meta.id string");

    let edit = |stdin: &str, flags: &[&str]| -> Value {
        let edited = common::passworder(home.path())
            .args(["vault", "edit", id])
            .args(flags)
            .write_stdin(stdin.to_string())
            .output()
            .expect("vault edit output");
        assert!(edited.status.success());

        let get = common::passworder(home.path())
            .args(["vault", "get", id, "--json", "--reveal"])
            .write_stdin("pw\n")
            .output()
            .expect("vault get output");
        assert!(get.status.success());
        let json: Value = serde_json::from_slice(&get.stdout).expect("valid json");
        json["meta"]["item"].clone()
    };

    let item = edit("pw\nnew\n", &["--new-notes"]);
    assert_eq!(item["notes"], "new");
    assert_eq!(item["path"], "work");
    assert_eq!(item["username"], "octocat");
    assert_eq!(item["tags"][0], "dev");
    assert_eq!(item["urls"][0], "https://github.com");

    let item = edit(
        "pw\n",
        &[
            "--clear-path",
            "--clear-tags",
            "--clear-username",
            "--clear-urls",
            "--clear-notes",
        ],
    );
    for field in ["path", "username", "notes"] {
        assert!(item[field].is_null(), "{field} cleared");
    }
    for field in ["tags", "urls"] {
        assert_eq!(
            item[field].as_array().map(Vec::len),
            Some(0),
            "{field} cleared"
        );
    }

    let item = edit(
        "pw\n",
        &[
            "--item-path",
            "home",
            "--username",
            "hubot",
            "--tag",
            "ops",
            "--url",
            "https://example.com",
        ],
    );
    assert_eq!(item["path"], "home");
    assert_eq!(item["username"], "hubot");
    assert_eq!(item["tags"][0], "ops");
    assert_eq!(item["urls"][0], "https://example.com");

    let item = edit("pw\n", &["--tag", " ", "--url", " "]);
    for field in ["tags", "urls"] {
        assert_eq!(
            item[field].as_array().map(Vec::len),
            Some(0),
            "{field} blank"
        );
    }
}

#[test]
fn vault_get_hides_notes_unless_revealed() {
    let home = tempfile::tempdir().expect("temp home");
    let id = init_with_login(home.path());

    let get = |flags: &[&str]| -> String {
        let output = common::passworder(home.path())
            .args(["vault", "get", id.as_str()])
            .args(flags)
            .write_stdin("pw\n")
            .output()
            .expect("vault get output");
        assert!(output.status.success());
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    for flags in [&[][..], &["--json"], &["--quiet"], &["--reveal", "--quiet"]] {
        assert!(!get(flags).contains("private-note"), "{flags:?}");
    }
    assert!(get(&[]).contains("notes:\t[REDACTED]"));
    let json: Value = serde_json::from_str(&get(&["--json"])).expect("valid json");
    assert_eq!(json["meta"]["item"]["notes_redacted"], true);

    assert!(get(&["--reveal"]).contains("notes:\tprivate-note"));
    let json: Value = serde_json::from_str(&get(&["--reveal", "--json"])).expect("valid json");
    assert_eq!(json["meta"]["item"]["notes"], "private-note");
    assert_eq!(json["meta"]["item"]["secret"], "s3cr3t");
}

#[test]
fn vault_edit_new_notes_keeps_old_notes_when_the_prompt_fails() {
    let home = tempfile::tempdir().expect("temp home");
    let id = init_with_login(home.path());

    let edit = |stdin: &str| {
        common::passworder(home.path())
            .args(["vault", "edit", id.as_str(), "--new-notes"])
            .write_stdin(stdin.to_string())
            .output()
            .expect("vault edit output")
    };

    let wrong = edit("wrong\nnew-note\n");
    assert_eq!(wrong.status.code(), Some(64));
    assert!(!String::from_utf8_lossy(&wrong.stderr).contains("New notes:"));

    let empty = edit("pw\n\n");
    assert_eq!(empty.status.code(), Some(64));

    let get = common::passworder(home.path())
        .args(["vault", "get", id.as_str(), "--json", "--reveal"])
        .write_stdin("pw\n")
        .output()
        .expect("vault get output");
    let json: Value = serde_json::from_slice(&get.stdout).expect("valid json");
    assert_eq!(json["meta"]["item"]["notes"], "private-note");
}

#[test]
fn vault_edit_new_secret_prompts_after_the_password_is_checked() {
    let home = tempfile::tempdir().expect("temp home");
    let id = init_with_login(home.path());

    let wrong = common::passworder(home.path())
        .args(["vault", "edit", id.as_str(), "--new-secret"])
        .write_stdin("wrong\nnew-value\n")
        .output()
        .expect("vault edit output");
    assert_eq!(wrong.status.code(), Some(64));
    assert!(!String::from_utf8_lossy(&wrong.stderr).contains("New secret:"));

    let edit = common::passworder(home.path())
        .args(["vault", "edit", id.as_str(), "--new-secret"])
        .write_stdin("pw\nnew-value\n")
        .output()
        .expect("vault edit output");
    assert!(edit.status.success());

    let reveal = common::passworder(home.path())
        .args(["vault", "get", id.as_str(), "--reveal", "--quiet"])
        .write_stdin("pw\n")
        .output()
        .expect("vault get output");
    assert_eq!(
        String::from_utf8_lossy(&reveal.stdout).trim_end(),
        "new-value"
    );
}

fn init_with_login(home: &std::path::Path) -> String {
    let init = common::passworder(home)
        .env("PASSWORDER_VAULT_TEST_KDF", "1")
        .args(["vault", "init"])
        .write_stdin("pw\npw\n")
        .output()
        .expect("vault init output");
    assert!(init.status.success());

    let add = common::passworder(home)
        .args([
            "vault",
            "add",
            "--quiet",
            "--type",
            "login",
            "--name",
            "github",
            "--with-notes",
        ])
        .write_stdin("pw\ns3cr3t\nprivate-note\n")
        .output()
        .expect("vault add output");
    assert!(add.status.success());
    String::from_utf8_lossy(&add.stdout).trim_end().to_string()
}

fn token(name: &str) -> AddItemInput {
    AddItemInput {
        item_type: VaultItemType::ApiToken,
        name: name.to_string(),
        path: None,
        tags: Vec::new(),
        username: None,
        secret: "s3cr3t".into(),
        urls: Vec::new(),
        notes: None,
    }
}
