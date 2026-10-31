#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use serde_json::Value;
use std::fs;

#[test]
fn env_outputs_bash_and_json_and_is_guarded() {
    let home = tempfile::tempdir().expect("temp home");

    let init = common::passworder(home.path())
        .env("PASSWORDER_VAULT_TEST_KDF", "1")
        .args(["vault", "init"])
        .write_stdin("pw\npw\n")
        .output()
        .expect("vault init");
    assert!(init.status.success());

    let add1 = common::passworder(home.path())
        .args([
            "vault",
            "add",
            "--type",
            "api-token",
            "--name",
            "API_KEY",
            "--secret",
            "abc123",
            "--item-path",
            "dev",
        ])
        .write_stdin("pw\n")
        .output()
        .expect("vault add");
    assert!(add1.status.success());

    let add2 = common::passworder(home.path())
        .args([
            "vault",
            "add",
            "--type",
            "api-token",
            "--name",
            "OAUTH_TOKEN",
            "--secret",
            "sek'ret",
            "--item-path",
            "dev",
        ])
        .write_stdin("pw\n")
        .output()
        .expect("vault add");
    assert!(add2.status.success());

    let guarded = common::passworder(home.path())
        .args(["env", "--profile", "dev", "--format", "bash"])
        .write_stdin("pw\n")
        .output()
        .expect("env output");
    assert_eq!(guarded.status.code(), Some(64));

    let bash = common::passworder(home.path())
        .args(["env", "--profile", "dev", "--format", "bash", "--unsafe"])
        .write_stdin("pw\n")
        .output()
        .expect("env bash output");
    assert!(bash.status.success());
    let stdout = String::from_utf8_lossy(&bash.stdout);
    assert!(stdout.contains("export API_KEY='abc123'\n"));
    assert!(stdout.contains("export OAUTH_TOKEN='sek'\\''ret'\n"));

    let json = common::passworder(home.path())
        .args(["env", "--profile", "dev", "--format", "json", "--unsafe"])
        .write_stdin("pw\n")
        .output()
        .expect("env json output");
    assert!(json.status.success());
    let stdout = String::from_utf8_lossy(&json.stdout);
    let obj: Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(obj.get("API_KEY").and_then(Value::as_str), Some("abc123"));
    assert_eq!(
        obj.get("OAUTH_TOKEN").and_then(Value::as_str),
        Some("sek'ret")
    );
}

#[test]
fn run_injects_env_and_inject_substitutes_template() {
    let home = tempfile::tempdir().expect("temp home");
    let dir = tempfile::tempdir().expect("temp dir");

    let init = common::passworder(home.path())
        .env("PASSWORDER_VAULT_TEST_KDF", "1")
        .args(["vault", "init"])
        .write_stdin("pw\npw\n")
        .output()
        .expect("vault init");
    assert!(init.status.success());

    let add = common::passworder(home.path())
        .args([
            "vault",
            "add",
            "--type",
            "api-token",
            "--name",
            "API_KEY",
            "--secret",
            "abc123",
            "--item-path",
            "dev",
        ])
        .write_stdin("pw\n")
        .output()
        .expect("vault add");
    assert!(add.status.success());

    let run = common::passworder(home.path())
        .args([
            "run",
            "--profile",
            "dev",
            "--unsafe",
            "--",
            "sh",
            "-c",
            "[ \"$API_KEY\" = \"abc123\" ]",
        ])
        .write_stdin("pw\n")
        .output()
        .expect("run");
    assert!(run.status.success());

    let template_path = dir.path().join("template.txt");
    let out_path = dir.path().join("out.txt");
    fs::write(&template_path, "token=${API_KEY}\n").expect("write template");

    let inject = common::passworder(home.path())
        .args([
            "inject",
            "--profile",
            "dev",
            "--in",
            template_path.to_str().unwrap(),
            "--out",
            out_path.to_str().unwrap(),
            "--unsafe",
        ])
        .write_stdin("pw\n")
        .output()
        .expect("inject");
    assert!(inject.status.success());

    let rendered = fs::read_to_string(&out_path).expect("read out");
    assert_eq!(rendered, "token=abc123\n");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&out_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
