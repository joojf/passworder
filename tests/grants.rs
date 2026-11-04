#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use serde_json::Value;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Output;
use tempfile::TempDir;

/// A vault with one item, and a bin directory of fake programs. The programs are never run.
struct Fixture {
    home: TempDir,
    item_id: String,
}

impl Fixture {
    fn new() -> Self {
        let home = tempfile::tempdir().expect("temp home");
        let fixture = Self {
            home,
            item_id: String::new(),
        };
        let init = fixture
            .passworder(&["vault", "init"], "pw\npw\n")
            .env("PASSWORDER_VAULT_TEST_KDF", "1")
            .output()
            .expect("vault init");
        assert!(init.status.success());

        fs::create_dir(fixture.bin()).unwrap();
        for name in ["tool", "bash", "python3.12"] {
            fixture.write_program(name, 0o755);
        }
        fixture.write_program("not-executable", 0o644);
        symlink(fixture.bin().join("bash"), fixture.bin().join("innocent")).unwrap();

        let item_id = fixture.add_item("API_KEY");
        Self { item_id, ..fixture }
    }

    fn bin(&self) -> PathBuf {
        self.home.path().join("bin")
    }

    fn write_program(&self, name: &str, mode: u32) {
        let path = self.bin().join(name);
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn passworder(&self, args: &[&str], stdin: &str) -> assert_cmd::Command {
        let mut command = common::passworder(self.home.path());
        command
            .env("PATH", self.bin())
            .args(args)
            .write_stdin(stdin);
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.passworder(args, "pw\n").output().expect("run command")
    }

    fn add_item(&self, name: &str) -> String {
        let output = self
            .passworder(
                &[
                    "--quiet",
                    "vault",
                    "add",
                    "--type",
                    "api-token",
                    "--name",
                    name,
                ],
                "pw\nsecret\n",
            )
            .output()
            .expect("vault add");
        assert!(output.status.success());
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn add_grant(&self, program: &str, env: &str) -> Output {
        self.run(&[
            "grant",
            "add",
            "--item",
            &self.item_id,
            "--program",
            program,
            "--env",
            env,
        ])
    }

    fn grants(&self) -> Vec<Value> {
        let output = self.run(&["--json", "grant", "list"]);
        assert!(output.status.success(), "{output:?}");
        let json: Value = serde_json::from_slice(&output.stdout).expect("json");
        json["meta"]["grants"].as_array().expect("grants").clone()
    }
}

fn canonical(path: &Path) -> String {
    fs::canonicalize(path).unwrap().display().to_string()
}

fn assert_refused(output: &Output, message: &str) {
    assert_eq!(output.status.code(), Some(64), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(message), "{stderr}");
}

#[test]
fn grants_can_be_added_listed_and_removed() {
    let fixture = Fixture::new();
    let program = fixture.bin().join("tool");

    let add = fixture.add_grant(program.to_str().unwrap(), "API_KEY");
    assert!(add.status.success(), "{add:?}");

    let grants = fixture.grants();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0]["program"], canonical(&program));
    assert_eq!(grants[0]["env"], "API_KEY");
    assert_eq!(grants[0]["item_name"], "API_KEY");

    let id = grants[0]["id"].as_str().unwrap();
    assert!(fixture.run(&["grant", "rm", id]).status.success());
    assert!(fixture.grants().is_empty());
}

#[test]
fn program_names_resolve_through_path_and_relative_paths() {
    let fixture = Fixture::new();

    assert!(fixture.add_grant("tool", "FROM_PATH").status.success());
    let relative = fixture
        .passworder(
            &[
                "grant",
                "add",
                "--item",
                &fixture.item_id,
                "--program",
                "./bin/tool",
                "--env",
                "FROM_RELATIVE",
            ],
            "pw\n",
        )
        .current_dir(fixture.home.path())
        .output()
        .expect("grant add");
    assert!(relative.status.success(), "{relative:?}");

    let expected = canonical(&fixture.bin().join("tool"));
    let grants = fixture.grants();
    let envs: Vec<&str> = grants.iter().map(|g| g["env"].as_str().unwrap()).collect();
    assert_eq!(envs, ["FROM_PATH", "FROM_RELATIVE"]);
    for grant in grants {
        assert_eq!(grant["program"], expected);
    }
}

#[test]
fn programs_that_run_other_programs_are_refused() {
    let fixture = Fixture::new();

    for program in ["bash", "python3.12", "innocent"] {
        let output = fixture.add_grant(program, "API_KEY");
        assert_refused(&output, "can run other programs");
    }
    assert!(fixture.grants().is_empty());
}

#[test]
fn directories_and_files_without_execute_permission_are_refused() {
    let fixture = Fixture::new();

    let not_executable = fixture.bin().join("not-executable");
    let output = fixture.add_grant(not_executable.to_str().unwrap(), "API_KEY");
    assert_refused(&output, "not an executable file");

    let output = fixture.add_grant(fixture.bin().to_str().unwrap(), "API_KEY");
    assert_refused(&output, "not an executable file");

    let output = fixture.add_grant("missing", "API_KEY");
    assert_refused(&output, "not found");
}

#[test]
fn invalid_and_execution_control_env_names_are_refused() {
    let fixture = Fixture::new();

    for env in ["1KEY", "API-KEY", ""] {
        assert_refused(&fixture.add_grant("tool", env), "invalid environment");
    }
    for env in ["LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PATH", "BASH_ENV"] {
        assert_refused(&fixture.add_grant("tool", env), "controls how programs run");
    }
}

#[test]
fn a_program_cannot_receive_the_same_variable_twice() {
    let fixture = Fixture::new();
    assert!(fixture.add_grant("tool", "API_KEY").status.success());

    let other_item = fixture.add_item("OTHER");
    let output = fixture.run(&[
        "grant",
        "add",
        "--item",
        &other_item,
        "--program",
        "tool",
        "--env",
        "API_KEY",
    ]);

    assert_refused(&output, "already receives API_KEY");
}

#[test]
fn unknown_items_and_grants_are_refused() {
    let fixture = Fixture::new();
    let unknown = "00000000-0000-0000-0000-000000000000";

    let output = fixture.run(&[
        "grant",
        "add",
        "--item",
        unknown,
        "--program",
        "tool",
        "--env",
        "API_KEY",
    ]);
    assert_refused(&output, "item not found");

    assert_refused(&fixture.run(&["grant", "rm", unknown]), "grant not found");
}

#[test]
fn removing_an_item_removes_its_grants() {
    let fixture = Fixture::new();
    assert!(fixture.add_grant("tool", "API_KEY").status.success());

    assert!(
        fixture
            .run(&["vault", "rm", &fixture.item_id])
            .status
            .success()
    );

    assert!(fixture.grants().is_empty());
}
