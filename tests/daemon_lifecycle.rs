#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::fs::{self, DirBuilder};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const DEADLINE: Duration = Duration::from_secs(60);

/// Lives under /tmp because Unix socket paths are limited to about 100 bytes.
struct Sandbox {
    home: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        Self::with_password("pw")
    }

    fn with_password(password: &str) -> Self {
        let home = tempfile::Builder::new()
            .prefix("pwd")
            .tempdir_in("/tmp")
            .expect("temp home");
        DirBuilder::new()
            .mode(0o700)
            .create(home.path().join("run"))
            .expect("runtime dir");

        let sandbox = Self { home };
        let init = sandbox
            .passworder(&["vault", "init"], &format!("{password}\n{password}\n"))
            .env("PASSWORDER_VAULT_TEST_KDF", "1")
            .output()
            .expect("vault init");
        assert!(init.status.success());
        sandbox
    }

    fn runtime_dir(&self) -> PathBuf {
        self.home.path().join("run")
    }

    fn socket(&self) -> PathBuf {
        self.runtime_dir().join("passworder/agent.sock")
    }

    fn passworder(&self, args: &[&str], stdin: &str) -> assert_cmd::Command {
        let mut command = common::passworder(self.home.path());
        command
            .env("XDG_RUNTIME_DIR", self.runtime_dir())
            .args(args)
            .write_stdin(stdin)
            .timeout(DEADLINE);
        command
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
        self.passworder(args, stdin).output().expect("run command")
    }

    fn status(&self) -> String {
        let output = self.run(&["status"], "");
        assert!(output.status.success(), "{output:?}");
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn daemon_command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_passworder"));
        command
            .arg("daemon")
            .env("HOME", self.home.path())
            .env("XDG_CONFIG_HOME", self.home.path().join(".config"))
            .env("XDG_RUNTIME_DIR", self.runtime_dir())
            .env_remove("PASSWORDER_VAULT")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    fn start_daemon(&self) -> Daemon {
        self.start(self.daemon_command())
    }

    fn start(&self, mut command: Command) -> Daemon {
        let daemon = Daemon(command.spawn().expect("spawn daemon"));
        wait_until("the daemon to answer", || {
            self.run(&["status"], "").status.success()
        });
        daemon
    }

    /// Speaks the protocol directly, as a client other than our CLI would.
    fn raw_request(&self, request: &[u8]) -> String {
        let mut stream = UnixStream::connect(self.socket()).expect("connect");
        stream.set_read_timeout(Some(DEADLINE)).unwrap();
        stream.set_write_timeout(Some(DEADLINE)).unwrap();
        // The daemon replies and closes without reading an oversized request to its end, which
        // can fail this side's writes and reset the connection after the reply arrives.
        let _ = stream.write_all(request);
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut reply = Vec::new();
        let _ = stream.read_to_end(&mut reply);
        String::from_utf8(reply).expect("utf-8 reply")
    }

    /// Returns the exit code and error output of a daemon expected to refuse to start.
    fn refused_daemon(&self) -> (Option<i32>, String) {
        let mut command = self.daemon_command();
        let child = command
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn daemon");
        let mut daemon = Daemon(child);

        let mut status = None;
        wait_until("the daemon to exit", || {
            status = daemon.0.try_wait().expect("wait for daemon");
            status.is_some()
        });

        let mut error_output = String::new();
        let pipe = daemon.0.stderr.as_mut().expect("piped stderr");
        pipe.read_to_string(&mut error_output).expect("read stderr");
        (status.and_then(|s| s.code()), error_output)
    }
}

/// Kills the daemon even when an assertion fails.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let start = Instant::now();
    while !condition() {
        assert!(start.elapsed() < DEADLINE, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn unlock_status_and_lock_change_the_state() {
    let sandbox = Sandbox::new();
    let _daemon = sandbox.start_daemon();
    assert_eq!(sandbox.status(), "locked");

    assert!(sandbox.run(&["unlock"], "pw\n").status.success());
    assert_eq!(sandbox.status(), "unlocked");

    assert!(sandbox.run(&["lock"], "").status.success());
    assert_eq!(sandbox.status(), "locked");
}

#[test]
fn wrong_password_leaves_the_vault_locked() {
    let sandbox = Sandbox::new();
    let _daemon = sandbox.start_daemon();

    let output = sandbox.run(&["unlock"], "wrong\n");

    assert_eq!(output.status.code(), Some(64));
    assert_eq!(sandbox.status(), "locked");
}

#[test]
fn clients_report_when_the_daemon_is_not_running() {
    let sandbox = Sandbox::new();

    for command in ["status", "lock", "unlock"] {
        let output = sandbox.run(&[command], "pw\n");
        assert_eq!(output.status.code(), Some(2));
        assert!(stderr(&output).contains("not running"), "{output:?}");
    }
}

#[test]
fn clients_refuse_a_socket_directory_other_users_can_reach() {
    let sandbox = Sandbox::new();
    let dir = sandbox.socket().parent().unwrap().to_path_buf();
    {
        let _daemon = sandbox.start_daemon();
    }
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

    let output = sandbox.run(&["unlock"], "pw\n");

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("only your user"), "{output:?}");
}

#[test]
fn passwords_with_json_special_characters_unlock_the_vault() {
    let sandbox = Sandbox::with_password("p\"w\\é");
    let _daemon = sandbox.start_daemon();

    assert!(sandbox.run(&["unlock"], "p\"w\\é\n").status.success());

    assert_eq!(sandbox.status(), "unlocked");
}

// Release builds ignore the test timeout.
#[cfg(debug_assertions)]
#[test]
fn requests_without_use_do_not_extend_the_idle_timeout() {
    let sandbox = Sandbox::new();
    let mut command = sandbox.daemon_command();
    command.env("PASSWORDER_TEST_IDLE_TIMEOUT_SECS", "2");
    let _daemon = sandbox.start(command);

    assert!(sandbox.run(&["unlock"], "pw\n").status.success());
    let unlocked_at = Instant::now();

    wait_until("the vault to lock", || {
        sandbox.raw_request(b"{\"v\":1,\"op\":\"unlock\",\"password_base64\":\"d3Jvbmc=\"}\n");
        sandbox.status() == "locked"
    });

    // A forward wall-clock jump locks early and can hide an extended deadline. This bound narrows
    // that window to 10 seconds, and only a jump inside it can let a regression pass.
    assert!(unlocked_at.elapsed() < Duration::from_secs(10));
}

// Release builds ignore the test timeout.
#[cfg(debug_assertions)]
#[test]
fn idle_vault_locks_itself_with_no_client_connected() {
    let sandbox = Sandbox::new();
    let log_path = sandbox.home.path().join("daemon.log");
    let mut command = sandbox.daemon_command();
    command
        .env("PASSWORDER_TEST_IDLE_TIMEOUT_SECS", "2")
        .stderr(fs::File::create(&log_path).expect("daemon log"));
    let _daemon = sandbox.start(command);

    assert!(sandbox.run(&["unlock"], "pw\n").status.success());

    wait_until("the daemon to report locking", || {
        fs::read_to_string(&log_path)
            .expect("read daemon log")
            .contains("Locked after the idle timeout")
    });
}

#[test]
fn second_daemon_is_refused() {
    let sandbox = Sandbox::new();
    let _daemon = sandbox.start_daemon();

    let (code, error_output) = sandbox.refused_daemon();

    assert_eq!(code, Some(2));
    assert!(error_output.contains("already running"), "{error_output}");
    assert_eq!(sandbox.status(), "locked");
}

#[test]
fn daemon_refuses_a_socket_directory_other_users_can_reach() {
    let sandbox = Sandbox::new();
    let dir = sandbox.socket().parent().unwrap().to_path_buf();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

    let (code, error_output) = sandbox.refused_daemon();

    assert_eq!(code, Some(2));
    assert!(error_output.contains("only your user"), "{error_output}");
}

#[test]
fn daemon_starts_after_a_previous_one_was_killed() {
    let sandbox = Sandbox::new();
    {
        let _killed = sandbox.start_daemon();
    }
    assert!(Path::new(&sandbox.socket()).exists());

    let _daemon = sandbox.start_daemon();

    assert_eq!(sandbox.status(), "locked");
}

#[test]
fn requests_outside_the_protocol_are_rejected() {
    let sandbox = Sandbox::new();
    let _daemon = sandbox.start_daemon();
    assert!(sandbox.run(&["unlock"], "pw\n").status.success());

    let bad_request = "{\"error\":\"bad_request\"}";
    let cases: [&[u8]; 6] = [
        b"{\"v\":1,\"op\":\"read_secret\",\"id\":\"x\"}\n",
        b"not json\n",
        b"{\"v\":1,\"op\":\"status\"}",
        b"{\"v\":1,\"op\":\"status\",\"password_base64\":\"cHc=\"}\n",
        b"{\"v\":1,\"op\":\"unlock\",\"password_base64\":\"\\u0063Hc=\"}\n",
        b"{\"v\":1,\"op\":\"unlock\",\"password_base64\":\"not base64\"}\n",
    ];
    for request in cases {
        assert_eq!(sandbox.raw_request(request), bad_request);
    }
    assert_eq!(
        sandbox.raw_request(&vec![b'x'; 70_000]),
        bad_request,
        "oversized"
    );
    assert_eq!(
        sandbox.raw_request(b"{\"v\":2,\"op\":\"status\"}\n"),
        "{\"error\":\"unsupported_version\"}"
    );
    assert_eq!(sandbox.status(), "unlocked");
}

#[test]
fn a_client_sending_slowly_cannot_hold_the_daemon_past_the_deadline() {
    let sandbox = Sandbox::new();
    let _daemon = sandbox.start_daemon();

    let mut stream = UnixStream::connect(sandbox.socket()).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();

    let start = Instant::now();
    let mut reply = String::new();
    while reply.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(30), "no reply");
        // Writing fails with EPIPE once the daemon closes the connection.
        let _ = stream.write_all(b" ");
        let _ = stream.read_to_string(&mut reply);
    }

    assert_eq!(reply, "{\"error\":\"bad_request\"}");
    assert_eq!(sandbox.status(), "locked");
}
