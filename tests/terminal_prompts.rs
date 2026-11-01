#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(60);

/// Runs passworder as the session leader of a real terminal, with no shell to tidy up after it.
struct Terminal {
    master: File,
    slave: OwnedFd,
    child: Child,
    output: String,
}

impl Terminal {
    fn spawn(home: &Path, args: &[&str]) -> Self {
        let (mut master_fd, mut slave_fd) = (-1, -1);
        let opened = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(opened, 0, "openpty");
        let master = unsafe { File::from_raw_fd(master_fd) };
        let slave = unsafe { OwnedFd::from_raw_fd(slave_fd) };

        let flags = unsafe { libc::fcntl(master_fd, libc::F_GETFL) };
        unsafe { libc::fcntl(master_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };

        let mut command = Command::new(env!("CARGO_BIN_EXE_passworder"));
        command
            .args(args)
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env_remove("PASSWORDER_VAULT")
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()));
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        Self {
            master,
            slave,
            child: command.spawn().expect("spawn passworder"),
            output: String::new(),
        }
    }

    fn type_input(&mut self, input: &str) {
        self.master
            .write_all(input.as_bytes())
            .expect("write to terminal");
    }

    fn drain_output(&mut self) {
        let mut buffer = [0u8; 1024];
        // The master is non-blocking, so a read fails once the buffer is empty.
        while let Ok(count @ 1..) = self.master.read(&mut buffer) {
            self.output
                .push_str(&String::from_utf8_lossy(&buffer[..count]));
        }
    }

    fn wait_for_output(&mut self, expected: &str, mut on_each_poll: impl FnMut(&Self)) {
        let start = Instant::now();
        while !self.output.contains(expected) {
            assert!(
                start.elapsed() < DEADLINE,
                "no {expected:?} in {:?}",
                self.output
            );
            on_each_poll(self);
            self.drain_output();
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn wait_for_exit(&mut self) -> ExitStatus {
        let start = Instant::now();
        loop {
            self.drain_output();
            if let Some(status) = self.child.try_wait().expect("wait for child") {
                self.drain_output();
                return status;
            }
            assert!(
                start.elapsed() < DEADLINE,
                "child still running: {:?}",
                self.output
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn echo_is_on(&self) -> bool {
        let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
        let result = unsafe { libc::tcgetattr(self.slave.as_raw_fd(), &mut termios) };
        assert_eq!(result, 0, "tcgetattr");
        termios.c_lflag & libc::ECHO != 0
    }

    fn unread_input_bytes(&self) -> libc::c_int {
        let mut count: libc::c_int = 0;
        let result =
            unsafe { libc::ioctl(self.slave.as_raw_fd(), libc::FIONREAD as _, &mut count) };
        assert_eq!(result, 0, "FIONREAD");
        count
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn init_vault(home: &Path) {
    let init = common::passworder(home)
        .env("PASSWORDER_VAULT_TEST_KDF", "1")
        .args(["vault", "init"])
        .write_stdin("pw\npw\n")
        .output()
        .expect("vault init");
    assert!(init.status.success());
}

#[test]
fn ctrl_c_at_a_prompt_turns_echo_back_on_and_dies_by_the_signal() {
    let home = tempfile::tempdir().expect("temp home");
    init_vault(home.path());

    let mut terminal = Terminal::spawn(home.path(), &["vault", "list"]);
    terminal.wait_for_output("Master password: ", |_| {});
    assert!(!terminal.echo_is_on());

    terminal.type_input("\x03");

    assert_eq!(terminal.wait_for_exit().signal(), Some(libc::SIGINT));
    assert!(terminal.echo_is_on());
}

#[test]
fn echo_stays_off_while_the_vault_unlocks_between_prompts() {
    let home = tempfile::tempdir().expect("temp home");
    init_vault(home.path());

    let args = ["vault", "add", "--type", "api-token", "--name", "KEY"];
    let mut terminal = Terminal::spawn(home.path(), &args);
    terminal.wait_for_output("Master password: ", |_| {});

    terminal.type_input("pw\n");
    terminal.wait_for_output("Secret: ", |terminal| assert!(!terminal.echo_is_on()));

    terminal.type_input("SECRETVALUE\n");

    assert_eq!(terminal.wait_for_exit().code(), Some(0));
    assert!(terminal.echo_is_on());
    assert!(!terminal.output.contains("SECRETVALUE"));
}

#[test]
fn input_typed_ahead_of_a_failed_unlock_does_not_reach_the_shell() {
    let home = tempfile::tempdir().expect("temp home");
    init_vault(home.path());

    let args = ["vault", "add", "--type", "api-token", "--name", "KEY"];
    let mut terminal = Terminal::spawn(home.path(), &args);
    terminal.wait_for_output("Master password: ", |_| {});

    terminal.type_input("wrong\nSECRETVALUE\n");

    assert_eq!(terminal.wait_for_exit().code(), Some(64));
    assert!(terminal.echo_is_on());
    assert!(!terminal.output.contains("SECRETVALUE"));
    assert_eq!(terminal.unread_input_bytes(), 0);
}
