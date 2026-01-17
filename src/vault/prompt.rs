use secrecy::SecretString;
use std::io::IsTerminal;
use std::io::{self, BufRead, Write};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PromptError {
    #[error("io error")]
    Io(#[from] io::Error),

    #[error("input cannot be empty")]
    Empty,

    #[error("passwords do not match")]
    Mismatch,
}

pub fn prompt_new_master_password() -> Result<SecretString, PromptError> {
    let first = read_secret_line("Master password: ")?;
    if first.is_empty() {
        return Err(PromptError::Empty);
    }
    let confirm = read_secret_line("Confirm master password: ")?;
    if first != confirm {
        return Err(PromptError::Mismatch);
    }
    Ok(SecretString::new(first.into_boxed_str()))
}

pub fn prompt_master_password() -> Result<SecretString, PromptError> {
    let pw = read_secret_line("Master password: ")?;
    if pw.is_empty() {
        return Err(PromptError::Empty);
    }
    Ok(SecretString::new(pw.into_boxed_str()))
}

pub fn prompt_secret(label: &str) -> Result<String, PromptError> {
    let value = read_secret_line(label)?;
    if value.is_empty() {
        return Err(PromptError::Empty);
    }
    Ok(value)
}

fn read_secret_line(prompt: &str) -> Result<String, PromptError> {
    eprint!("{prompt}");
    io::stderr().flush()?;

    if io::stdin().is_terminal() {
        #[cfg(unix)]
        {
            return read_line_no_echo_unix();
        }
    }

    read_line_plain()
}

fn read_line_plain() -> Result<String, PromptError> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(trim_line_endings(&line))
}

#[cfg(unix)]
fn read_line_no_echo_unix() -> Result<String, PromptError> {
    use std::mem::MaybeUninit;
    use std::os::unix::io::AsRawFd;

    let stdin = io::stdin();
    let fd = stdin.as_raw_fd();

    unsafe {
        let mut original = MaybeUninit::<libc::termios>::uninit();
        if libc::tcgetattr(fd, original.as_mut_ptr()) != 0 {
            return read_line_plain();
        }
        let original = original.assume_init();

        let mut modified = original;
        modified.c_lflag &= !(libc::ECHO | libc::ECHONL);
        let _guard = TermiosGuard {
            fd,
            original,
            active: libc::tcsetattr(fd, libc::TCSANOW, &modified) == 0,
        };

        let line = read_line_plain()?;
        eprintln!();
        Ok(line)
    }
}

#[cfg(unix)]
struct TermiosGuard {
    fd: i32,
    original: libc::termios,
    active: bool,
}

#[cfg(unix)]
impl Drop for TermiosGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                let _ = libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
            }
        }
    }
}

fn trim_line_endings(s: &str) -> String {
    s.trim_end_matches(&['\n', '\r'][..]).to_string()
}
