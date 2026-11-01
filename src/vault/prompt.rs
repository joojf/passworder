use secrecy::SecretString;
use std::io::{self, BufRead, IsTerminal, Write};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PromptError {
    #[error("io error")]
    Io(#[from] io::Error),

    #[error("input cannot be empty")]
    Empty,

    #[error("passwords do not match")]
    Mismatch,

    #[error("cannot disable terminal echo, so refusing to read sensitive input: {0}")]
    EchoControl(io::Error),
}

pub fn prompt_new_master_password() -> Result<SecretString, PromptError> {
    let _hidden = hide_input()?;
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

pub fn prompt_secret(label: &str) -> Result<SecretString, PromptError> {
    let value = read_secret_line(label)?;
    if value.is_empty() {
        return Err(PromptError::Empty);
    }
    Ok(value.into())
}

fn read_secret_line(prompt: &str) -> Result<String, PromptError> {
    let _hidden = hide_input()?;
    eprint!("{prompt}");
    io::stderr().flush()?;

    let mut line = String::new();
    let result = io::stdin().lock().read_line(&mut line);
    // With echo off, the terminal doesn't show the newline the user typed.
    if io::stdin().is_terminal() {
        eprintln!();
    }
    result?;
    Ok(trim_line_endings(&line))
}

#[cfg(not(unix))]
pub struct HiddenInput;

#[cfg(not(unix))]
pub fn hide_input() -> Result<HiddenInput, PromptError> {
    if io::stdin().is_terminal() {
        return Err(PromptError::EchoControl(io::ErrorKind::Unsupported.into()));
    }
    Ok(HiddenInput)
}

/// Keeps terminal echo off until dropped. A guard taken while another is alive does nothing.
#[cfg(unix)]
pub struct HiddenInput(Option<SavedTerminal>);

#[cfg(unix)]
struct SavedTerminal {
    termios: libc::termios,
    signal_actions: [libc::sigaction; TERMINATING_SIGNALS.len() + 1],
}

#[cfg(unix)]
const TERMINATING_SIGNALS: [libc::c_int; 4] =
    [libc::SIGINT, libc::SIGTERM, libc::SIGQUIT, libc::SIGHUP];

/// Read by the signal handler, which can't reach the guard.
#[cfg(unix)]
static ORIGINAL_TERMIOS: std::sync::OnceLock<libc::termios> = std::sync::OnceLock::new();

#[cfg(unix)]
static GUARD_HELD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
pub fn hide_input() -> Result<HiddenInput, PromptError> {
    use std::mem::MaybeUninit;
    use std::sync::atomic::Ordering;

    if !io::stdin().is_terminal() || GUARD_HELD.load(Ordering::Relaxed) {
        return Ok(HiddenInput(None));
    }

    unsafe {
        let mut termios = MaybeUninit::<libc::termios>::uninit();
        if libc::tcgetattr(libc::STDIN_FILENO, termios.as_mut_ptr()) != 0 {
            return Err(PromptError::EchoControl(io::Error::last_os_error()));
        }
        let termios = termios.assume_init();

        // The handler must be able to restore the terminal before echo goes off.
        ORIGINAL_TERMIOS.get_or_init(|| termios);
        let signal_actions = install_signal_actions();

        let mut hidden = termios;
        hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
        if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &hidden) != 0 {
            let error = io::Error::last_os_error();
            restore_signal_actions(&signal_actions);
            return Err(PromptError::EchoControl(error));
        }

        GUARD_HELD.store(true, Ordering::Relaxed);
        Ok(HiddenInput(Some(SavedTerminal {
            termios,
            signal_actions,
        })))
    }
}

#[cfg(unix)]
unsafe fn install_signal_actions() -> [libc::sigaction; TERMINATING_SIGNALS.len() + 1] {
    use std::mem::zeroed;

    unsafe {
        let mut restore: libc::sigaction = zeroed();
        restore.sa_sigaction = restore_terminal_and_reraise as *const () as libc::sighandler_t;
        restore.sa_flags = libc::SA_RESETHAND;
        // Another signal must not interrupt the restore, and SIGTTOU would stop a background job.
        libc::sigemptyset(&mut restore.sa_mask);
        libc::sigaddset(&mut restore.sa_mask, libc::SIGTTOU);
        for signal in TERMINATING_SIGNALS {
            libc::sigaddset(&mut restore.sa_mask, signal);
        }

        // After Ctrl-Z and `fg`, the shell may have turned echo back on.
        let mut ignore: libc::sigaction = zeroed();
        ignore.sa_sigaction = libc::SIG_IGN;
        libc::sigemptyset(&mut ignore.sa_mask);

        let mut previous: [libc::sigaction; TERMINATING_SIGNALS.len() + 1] = zeroed();
        for (signal, previous) in TERMINATING_SIGNALS.iter().zip(&mut previous) {
            libc::sigaction(*signal, &restore, previous);
        }
        libc::sigaction(
            libc::SIGTSTP,
            &ignore,
            &mut previous[TERMINATING_SIGNALS.len()],
        );
        previous
    }
}

#[cfg(unix)]
unsafe fn restore_signal_actions(actions: &[libc::sigaction; TERMINATING_SIGNALS.len() + 1]) {
    unsafe {
        for (signal, action) in TERMINATING_SIGNALS.iter().zip(actions) {
            libc::sigaction(*signal, action, std::ptr::null_mut());
        }
        libc::sigaction(
            libc::SIGTSTP,
            &actions[TERMINATING_SIGNALS.len()],
            std::ptr::null_mut(),
        );
    }
}

/// Signal handlers can only make async-signal-safe calls, so this can't print or allocate.
/// SA_RESETHAND restored the default action, so the raised signal ends the process on return.
#[cfg(unix)]
extern "C" fn restore_terminal_and_reraise(signal: libc::c_int) {
    unsafe {
        if let Some(termios) = ORIGINAL_TERMIOS.get() {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, termios);
        }
        libc::raise(signal);
    }
}

#[cfg(unix)]
impl Drop for HiddenInput {
    fn drop(&mut self) {
        use std::mem::zeroed;

        let Some(saved) = &self.0 else { return };

        unsafe {
            let mut sigttou: libc::sigset_t = zeroed();
            let mut previous_mask: libc::sigset_t = zeroed();
            libc::sigemptyset(&mut sigttou);
            libc::sigaddset(&mut sigttou, libc::SIGTTOU);
            libc::pthread_sigmask(libc::SIG_BLOCK, &sigttou, &mut previous_mask);

            // TCSAFLUSH discards unread input, which the shell would otherwise read after exit.
            let restored = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &saved.termios);
            let error = io::Error::last_os_error();

            libc::pthread_sigmask(libc::SIG_SETMASK, &previous_mask, std::ptr::null_mut());
            restore_signal_actions(&saved.signal_actions);
            GUARD_HELD.store(false, std::sync::atomic::Ordering::Relaxed);

            if restored != 0 {
                let _ = writeln!(
                    io::stderr(),
                    "Warning: cannot restore terminal echo: {error}"
                );
            }
        }
    }
}

fn trim_line_endings(s: &str) -> String {
    s.trim_end_matches(&['\n', '\r'][..]).to_string()
}
