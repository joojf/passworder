use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::PathBuf;
use thiserror::Error;

/// Programs whose main job is running other code. This list only catches the common ones: a
/// program that reads scripts, hooks or plugins can still run code the agent chose.
const COMMAND_RUNNERS: &[&str] = &[
    "sh",
    "ash",
    "bash",
    "rbash",
    "dash",
    "zsh",
    "fish",
    "ksh",
    "mksh",
    "csh",
    "tcsh",
    "busybox",
    "python",
    "pypy",
    "node",
    "nodejs",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
    "lua",
    "luajit",
    "tclsh",
    "wish",
    "R",
    "Rscript",
    "julia",
    "osascript",
    "java",
    "env",
    "sudo",
    "doas",
    "su",
    "pkexec",
    "runuser",
    "xargs",
    "nohup",
    "timeout",
    "time",
    "nice",
    "ionice",
    "chrt",
    "taskset",
    "setsid",
    "stdbuf",
    "chroot",
    "unshare",
    "nsenter",
    "flock",
    "script",
    "watch",
    "strace",
    "ltrace",
    "gdb",
    "lldb",
    "valgrind",
];

/// Variables that change how a program runs. A secret has no business there.
const EXECUTION_CONTROL_ENV: &[&str] =
    &["PATH", "ENV", "BASH_ENV", "NODE_OPTIONS", "PYTHONSTARTUP"];
const EXECUTION_CONTROL_ENV_PREFIXES: &[&str] = &["LD_", "DYLD_"];

#[derive(Debug, Error)]
pub enum GrantError {
    #[error("PATH is not set, so give the program as a path")]
    PathUnset,

    #[error("program not found in PATH: {0}")]
    ProgramNotFound(String),

    #[error("cannot use program {program}: {source}")]
    Program { program: String, source: io::Error },

    #[error("not an executable file: {}", .0.display())]
    NotExecutable(PathBuf),

    #[error("{0} can run other programs, so it can't receive secrets")]
    CommandRunner(String),

    #[error("invalid environment variable name: {0}")]
    InvalidEnvName(String),

    #[error("{0} controls how programs run, so it can't hold a secret")]
    ExecutionControlEnv(String),

    #[error("{} already receives {env}", program.display())]
    Duplicate { program: PathBuf, env: String },

    #[error("grant not found: {0}")]
    NotFound(String),
}

pub fn validate_env_name(name: &str) -> Result<(), GrantError> {
    let mut chars = name.chars();
    let valid = chars
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric());
    if !valid {
        return Err(GrantError::InvalidEnvName(name.to_string()));
    }
    if EXECUTION_CONTROL_ENV.contains(&name)
        || EXECUTION_CONTROL_ENV_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
    {
        return Err(GrantError::ExecutionControlEnv(name.to_string()));
    }
    Ok(())
}

/// Finds the program like a shell would, then resolves symlinks so the grant names the real file.
pub fn resolve_program(program: &str) -> Result<PathBuf, GrantError> {
    let found = if program.contains('/') {
        PathBuf::from(program)
    } else {
        let path = std::env::var_os("PATH").ok_or(GrantError::PathUnset)?;
        std::env::split_paths(&path)
            .map(|dir| dir.join(program))
            .find(|candidate| is_executable_file(candidate))
            .ok_or_else(|| GrantError::ProgramNotFound(program.to_string()))?
    };

    let canonical = fs::canonicalize(&found).map_err(|source| GrantError::Program {
        program: program.to_string(),
        source,
    })?;
    if !is_executable_file(&canonical) {
        return Err(GrantError::NotExecutable(canonical));
    }

    // Checking both names catches an innocent-looking symlink to a shell.
    for name in [found.file_name(), canonical.file_name()]
        .into_iter()
        .flatten()
    {
        if runs_other_commands(name) {
            return Err(GrantError::CommandRunner(
                name.to_string_lossy().into_owned(),
            ));
        }
    }
    Ok(canonical)
}

/// Ignores version suffixes, so python3.12, python3.13t and perl5.38 count as python and perl.
/// A suffix that isn't a version, as in python3-config, names a different program.
fn runs_other_commands(file_name: &OsStr) -> bool {
    let name = file_name.to_string_lossy();
    // Dynamic loaders (ld-linux-x86-64.so.2, ld-musl-x86_64.so.1, ld.so) run any program given.
    if name.starts_with("ld") && name.contains(".so") {
        return true;
    }
    let (base, suffix) = name.split_at(
        name.find(|c: char| c.is_ascii_digit())
            .unwrap_or(name.len()),
    );
    let is_version = suffix
        .trim_end_matches('t')
        .chars()
        .all(|c| c.is_ascii_digit() || c == '.');
    is_version && COMMAND_RUNNERS.contains(&base.trim_end_matches(['-', '.']))
}

#[cfg(unix)]
fn is_executable_file(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(path: &std::path::Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versioned_interpreter_names_are_command_runners() {
        for name in [
            "bash",
            "python3",
            "python3.12",
            "python3.13t",
            "perl5.38",
            "luajit-2.1",
            "ld-linux-x86-64.so.2",
            "ld-musl-x86_64.so.1",
        ] {
            assert!(runs_other_commands(OsStr::new(name)), "{name}");
        }
        for name in [
            "curl",
            "ssh",
            "envsubst",
            "pythonista",
            "python3-config",
            "ldd",
        ] {
            assert!(!runs_other_commands(OsStr::new(name)), "{name}");
        }
    }
}
