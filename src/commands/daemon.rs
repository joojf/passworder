use crate::app::AppContext;
use crate::daemon::{self, ErrorCode, Op, Response, State};
use crate::{cli, exit_codes, output, vault};
use serde_json::json;
use std::io;
use std::process::ExitCode;

pub fn serve(args: cli::DaemonArgs, ctx: &AppContext) -> ExitCode {
    if ctx.output_mode.json || ctx.output_mode.quiet || ctx.copy_requested {
        eprintln!("Error: `daemon` does not support `--json`, `--quiet`, or `--copy`.");
        return ExitCode::from(exit_codes::EXIT_USAGE);
    }

    let vault_path = match vault::vault_path(args.path.path.as_deref()) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("Error: {error}");
            return exit_codes::exit_code_for_vault_error(&error);
        }
    };

    match daemon::serve(vault_path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::from(exit_codes::EXIT_IO)
        }
    }
}

pub fn unlock(ctx: &AppContext) -> ExitCode {
    if let Some(code) = reject_copy(ctx) {
        return code;
    }

    // Ask first, so nobody types a password with no daemon to receive it.
    match daemon::send(Op::Status, None) {
        Ok(Response::State(State::Locked)) => {}
        result => return report(result, ctx),
    }

    let password = match vault::prompt_master_password() {
        Ok(password) => password,
        Err(error) => {
            eprintln!("Error: {error}");
            return exit_codes::exit_code_for_vault_prompt_error(&error);
        }
    };

    report(daemon::send(Op::Unlock, Some(&password)), ctx)
}

pub fn lock(ctx: &AppContext) -> ExitCode {
    reject_copy(ctx).unwrap_or_else(|| report(daemon::send(Op::Lock, None), ctx))
}

pub fn status(ctx: &AppContext) -> ExitCode {
    reject_copy(ctx).unwrap_or_else(|| report(daemon::send(Op::Status, None), ctx))
}

fn reject_copy(ctx: &AppContext) -> Option<ExitCode> {
    ctx.copy_requested.then(|| {
        eprintln!("Error: this command does not support `--copy`.");
        ExitCode::from(exit_codes::EXIT_USAGE)
    })
}

fn report(result: io::Result<Response>, ctx: &AppContext) -> ExitCode {
    match result {
        Ok(Response::State(state)) => output::print_value(
            state.as_str().to_string(),
            json!({ "kind": "daemon-state", "state": state.as_str() }),
            &ctx.output_mode,
            false,
        ),
        Ok(Response::Error(code)) => report_daemon_error(code),
        Err(error) if is_not_running(&error) => {
            eprintln!("Error: the daemon is not running (start it with `passworder daemon`).");
            ExitCode::from(exit_codes::EXIT_IO)
        }
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::from(exit_codes::EXIT_IO)
        }
    }
}

fn is_not_running(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    )
}

fn report_daemon_error(code: ErrorCode) -> ExitCode {
    let (message, exit_code) = match code {
        ErrorCode::AuthFailed => ("authentication failed", exit_codes::EXIT_USAGE),
        ErrorCode::VaultMissing => ("the vault does not exist", exit_codes::EXIT_USAGE),
        ErrorCode::BadRequest => ("the daemon rejected the request", exit_codes::EXIT_SOFTWARE),
        ErrorCode::UnsupportedVersion => (
            "the daemon runs a different version, so restart it",
            exit_codes::EXIT_SOFTWARE,
        ),
        ErrorCode::Internal => (
            "the daemon failed, see its output",
            exit_codes::EXIT_SOFTWARE,
        ),
    };
    eprintln!("Error: {message}");
    ExitCode::from(exit_code)
}
