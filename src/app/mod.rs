use crate::{cli, commands, exit_codes, output};
use clap::{ColorChoice, CommandFactory, FromArgMatches, error::ErrorKind as ClapErrorKind};
use std::io::IsTerminal;
use std::process::ExitCode;

pub(crate) struct AppContext {
    pub output_mode: output::OutputMode,
    pub copy_requested: bool,
    pub dev_seed: Option<u64>,
}

#[cfg(any(debug_assertions, feature = "dev-seed"))]
fn emit_dev_seed_warning(seed: u64) {
    eprintln!(
        "⚠️  WARNING: Using dev seed ({}) - output is deterministic and NOT cryptographically secure!",
        seed
    );
    eprintln!("⚠️  This mode is for testing only. Never use in production.");
}

pub fn run() -> ExitCode {
    let cli = match parse_cli() {
        Ok(cli) => cli,
        Err(code) => return code,
    };

    let output_mode = output::OutputMode {
        json: cli.json,
        quiet: cli.quiet,
    };

    #[cfg(any(debug_assertions, feature = "dev-seed"))]
    let dev_seed = cli.dev_seed;
    #[cfg(not(any(debug_assertions, feature = "dev-seed")))]
    let dev_seed: Option<u64> = None;

    #[cfg(any(debug_assertions, feature = "dev-seed"))]
    if let Some(seed) = dev_seed {
        emit_dev_seed_warning(seed);
    }

    let Some(command) = cli.command else {
        let mut cmd = configure_command_colors(cli::Cli::command());
        cmd.print_help().expect("help to be printed");
        println!();
        return ExitCode::from(exit_codes::EXIT_USAGE);
    };

    let ctx = AppContext {
        output_mode,
        copy_requested: cli.copy,
        dev_seed,
    };

    commands::dispatch(command, &ctx)
}

fn parse_cli() -> Result<cli::Cli, ExitCode> {
    let cmd = configure_command_colors(cli::Cli::command());

    let matches = match cmd.try_get_matches() {
        Ok(matches) => matches,
        Err(err) => {
            let kind = err.kind();
            if matches!(
                kind,
                ClapErrorKind::DisplayHelp | ClapErrorKind::DisplayVersion
            ) {
                let _ = err.print();
                return Err(ExitCode::SUCCESS);
            }

            let _ = err.print();
            return Err(ExitCode::from(exit_codes::EXIT_USAGE));
        }
    };

    match cli::Cli::from_arg_matches(&matches) {
        Ok(cli) => Ok(cli),
        Err(err) => {
            let _ = err.print();
            Err(ExitCode::from(exit_codes::EXIT_USAGE))
        }
    }
}

fn configure_command_colors(mut cmd: clap::Command) -> clap::Command {
    let no_color = std::env::var_os("NO_COLOR").is_some();
    let stdout_is_tty = std::io::stdout().is_terminal();
    let stderr_is_tty = std::io::stderr().is_terminal();

    if no_color || !(stdout_is_tty && stderr_is_tty) {
        cmd = cmd.color(ColorChoice::Never);
    }

    cmd
}
