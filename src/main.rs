mod cli;
mod config;
mod entropy;
mod passphrase;
mod password;
mod token;
mod vault;
mod version;

use clap::{error::ErrorKind as ClapErrorKind, ColorChoice, CommandFactory, FromArgMatches};
use serde_json::json;
use std::io::IsTerminal;
use std::process::ExitCode;

const EXIT_USAGE: u8 = 64;
const EXIT_IO: u8 = 2;
const EXIT_SOFTWARE: u8 = 1;

#[cfg(any(debug_assertions, feature = "dev-seed"))]
fn emit_dev_seed_warning(seed: u64) {
    eprintln!("⚠️  WARNING: Using dev seed ({}) - output is deterministic and NOT cryptographically secure!", seed);
    eprintln!("⚠️  This mode is for testing only. Never use in production.");
}

fn main() -> ExitCode {
    let cli = match parse_cli() {
        Ok(cli) => cli,
        Err(code) => return code,
    };
    let copy_requested = cli.copy;
    let output_mode = OutputMode {
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

    match cli.command {
        Some(cli::Commands::Password(args)) => {
            let mut config = match args.profile.as_deref() {
                Some(name) => match config::get_profile(name) {
                    Ok(profile) => profile,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_config_error(&error);
                    }
                },
                None => password::PasswordConfig::default(),
            };

            args.options.apply_to_config(&mut config);

            match password::generate(config, dev_seed) {
                Ok(password) => print_value(
                    password,
                    json!({
                        "kind": "password",
                        "profile": args.profile,
                        "config": config,
                    }),
                    &output_mode,
                    copy_requested,
                ),
                Err(error) => {
                    eprintln!("Error: {error}");
                    exit_code_for_password_error(&error)
                }
            }
        }
        Some(cli::Commands::Profile(profile_args)) => match profile_args.command {
            cli::ProfileCommands::Save(save_args) => {
                let mut profile = password::PasswordConfig::default();
                save_args.options.apply_to_config(&mut profile);
                match config::save_profile(&save_args.name, profile) {
                    Ok(()) => {
                        if !output_mode.quiet && !output_mode.json {
                            println!("Saved profile '{}'", save_args.name);
                        } else if output_mode.json {
                            let payload = json!({
                                "value": save_args.name,
                                "meta": {
                                    "kind": "profile-save",
                                }
                            });
                            println!("{payload}");
                        }
                        ExitCode::SUCCESS
                    }
                    Err(error) => {
                        eprintln!("Error: {error}");
                        exit_code_for_config_error(&error)
                    }
                }
            }
            cli::ProfileCommands::List => match config::list_profiles() {
                Ok(profiles) => {
                    if output_mode.json {
                        let payload = json!({
                            "value": profiles.iter().map(|(name, _)| name).collect::<Vec<_>>(),
                            "meta": {
                                "kind": "profile-list",
                                "profiles": profiles,
                            }
                        });
                        println!("{payload}");
                    } else if !output_mode.quiet {
                        if profiles.is_empty() {
                            println!("No profiles saved.");
                        } else {
                            for (name, profile) in profiles {
                                println!(
                                    "{name}: length={} lowercase={} min_lower={} uppercase={} min_upper={} digits={} min_digit={} symbols={} min_symbol={} allow_ambiguous={}",
                                    profile.length,
                                    profile.include_lowercase,
                                    profile.min_lowercase,
                                    profile.include_uppercase,
                                    profile.min_uppercase,
                                    profile.include_digits,
                                    profile.min_digits,
                                    profile.include_symbols,
                                    profile.min_symbols,
                                    profile.allow_ambiguous
                                );
                            }
                        }
                    }
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("Error: {error}");
                    exit_code_for_config_error(&error)
                }
            },
            cli::ProfileCommands::Rm(remove_args) => {
                match config::remove_profile(&remove_args.name) {
                    Ok(()) => {
                        if !output_mode.quiet && !output_mode.json {
                            println!("Removed profile '{}'", remove_args.name);
                        } else if output_mode.json {
                            let payload = json!({
                                "value": remove_args.name,
                                "meta": {
                                    "kind": "profile-rm",
                                }
                            });
                            println!("{payload}");
                        }
                        ExitCode::SUCCESS
                    }
                    Err(error) => {
                        eprintln!("Error: {error}");
                        exit_code_for_config_error(&error)
                    }
                }
            }
        },
        Some(cli::Commands::Passphrase(args)) => {
            let config = passphrase::PassphraseConfig {
                word_count: args.words,
                separator: args.separator.clone(),
                title_case: args.title,
                wordlist: args.wordlist.clone(),
            };

            let meta = json!({
                "kind": "passphrase",
                "config": {
                    "word_count": config.word_count,
                    "separator": config.separator,
                    "title_case": config.title_case,
                    "wordlist": config.wordlist.as_ref().map(|p| p.display().to_string()),
                }
            });

            match passphrase::generate(config, dev_seed) {
                Ok(phrase) => print_value(
                    phrase,
                    meta,
                    &output_mode,
                    copy_requested,
                ),
                Err(error) => {
                    eprintln!("Error: {error}");
                    exit_code_for_passphrase_error(&error)
                }
            }
        }
        Some(cli::Commands::Token(token_args)) => match token::handle(token_args.command, dev_seed) {
            Ok(output) => print_value(
                output,
                json!({
                    "kind": "token",
                }),
                &output_mode,
                copy_requested,
            ),
            Err(error) => {
                eprintln!("Error: {error}");
                exit_code_for_token_error(&error)
            }
        },
        Some(cli::Commands::Entropy(args)) => {
            let config = entropy::EntropyConfig { input: args.input };
            match entropy::analyze(config) {
                Ok(report) => {
                    if output_mode.json {
                        let meta_report = serde_json::from_str(&report).unwrap_or_else(|_| {
                            json!({
                                "raw": report,
                            })
                        });
                        print_value(
                            report.clone(),
                            json!({
                                "kind": "entropy",
                                "report": meta_report,
                            }),
                            &output_mode,
                            copy_requested,
                        )
                    } else {
                        print_value(
                            report,
                            json!({
                                "kind": "entropy",
                            }),
                            &output_mode,
                            copy_requested,
                        )
                    }
                }
                Err(error) => {
                    eprintln!("Error: {error}");
                    exit_code_for_entropy_error(&error)
                }
            }
        }
        None => {
            // No subcommand provided; show help and exit with usage code.
            let mut cmd = configure_command_colors(cli::Cli::command());
            cmd.print_help().expect("help to be printed");
            println!();
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn parse_cli() -> Result<cli::Cli, ExitCode> {
    let mut cmd = configure_command_colors(cli::Cli::command());

    let matches = match cmd.try_get_matches() {
        Ok(matches) => matches,
        Err(err) => {
            let kind = err.kind();
            // Help/version are treated as successful exits.
            if matches!(kind, ClapErrorKind::DisplayHelp | ClapErrorKind::DisplayVersion) {
                let _ = err.print();
                return Err(ExitCode::SUCCESS);
            }

            let _ = err.print();
            return Err(ExitCode::from(EXIT_USAGE));
        }
    };

    match cli::Cli::from_arg_matches(&matches) {
        Ok(cli) => Ok(cli),
        Err(err) => {
            let _ = err.print();
            Err(ExitCode::from(EXIT_USAGE))
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

struct OutputMode {
    json: bool,
    quiet: bool,
}

fn print_value(
    value: String,
    meta: serde_json::Value,
    output_mode: &OutputMode,
    copy_requested: bool,
) -> ExitCode {
    if output_mode.json {
        let payload = json!({
            "value": value,
            "meta": meta,
        });
        println!("{payload}");
    } else {
        println!("{value}");
    }

    match maybe_copy(&value, copy_requested) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::from(EXIT_IO)
        }
    }
}

fn exit_code_for_config_error(error: &config::ConfigError) -> ExitCode {
    use config::ConfigError::*;

    match error {
        ConfigDirUnavailable | Io(_) => ExitCode::from(EXIT_IO),
        MissingProfile(_) | InvalidProfile(_) => ExitCode::from(EXIT_USAGE),
        Parse(_) | Serialize(_) | UnsupportedSchemaVersion(_) => ExitCode::from(EXIT_SOFTWARE),
    }
}

fn exit_code_for_password_error(error: &password::GenerationError) -> ExitCode {
    use password::GenerationError::*;

    match error {
        EmptyClass(_)
        | EmptyPool
        | LengthTooShort { .. }
        | NoClassesEnabled
        | MinimumRequiresDisabledClass(_) => ExitCode::from(EXIT_USAGE),
    }
}

fn exit_code_for_passphrase_error(error: &passphrase::PassphraseError) -> ExitCode {
    use passphrase::PassphraseError::*;

    match error {
        WordCountZero => ExitCode::from(EXIT_USAGE),
        Io { .. } => ExitCode::from(EXIT_IO),
        EmptyWordList { .. } => ExitCode::from(EXIT_SOFTWARE),
    }
}

fn exit_code_for_token_error(error: &token::TokenError) -> ExitCode {
    use token::TokenError::*;

    match error {
        ByteLengthZero => ExitCode::from(EXIT_USAGE),
        SampleBytesFailed => ExitCode::from(EXIT_IO),
    }
}

fn exit_code_for_entropy_error(error: &entropy::EntropyError) -> ExitCode {
    use entropy::EntropyError::*;

    match error {
        Io(_) => ExitCode::from(EXIT_IO),
        InvalidUtf8 => ExitCode::from(EXIT_USAGE),
        Serialization(_) | Strength(_) => ExitCode::from(EXIT_SOFTWARE),
    }
}

fn maybe_copy(output: &str, copy_requested: bool) -> Result<(), String> {
    if !copy_requested {
        return Ok(());
    }

    copy_to_clipboard(output)
}

#[cfg(feature = "clipboard")]
fn copy_to_clipboard(output: &str) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|error| format!("Failed to access clipboard: {error}"))?;
    clipboard
        .set_text(output.to_owned())
        .map_err(|error| format!("Failed to copy output to clipboard: {error}"))?;
    Ok(())
}

#[cfg(not(feature = "clipboard"))]
fn copy_to_clipboard(_output: &str) -> Result<(), String> {
    eprintln!("Warning: `--copy` requires building with `--features clipboard`.");
    Ok(())
}
