mod cli;
mod config;
mod entropy;
mod passphrase;
mod password;
mod token;
mod version;

use clap::{CommandFactory, Parser};
use serde_json::json;
use std::process::ExitCode;

#[cfg(any(debug_assertions, feature = "dev-seed"))]
fn emit_dev_seed_warning(seed: u64) {
    eprintln!("⚠️  WARNING: Using dev seed ({}) - output is deterministic and NOT cryptographically secure!", seed);
    eprintln!("⚠️  This mode is for testing only. Never use in production.");
}

fn main() -> ExitCode {
    let cli = cli::Cli::parse();
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
                        return ExitCode::FAILURE;
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
                    ExitCode::FAILURE
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
                        ExitCode::FAILURE
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
                    ExitCode::FAILURE
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
                        ExitCode::FAILURE
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
                    ExitCode::FAILURE
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
                ExitCode::FAILURE
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
                    ExitCode::FAILURE
                }
            }
        }
        None => {
            let mut cmd = cli::Cli::command();
            cmd.print_help().expect("help to be printed");
            println!();
            ExitCode::SUCCESS
        }
    }
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
            ExitCode::FAILURE
        }
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
