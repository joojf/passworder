mod cli;
mod config;
mod entropy;
mod passphrase;
mod password;
mod token;

use clap::{CommandFactory, Parser};
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();

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

            match password::generate(config) {
                Ok(password) => {
                    println!("{password}");
                    ExitCode::SUCCESS
                }
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
                        println!("Saved profile '{}'", save_args.name);
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
                    if profiles.is_empty() {
                        println!("No profiles saved.");
                    } else {
                        for (name, profile) in profiles {
                            println!(
                                "{name}: length={} lowercase={} uppercase={} digits={} symbols={} allow_ambiguous={}",
                                profile.length,
                                profile.include_lowercase,
                                profile.include_uppercase,
                                profile.include_digits,
                                profile.include_symbols,
                                profile.allow_ambiguous
                            );
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
                        println!("Removed profile '{}'", remove_args.name);
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

            match passphrase::generate(config) {
                Ok(phrase) => {
                    println!("{phrase}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("Error: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(cli::Commands::Token(token_args)) => match token::handle(token_args.command) {
            Ok(output) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("Error: {error}");
                ExitCode::FAILURE
            }
        },
        Some(cli::Commands::Entropy(args)) => {
            let config = entropy::EntropyConfig { input: args.input };
            match entropy::analyze(config) {
                Ok(report) => {
                    println!("{report}");
                    ExitCode::SUCCESS
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
