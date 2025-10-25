mod cli;
mod passphrase;
mod password;

use clap::{CommandFactory, Parser};
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();

    match cli.command {
        Some(cli::Commands::Password(args)) => {
            let config = password::PasswordConfig {
                length: args.length,
                allow_ambiguous: args.allow_ambiguous,
                include_lowercase: args.include_lowercase(),
                include_uppercase: args.include_uppercase(),
                include_digits: args.include_digits(),
                include_symbols: args.include_symbols(),
            };

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
        None => {
            let mut cmd = cli::Cli::command();
            cmd.print_help().expect("help to be printed");
            println!();
            ExitCode::SUCCESS
        }
    }
}
