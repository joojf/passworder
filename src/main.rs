mod cli;
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
        None => {
            let mut cmd = cli::Cli::command();
            cmd.print_help().expect("help to be printed");
            println!();
            ExitCode::SUCCESS
        }
    }
}
