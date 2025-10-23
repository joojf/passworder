mod cli;

use clap::{CommandFactory, Parser};
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();

    match cli.command {
        Some(cli::Commands::Generate) => {
            eprintln!("Password generation is not implemented yet. Stay tuned!");
            ExitCode::SUCCESS
        }
        None => {
            let mut cmd = cli::Cli::command();
            cmd.print_help().expect("help to be printed");
            println!();
            ExitCode::SUCCESS
        }
    }
}
