mod entropy;
mod passphrase;
mod password;
mod profile;
mod token;
mod tui;
mod vault;
mod workflows;

use crate::app::AppContext;
use crate::cli;
use std::process::ExitCode;

pub fn dispatch(command: cli::Commands, ctx: &AppContext) -> ExitCode {
    match command {
        cli::Commands::Password(args) => password::run(args, ctx),
        cli::Commands::Profile(args) => profile::run(args, ctx),
        cli::Commands::Passphrase(args) => passphrase::run(args, ctx),
        cli::Commands::Token(args) => token::run(args, ctx),
        cli::Commands::Entropy(args) => entropy::run(args, ctx),
        cli::Commands::Tui => tui::run(ctx),
        cli::Commands::Env(args) => workflows::env(args, ctx),
        cli::Commands::Run(args) => workflows::run(args, ctx),
        cli::Commands::Inject(args) => workflows::inject(args, ctx),
        cli::Commands::Vault(args) => vault::run(args, ctx),
    }
}
