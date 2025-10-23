use clap::{Args, Parser, Subcommand};
#[derive(Debug, Parser)]
#[command(
    name = "passworder",
    author,
    version,
    about = "A Rust-first password generator CLI for developers.",
    long_about = "A Rust-first password generator CLI for developers. Functionality is coming soon."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(about = "Generate a password with sensible defaults.")]
    Password(PasswordArgs),
}

#[derive(Debug, Args)]
pub struct PasswordArgs {
    #[arg(short, long, default_value_t = 20usize, help = "Password length.")]
    pub length: usize,

    #[arg(
        long,
        help = "Allow ambiguous characters such as 0, O, l, 1, and |.",
        action = clap::ArgAction::SetTrue
    )]
    pub allow_ambiguous: bool,
}
