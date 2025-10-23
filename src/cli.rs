use clap::{Parser, Subcommand};
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
    #[command(about = "Generate a password (coming soon).")]
    Generate,
}
