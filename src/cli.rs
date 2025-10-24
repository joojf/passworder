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

    #[arg(
        long,
        value_name = "BOOL",
        help = "Include lowercase letters (a-z).",
        default_missing_value = "true",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub lowercase: Option<bool>,
    #[arg(
        long = "no-lowercase",
        action = clap::ArgAction::SetTrue,
        help = "Disable lowercase letters."
    )]
    pub no_lowercase: bool,

    #[arg(
        long,
        value_name = "BOOL",
        help = "Include uppercase letters (A-Z).",
        default_missing_value = "true",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub uppercase: Option<bool>,
    #[arg(
        long = "no-uppercase",
        action = clap::ArgAction::SetTrue,
        help = "Disable uppercase letters."
    )]
    pub no_uppercase: bool,

    #[arg(
        long,
        value_name = "BOOL",
        help = "Include digits (0-9).",
        default_missing_value = "true",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub digits: Option<bool>,
    #[arg(
        long = "no-digits",
        action = clap::ArgAction::SetTrue,
        help = "Disable digits."
    )]
    pub no_digits: bool,

    #[arg(
        long,
        value_name = "BOOL",
        help = "Include symbol characters.",
        default_missing_value = "true",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub symbols: Option<bool>,
    #[arg(
        long = "no-symbols",
        action = clap::ArgAction::SetTrue,
        help = "Disable symbol characters."
    )]
    pub no_symbols: bool,
}

impl PasswordArgs {
    pub fn include_lowercase(&self) -> bool {
        resolve_toggle(self.lowercase, self.no_lowercase)
    }

    pub fn include_uppercase(&self) -> bool {
        resolve_toggle(self.uppercase, self.no_uppercase)
    }

    pub fn include_digits(&self) -> bool {
        resolve_toggle(self.digits, self.no_digits)
    }

    pub fn include_symbols(&self) -> bool {
        resolve_toggle(self.symbols, self.no_symbols)
    }
}

fn resolve_toggle(choice: Option<bool>, negated: bool) -> bool {
    choice.unwrap_or(!negated)
}
