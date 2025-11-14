use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
#[derive(Debug, Parser)]
#[command(
    name = "passworder",
    author,
    version = crate::version::SHORT,
    long_version = crate::version::LONG,
    about = "A Rust-first password generator CLI for developers.",
    long_about = "A Rust-first password generator CLI for developers. Functionality is coming soon."
)]
pub struct Cli {
    #[arg(
        long,
        global = true,
        help = "Copy generated output to the system clipboard (requires `--features clipboard`)."
    )]
    pub copy: bool,
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(about = "Generate a password with sensible defaults.")]
    Password(PasswordArgs),
    #[command(about = "Generate a passphrase from a word list.")]
    Passphrase(PassphraseArgs),
    #[command(subcommand_required = true, about = "Generate random tokens.")]
    Token(TokenArgs),
    #[command(about = "Estimate entropy for a given input string.")]
    Entropy(EntropyArgs),
    #[command(
        subcommand_required = true,
        about = "Manage reusable password profiles."
    )]
    Profile(ProfileArgs),
}

#[derive(Debug, Args)]
pub struct PasswordArgs {
    #[arg(long, help = "Use a saved profile for password generation.")]
    pub profile: Option<String>,
    #[command(flatten)]
    pub options: PasswordOptionsArgs,
}

#[derive(Debug, Args, Clone, Default)]
pub struct PasswordOptionsArgs {
    #[arg(
        short,
        long,
        value_name = "N",
        help = "Password length.",
        value_parser = clap::value_parser!(usize)
    )]
    pub length: Option<usize>,

    #[arg(
        long = "allow-ambiguous",
        value_name = "BOOL",
        default_missing_value = "true",
        value_parser = clap::builder::BoolishValueParser::new(),
        help = "Allow ambiguous characters such as 0, O, l, 1, and |."
    )]
    pub allow_ambiguous: Option<bool>,
    #[arg(
        long = "no-allow-ambiguous",
        action = clap::ArgAction::SetTrue,
        help = "Disallow ambiguous characters."
    )]
    pub no_allow_ambiguous: bool,

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
        long = "min-lower",
        value_name = "N",
        help = "Require at least N lowercase characters.",
        value_parser = clap::value_parser!(usize)
    )]
    pub min_lower: Option<usize>,

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
        long = "min-upper",
        value_name = "N",
        help = "Require at least N uppercase characters.",
        value_parser = clap::value_parser!(usize)
    )]
    pub min_upper: Option<usize>,

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
        long = "min-digit",
        value_name = "N",
        help = "Require at least N digits.",
        value_parser = clap::value_parser!(usize)
    )]
    pub min_digit: Option<usize>,

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

    #[arg(
        long = "min-symbol",
        value_name = "N",
        help = "Require at least N symbols.",
        value_parser = clap::value_parser!(usize)
    )]
    pub min_symbol: Option<usize>,
}

impl PasswordOptionsArgs {
    pub fn apply_to_config(&self, config: &mut crate::password::PasswordConfig) {
        if let Some(length) = self.length {
            config.length = length;
        }

        apply_bool_option(
            self.allow_ambiguous,
            self.no_allow_ambiguous,
            &mut config.allow_ambiguous,
        );
        apply_bool_option(
            self.lowercase,
            self.no_lowercase,
            &mut config.include_lowercase,
        );
        if !config.include_lowercase {
            config.min_lowercase = 0;
        }
        apply_bool_option(
            self.uppercase,
            self.no_uppercase,
            &mut config.include_uppercase,
        );
        if !config.include_uppercase {
            config.min_uppercase = 0;
        }
        apply_bool_option(self.digits, self.no_digits, &mut config.include_digits);
        if !config.include_digits {
            config.min_digits = 0;
        }
        apply_bool_option(self.symbols, self.no_symbols, &mut config.include_symbols);
        if !config.include_symbols {
            config.min_symbols = 0;
        }

        if let Some(min_lower) = self.min_lower {
            config.min_lowercase = min_lower;
            if min_lower > 0 {
                config.include_lowercase = true;
            }
        }
        if let Some(min_upper) = self.min_upper {
            config.min_uppercase = min_upper;
            if min_upper > 0 {
                config.include_uppercase = true;
            }
        }
        if let Some(min_digit) = self.min_digit {
            config.min_digits = min_digit;
            if min_digit > 0 {
                config.include_digits = true;
            }
        }
        if let Some(min_symbol) = self.min_symbol {
            config.min_symbols = min_symbol;
            if min_symbol > 0 {
                config.include_symbols = true;
            }
        }
    }
}

fn apply_bool_option(choice: Option<bool>, negated: bool, value: &mut bool) {
    if let Some(explicit) = choice {
        *value = explicit;
    } else if negated {
        *value = false;
    }
}

#[derive(Debug, Args)]
pub struct PassphraseArgs {
    #[arg(
        short,
        long,
        default_value_t = 6usize,
        help = "Number of words in the passphrase."
    )]
    pub words: usize,

    #[arg(
        short,
        long,
        default_value = "-",
        help = "Separator placed between words."
    )]
    pub separator: String,

    #[arg(long, help = "Title-case each word in the passphrase.")]
    pub title: bool,

    #[arg(
        long,
        value_name = "FILE",
        help = "Path to a custom word list (one word per line)."
    )]
    pub wordlist: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ProfileArgs {
    #[command(subcommand)]
    pub command: ProfileCommands,
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommands {
    #[command(about = "Create or update a profile with the provided options.")]
    Save(ProfileSaveArgs),
    #[command(about = "List saved profiles.")]
    List,
    #[command(about = "Remove a saved profile.")]
    Rm(ProfileRemoveArgs),
}

#[derive(Debug, Args)]
pub struct ProfileSaveArgs {
    #[arg(value_name = "NAME", help = "Profile name to create or update.")]
    pub name: String,
    #[command(flatten)]
    pub options: PasswordOptionsArgs,
}

#[derive(Debug, Args)]
pub struct ProfileRemoveArgs {
    #[arg(value_name = "NAME", help = "Profile name to remove.")]
    pub name: String,
}

#[derive(Debug, Subcommand)]
pub enum TokenCommands {
    #[command(about = "Generate a hexadecimal token.")]
    Hex(TokenBytesArgs),
    #[command(about = "Generate a base64 (unpadded) token.")]
    B64(TokenBytesArgs),
    #[command(about = "Generate an RFC 4122 UUID v4.")]
    Uuid,
}

#[derive(Debug, Args)]
pub struct TokenBytesArgs {
    #[arg(
        short,
        long,
        default_value_t = 16usize,
        help = "Number of random bytes to generate."
    )]
    pub bytes: usize,
}

#[derive(Debug, Args)]
pub struct TokenArgs {
    #[command(subcommand)]
    pub command: TokenCommands,
}

#[derive(Debug, Args)]
pub struct EntropyArgs {
    #[arg(
        long,
        value_name = "STRING",
        help = "Input string to analyze; falls back to STDIN when omitted."
    )]
    pub input: Option<String>,
}
