# passworder

Rust-powered password generator CLI focused on developer ergonomics.

## Project Status

The current release only ships the project scaffold. Command parsing is wired up with [`clap`](https://github.com/clap-rs/clap) and ready for future subcommands.

## Getting Started

```bash
cargo run -- password
```

The command returns a 20-character password drawn from upper, lower, digit, and symbol classes, omitting ambiguous characters like `0`, `O`, `l`, and `1` by default.

### Options

- `--length <N>`: adjust password length (default: `20`).
- `--lowercase=<bool>` / `--no-lowercase`: toggle lowercase letters.
- `--uppercase=<bool>` / `--no-uppercase`: toggle uppercase letters.
- `--digits=<bool>` / `--no-digits`: toggle digits.
- `--symbols=<bool>` / `--no-symbols`: toggle symbol characters.
- `--allow-ambiguous`: allow characters such as `0`, `O`, `l`, `1`, and `|`.

Example enforcing uppercase-only passwords with custom length:

```bash
cargo run -- password --length 32 --lowercase=false --no-digits --no-symbols
```

### Passphrases

```bash
cargo run -- passphrase
```

Generates a six-word passphrase separated by hyphens using a small built-in word list. Flags:

- `--words <N>`: number of words (default: `6`).
- `--separator <SEP>`: custom separator string (default: `-`).
- `--title`: title-case each word.
- `--wordlist <FILE>`: provide a custom word list file (one word per line). Recommended for production use (e.g., a Diceware list).

Example using a custom Diceware file and spaces:

```bash
cargo run -- passphrase --wordlist ~/diceware.txt --separator " " --words 8 --title
```

## Development

- Rust 1.76+ (2024 edition)
- `cargo fmt` / `cargo clippy` recommended before contributing

Feel free to sketch new subcommands under `src/cli.rs` and corresponding logic in new modules.
