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

### Clipboard Copy

Build with the optional clipboard feature to mirror output to your system clipboard:

```bash
cargo run --features clipboard -- password --copy
```

`--copy` works with password, passphrase, token, and entropy outputs. The value is still printed to STDOUT so scripts keep working, but it is also written to the clipboard when the feature is enabled. Without the feature, the flag emits a warning and execution continues.

Security notes:
- Clipboard contents are shared across applications and history managers; treat copied secrets as exposed until you clear them.
- On some platforms the clipboard may be unavailable in headless sessions or when access is denied, causing the copy step to fail ([`arboard::Clipboard` docs](https://docs.rs/arboard/latest/arboard/struct.Clipboard.html)).

Remember to clear your clipboard after use if your OS does not do so automatically.

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

### Tokens

```bash
cargo run -- token hex --bytes 16
```

The `token` subcommand provides quick random identifiers:

- `hex` (default 16 bytes → 32 hex chars) with `--bytes <N>` for length.
- `b64` (URL-safe base64 without padding) with `--bytes <N>`.
- `uuid` generates an RFC 4122 version 4 UUID.

### Profiles

```bash
cargo run -- profile save team --length 24 --no-digits
```

Profiles let teams codify password policies:

- `profile save NAME ...flags` stores password options (same flags as `password`).
- `profile list` shows saved profiles and their settings.
- `profile rm NAME` removes a profile.
- `password --profile NAME` generates using the saved settings (flags can still override).

### Entropy

```bash
echo -n "Tr0ub4dor&3" | cargo run -- entropy
```

Outputs a JSON report with the input length and a Shannon entropy estimate in bits. You can also pass data directly without STDIN:

```bash
cargo run -- entropy --input "correcthorsebatterystaple"
```

Build with `--features strength` to augment the entropy output with [zxcvbn](https://github.com/dropbox/zxcvbn) strength data. When the feature is enabled you will see `guesses_log10`, `score`, and friendly `crack_times_display` strings in the JSON response, matching the library's estimator fields.[^zxcvbn]

Without the feature, the command falls back to the original Shannon estimate so existing consumers remain compatible.

[^zxcvbn]: zxcvbn exposes the strength fields documented in `result.guesses_log10`, `result.score`, and `result.crack_times_display` ([source](https://github.com/dropbox/zxcvbn/blob/master/README.md)).

## Development

- Rust 1.76+ (2024 edition)
- `cargo fmt` / `cargo clippy` recommended before contributing

Feel free to sketch new subcommands under `src/cli.rs` and corresponding logic in new modules.
