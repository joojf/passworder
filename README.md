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
- `--min-lower <N>` / `--min-upper <N>` / `--min-digit <N>` / `--min-symbol <N>`: require at least `N` characters from the respective class (defaults to `1` for enabled classes).
- Total required characters (sum of the `--min-*` values for enabled classes) must not exceed `--length`.
- `--allow-ambiguous`: allow characters such as `0`, `O`, `l`, `1`, and `|`.

Example enforcing uppercase-only passwords with custom length:

```bash
cargo run -- password --length 32 --lowercase=false --no-digits --no-symbols
```

### Output Modes

By default commands print the primary value to STDOUT (for example, the generated password or token) followed by a newline.

- `--json`: wraps the value in a stable JSON envelope:  
  `{ "value": "<string>", "meta": { ... } }`
- `--quiet`: prints only the generated value on STDOUT, without extra messages. This is most useful with profile commands or when combined with `--copy`.

Examples:

```bash
cargo run -- password --json
# => {"value":"s3cr3t...","meta":{"kind":"password","profile":null,"config":{...}}}

cargo run -- entropy --input "abc" --json
# => {"value":"{\"length\":3,...}","meta":{"kind":"entropy","report":{"length":3,"shannon_bits_estimate":...}}}
```

The `meta.kind` field identifies the command (`"password"`, `"passphrase"`, `"token"`, `"entropy"`, `"profile-save"`, `"profile-list"`, `"profile-rm"`), and additional metadata fields are stable for a given kind (for example, password `config` matches the `PasswordConfig` structure in `src/password.rs`).

### Clipboard Copy

```bash
cargo run -- password --copy
```

`--copy` works with password, passphrase, token, and entropy outputs. The value is still printed to STDOUT so scripts keep working, and it is also written to the clipboard when possible. If the clipboard is unavailable (for example in headless sessions), the flag emits a warning and execution continues.

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

#### Custom word lists

- `--wordlist` expects a UTF-8 text file with one entry per line. Lines are streamed, trimmed, and blank entries are ignored so it is safe to include comments or spacing for readability.
- The loader reads the file incrementally, so memory usage is roughly the size of the normalized vocabulary. As a rule of thumb, a 100k-word Diceware list with 8-character averages stays under ~2 MB of RAM (roughly `word_count * (avg_len + 8 bytes)` for `String` storage).
- Sequential I/O dominates load time. Keeping large lists on SSD/NVMe storage avoids the extra seek latency you would see on HDDs; on spinning disks expect the first load to take noticeably longer until the OS cache is warm.
- Invalid UTF-8 or empty lists trigger descriptive errors so CI pipelines can surface bad enterprise-approved word lists quickly.

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

## Exit Codes & TTY Behavior

`passworder` is intended to be script-friendly. Exit codes are stable across releases:

| Code | Meaning                    | Examples                                                                 |
|------|----------------------------|--------------------------------------------------------------------------|
| 0    | Success                    | Normal generation, profile commands that succeed.                        |
| 1    | Internal / software error  | Unexpected failures (serialization, strength estimator, config schema).  |
| 2    | IO / OS error              | Config file IO, wordlist file IO, RNG failure, clipboard access errors.  |
| 64   | Usage error (`EX_USAGE`)   | Invalid CLI flags, impossible password policies, zero-length settings, invalid UTF-8 on STDIN, unknown profiles. |

Argument parsing errors (reported by `clap`) use code `64`. Module-specific errors are mapped into the same table so that future `anyhow`-based code paths can downcast to the underlying error type and reuse these categories.

ANSI styling is only enabled when both STDOUT and STDERR are attached to a TTY and `NO_COLOR` is not set. In practice this means:

- Piped usage/errors (`passworder ... 2>&1 | ...`) are always plain text.
- Setting `NO_COLOR=1` disables all ANSI styling even in interactive terminals.

## Development

- Rust 1.76+ (2024 edition)
- `cargo fmt` / `cargo clippy` recommended before contributing

Feel free to sketch new subcommands under `src/cli.rs` and corresponding logic in new modules.
