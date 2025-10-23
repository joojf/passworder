# passworder

Rust-powered password generator CLI focused on developer ergonomics.

## Project Status

The current release only ships the project scaffold. Command parsing is wired up with [`clap`](https://github.com/clap-rs/clap) and ready for future subcommands.

## Getting Started

```bash
cargo run -- generate
```

The `generate` subcommand is a placeholder for now and simply confirms that the CLI plumbing works.

## Development

- Rust 1.76+ (2024 edition)
- `cargo fmt` / `cargo clippy` recommended before contributing

Feel free to sketch new subcommands under `src/cli.rs` and corresponding logic in new modules.
