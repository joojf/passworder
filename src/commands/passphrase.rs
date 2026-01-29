use crate::app::AppContext;
use crate::{cli, exit_codes, output, passphrase};
use serde_json::json;
use std::process::ExitCode;

pub fn run(args: cli::PassphraseArgs, ctx: &AppContext) -> ExitCode {
    let config = passphrase::PassphraseConfig {
        word_count: args.words,
        separator: args.separator.clone(),
        title_case: args.title,
        wordlist: args.wordlist.clone(),
    };

    let meta = json!({
        "kind": "passphrase",
        "config": {
            "word_count": config.word_count,
            "separator": config.separator,
            "title_case": config.title_case,
            "wordlist": config.wordlist.as_ref().map(|p| p.display().to_string()),
        }
    });

    match passphrase::generate(config, ctx.dev_seed) {
        Ok(phrase) => output::print_value(phrase, meta, &ctx.output_mode, ctx.copy_requested),
        Err(error) => {
            eprintln!("Error: {error}");
            exit_codes::exit_code_for_passphrase_error(&error)
        }
    }
}
