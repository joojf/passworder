use crate::app::AppContext;
use crate::{cli, exit_codes, output, token};
use serde_json::json;
use std::process::ExitCode;

pub fn run(args: cli::TokenArgs, ctx: &AppContext) -> ExitCode {
    match token::handle(args.command, ctx.dev_seed) {
        Ok(value) => output::print_value(
            value,
            json!({
                "kind": "token",
            }),
            &ctx.output_mode,
            ctx.copy_requested,
        ),
        Err(error) => {
            eprintln!("Error: {error}");
            exit_codes::exit_code_for_token_error(&error)
        }
    }
}
