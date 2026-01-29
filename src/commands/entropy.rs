use crate::app::AppContext;
use crate::{cli, entropy, exit_codes, output};
use serde_json::json;
use std::process::ExitCode;

pub fn run(args: cli::EntropyArgs, ctx: &AppContext) -> ExitCode {
    let config = entropy::EntropyConfig { input: args.input };
    match entropy::analyze(config) {
        Ok(report) => {
            if ctx.output_mode.json {
                let meta_report = serde_json::from_str(&report).unwrap_or_else(|_| {
                    json!({
                        "raw": report,
                    })
                });
                output::print_value(
                    report.clone(),
                    json!({
                        "kind": "entropy",
                        "report": meta_report,
                    }),
                    &ctx.output_mode,
                    ctx.copy_requested,
                )
            } else {
                output::print_value(
                    report,
                    json!({
                        "kind": "entropy",
                    }),
                    &ctx.output_mode,
                    ctx.copy_requested,
                )
            }
        }
        Err(error) => {
            eprintln!("Error: {error}");
            exit_codes::exit_code_for_entropy_error(&error)
        }
    }
}
