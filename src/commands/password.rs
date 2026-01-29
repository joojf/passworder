use crate::app::AppContext;
use crate::{cli, config, exit_codes, output, password};
use serde_json::json;
use std::process::ExitCode;

pub fn run(args: cli::PasswordArgs, ctx: &AppContext) -> ExitCode {
    let mut config = match args.profile.as_deref() {
        Some(name) => match config::get_profile(name) {
            Ok(profile) => profile,
            Err(error) => {
                eprintln!("Error: {error}");
                return exit_codes::exit_code_for_config_error(&error);
            }
        },
        None => password::PasswordConfig::default(),
    };

    args.options.apply_to_config(&mut config);

    match password::generate(config, ctx.dev_seed) {
        Ok(password) => output::print_value(
            password,
            json!({
                "kind": "password",
                "profile": args.profile,
                "config": config,
            }),
            &ctx.output_mode,
            ctx.copy_requested,
        ),
        Err(error) => {
            eprintln!("Error: {error}");
            exit_codes::exit_code_for_password_error(&error)
        }
    }
}
