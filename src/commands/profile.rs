use crate::app::AppContext;
use crate::{cli, config, exit_codes, password};
use serde_json::json;
use std::process::ExitCode;

pub fn run(args: cli::ProfileArgs, ctx: &AppContext) -> ExitCode {
    match args.command {
        cli::ProfileCommands::Save(save_args) => {
            let mut profile = password::PasswordConfig::default();
            save_args.options.apply_to_config(&mut profile);
            match config::save_profile(&save_args.name, profile) {
                Ok(()) => {
                    if !ctx.output_mode.quiet && !ctx.output_mode.json {
                        println!("Saved profile '{}'", save_args.name);
                    } else if ctx.output_mode.json {
                        let payload = json!({
                            "value": save_args.name,
                            "meta": {
                                "kind": "profile-save",
                            }
                        });
                        println!("{payload}");
                    }
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("Error: {error}");
                    exit_codes::exit_code_for_config_error(&error)
                }
            }
        }
        cli::ProfileCommands::List => match config::list_profiles() {
            Ok(profiles) => {
                if ctx.output_mode.json {
                    let payload = json!({
                        "value": profiles.iter().map(|(name, _)| name).collect::<Vec<_>>(),
                        "meta": {
                            "kind": "profile-list",
                            "profiles": profiles,
                        }
                    });
                    println!("{payload}");
                } else if !ctx.output_mode.quiet {
                    if profiles.is_empty() {
                        println!("No profiles saved.");
                    } else {
                        for (name, profile) in profiles {
                            println!(
                                "{name}: length={} lowercase={} min_lower={} uppercase={} min_upper={} digits={} min_digit={} symbols={} min_symbol={} allow_ambiguous={}",
                                profile.length,
                                profile.include_lowercase,
                                profile.min_lowercase,
                                profile.include_uppercase,
                                profile.min_uppercase,
                                profile.include_digits,
                                profile.min_digits,
                                profile.include_symbols,
                                profile.min_symbols,
                                profile.allow_ambiguous
                            );
                        }
                    }
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("Error: {error}");
                exit_codes::exit_code_for_config_error(&error)
            }
        },
        cli::ProfileCommands::Rm(remove_args) => match config::remove_profile(&remove_args.name) {
            Ok(()) => {
                if !ctx.output_mode.quiet && !ctx.output_mode.json {
                    println!("Removed profile '{}'", remove_args.name);
                } else if ctx.output_mode.json {
                    let payload = json!({
                        "value": remove_args.name,
                        "meta": {
                            "kind": "profile-rm",
                        }
                    });
                    println!("{payload}");
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("Error: {error}");
                exit_codes::exit_code_for_config_error(&error)
            }
        },
    }
}
