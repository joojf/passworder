use crate::app::AppContext;
use crate::{cli, dev_workflows, exit_codes, vault};
use std::process::{ExitCode, Stdio};

pub fn env(args: cli::EnvArgs, ctx: &AppContext) -> ExitCode {
    if ctx.output_mode.json || ctx.output_mode.quiet || ctx.copy_requested {
        eprintln!("Error: `env` does not support `--json`, `--quiet`, or `--copy`.");
        return ExitCode::from(exit_codes::EXIT_USAGE);
    }
    if !args.unsafe_mode {
        eprintln!("Error: `env` prints secrets; re-run with `--unsafe` to proceed.");
        return ExitCode::from(exit_codes::EXIT_USAGE);
    }
    if std::env::var_os("CI").is_some() {
        eprintln!("Warning: CI detected; secret output may be logged.");
    }

    let vault_path = match vault::vault_path(args.vault.path.as_deref()) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("Error: {error}");
            return exit_codes::exit_code_for_vault_error(&error);
        }
    };

    let master_password = match vault::prompt_master_password() {
        Ok(pw) => pw,
        Err(error) => {
            eprintln!("Error: {error}");
            return exit_codes::exit_code_for_vault_prompt_error(&error);
        }
    };

    let items = match vault::vault_list_items_v1(&vault_path, &master_password) {
        Ok(items) => items,
        Err(error) => {
            eprintln!("Error: {error}");
            return exit_codes::exit_code_for_vault_error(&error);
        }
    };
    let vars = dev_workflows::env_vars_for_profile(&items, &args.profile);
    if vars.is_empty() {
        eprintln!("Warning: profile '{}' has no items.", args.profile);
    }

    match args.format {
        cli::EnvFormat::Bash => match dev_workflows::bash_export_lines(&vars) {
            Ok(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("Error: {error}");
                ExitCode::from(exit_codes::EXIT_USAGE)
            }
        },
        cli::EnvFormat::Json => {
            let json = serde_json::to_string(&vars).expect("json serialization");
            println!("{json}");
            ExitCode::SUCCESS
        }
    }
}

pub fn run(args: cli::RunArgs, ctx: &AppContext) -> ExitCode {
    if ctx.output_mode.json || ctx.output_mode.quiet || ctx.copy_requested {
        eprintln!("Error: `run` does not support `--json`, `--quiet`, or `--copy`.");
        return ExitCode::from(exit_codes::EXIT_USAGE);
    }
    if std::env::var_os("CI").is_some() && !args.unsafe_mode {
        eprintln!("Error: refusing to run in CI without `--unsafe` (env may be logged).");
        return ExitCode::from(exit_codes::EXIT_USAGE);
    }

    let vault_path = match vault::vault_path(args.vault.path.as_deref()) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("Error: {error}");
            return exit_codes::exit_code_for_vault_error(&error);
        }
    };

    let master_password = match vault::prompt_master_password() {
        Ok(pw) => pw,
        Err(error) => {
            eprintln!("Error: {error}");
            return exit_codes::exit_code_for_vault_prompt_error(&error);
        }
    };

    let items = match vault::vault_list_items_v1(&vault_path, &master_password) {
        Ok(items) => items,
        Err(error) => {
            eprintln!("Error: {error}");
            return exit_codes::exit_code_for_vault_error(&error);
        }
    };
    let vars = dev_workflows::env_vars_for_profile(&items, &args.profile);
    if vars.is_empty() {
        eprintln!("Warning: profile '{}' has no items.", args.profile);
    } else {
        eprintln!(
            "Warning: injecting {} env vars into child process.",
            vars.len()
        );
    }

    let Some((program, args_rest)) = args.cmd.split_first() else {
        eprintln!("Error: missing command to run (use `--`).");
        return ExitCode::from(exit_codes::EXIT_USAGE);
    };

    let mut cmd = std::process::Command::new(program);
    cmd.args(args_rest);
    cmd.env_clear();
    cmd.envs(std::env::vars_os());
    cmd.envs(vars.iter());
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    let status = match cmd.status() {
        Ok(s) => s,
        Err(error) => {
            eprintln!("Error: {error}");
            return ExitCode::from(exit_codes::EXIT_IO);
        }
    };

    ExitCode::from(status.code().unwrap_or(exit_codes::EXIT_SOFTWARE as i32) as u8)
}

pub fn inject(args: cli::InjectArgs, ctx: &AppContext) -> ExitCode {
    if ctx.output_mode.json || ctx.output_mode.quiet || ctx.copy_requested {
        eprintln!("Error: `inject` does not support `--json`, `--quiet`, or `--copy`.");
        return ExitCode::from(exit_codes::EXIT_USAGE);
    }
    if !args.unsafe_mode {
        eprintln!("Error: `inject` writes secrets to disk; re-run with `--unsafe` to proceed.");
        return ExitCode::from(exit_codes::EXIT_USAGE);
    }
    if std::env::var_os("CI").is_some() {
        eprintln!("Warning: CI detected; written secrets may be logged or cached.");
    }

    if args.output.exists() && !args.force {
        eprintln!(
            "Error: output file already exists (pass --force to overwrite): {}",
            args.output.display()
        );
        return ExitCode::from(exit_codes::EXIT_USAGE);
    }

    let vault_path = match vault::vault_path(args.vault.path.as_deref()) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("Error: {error}");
            return exit_codes::exit_code_for_vault_error(&error);
        }
    };

    let master_password = match vault::prompt_master_password() {
        Ok(pw) => pw,
        Err(error) => {
            eprintln!("Error: {error}");
            return exit_codes::exit_code_for_vault_prompt_error(&error);
        }
    };

    let items = match vault::vault_list_items_v1(&vault_path, &master_password) {
        Ok(items) => items,
        Err(error) => {
            eprintln!("Error: {error}");
            return exit_codes::exit_code_for_vault_error(&error);
        }
    };
    let vars = dev_workflows::env_vars_for_profile(&items, &args.profile);
    if vars.is_empty() {
        eprintln!("Warning: profile '{}' has no items.", args.profile);
    }

    let template = match std::fs::read_to_string(&args.input) {
        Ok(s) => s,
        Err(error) => {
            eprintln!("Error: {error}");
            return ExitCode::from(exit_codes::EXIT_IO);
        }
    };

    let rendered = match dev_workflows::render_template(&template, &vars) {
        Ok(s) => s,
        Err(error) => {
            eprintln!("Error: {error}");
            return ExitCode::from(exit_codes::EXIT_USAGE);
        }
    };

    if let Err(error) =
        dev_workflows::write_sensitive_file_atomic(&args.output, rendered.as_bytes())
    {
        eprintln!("Error: {error}");
        return ExitCode::from(exit_codes::EXIT_IO);
    }

    println!("{}", args.output.display());
    ExitCode::SUCCESS
}
