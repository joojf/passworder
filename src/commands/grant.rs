use crate::app::AppContext;
use crate::{cli, exit_codes, output, vault};
use serde_json::{Value, json};
use std::process::ExitCode;

pub fn run(args: cli::GrantArgs, ctx: &AppContext) -> ExitCode {
    let path_args = match &args.command {
        cli::GrantCommands::Add(add) => &add.path,
        cli::GrantCommands::List(list) => &list.path,
        cli::GrantCommands::Rm(rm) => &rm.path,
    };
    let path = match vault::vault_path(path_args.path.as_deref()) {
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

    let unlocked = match vault::UnlockedVault::open(&path, &master_password) {
        Ok(unlocked) => unlocked,
        Err(error) => {
            eprintln!("Error: {error}");
            return exit_codes::exit_code_for_vault_error(&error);
        }
    };

    let quiet = ctx.output_mode.quiet;
    let result = match args.command {
        cli::GrantCommands::Add(add) => add_grant(&unlocked, add, quiet),
        cli::GrantCommands::List(_) => list_grants(&unlocked, quiet),
        cli::GrantCommands::Rm(rm) => remove_grant(&unlocked, rm, quiet),
    };

    match result {
        Ok((value, mut meta)) => {
            meta["path"] = json!(path.display().to_string());
            output::print_value(value, meta, &ctx.output_mode, false)
        }
        Err(error) => {
            eprintln!("Error: {error}");
            exit_codes::exit_code_for_vault_error(&error)
        }
    }
}

fn add_grant(
    unlocked: &vault::UnlockedVault,
    args: cli::GrantAddArgs,
    quiet: bool,
) -> Result<(String, Value), vault::VaultError> {
    let grant = unlocked.add_grant(args.item, &args.program, &args.env)?;
    let id = grant.id.to_string();
    let value = if quiet {
        id.clone()
    } else {
        format!(
            "Granted {} to {} ({id})",
            grant.env,
            grant.program.display()
        )
    };
    let meta = json!({
        "kind": "grant-add",
        "id": id,
        "item_id": grant.item_id.to_string(),
        "program": grant.program,
        "env": grant.env,
    });
    Ok((value, meta))
}

fn list_grants(
    unlocked: &vault::UnlockedVault,
    quiet: bool,
) -> Result<(String, Value), vault::VaultError> {
    let grants = unlocked.list_grants()?;
    let lines: Vec<String> = grants
        .iter()
        .map(|(grant, item_name)| {
            if quiet {
                grant.id.to_string()
            } else {
                let program = grant.program.display();
                format!("{}\t{}\t{program}\t{item_name}", grant.id, grant.env)
            }
        })
        .collect();
    let rows: Vec<Value> = grants
        .iter()
        .map(|(grant, item_name)| {
            json!({
                "id": grant.id.to_string(),
                "item_id": grant.item_id.to_string(),
                "item_name": item_name,
                "program": grant.program,
                "env": grant.env,
                "created_at": grant.created_at,
            })
        })
        .collect();
    let meta = json!({ "kind": "grant-list", "count": rows.len(), "grants": rows });
    Ok((lines.join("\n"), meta))
}

fn remove_grant(
    unlocked: &vault::UnlockedVault,
    args: cli::GrantRmArgs,
    quiet: bool,
) -> Result<(String, Value), vault::VaultError> {
    unlocked.remove_grant(args.id)?;
    let id = args.id.to_string();
    let value = if quiet {
        id.clone()
    } else {
        format!("Removed {id}")
    };
    Ok((value, json!({ "kind": "grant-rm", "id": id })))
}
