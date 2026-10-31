use crate::app::AppContext;
use crate::{cli, exit_codes, output, vault};
use output::vault_item::{
    vault_item_json, vault_item_summary_json, vault_item_summary_text, vault_item_text,
};
use secrecy::ExposeSecret;
use serde_json::json;
use std::process::ExitCode;

pub fn run(args: cli::VaultArgs, ctx: &AppContext) -> ExitCode {
    match args.command {
        cli::VaultCommands::Path(args) => {
            let path = match vault::vault_path(args.path.path.as_deref()) {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("Error: {error}");
                    return exit_codes::exit_code_for_vault_error(&error);
                }
            };

            output::print_value(
                path.display().to_string(),
                json!({
                    "kind": "vault-path",
                    "path": path.display().to_string(),
                }),
                &ctx.output_mode,
                ctx.copy_requested,
            )
        }
        cli::VaultCommands::Status(args) => {
            let path = match vault::vault_path(args.path.path.as_deref()) {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("Error: {error}");
                    return exit_codes::exit_code_for_vault_error(&error);
                }
            };

            match vault::vault_status_v1(&path) {
                Ok((status, version)) => output::print_value(
                    status.as_str().to_string(),
                    json!({
                        "kind": "vault-status",
                        "path": path.display().to_string(),
                        "status": status.as_str(),
                        "version": version,
                    }),
                    &ctx.output_mode,
                    ctx.copy_requested,
                ),
                Err(error) => {
                    eprintln!("Error: {error}");
                    exit_codes::exit_code_for_vault_error(&error)
                }
            }
        }
        cli::VaultCommands::Init(args) => {
            let path = match vault::vault_path(args.path.path.as_deref()) {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("Error: {error}");
                    return exit_codes::exit_code_for_vault_error(&error);
                }
            };

            let master_password = match vault::prompt_new_master_password() {
                Ok(pw) => pw,
                Err(error) => {
                    eprintln!("Error: {error}");
                    return exit_codes::exit_code_for_vault_prompt_error(&error);
                }
            };

            match vault::vault_init_v1(&path, &master_password) {
                Ok(()) => output::print_value(
                    path.display().to_string(),
                    json!({
                        "kind": "vault-init",
                        "path": path.display().to_string(),
                    }),
                    &ctx.output_mode,
                    ctx.copy_requested,
                ),
                Err(error) => {
                    eprintln!("Error: {error}");
                    exit_codes::exit_code_for_vault_error(&error)
                }
            }
        }
        cli::VaultCommands::Add(args) => {
            let path = match vault::vault_path(args.path.path.as_deref()) {
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

            let secret = match args.secret {
                Some(s) => s.into(),
                None => match vault::prompt_secret("Secret: ") {
                    Ok(s) => s,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_codes::exit_code_for_vault_prompt_error(&error);
                    }
                },
            };

            let input = vault::AddItemInput {
                item_type: args.item_type,
                name: args.name,
                path: args.item_path,
                tags: args.tags,
                username: args.username,
                secret,
                urls: args.urls,
                notes: args.notes,
            };

            match vault::UnlockedVault::open(&path, &master_password)
                .and_then(|v| v.add_item(input))
            {
                Ok(id) => {
                    let value = id.to_string();
                    let meta = json!({
                        "kind": "vault-add",
                        "path": path.display().to_string(),
                        "id": value,
                    });

                    if ctx.output_mode.quiet {
                        output::print_value(value, meta, &ctx.output_mode, false)
                    } else {
                        output::print_value(format!("Added {value}"), meta, &ctx.output_mode, false)
                    }
                }
                Err(error) => {
                    eprintln!("Error: {error}");
                    exit_codes::exit_code_for_vault_error(&error)
                }
            }
        }
        cli::VaultCommands::Get(args) => {
            let path = match vault::vault_path(args.path.path.as_deref()) {
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

            match vault::UnlockedVault::open(&path, &master_password)
                .and_then(|v| v.get_item(args.id))
            {
                Ok(item) => {
                    let reveal = args.reveal;
                    let copied = ctx.copy_requested;

                    if copied
                        && let Err(error) = output::copy_to_clipboard(item.secret.expose_secret())
                    {
                        eprintln!("Error: {error}");
                        return ExitCode::from(exit_codes::EXIT_IO);
                    }

                    let meta = json!({
                        "kind": "vault-get",
                        "path": path.display().to_string(),
                        "id": item.id.to_string(),
                        "revealed": reveal,
                        "copied": copied,
                        "item": vault_item_json(&item, reveal),
                    });

                    if ctx.output_mode.quiet {
                        if reveal {
                            output::print_value(
                                item.secret.expose_secret().to_owned(),
                                meta,
                                &ctx.output_mode,
                                false,
                            )
                        } else {
                            output::print_value(item.id.to_string(), meta, &ctx.output_mode, false)
                        }
                    } else {
                        output::print_value(
                            vault_item_text(&item, reveal),
                            meta,
                            &ctx.output_mode,
                            false,
                        )
                    }
                }
                Err(error) => {
                    eprintln!("Error: {error}");
                    exit_codes::exit_code_for_vault_error(&error)
                }
            }
        }
        cli::VaultCommands::Edit(args) => {
            let path = match vault::vault_path(args.path.path.as_deref()) {
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

            let input = vault::EditItemInput {
                id: args.id,
                item_type: args.item_type,
                name: args.name,
                path: if args.clear_path {
                    vault::Change::Clear
                } else {
                    args.item_path
                        .map_or(vault::Change::Keep, vault::Change::Set)
                },
                tags: if args.clear_tags {
                    Some(Vec::new())
                } else if args.tags.is_empty() {
                    None
                } else {
                    Some(args.tags)
                },
                username: if args.clear_username {
                    vault::Change::Clear
                } else {
                    args.username
                        .map_or(vault::Change::Keep, vault::Change::Set)
                },
                secret: args.secret.map(Into::into),
                urls: if args.clear_urls {
                    Some(Vec::new())
                } else if args.urls.is_empty() {
                    None
                } else {
                    Some(args.urls)
                },
                notes: if args.clear_notes {
                    vault::Change::Clear
                } else {
                    args.notes.map_or(vault::Change::Keep, vault::Change::Set)
                },
            };

            match vault::UnlockedVault::open(&path, &master_password)
                .and_then(|v| v.edit_item(input))
            {
                Ok(()) => {
                    let value = args.id.to_string();
                    let meta = json!({
                        "kind": "vault-edit",
                        "path": path.display().to_string(),
                        "id": value,
                    });

                    if ctx.output_mode.quiet {
                        output::print_value(value, meta, &ctx.output_mode, false)
                    } else {
                        output::print_value(
                            format!("Edited {value}"),
                            meta,
                            &ctx.output_mode,
                            false,
                        )
                    }
                }
                Err(error) => {
                    eprintln!("Error: {error}");
                    exit_codes::exit_code_for_vault_error(&error)
                }
            }
        }
        cli::VaultCommands::Rm(args) => {
            let path = match vault::vault_path(args.path.path.as_deref()) {
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

            match vault::UnlockedVault::open(&path, &master_password)
                .and_then(|v| v.remove_item(args.id))
            {
                Ok(()) => {
                    let value = args.id.to_string();
                    let meta = json!({
                        "kind": "vault-rm",
                        "path": path.display().to_string(),
                        "id": value,
                    });

                    if ctx.output_mode.quiet {
                        output::print_value(value, meta, &ctx.output_mode, false)
                    } else {
                        output::print_value(
                            format!("Removed {value}"),
                            meta,
                            &ctx.output_mode,
                            false,
                        )
                    }
                }
                Err(error) => {
                    eprintln!("Error: {error}");
                    exit_codes::exit_code_for_vault_error(&error)
                }
            }
        }
        cli::VaultCommands::List(args) => {
            let path = match vault::vault_path(args.path.path.as_deref()) {
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

            match vault::UnlockedVault::open(&path, &master_password).and_then(|v| v.list_items()) {
                Ok(items) => {
                    let value = if ctx.output_mode.quiet {
                        items
                            .iter()
                            .map(|i| i.id.to_string())
                            .collect::<Vec<_>>()
                            .join("\n")
                    } else {
                        items
                            .iter()
                            .map(vault_item_summary_text)
                            .collect::<Vec<_>>()
                            .join("\n")
                    };

                    let meta = json!({
                        "kind": "vault-list",
                        "path": path.display().to_string(),
                        "count": items.len(),
                        "items": items.iter().map(vault_item_summary_json).collect::<Vec<_>>(),
                    });

                    output::print_value(value, meta, &ctx.output_mode, false)
                }
                Err(error) => {
                    eprintln!("Error: {error}");
                    exit_codes::exit_code_for_vault_error(&error)
                }
            }
        }
        cli::VaultCommands::Search(args) => {
            let path = match vault::vault_path(args.path.path.as_deref()) {
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

            let result = if args.query.trim().is_empty() {
                Ok(Vec::new())
            } else {
                vault::UnlockedVault::open(&path, &master_password)
                    .and_then(|v| v.search_items(&args.query))
            };

            match result {
                Ok(items) => {
                    let value = if ctx.output_mode.quiet {
                        items
                            .iter()
                            .map(|i| i.id.to_string())
                            .collect::<Vec<_>>()
                            .join("\n")
                    } else {
                        items
                            .iter()
                            .map(vault_item_summary_text)
                            .collect::<Vec<_>>()
                            .join("\n")
                    };

                    let meta = json!({
                        "kind": "vault-search",
                        "path": path.display().to_string(),
                        "query": args.query,
                        "count": items.len(),
                        "items": items.iter().map(vault_item_summary_json).collect::<Vec<_>>(),
                    });

                    output::print_value(value, meta, &ctx.output_mode, false)
                }
                Err(error) => {
                    eprintln!("Error: {error}");
                    exit_codes::exit_code_for_vault_error(&error)
                }
            }
        }
    }
}
