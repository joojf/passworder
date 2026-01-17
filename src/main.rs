mod cli;
mod config;
mod dev_workflows;
mod entropy;
mod passphrase;
mod password;
mod token;
mod vault;
mod version;

use clap::{error::ErrorKind as ClapErrorKind, ColorChoice, CommandFactory, FromArgMatches};
use serde_json::json;
use std::io::IsTerminal;
use std::process::Stdio;
use std::process::ExitCode;

const EXIT_USAGE: u8 = 64;
const EXIT_IO: u8 = 2;
const EXIT_SOFTWARE: u8 = 1;

#[cfg(any(debug_assertions, feature = "dev-seed"))]
fn emit_dev_seed_warning(seed: u64) {
    eprintln!("⚠️  WARNING: Using dev seed ({}) - output is deterministic and NOT cryptographically secure!", seed);
    eprintln!("⚠️  This mode is for testing only. Never use in production.");
}

fn main() -> ExitCode {
    let cli = match parse_cli() {
        Ok(cli) => cli,
        Err(code) => return code,
    };
    let copy_requested = cli.copy;
    let output_mode = OutputMode {
        json: cli.json,
        quiet: cli.quiet,
    };

    #[cfg(any(debug_assertions, feature = "dev-seed"))]
    let dev_seed = cli.dev_seed;
    #[cfg(not(any(debug_assertions, feature = "dev-seed")))]
    let dev_seed: Option<u64> = None;

    #[cfg(any(debug_assertions, feature = "dev-seed"))]
    if let Some(seed) = dev_seed {
        emit_dev_seed_warning(seed);
    }

    match cli.command {
        Some(cli::Commands::Password(args)) => {
            let mut config = match args.profile.as_deref() {
                Some(name) => match config::get_profile(name) {
                    Ok(profile) => profile,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_config_error(&error);
                    }
                },
                None => password::PasswordConfig::default(),
            };

            args.options.apply_to_config(&mut config);

            match password::generate(config, dev_seed) {
                Ok(password) => print_value(
                    password,
                    json!({
                        "kind": "password",
                        "profile": args.profile,
                        "config": config,
                    }),
                    &output_mode,
                    copy_requested,
                ),
                Err(error) => {
                    eprintln!("Error: {error}");
                    exit_code_for_password_error(&error)
                }
            }
        }
        Some(cli::Commands::Profile(profile_args)) => match profile_args.command {
            cli::ProfileCommands::Save(save_args) => {
                let mut profile = password::PasswordConfig::default();
                save_args.options.apply_to_config(&mut profile);
                match config::save_profile(&save_args.name, profile) {
                    Ok(()) => {
                        if !output_mode.quiet && !output_mode.json {
                            println!("Saved profile '{}'", save_args.name);
                        } else if output_mode.json {
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
                        exit_code_for_config_error(&error)
                    }
                }
            }
            cli::ProfileCommands::List => match config::list_profiles() {
                Ok(profiles) => {
                    if output_mode.json {
                        let payload = json!({
                            "value": profiles.iter().map(|(name, _)| name).collect::<Vec<_>>(),
                            "meta": {
                                "kind": "profile-list",
                                "profiles": profiles,
                            }
                        });
                        println!("{payload}");
                    } else if !output_mode.quiet {
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
                    exit_code_for_config_error(&error)
                }
            },
            cli::ProfileCommands::Rm(remove_args) => {
                match config::remove_profile(&remove_args.name) {
                    Ok(()) => {
                        if !output_mode.quiet && !output_mode.json {
                            println!("Removed profile '{}'", remove_args.name);
                        } else if output_mode.json {
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
                        exit_code_for_config_error(&error)
                    }
                }
            }
        },
        Some(cli::Commands::Passphrase(args)) => {
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

            match passphrase::generate(config, dev_seed) {
                Ok(phrase) => print_value(
                    phrase,
                    meta,
                    &output_mode,
                    copy_requested,
                ),
                Err(error) => {
                    eprintln!("Error: {error}");
                    exit_code_for_passphrase_error(&error)
                }
            }
        }
        Some(cli::Commands::Token(token_args)) => match token::handle(token_args.command, dev_seed) {
            Ok(output) => print_value(
                output,
                json!({
                    "kind": "token",
                }),
                &output_mode,
                copy_requested,
            ),
            Err(error) => {
                eprintln!("Error: {error}");
                exit_code_for_token_error(&error)
            }
        },
        Some(cli::Commands::Entropy(args)) => {
            let config = entropy::EntropyConfig { input: args.input };
            match entropy::analyze(config) {
                Ok(report) => {
                    if output_mode.json {
                        let meta_report = serde_json::from_str(&report).unwrap_or_else(|_| {
                            json!({
                                "raw": report,
                            })
                        });
                        print_value(
                            report.clone(),
                            json!({
                                "kind": "entropy",
                                "report": meta_report,
                            }),
                            &output_mode,
                            copy_requested,
                        )
                    } else {
                        print_value(
                            report,
                            json!({
                                "kind": "entropy",
                            }),
                            &output_mode,
                            copy_requested,
                        )
                    }
                }
                Err(error) => {
                    eprintln!("Error: {error}");
                    exit_code_for_entropy_error(&error)
                }
            }
        }
        Some(cli::Commands::Env(args)) => {
            if output_mode.json || output_mode.quiet || copy_requested {
                eprintln!("Error: `env` does not support `--json`, `--quiet`, or `--copy`.");
                return ExitCode::from(EXIT_USAGE);
            }
            if !args.unsafe_mode {
                eprintln!("Error: `env` prints secrets; re-run with `--unsafe` to proceed.");
                return ExitCode::from(EXIT_USAGE);
            }
            if std::env::var_os("CI").is_some() {
                eprintln!("Warning: CI detected; secret output may be logged.");
            }

            let vault_path = match vault::vault_path(args.vault.path.as_deref()) {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("Error: {error}");
                    return exit_code_for_vault_error(&error);
                }
            };

            let master_password = match vault::prompt_master_password() {
                Ok(pw) => pw,
                Err(error) => {
                    eprintln!("Error: {error}");
                    return exit_code_for_vault_prompt_error(&error);
                }
            };

            let items = match vault::vault_list_items_v1(&vault_path, &master_password) {
                Ok(items) => items,
                Err(error) => {
                    eprintln!("Error: {error}");
                    return exit_code_for_vault_error(&error);
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
                        ExitCode::from(EXIT_USAGE)
                    }
                },
                cli::EnvFormat::Json => {
                    let json = serde_json::to_string(&vars).expect("json serialization");
                    println!("{json}");
                    ExitCode::SUCCESS
                }
            }
        }
        Some(cli::Commands::Run(args)) => {
            if output_mode.json || output_mode.quiet || copy_requested {
                eprintln!("Error: `run` does not support `--json`, `--quiet`, or `--copy`.");
                return ExitCode::from(EXIT_USAGE);
            }
            if std::env::var_os("CI").is_some() && !args.unsafe_mode {
                eprintln!("Error: refusing to run in CI without `--unsafe` (env may be logged).");
                return ExitCode::from(EXIT_USAGE);
            }

            let vault_path = match vault::vault_path(args.vault.path.as_deref()) {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("Error: {error}");
                    return exit_code_for_vault_error(&error);
                }
            };

            let master_password = match vault::prompt_master_password() {
                Ok(pw) => pw,
                Err(error) => {
                    eprintln!("Error: {error}");
                    return exit_code_for_vault_prompt_error(&error);
                }
            };

            let items = match vault::vault_list_items_v1(&vault_path, &master_password) {
                Ok(items) => items,
                Err(error) => {
                    eprintln!("Error: {error}");
                    return exit_code_for_vault_error(&error);
                }
            };
            let vars = dev_workflows::env_vars_for_profile(&items, &args.profile);
            if vars.is_empty() {
                eprintln!("Warning: profile '{}' has no items.", args.profile);
            } else {
                eprintln!("Warning: running with {} injected env vars.", vars.len());
            }

            let program = &args.cmd[0];
            let mut cmd = std::process::Command::new(program);
            cmd.args(&args.cmd[1..]);
            cmd.envs(vars);
            cmd.stdin(Stdio::inherit());
            cmd.stdout(Stdio::inherit());
            cmd.stderr(Stdio::inherit());

            match cmd.status() {
                Ok(status) => match status.code() {
                    Some(code) if (0..=255).contains(&code) => ExitCode::from(code as u8),
                    Some(_) => ExitCode::from(1),
                    None => ExitCode::from(1),
                },
                Err(error) => {
                    eprintln!("Error: {error}");
                    ExitCode::from(EXIT_IO)
                }
            }
        }
        Some(cli::Commands::Inject(args)) => {
            if output_mode.json || output_mode.quiet || copy_requested {
                eprintln!("Error: `inject` does not support `--json`, `--quiet`, or `--copy`.");
                return ExitCode::from(EXIT_USAGE);
            }
            if !args.unsafe_mode {
                eprintln!("Error: `inject` writes secrets to disk; re-run with `--unsafe` to proceed.");
                return ExitCode::from(EXIT_USAGE);
            }
            if std::env::var_os("CI").is_some() {
                eprintln!("Warning: CI detected; secret output files may be archived or logged.");
            }
            if args.output.exists() && !args.force {
                eprintln!(
                    "Error: output file already exists: {} (use `--force` to overwrite).",
                    args.output.display()
                );
                return ExitCode::from(EXIT_USAGE);
            }

            let vault_path = match vault::vault_path(args.vault.path.as_deref()) {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("Error: {error}");
                    return exit_code_for_vault_error(&error);
                }
            };

            let master_password = match vault::prompt_master_password() {
                Ok(pw) => pw,
                Err(error) => {
                    eprintln!("Error: {error}");
                    return exit_code_for_vault_prompt_error(&error);
                }
            };

            let items = match vault::vault_list_items_v1(&vault_path, &master_password) {
                Ok(items) => items,
                Err(error) => {
                    eprintln!("Error: {error}");
                    return exit_code_for_vault_error(&error);
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
                    return ExitCode::from(EXIT_IO);
                }
            };

            let rendered = match dev_workflows::render_template(&template, &vars) {
                Ok(s) => s,
                Err(error) => {
                    eprintln!("Error: {error}");
                    return ExitCode::from(EXIT_USAGE);
                }
            };

            if let Err(error) = dev_workflows::write_sensitive_file_atomic(&args.output, rendered.as_bytes()) {
                eprintln!("Error: {error}");
                return ExitCode::from(EXIT_IO);
            }

            println!("{}", args.output.display());
            ExitCode::SUCCESS
        }
        Some(cli::Commands::Vault(vault_args)) => match vault_args.command {
            cli::VaultCommands::Path(args) => {
                let path = match vault::vault_path(args.path.path.as_deref()) {
                    Ok(path) => path,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_vault_error(&error);
                    }
                };

                print_value(
                    path.display().to_string(),
                    json!({
                        "kind": "vault-path",
                        "path": path.display().to_string(),
                    }),
                    &output_mode,
                    copy_requested,
                )
            }
            cli::VaultCommands::Status(args) => {
                let path = match vault::vault_path(args.path.path.as_deref()) {
                    Ok(path) => path,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_vault_error(&error);
                    }
                };

                match vault::vault_status_v1(&path) {
                    Ok((status, version)) => print_value(
                        status.as_str().to_string(),
                        json!({
                            "kind": "vault-status",
                            "path": path.display().to_string(),
                            "status": status.as_str(),
                            "version": version,
                        }),
                        &output_mode,
                        copy_requested,
                    ),
                    Err(error) => {
                        eprintln!("Error: {error}");
                        exit_code_for_vault_error(&error)
                    }
                }
            }
            cli::VaultCommands::Init(args) => {
                let path = match vault::vault_path(args.path.path.as_deref()) {
                    Ok(path) => path,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_vault_error(&error);
                    }
                };

                let master_password = match vault::prompt_new_master_password() {
                    Ok(pw) => pw,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_vault_prompt_error(&error);
                    }
                };

                match vault::vault_init_v1(&path, &master_password) {
                    Ok(()) => print_value(
                        path.display().to_string(),
                        json!({
                            "kind": "vault-init",
                            "path": path.display().to_string(),
                        }),
                        &output_mode,
                        copy_requested,
                    ),
                    Err(error) => {
                        eprintln!("Error: {error}");
                        exit_code_for_vault_error(&error)
                    }
                }
            }
            cli::VaultCommands::Add(args) => {
                let path = match vault::vault_path(args.path.path.as_deref()) {
                    Ok(path) => path,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_vault_error(&error);
                    }
                };

                let master_password = match vault::prompt_master_password() {
                    Ok(pw) => pw,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_vault_prompt_error(&error);
                    }
                };

                let secret = match args.secret {
                    Some(s) => s,
                    None => match vault::prompt_secret("Secret: ") {
                        Ok(s) => s,
                        Err(error) => {
                            eprintln!("Error: {error}");
                            return exit_code_for_vault_prompt_error(&error);
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

                match vault::vault_add_item_v1(&path, &master_password, input) {
                    Ok(id) => {
                        let value = id.to_string();
                        let meta = json!({
                            "kind": "vault-add",
                            "path": path.display().to_string(),
                            "id": value,
                        });

                        if output_mode.quiet {
                            print_value(value, meta, &output_mode, false)
                        } else {
                            print_value(
                                format!("Added {value}"),
                                meta,
                                &output_mode,
                                false,
                            )
                        }
                    }
                    Err(error) => {
                        eprintln!("Error: {error}");
                        exit_code_for_vault_error(&error)
                    }
                }
            }
            cli::VaultCommands::Get(args) => {
                let path = match vault::vault_path(args.path.path.as_deref()) {
                    Ok(path) => path,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_vault_error(&error);
                    }
                };

                let master_password = match vault::prompt_master_password() {
                    Ok(pw) => pw,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_vault_prompt_error(&error);
                    }
                };

                match vault::vault_get_item_v1(&path, &master_password, args.id) {
                    Ok(item) => {
                        let reveal = args.reveal;
                        let copied = copy_requested;

                        if copied {
                            if let Err(error) = copy_to_clipboard(&item.secret) {
                                eprintln!("Error: {error}");
                                return ExitCode::from(EXIT_IO);
                            }
                        }

                        let meta = json!({
                            "kind": "vault-get",
                            "path": path.display().to_string(),
                            "id": item.id.to_string(),
                            "revealed": reveal,
                            "copied": copied,
                            "item": vault_item_json(&item, reveal),
                        });

                        if output_mode.quiet {
                            if reveal {
                                print_value(item.secret, meta, &output_mode, false)
                            } else {
                                print_value(item.id.to_string(), meta, &output_mode, false)
                            }
                        } else {
                            print_value(vault_item_text(&item, reveal), meta, &output_mode, false)
                        }
                    }
                    Err(error) => {
                        eprintln!("Error: {error}");
                        exit_code_for_vault_error(&error)
                    }
                }
            }
            cli::VaultCommands::Edit(args) => {
                let path = match vault::vault_path(args.path.path.as_deref()) {
                    Ok(path) => path,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_vault_error(&error);
                    }
                };

                let master_password = match vault::prompt_master_password() {
                    Ok(pw) => pw,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_vault_prompt_error(&error);
                    }
                };

                let input = vault::EditItemInput {
                    id: args.id,
                    item_type: args.item_type,
                    name: args.name,
                    path: args.item_path,
                    clear_path: args.clear_path,
                    tags: if args.tags.is_empty() { None } else { Some(args.tags) },
                    clear_tags: args.clear_tags,
                    username: args.username,
                    clear_username: args.clear_username,
                    secret: args.secret,
                    urls: if args.urls.is_empty() { None } else { Some(args.urls) },
                    clear_urls: args.clear_urls,
                    notes: args.notes,
                    clear_notes: args.clear_notes,
                };

                match vault::vault_edit_item_v1(&path, &master_password, input) {
                    Ok(()) => {
                        let value = args.id.to_string();
                        let meta = json!({
                            "kind": "vault-edit",
                            "path": path.display().to_string(),
                            "id": value,
                        });

                        if output_mode.quiet {
                            print_value(value, meta, &output_mode, false)
                        } else {
                            print_value(format!("Edited {value}"), meta, &output_mode, false)
                        }
                    }
                    Err(error) => {
                        eprintln!("Error: {error}");
                        exit_code_for_vault_error(&error)
                    }
                }
            }
            cli::VaultCommands::Rm(args) => {
                let path = match vault::vault_path(args.path.path.as_deref()) {
                    Ok(path) => path,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_vault_error(&error);
                    }
                };

                let master_password = match vault::prompt_master_password() {
                    Ok(pw) => pw,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_vault_prompt_error(&error);
                    }
                };

                match vault::vault_remove_item_v1(&path, &master_password, args.id) {
                    Ok(()) => {
                        let value = args.id.to_string();
                        let meta = json!({
                            "kind": "vault-rm",
                            "path": path.display().to_string(),
                            "id": value,
                        });

                        if output_mode.quiet {
                            print_value(value, meta, &output_mode, false)
                        } else {
                            print_value(format!("Removed {value}"), meta, &output_mode, false)
                        }
                    }
                    Err(error) => {
                        eprintln!("Error: {error}");
                        exit_code_for_vault_error(&error)
                    }
                }
            }
            cli::VaultCommands::List(args) => {
                let path = match vault::vault_path(args.path.path.as_deref()) {
                    Ok(path) => path,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_vault_error(&error);
                    }
                };

                let master_password = match vault::prompt_master_password() {
                    Ok(pw) => pw,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_vault_prompt_error(&error);
                    }
                };

                match vault::vault_list_items_v1(&path, &master_password) {
                    Ok(items) => {
                        let value = if output_mode.quiet {
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

                        print_value(value, meta, &output_mode, false)
                    }
                    Err(error) => {
                        eprintln!("Error: {error}");
                        exit_code_for_vault_error(&error)
                    }
                }
            }
            cli::VaultCommands::Search(args) => {
                let path = match vault::vault_path(args.path.path.as_deref()) {
                    Ok(path) => path,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_vault_error(&error);
                    }
                };

                let master_password = match vault::prompt_master_password() {
                    Ok(pw) => pw,
                    Err(error) => {
                        eprintln!("Error: {error}");
                        return exit_code_for_vault_prompt_error(&error);
                    }
                };

                match vault::vault_search_items_v1(&path, &master_password, &args.query) {
                    Ok(items) => {
                        let value = if output_mode.quiet {
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

                        print_value(value, meta, &output_mode, false)
                    }
                    Err(error) => {
                        eprintln!("Error: {error}");
                        exit_code_for_vault_error(&error)
                    }
                }
            }
        },
        None => {
            // No subcommand provided; show help and exit with usage code.
            let mut cmd = configure_command_colors(cli::Cli::command());
            cmd.print_help().expect("help to be printed");
            println!();
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn parse_cli() -> Result<cli::Cli, ExitCode> {
    let cmd = configure_command_colors(cli::Cli::command());

    let matches = match cmd.try_get_matches() {
        Ok(matches) => matches,
        Err(err) => {
            let kind = err.kind();
            // Help/version are treated as successful exits.
            if matches!(kind, ClapErrorKind::DisplayHelp | ClapErrorKind::DisplayVersion) {
                let _ = err.print();
                return Err(ExitCode::SUCCESS);
            }

            let _ = err.print();
            return Err(ExitCode::from(EXIT_USAGE));
        }
    };

    match cli::Cli::from_arg_matches(&matches) {
        Ok(cli) => Ok(cli),
        Err(err) => {
            let _ = err.print();
            Err(ExitCode::from(EXIT_USAGE))
        }
    }
}

fn configure_command_colors(mut cmd: clap::Command) -> clap::Command {
    let no_color = std::env::var_os("NO_COLOR").is_some();
    let stdout_is_tty = std::io::stdout().is_terminal();
    let stderr_is_tty = std::io::stderr().is_terminal();

    if no_color || !(stdout_is_tty && stderr_is_tty) {
        cmd = cmd.color(ColorChoice::Never);
    }

    cmd
}

struct OutputMode {
    json: bool,
    quiet: bool,
}

fn print_value(
    value: String,
    meta: serde_json::Value,
    output_mode: &OutputMode,
    copy_requested: bool,
) -> ExitCode {
    if output_mode.json {
        let payload = json!({
            "value": value,
            "meta": meta,
        });
        println!("{payload}");
    } else {
        println!("{value}");
    }

    match maybe_copy(&value, copy_requested) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::from(EXIT_IO)
        }
    }
}

fn vault_item_summary_text(item: &vault::VaultItemV1) -> String {
    let path = item.path.as_deref().unwrap_or("");
    format!(
        "{}\t{}\t{}\t{}",
        item.id,
        vault_item_type_str(item.item_type),
        path,
        item.name
    )
}

fn vault_item_summary_json(item: &vault::VaultItemV1) -> serde_json::Value {
    json!({
        "id": item.id.to_string(),
        "type": vault_item_type_str(item.item_type),
        "name": item.name.as_str(),
        "path": item.path.as_deref(),
        "tags": &item.tags,
        "username": item.username.as_deref(),
        "urls": &item.urls,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    })
}

fn vault_item_json(item: &vault::VaultItemV1, reveal: bool) -> serde_json::Value {
    if reveal {
        json!({
            "id": item.id.to_string(),
            "type": vault_item_type_str(item.item_type),
            "name": item.name.as_str(),
            "path": item.path.as_deref(),
            "tags": &item.tags,
            "username": item.username.as_deref(),
            "secret": item.secret.as_str(),
            "urls": &item.urls,
            "notes": item.notes.as_deref(),
            "created_at": item.created_at,
            "updated_at": item.updated_at,
        })
    } else {
        json!({
            "id": item.id.to_string(),
            "type": vault_item_type_str(item.item_type),
            "name": item.name.as_str(),
            "path": item.path.as_deref(),
            "tags": &item.tags,
            "username": item.username.as_deref(),
            "secret_redacted": true,
            "urls": &item.urls,
            "notes": item.notes.as_deref(),
            "created_at": item.created_at,
            "updated_at": item.updated_at,
        })
    }
}

fn vault_item_text(item: &vault::VaultItemV1, reveal: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!("id:\t{}\n", item.id));
    out.push_str(&format!("type:\t{}\n", vault_item_type_str(item.item_type)));
    out.push_str(&format!("name:\t{}\n", item.name));
    if let Some(path) = &item.path {
        out.push_str(&format!("path:\t{}\n", path));
    }
    if !item.tags.is_empty() {
        out.push_str(&format!("tags:\t{}\n", item.tags.join(",")));
    }
    if let Some(username) = &item.username {
        out.push_str(&format!("username:\t{}\n", username));
    }
    if !item.urls.is_empty() {
        out.push_str(&format!("urls:\t{}\n", item.urls.join(",")));
    }
    if let Some(notes) = &item.notes {
        out.push_str(&format!("notes:\t{}\n", notes));
    }
    out.push_str(&format!(
        "secret:\t{}\n",
        if reveal { &item.secret } else { "[REDACTED]" }
    ));
    out.push_str(&format!("created_at:\t{}\n", item.created_at));
    out.push_str(&format!("updated_at:\t{}", item.updated_at));
    out
}

fn vault_item_type_str(t: vault::VaultItemType) -> &'static str {
    match t {
        vault::VaultItemType::Login => "login",
        vault::VaultItemType::SecureNote => "secure-note",
        vault::VaultItemType::ApiToken => "api-token",
    }
}

fn exit_code_for_config_error(error: &config::ConfigError) -> ExitCode {
    use config::ConfigError::*;

    match error {
        ConfigDirUnavailable | Io(_) => ExitCode::from(EXIT_IO),
        MissingProfile(_) | InvalidProfile(_) => ExitCode::from(EXIT_USAGE),
        Parse(_) | Serialize(_) | UnsupportedSchemaVersion(_) => ExitCode::from(EXIT_SOFTWARE),
    }
}

fn exit_code_for_password_error(error: &password::GenerationError) -> ExitCode {
    use password::GenerationError::*;

    match error {
        EmptyClass(_)
        | EmptyPool
        | LengthTooShort { .. }
        | NoClassesEnabled
        | MinimumRequiresDisabledClass(_) => ExitCode::from(EXIT_USAGE),
    }
}

fn exit_code_for_passphrase_error(error: &passphrase::PassphraseError) -> ExitCode {
    use passphrase::PassphraseError::*;

    match error {
        WordCountZero => ExitCode::from(EXIT_USAGE),
        Io { .. } => ExitCode::from(EXIT_IO),
        EmptyWordList { .. } => ExitCode::from(EXIT_SOFTWARE),
    }
}

fn exit_code_for_token_error(error: &token::TokenError) -> ExitCode {
    use token::TokenError::*;

    match error {
        ByteLengthZero => ExitCode::from(EXIT_USAGE),
        SampleBytesFailed => ExitCode::from(EXIT_IO),
    }
}

fn exit_code_for_entropy_error(error: &entropy::EntropyError) -> ExitCode {
    use entropy::EntropyError::*;

    match error {
        Io(_) => ExitCode::from(EXIT_IO),
        InvalidUtf8 => ExitCode::from(EXIT_USAGE),
        Serialization(_) | Strength(_) => ExitCode::from(EXIT_SOFTWARE),
    }
}

fn exit_code_for_vault_prompt_error(error: &vault::PromptError) -> ExitCode {
    use vault::PromptError::*;

    match error {
        Io(_) => ExitCode::from(EXIT_IO),
        Empty | Mismatch => ExitCode::from(EXIT_USAGE),
    }
}

fn exit_code_for_vault_error(error: &vault::VaultError) -> ExitCode {
    use vault::VaultError::*;

    match error {
        VaultDirUnavailable | Io(_) => ExitCode::from(EXIT_IO),
        AlreadyExists(_)
        | NotInitialized
        | AuthFailed
        | ItemNotFound(_)
        | Prompt(_) => ExitCode::from(EXIT_USAGE),
        UnsupportedPayloadSchema(_) | Crypto(_) | Format(_) | Json(_) => ExitCode::from(EXIT_SOFTWARE),
    }
}

fn maybe_copy(output: &str, copy_requested: bool) -> Result<(), String> {
    if !copy_requested {
        return Ok(());
    }

    copy_to_clipboard(output)
}

#[cfg(feature = "clipboard")]
fn copy_to_clipboard(output: &str) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|error| format!("Failed to access clipboard: {error}"))?;
    clipboard
        .set_text(output.to_owned())
        .map_err(|error| format!("Failed to copy output to clipboard: {error}"))?;
    Ok(())
}

#[cfg(not(feature = "clipboard"))]
fn copy_to_clipboard(_output: &str) -> Result<(), String> {
    eprintln!("Warning: `--copy` requires building with `--features clipboard`.");
    Ok(())
}
