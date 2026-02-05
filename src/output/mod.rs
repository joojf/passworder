use serde_json::json;
use std::process::ExitCode;

pub struct OutputMode {
    pub json: bool,
    pub quiet: bool,
}

pub fn print_value(
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
            eprintln!("Warning: {error}");
            ExitCode::SUCCESS
        }
    }
}

pub fn maybe_copy(output: &str, copy_requested: bool) -> Result<(), String> {
    if !copy_requested {
        return Ok(());
    }

    copy_to_clipboard(output)
}

pub fn copy_to_clipboard(output: &str) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|error| format!("Failed to access clipboard: {error}"))?;
    clipboard
        .set_text(output.to_owned())
        .map_err(|error| format!("Failed to copy output to clipboard: {error}"))?;
    Ok(())
}

pub mod vault_item;
