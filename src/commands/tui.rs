use crate::app::AppContext;
use crate::exit_codes;
use crate::tui;
use std::process::ExitCode;

pub fn run(_ctx: &AppContext) -> ExitCode {
    match tui::run(_ctx.dev_seed) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::from(exit_codes::EXIT_IO)
        }
    }
}
