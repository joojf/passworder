mod action;
mod effect;
mod state;
mod update;

use crate::tui::action::Action;
use crate::tui::effect::Effect;
use crate::tui::state::AppState;
use crate::tui::update::update;
use crossterm::event::{self, Event, KeyEventKind};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::Style;
use ratatui::widgets::{Block, Paragraph, Wrap};
use std::error::Error;
use std::time::{Duration, Instant};

struct RestoreGuard;

impl Drop for RestoreGuard {
    fn drop(&mut self) {
        let _ = ratatui::try_restore();
    }
}

pub fn run(dev_seed: Option<u64>) -> Result<(), Box<dyn Error>> {
    let _restore = RestoreGuard;
    let mut terminal = ratatui::init();
    let mut state = AppState::default();

    match crate::config::list_profiles() {
        Ok(entries) => {
            state.password.profiles = entries
                .into_iter()
                .map(|(name, config)| crate::tui::state::ProfileEntry { name, config })
                .collect();
        }
        Err(err) => {
            state.password.message = Some(format!("Failed to load profiles: {err}"));
        }
    }

    let tick_rate = Duration::from_millis(250);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|frame| render(frame, &state))?;

        if state.should_quit {
            break Ok(());
        }

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    let effects = update(
                        &mut state,
                        Action::KeyPress {
                            code: key.code,
                            modifiers: key.modifiers,
                        },
                    );
                    run_effects(&mut state, effects, dev_seed);
                }
                Event::Resize(width, height) => {
                    let effects = update(&mut state, Action::Resize { width, height });
                    run_effects(&mut state, effects, dev_seed);
                }
                _ => {}
            }
        }

        if last_tick.elapsed() >= tick_rate {
            let effects = update(&mut state, Action::Tick);
            run_effects(&mut state, effects, dev_seed);
            last_tick = Instant::now();
        }
    }
}

fn render(frame: &mut Frame, state: &AppState) {
    let area = frame.area();

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(area);

    let header = Paragraph::new("passworder TUI — q/Esc quit • g generate • c copy • [/] cycle profiles • +/- length • l/u/d/s toggle • a ambiguous")
        .alignment(Alignment::Center)
        .style(Style::new().dim())
        .wrap(Wrap { trim: true })
        .block(Block::bordered().title("Help"));

    frame.render_widget(header, layout[0]);

    match state.route {
        crate::tui::state::Route::Home => {
            let body = Paragraph::new("Home (stub)\n\nPress p for Password screen.")
                .block(Block::bordered().title("Home"))
                .wrap(Wrap { trim: true });
            frame.render_widget(body, layout[1]);
        }
        crate::tui::state::Route::Password => render_password(frame, layout[1], state),
    }

    let mut footer_lines = Vec::new();
    if let Some(msg) = state.password.message.as_deref() {
        footer_lines.push(format!("Message: {msg}"));
    }
    if let Some(err) = state.password.error.as_deref() {
        footer_lines.push(format!("Error: {err}"));
    }
    let footer_text = if footer_lines.is_empty() {
        "Ready.".to_string()
    } else {
        footer_lines.join(" • ")
    };
    let footer = Paragraph::new(footer_text)
        .block(Block::bordered().title("Status"))
        .wrap(Wrap { trim: true });
    frame.render_widget(footer, layout[2]);
}

fn render_password(frame: &mut Frame, area: ratatui::layout::Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(area);

    let profile_name = state
        .password
        .active_profile
        .and_then(|idx| state.password.profiles.get(idx))
        .map(|p| p.name.as_str())
        .unwrap_or("custom/default");

    let c = &state.password.config;
    let options = format!(
        "Profile: {profile_name}\nLength: {} (+/-)\nClasses: [l]lower={} [u]upper={} [d]digits={} [s]symbols={}\nAmbiguous: [a]allow_ambiguous={}\n\nGenerate: g / Enter   Copy: c",
        c.length,
        c.include_lowercase,
        c.include_uppercase,
        c.include_digits,
        c.include_symbols,
        c.allow_ambiguous
    );

    let options = Paragraph::new(options)
        .block(Block::bordered().title("Password Options"))
        .wrap(Wrap { trim: true });
    frame.render_widget(options, chunks[0]);

    let mut output_lines = Vec::new();
    if let Some(value) = state.password.generated.as_deref() {
        output_lines.push(format!("Password: {value}"));
        if let Some(score) = state.password.strength_score {
            output_lines.push(format!("Strength score: {score}/4"));
        }
    } else {
        output_lines.push("Password: (none yet)".to_string());
    }
    let output = Paragraph::new(output_lines.join("\n"))
        .block(Block::bordered().title("Output"))
        .wrap(Wrap { trim: true });
    frame.render_widget(output, chunks[1]);
}

fn run_effects(state: &mut AppState, effects: Vec<Effect>, dev_seed: Option<u64>) {
    for effect in effects {
        match effect {
            Effect::GeneratePassword => {
                let result = crate::password::generate(state.password.config, dev_seed);
                match result {
                    Ok(value) => {
                        state.password.generated = Some(value.clone());
                        state.password.error = None;
                        state.password.message = Some("Generated.".into());
                        state.password.strength_score = strength_score(&value);
                    }
                    Err(err) => {
                        state.password.error = Some(err.to_string());
                        state.password.message = None;
                        state.password.strength_score = None;
                    }
                }
            }
            Effect::CopyGeneratedPassword => {
                let Some(value) = state.password.generated.as_deref() else {
                    continue;
                };
                match crate::output::copy_to_clipboard(value) {
                    Ok(()) => {
                        state.password.message = Some("Copied to clipboard.".into());
                        state.password.error = None;
                    }
                    Err(err) => {
                        state.password.error = Some(err);
                        state.password.message = None;
                    }
                }
            }
        }
    }
}

fn strength_score(value: &str) -> Option<u8> {
    #[cfg(feature = "strength")]
    {
        return match zxcvbn::zxcvbn(value, &[]) {
            Ok(result) => Some(result.score()),
            Err(_) => None,
        };
    }
    #[cfg(not(feature = "strength"))]
    {
        let _ = value;
        None
    }
}
