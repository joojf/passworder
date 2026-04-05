mod action;
mod effect;
mod state;
mod update;

use crate::tui::action::Action;
use crate::tui::effect::Effect;
use crate::tui::state::AppState;
use crate::tui::update::{SPLASH_TOTAL_TICKS, update};
use crossterm::event::{self, Event, KeyEventKind};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Gauge, Padding, Paragraph, Tabs};
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

fn rounded_block(title: &str) -> Block<'_> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .padding(Padding::horizontal(1))
        .title(format!(" {title} "))
}

fn toggle_line<'a>(key: char, label: &'a str, enabled: bool) -> Line<'a> {
    let indicator = if enabled { " ✓" } else { " ✗" };
    let indicator_color = if enabled { Color::Green } else { Color::Red };
    Line::from(vec![
        Span::styled(format!(" [{key}]"), Style::default().fg(Color::Cyan).bold()),
        Span::raw(format!(" {label}")),
        Span::styled(indicator, Style::default().fg(indicator_color).bold()),
    ])
}

fn render(frame: &mut Frame, state: &AppState) {
    let area = frame.area();

    if state.route == crate::tui::state::Route::Splash {
        render_splash(frame, area, state);
        return;
    }

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);

    // Tab bar
    let tab_index = match state.route {
        crate::tui::state::Route::Password | crate::tui::state::Route::Splash => 0,
        crate::tui::state::Route::Passphrase => 1,
        crate::tui::state::Route::Entropy => 2,
        crate::tui::state::Route::Home => 0,
    };
    let tabs = Tabs::new(vec![" [p] Password ", " [w] Passphrase ", " [e] Entropy "])
        .select(tab_index)
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(Style::default().fg(Color::Cyan).bold())
        .divider(Span::styled("│", Style::default().fg(Color::DarkGray)))
        .block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(" passworder ")
                .title_style(Style::default().fg(Color::Cyan).bold()),
        );
    frame.render_widget(tabs, layout[0]);

    // Body
    match state.route {
        crate::tui::state::Route::Splash => unreachable!(),
        crate::tui::state::Route::Home => {
            let body = Paragraph::new("Press p for Password · Press w for Passphrase")
                .alignment(Alignment::Center)
                .block(rounded_block("Home"));
            frame.render_widget(body, layout[1]);
        }
        crate::tui::state::Route::Password => render_password(frame, layout[1], state),
        crate::tui::state::Route::Passphrase => render_passphrase(frame, layout[1], state),
        crate::tui::state::Route::Entropy => render_entropy(frame, layout[1], state),
    }

    // Status bar
    let status_line = if let Some(err) = current_error(state) {
        Line::from(vec![
            Span::styled(" ✗ ", Style::default().fg(Color::Red).bold()),
            Span::styled(err, Style::default().fg(Color::Red)),
        ])
    } else if let Some(msg) = current_message(state) {
        Line::from(vec![
            Span::styled(" ✓ ", Style::default().fg(Color::Green).bold()),
            Span::styled(msg, Style::default().fg(Color::Green)),
        ])
    } else {
        Line::from(Span::styled(" Ready", Style::default().fg(Color::DarkGray)))
    };
    let status = Paragraph::new(status_line).block(
        Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(status, layout[2]);

    // Keybind hints
    let hints = if state.route == crate::tui::state::Route::Entropy {
        Line::from(vec![
            Span::styled(" q", Style::default().fg(Color::Cyan)),
            Span::styled(" quit  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Enter", Style::default().fg(Color::Cyan)),
            Span::styled(" analyze  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Ctrl+m", Style::default().fg(Color::Cyan)),
            Span::styled(" mask  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Ctrl+r", Style::default().fg(Color::Cyan)),
            Span::styled(" reset", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" q", Style::default().fg(Color::Cyan)),
            Span::styled(" quit  ", Style::default().fg(Color::DarkGray)),
            Span::styled("g", Style::default().fg(Color::Cyan)),
            Span::styled(" generate  ", Style::default().fg(Color::DarkGray)),
            Span::styled("c", Style::default().fg(Color::Cyan)),
            Span::styled(" copy  ", Style::default().fg(Color::DarkGray)),
            Span::styled("+/-", Style::default().fg(Color::Cyan)),
            Span::styled(" adjust  ", Style::default().fg(Color::DarkGray)),
            Span::styled("r", Style::default().fg(Color::Cyan)),
            Span::styled(" reset", Style::default().fg(Color::DarkGray)),
        ])
    };
    let hint_bar = Paragraph::new(hints).alignment(Alignment::Center);
    frame.render_widget(hint_bar, layout[3]);
}

fn current_message(state: &AppState) -> Option<&str> {
    match state.route {
        crate::tui::state::Route::Splash | crate::tui::state::Route::Home => None,
        crate::tui::state::Route::Password => state.password.message.as_deref(),
        crate::tui::state::Route::Passphrase => state.passphrase.message.as_deref(),
        crate::tui::state::Route::Entropy => state.entropy.message.as_deref(),
    }
}

fn current_error(state: &AppState) -> Option<&str> {
    match state.route {
        crate::tui::state::Route::Splash | crate::tui::state::Route::Home => None,
        crate::tui::state::Route::Password => state.password.error.as_deref(),
        crate::tui::state::Route::Passphrase => state.passphrase.error.as_deref(),
        crate::tui::state::Route::Entropy => state.entropy.error.as_deref(),
    }
}

fn render_splash(frame: &mut Frame, area: Rect, state: &AppState) {
    const BANNER: &[&str] = &[
        r"                                           _           ",
        r" _ __   __ _ ___ _____      _____  _ __ __| | ___ _ __ ",
        r"| '_ \ / _` / __/ __\ \ /\ / / _ \| '__/ _` |/ _ \ '__|",
        r"| |_) | (_| \__ \__ \\ V  V / (_) | | | (_| |  __/ |   ",
        r"| .__/ \__,_|___/___/ \_/\_/ \___/|_|  \__,_|\___|_|   ",
        r"|_|                                                      ",
    ];

    let banner_width = BANNER.iter().map(|l| l.len()).max().unwrap_or(0);
    let banner_height = BANNER.len();
    let tagline = "secure password generator";

    // Total content height: banner + 2 blank lines + tagline
    let total_height = banner_height + 3;
    let y_offset = if area.height as usize > total_height {
        (area.height as usize - total_height) / 2
    } else {
        0
    };
    let x_offset = if area.width as usize > banner_width {
        (area.width as usize - banner_width) / 2
    } else {
        0
    };

    // How many columns of the banner to reveal (left-to-right wipe)
    let progress = state.splash.tick.min(SPLASH_TOTAL_TICKS);
    let cols_to_show = if SPLASH_TOTAL_TICKS > 0 {
        (banner_width * progress) / SPLASH_TOTAL_TICKS
    } else {
        banner_width
    };

    // Gradient colors for the reveal — cycles through these
    let colors = [
        Color::Cyan,
        Color::LightCyan,
        Color::Blue,
        Color::LightBlue,
        Color::Magenta,
        Color::LightMagenta,
    ];

    let mut lines: Vec<Line> = Vec::new();

    // Vertical padding
    for _ in 0..y_offset {
        lines.push(Line::from(""));
    }

    // Banner lines with progressive reveal and color gradient
    for row in BANNER {
        let mut spans = Vec::new();
        // Left padding
        if x_offset > 0 {
            spans.push(Span::raw(" ".repeat(x_offset)));
        }

        let chars: Vec<char> = row.chars().collect();
        for (i, &ch) in chars.iter().enumerate() {
            if i < cols_to_show {
                let color_idx = (i + state.splash.tick) % colors.len();
                spans.push(Span::styled(
                    String::from(ch),
                    Style::default().fg(colors[color_idx]).bold(),
                ));
            }
        }
        lines.push(Line::from(spans));
    }

    // Tagline appears after banner is ~60% revealed
    let tagline_threshold = SPLASH_TOTAL_TICKS * 6 / 10;
    if state.splash.tick >= tagline_threshold {
        lines.push(Line::from(""));
        lines.push(Line::from(""));
        let tagline_x = if area.width as usize > tagline.len() {
            (area.width as usize - tagline.len()) / 2
        } else {
            0
        };
        let padding = " ".repeat(tagline_x);
        lines.push(Line::from(vec![
            Span::raw(padding),
            Span::styled(tagline, Style::default().fg(Color::DarkGray).italic()),
        ]));
    }

    // "Press any key" hint after the animation is nearly done
    if state.splash.tick >= SPLASH_TOTAL_TICKS - 2 {
        lines.push(Line::from(""));
        let hint = "press any key to continue";
        let hint_x = if area.width as usize > hint.len() {
            (area.width as usize - hint.len()) / 2
        } else {
            0
        };
        let padding = " ".repeat(hint_x);
        lines.push(Line::from(vec![
            Span::raw(padding),
            Span::styled(hint, Style::default().fg(Color::DarkGray).dim()),
        ]));
    }

    let splash = Paragraph::new(lines);
    frame.render_widget(splash, area);
}

fn render_password(frame: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(0)])
        .split(area);

    let profile_name = state
        .password
        .active_profile
        .and_then(|idx| state.password.profiles.get(idx))
        .map(|p| p.name.as_str())
        .unwrap_or("default");

    let c = &state.password.config;

    let lines = vec![
        Line::from(vec![
            Span::styled("  Profile  ", Style::default().fg(Color::DarkGray)),
            Span::styled(profile_name, Style::default().fg(Color::Cyan)),
            Span::styled("  [ ] / [ ] cycle", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled("  Length   ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}", c.length),
                Style::default().fg(Color::White).bold(),
            ),
            Span::styled("  +/- to adjust", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(""),
        toggle_line('l', "Lowercase", c.include_lowercase),
        toggle_line('u', "Uppercase", c.include_uppercase),
        toggle_line('d', "Digits   ", c.include_digits),
        toggle_line('s', "Symbols  ", c.include_symbols),
        toggle_line('a', "Ambiguous", c.allow_ambiguous),
    ];

    let options = Paragraph::new(lines).block(rounded_block("Options"));
    frame.render_widget(options, chunks[0]);

    // Output section
    let output_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(chunks[1]);

    let output_line = if let Some(value) = state.password.generated.as_deref() {
        Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(value, Style::default().fg(Color::Green).bold()),
        ])
    } else {
        Line::from(Span::styled(
            "  press g or Enter to generate",
            Style::default().fg(Color::DarkGray).italic(),
        ))
    };
    let output = Paragraph::new(output_line).block(rounded_block("Generated Password"));
    frame.render_widget(output, output_chunks[0]);

    // Strength gauge
    if let Some(score) = state.password.strength_score {
        let (ratio, label, color) = match score {
            0 => (0.05, "Very Weak (0/4)", Color::Red),
            1 => (0.25, "Weak (1/4)", Color::LightRed),
            2 => (0.50, "Fair (2/4)", Color::Yellow),
            3 => (0.75, "Strong (3/4)", Color::LightGreen),
            _ => (1.00, "Very Strong (4/4)", Color::Green),
        };
        let gauge = Gauge::default()
            .ratio(ratio)
            .label(label)
            .gauge_style(Style::default().fg(color).add_modifier(Modifier::BOLD))
            .block(rounded_block("Strength"));
        frame.render_widget(gauge, output_chunks[1]);
    } else {
        let placeholder = Paragraph::new(Span::styled(
            "  strength score appears after generation",
            Style::default().fg(Color::DarkGray).italic(),
        ))
        .block(rounded_block("Strength"));
        frame.render_widget(placeholder, output_chunks[1]);
    }
}

fn render_passphrase(frame: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(area);

    let c = &state.passphrase.config;

    let sep_display = match c.separator.as_str() {
        "-" => "hyphen (-)",
        " " => "space ( )",
        "_" => "underscore (_)",
        "." => "dot (.)",
        other => other,
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("  Words      ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}", c.word_count),
                Style::default().fg(Color::White).bold(),
            ),
            Span::styled("  +/- to adjust", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled(" [e]", Style::default().fg(Color::Cyan).bold()),
            Span::styled(" Separator  ", Style::default().fg(Color::DarkGray)),
            Span::styled(sep_display, Style::default().fg(Color::White).bold()),
        ]),
        Line::from(""),
        toggle_line('t', "Title Case", c.title_case),
        Line::from(""),
        Line::from(Span::styled(
            "  Wordlist: built-in",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let options = Paragraph::new(lines).block(rounded_block("Options"));
    frame.render_widget(options, chunks[0]);

    let output_line = if let Some(value) = state.passphrase.generated.as_deref() {
        Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(value, Style::default().fg(Color::Green).bold()),
        ])
    } else {
        Line::from(Span::styled(
            "  press g or Enter to generate",
            Style::default().fg(Color::DarkGray).italic(),
        ))
    };
    let output =
        Paragraph::new(output_line).block(rounded_block("Generated Passphrase"));
    frame.render_widget(output, chunks[1]);
}

fn render_entropy(frame: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(0)])
        .split(area);

    // Input section
    let display_value = if state.entropy.input.is_empty() {
        Span::styled(
            "  type a string and press Enter to analyze",
            Style::default().fg(Color::DarkGray).italic(),
        )
    } else if state.entropy.masked {
        Span::styled(
            format!("  {}", "*".repeat(state.entropy.input.chars().count())),
            Style::default().fg(Color::White).bold(),
        )
    } else {
        Span::styled(
            format!("  {}", &state.entropy.input),
            Style::default().fg(Color::White).bold(),
        )
    };

    let mask_label = if state.entropy.masked {
        "shown"
    } else {
        "hidden"
    };
    let input_lines = vec![
        Line::from(display_value),
        Line::from(""),
        Line::from(vec![
            Span::styled(" [Ctrl+m]", Style::default().fg(Color::Cyan).bold()),
            Span::styled(format!(" toggle mask ({})", mask_label), Style::default().fg(Color::DarkGray)),
            Span::styled("   [Ctrl+r]", Style::default().fg(Color::Cyan).bold()),
            Span::styled(" reset", Style::default().fg(Color::DarkGray)),
        ]),
    ];
    let input_block = Paragraph::new(input_lines).block(rounded_block("Input"));
    frame.render_widget(input_block, chunks[0]);

    // Results section
    if let Some(report) = &state.entropy.report {
        let mut lines = vec![
            Line::from(vec![
                Span::styled("  Length          ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{}", report.length),
                    Style::default().fg(Color::White).bold(),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Shannon bits    ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{}", report.shannon_bits_estimate),
                    Style::default().fg(Color::Cyan).bold(),
                ),
            ]),
        ];

        if let Some(log10) = report.guesses_log10 {
            lines.push(Line::from(vec![
                Span::styled("  Guesses log10   ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:.2}", log10),
                    Style::default().fg(Color::White).bold(),
                ),
            ]));
        }

        if let Some(score) = report.score {
            let (label, color) = match score {
                0 => ("Very Weak (0/4)", Color::Red),
                1 => ("Weak (1/4)", Color::LightRed),
                2 => ("Fair (2/4)", Color::Yellow),
                3 => ("Strong (3/4)", Color::LightGreen),
                _ => ("Very Strong (4/4)", Color::Green),
            };
            lines.push(Line::from(vec![
                Span::styled("  Score           ", Style::default().fg(Color::DarkGray)),
                Span::styled(label, Style::default().fg(color).bold()),
            ]));
        }

        if let Some(ct) = &report.crack_times_display {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  Crack times",
                Style::default().fg(Color::DarkGray).bold(),
            )));
            lines.push(Line::from(vec![
                Span::styled("    Online (throttled)   ", Style::default().fg(Color::DarkGray)),
                Span::styled(&ct.online_throttling_100_per_hour, Style::default().fg(Color::White)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("    Online (unthrottled) ", Style::default().fg(Color::DarkGray)),
                Span::styled(&ct.online_no_throttling_10_per_second, Style::default().fg(Color::White)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("    Offline (slow hash)  ", Style::default().fg(Color::DarkGray)),
                Span::styled(&ct.offline_slow_hashing_1e4_per_second, Style::default().fg(Color::White)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("    Offline (fast hash)  ", Style::default().fg(Color::DarkGray)),
                Span::styled(&ct.offline_fast_hashing_1e10_per_second, Style::default().fg(Color::White)),
            ]));
        }

        let results = Paragraph::new(lines).block(rounded_block("Results"));
        frame.render_widget(results, chunks[1]);
    } else {
        let placeholder = Paragraph::new(Span::styled(
            "  results appear after analysis",
            Style::default().fg(Color::DarkGray).italic(),
        ))
        .block(rounded_block("Results"));
        frame.render_widget(placeholder, chunks[1]);
    }
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
            Effect::GeneratePassphrase => {
                let result = crate::passphrase::generate(state.passphrase.config.clone(), dev_seed);
                match result {
                    Ok(value) => {
                        state.passphrase.generated = Some(value);
                        state.passphrase.error = None;
                        state.passphrase.message = Some("Generated.".into());
                    }
                    Err(err) => {
                        state.passphrase.error = Some(err.to_string());
                        state.passphrase.message = None;
                    }
                }
            }
            Effect::CopyGeneratedPassphrase => {
                let Some(value) = state.passphrase.generated.as_deref() else {
                    continue;
                };
                match crate::output::copy_to_clipboard(value) {
                    Ok(()) => {
                        state.passphrase.message = Some("Copied to clipboard.".into());
                        state.passphrase.error = None;
                    }
                    Err(err) => {
                        state.passphrase.error = Some(err);
                        state.passphrase.message = None;
                    }
                }
            }
            Effect::AnalyzeEntropy => {
                match crate::entropy::analyze_str(&state.entropy.input) {
                    Ok(report) => {
                        state.entropy.report = Some(report);
                        state.entropy.error = None;
                        state.entropy.message = Some("Analyzed.".into());
                    }
                    Err(err) => {
                        state.entropy.error = Some(err.to_string());
                        state.entropy.message = None;
                        state.entropy.report = None;
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
