mod action;
mod state;
mod update;

use crate::tui::action::Action;
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

pub fn run() -> Result<(), Box<dyn Error>> {
    let _restore = RestoreGuard;
    let mut terminal = ratatui::init();
    let mut state = AppState::default();

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
                Event::Key(key) if key.kind == KeyEventKind::Press => update(
                    &mut state,
                    Action::KeyPress {
                        code: key.code,
                        modifiers: key.modifiers,
                    },
                ),
                Event::Resize(width, height) => {
                    update(&mut state, Action::Resize { width, height })
                }
                _ => {}
            }
        }

        if last_tick.elapsed() >= tick_rate {
            update(&mut state, Action::Tick);
            last_tick = Instant::now();
        }
    }
}

fn render(frame: &mut Frame, _state: &AppState) {
    let area = frame.area();

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(5),
            Constraint::Min(0),
        ])
        .split(area);

    let block = Block::bordered().title("passworder");
    let content = Paragraph::new("Press q or Esc to quit.")
        .alignment(Alignment::Center)
        .style(Style::new().dim())
        .wrap(Wrap { trim: true })
        .block(block);

    frame.render_widget(content, layout[1]);
}
