use crate::tui::action::Action;
use crate::tui::state::AppState;
use crossterm::event::KeyCode;

pub fn update(state: &mut AppState, action: Action) {
    match action {
        Action::Tick => {}
        Action::Resize { .. } => {}
        Action::KeyPress { code, .. } => match code {
            KeyCode::Esc => state.should_quit = true,
            KeyCode::Char('q') => state.should_quit = true,
            _ => {}
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    #[test]
    fn q_sets_should_quit() {
        let mut state = AppState::default();
        update(
            &mut state,
            Action::KeyPress {
                code: KeyCode::Char('q'),
                modifiers: KeyModifiers::NONE,
            },
        );
        assert!(state.should_quit);
    }

    #[test]
    fn esc_sets_should_quit() {
        let mut state = AppState::default();
        update(
            &mut state,
            Action::KeyPress {
                code: KeyCode::Esc,
                modifiers: KeyModifiers::NONE,
            },
        );
        assert!(state.should_quit);
    }

    #[test]
    fn other_keys_do_not_quit() {
        let mut state = AppState::default();
        update(
            &mut state,
            Action::KeyPress {
                code: KeyCode::Char('x'),
                modifiers: KeyModifiers::NONE,
            },
        );
        assert!(!state.should_quit);
    }
}
