use crate::tui::action::Action;
use crate::tui::effect::Effect;
use crate::tui::state::AppState;
use crossterm::event::KeyCode;

pub fn update(state: &mut AppState, action: Action) -> Vec<Effect> {
    match action {
        Action::Tick => Vec::new(),
        Action::Resize { .. } => Vec::new(),
        Action::KeyPress { code, .. } => handle_key(state, code),
    }
}

fn handle_key(state: &mut AppState, code: KeyCode) -> Vec<Effect> {
    match code {
        KeyCode::Esc | KeyCode::Char('q') => {
            state.should_quit = true;
            Vec::new()
        }
        KeyCode::Char('h') => {
            state.route = crate::tui::state::Route::Home;
            Vec::new()
        }
        KeyCode::Char('p') => {
            state.route = crate::tui::state::Route::Password;
            Vec::new()
        }
        _ => match state.route {
            crate::tui::state::Route::Home => Vec::new(),
            crate::tui::state::Route::Password => handle_password_screen_key(state, code),
        },
    }
}

fn handle_password_screen_key(state: &mut AppState, code: KeyCode) -> Vec<Effect> {
    match code {
        KeyCode::Enter | KeyCode::Char('g') => vec![Effect::GeneratePassword],
        KeyCode::Char('c') => {
            if state.password.generated.is_some() {
                vec![Effect::CopyGeneratedPassword]
            } else {
                state.password.message = Some("Nothing to copy yet. Press g to generate.".into());
                Vec::new()
            }
        }
        KeyCode::Char('r') => {
            state.password.config = crate::password::PasswordConfig::default();
            state.password.active_profile = None;
            clear_password_outputs(state);
            Vec::new()
        }
        KeyCode::Char(']') => {
            cycle_profile(state, 1);
            Vec::new()
        }
        KeyCode::Char('[') => {
            cycle_profile(state, -1);
            Vec::new()
        }
        KeyCode::Char('+') | KeyCode::Char('=') => {
            bump_length(state, 1);
            Vec::new()
        }
        KeyCode::Char('-') => {
            bump_length(state, -1);
            Vec::new()
        }
        KeyCode::Char('l') => {
            toggle_class(state, CharClass::Lowercase);
            Vec::new()
        }
        KeyCode::Char('u') => {
            toggle_class(state, CharClass::Uppercase);
            Vec::new()
        }
        KeyCode::Char('d') => {
            toggle_class(state, CharClass::Digits);
            Vec::new()
        }
        KeyCode::Char('s') => {
            toggle_class(state, CharClass::Symbols);
            Vec::new()
        }
        KeyCode::Char('a') => {
            state.password.config.allow_ambiguous = !state.password.config.allow_ambiguous;
            state.password.active_profile = None;
            clear_password_outputs(state);
            Vec::new()
        }
        _ => Vec::new(),
    }
}

fn clear_password_outputs(state: &mut AppState) {
    state.password.generated = None;
    state.password.strength_score = None;
    state.password.error = None;
    state.password.message = None;
}

fn bump_length(state: &mut AppState, delta: i32) {
    let current = state.password.config.length as i32;
    let next = (current + delta).clamp(4, 128) as usize;
    if next != state.password.config.length {
        state.password.config.length = next;
        state.password.active_profile = None;
        clear_password_outputs(state);
    }
}

enum CharClass {
    Lowercase,
    Uppercase,
    Digits,
    Symbols,
}

fn toggle_class(state: &mut AppState, class: CharClass) {
    let config = &mut state.password.config;
    match class {
        CharClass::Lowercase => {
            config.include_lowercase = !config.include_lowercase;
            config.min_lowercase = if config.include_lowercase { 1 } else { 0 };
        }
        CharClass::Uppercase => {
            config.include_uppercase = !config.include_uppercase;
            config.min_uppercase = if config.include_uppercase { 1 } else { 0 };
        }
        CharClass::Digits => {
            config.include_digits = !config.include_digits;
            config.min_digits = if config.include_digits { 1 } else { 0 };
        }
        CharClass::Symbols => {
            config.include_symbols = !config.include_symbols;
            config.min_symbols = if config.include_symbols { 1 } else { 0 };
        }
    }

    state.password.active_profile = None;
    ensure_length_meets_required_minimum(config);
    clear_password_outputs(state);
}

fn ensure_length_meets_required_minimum(config: &mut crate::password::PasswordConfig) {
    let required =
        config.min_lowercase + config.min_uppercase + config.min_digits + config.min_symbols;
    if config.length < required {
        config.length = required;
    }
}

fn cycle_profile(state: &mut AppState, delta: i32) {
    if state.password.profiles.is_empty() {
        state.password.message =
            Some("No profiles found. Use CLI: `passworder profile ...`".into());
        return;
    }

    let len = state.password.profiles.len() as i32;
    let current = state.password.active_profile.unwrap_or(0) as i32;
    let next = (current + delta).rem_euclid(len) as usize;
    state.password.active_profile = Some(next);
    state.password.config = state.password.profiles[next].config;
    clear_password_outputs(state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    #[test]
    fn q_sets_should_quit() {
        let mut state = AppState::default();
        let effects = update(
            &mut state,
            Action::KeyPress {
                code: KeyCode::Char('q'),
                modifiers: KeyModifiers::NONE,
            },
        );
        assert!(state.should_quit);
        assert!(effects.is_empty());
    }

    #[test]
    fn esc_sets_should_quit() {
        let mut state = AppState::default();
        let effects = update(
            &mut state,
            Action::KeyPress {
                code: KeyCode::Esc,
                modifiers: KeyModifiers::NONE,
            },
        );
        assert!(state.should_quit);
        assert!(effects.is_empty());
    }

    #[test]
    fn other_keys_do_not_quit() {
        let mut state = AppState::default();
        let effects = update(
            &mut state,
            Action::KeyPress {
                code: KeyCode::Char('x'),
                modifiers: KeyModifiers::NONE,
            },
        );
        assert!(!state.should_quit);
        assert!(effects.is_empty());
    }

    #[test]
    fn generate_emits_effect() {
        let mut state = AppState::default();
        let effects = update(
            &mut state,
            Action::KeyPress {
                code: KeyCode::Char('g'),
                modifiers: KeyModifiers::NONE,
            },
        );
        assert_eq!(effects, vec![Effect::GeneratePassword]);
    }
}
