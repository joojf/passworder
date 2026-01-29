use crossterm::event::{KeyCode, KeyModifiers};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Tick,
    Resize {
        width: u16,
        height: u16,
    },
    KeyPress {
        code: KeyCode,
        modifiers: KeyModifiers,
    },
}
