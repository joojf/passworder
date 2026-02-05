use crate::password::PasswordConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Password,
    Home,
}

impl Default for Route {
    fn default() -> Self {
        Self::Password
    }
}

#[derive(Debug, Clone)]
pub struct ProfileEntry {
    pub name: String,
    pub config: PasswordConfig,
}

#[derive(Debug, Clone)]
pub struct PasswordScreenState {
    pub profiles: Vec<ProfileEntry>,
    pub active_profile: Option<usize>,
    pub config: PasswordConfig,
    pub generated: Option<String>,
    pub strength_score: Option<u8>,
    pub message: Option<String>,
    pub error: Option<String>,
}

impl Default for PasswordScreenState {
    fn default() -> Self {
        Self {
            profiles: Vec::new(),
            active_profile: None,
            config: PasswordConfig::default(),
            generated: None,
            strength_score: None,
            message: None,
            error: None,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct AppState {
    pub should_quit: bool,
    pub route: Route,
    pub password: PasswordScreenState,
}
