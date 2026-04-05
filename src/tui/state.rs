use crate::entropy::EntropyReport;
use crate::passphrase::PassphraseConfig;
use crate::password::PasswordConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Splash,
    Password,
    Passphrase,
    Entropy,
    Home,
}

impl Default for Route {
    fn default() -> Self {
        Self::Splash
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SplashState {
    pub tick: usize,
}

#[derive(Debug, Clone)]
pub struct ProfileEntry {
    pub name: String,
    pub config: PasswordConfig,
}

#[derive(Debug, Clone, Default)]
pub struct PasswordScreenState {
    pub profiles: Vec<ProfileEntry>,
    pub active_profile: Option<usize>,
    pub config: PasswordConfig,
    pub generated: Option<String>,
    pub strength_score: Option<u8>,
    pub message: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PassphraseScreenState {
    pub config: PassphraseConfig,
    pub generated: Option<String>,
    pub message: Option<String>,
    pub error: Option<String>,
}

impl Default for PassphraseScreenState {
    fn default() -> Self {
        Self {
            config: PassphraseConfig {
                word_count: 6,
                separator: "-".to_string(),
                title_case: false,
                wordlist: None,
            },
            generated: None,
            message: None,
            error: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct EntropyScreenState {
    pub input: String,
    pub masked: bool,
    pub report: Option<EntropyReport>,
    pub message: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct AppState {
    pub should_quit: bool,
    pub route: Route,
    pub splash: SplashState,
    pub password: PasswordScreenState,
    pub passphrase: PassphraseScreenState,
    pub entropy: EntropyScreenState,
}
