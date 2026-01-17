use crate::{config, entropy, passphrase, password, token, vault};
use std::process::ExitCode;

pub const EXIT_USAGE: u8 = 64;
pub const EXIT_IO: u8 = 2;
pub const EXIT_SOFTWARE: u8 = 1;

pub fn exit_code_for_config_error(error: &config::ConfigError) -> ExitCode {
    use config::ConfigError::*;

    match error {
        ConfigDirUnavailable | Io(_) => ExitCode::from(EXIT_IO),
        MissingProfile(_) | InvalidProfile(_) => ExitCode::from(EXIT_USAGE),
        Parse(_) | Serialize(_) | UnsupportedSchemaVersion(_) => ExitCode::from(EXIT_SOFTWARE),
    }
}

pub fn exit_code_for_password_error(error: &password::GenerationError) -> ExitCode {
    use password::GenerationError::*;

    match error {
        EmptyClass(_)
        | EmptyPool
        | LengthTooShort { .. }
        | NoClassesEnabled
        | MinimumRequiresDisabledClass(_) => ExitCode::from(EXIT_USAGE),
    }
}

pub fn exit_code_for_passphrase_error(error: &passphrase::PassphraseError) -> ExitCode {
    use passphrase::PassphraseError::*;

    match error {
        WordCountZero => ExitCode::from(EXIT_USAGE),
        Io { .. } => ExitCode::from(EXIT_IO),
        EmptyWordList { .. } => ExitCode::from(EXIT_SOFTWARE),
    }
}

pub fn exit_code_for_token_error(error: &token::TokenError) -> ExitCode {
    use token::TokenError::*;

    match error {
        ByteLengthZero => ExitCode::from(EXIT_USAGE),
        SampleBytesFailed => ExitCode::from(EXIT_IO),
    }
}

pub fn exit_code_for_entropy_error(error: &entropy::EntropyError) -> ExitCode {
    use entropy::EntropyError::*;

    match error {
        Io(_) => ExitCode::from(EXIT_IO),
        InvalidUtf8 => ExitCode::from(EXIT_USAGE),
        Serialization(_) | Strength(_) => ExitCode::from(EXIT_SOFTWARE),
    }
}

pub fn exit_code_for_vault_prompt_error(error: &vault::PromptError) -> ExitCode {
    use vault::PromptError::*;

    match error {
        Io(_) => ExitCode::from(EXIT_IO),
        Empty | Mismatch => ExitCode::from(EXIT_USAGE),
    }
}

pub fn exit_code_for_vault_error(error: &vault::VaultError) -> ExitCode {
    use vault::VaultError::*;

    match error {
        VaultDirUnavailable | Io(_) => ExitCode::from(EXIT_IO),
        AlreadyExists(_) | NotInitialized | AuthFailed | ItemNotFound(_) | Prompt(_) => {
            ExitCode::from(EXIT_USAGE)
        }
        UnsupportedPayloadSchema(_) | Crypto(_) | Format(_) | Json(_) => {
            ExitCode::from(EXIT_SOFTWARE)
        }
    }
}
