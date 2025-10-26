use crate::password::{self, PasswordConfig};
use dirs::config_dir;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

const CONFIG_ENV: &str = "PASSWORDER_CONFIG";
const APP_DIR: &str = "passworder";
const CONFIG_FILE_NAME: &str = "config.toml";

#[derive(Debug)]
pub enum ConfigError {
    ConfigDirUnavailable,
    Io(std::io::Error),
    Parse(toml::de::Error),
    Serialize(toml::ser::Error),
    MissingProfile(String),
    InvalidProfile(password::GenerationError),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::ConfigDirUnavailable => {
                write!(f, "unable to determine configuration directory")
            }
            ConfigError::Io(err) => write!(f, "filesystem error: {err}"),
            ConfigError::Parse(err) => write!(f, "failed to parse config: {err}"),
            ConfigError::Serialize(err) => write!(f, "failed to serialize config: {err}"),
            ConfigError::MissingProfile(name) => {
                write!(f, "profile '{name}' does not exist")
            }
            ConfigError::InvalidProfile(err) => write!(f, "invalid profile settings: {err}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Io(err) => Some(err),
            ConfigError::Parse(err) => Some(err),
            ConfigError::Serialize(err) => Some(err),
            ConfigError::InvalidProfile(err) => Some(err),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct FileConfig {
    #[serde(default)]
    profiles: HashMap<String, PasswordConfig>,
}

pub fn config_path() -> Result<PathBuf, ConfigError> {
    if let Ok(path) = env::var(CONFIG_ENV) {
        return Ok(PathBuf::from(path));
    }

    let mut dir = config_dir().ok_or(ConfigError::ConfigDirUnavailable)?;
    dir.push(APP_DIR);
    fs::create_dir_all(&dir).map_err(ConfigError::Io)?;
    dir.push(CONFIG_FILE_NAME);
    Ok(dir)
}

fn load_config(path: &Path) -> Result<FileConfig, ConfigError> {
    match fs::read_to_string(path) {
        Ok(contents) => toml::from_str(&contents).map_err(ConfigError::Parse),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(FileConfig::default()),
        Err(err) => Err(ConfigError::Io(err)),
    }
}

fn persist_config(path: &Path, config: &FileConfig) -> Result<(), ConfigError> {
    let parent = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    if !parent.exists() {
        fs::create_dir_all(&parent).map_err(ConfigError::Io)?;
    }

    let toml = toml::to_string_pretty(config).map_err(ConfigError::Serialize)?;
    let mut temp = NamedTempFile::new_in(&parent).map_err(ConfigError::Io)?;
    temp.write_all(toml.as_bytes()).map_err(ConfigError::Io)?;
    temp.flush().map_err(ConfigError::Io)?;
    temp.persist(path)
        .map_err(|err| ConfigError::Io(err.error))?;
    Ok(())
}

pub fn list_profiles() -> Result<Vec<(String, PasswordConfig)>, ConfigError> {
    let path = config_path()?;
    let config = load_config(&path)?;
    let mut entries: Vec<_> = config
        .profiles
        .into_iter()
        .map(|(name, profile)| (name, profile))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries)
}

pub fn get_profile(name: &str) -> Result<PasswordConfig, ConfigError> {
    let path = config_path()?;
    let config = load_config(&path)?;
    config
        .profiles
        .get(name)
        .copied()
        .ok_or_else(|| ConfigError::MissingProfile(name.to_string()))
}

pub fn save_profile(name: &str, profile: PasswordConfig) -> Result<(), ConfigError> {
    password::validate_config(&profile).map_err(ConfigError::InvalidProfile)?;

    let path = config_path()?;
    let mut config = load_config(&path)?;
    config.profiles.insert(name.to_string(), profile);
    persist_config(&path, &config)
}

pub fn remove_profile(name: &str) -> Result<(), ConfigError> {
    let path = config_path()?;
    let mut config = load_config(&path)?;
    if config.profiles.remove(name).is_none() {
        return Err(ConfigError::MissingProfile(name.to_string()));
    }
    persist_config(&path, &config)
}
