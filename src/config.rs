use crate::password::{self, PasswordConfig};
use dirs::config_dir;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

const CONFIG_ENV: &str = "PASSWORDER_CONFIG";
const APP_DIR: &str = "passworder";
const CONFIG_FILE_NAME: &str = "config.toml";
const CURRENT_SCHEMA_VERSION: u32 = 2;

#[derive(Debug)]
pub enum ConfigError {
    ConfigDirUnavailable,
    Io(std::io::Error),
    Parse(toml::de::Error),
    Serialize(toml::ser::Error),
    MissingProfile(String),
    InvalidProfile(password::GenerationError),
    UnsupportedSchemaVersion(u32),
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
            ConfigError::UnsupportedSchemaVersion(version) => {
                write!(f, "config schema version '{version}' is not supported")
            }
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

#[derive(Debug, Serialize, Deserialize)]
struct FileConfig {
    #[serde(default)]
    schema_version: Option<u32>,
    #[serde(default)]
    profiles: HashMap<String, PasswordConfig>,
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            schema_version: Some(CURRENT_SCHEMA_VERSION),
            profiles: HashMap::new(),
        }
    }
}

impl FileConfig {
    fn schema_version(&self) -> u32 {
        self.schema_version.unwrap_or(0)
    }

    fn ensure_current_version(&mut self) {
        self.schema_version = Some(CURRENT_SCHEMA_VERSION);
    }
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
        Ok(contents) => {
            let config: FileConfig = toml::from_str(&contents).map_err(ConfigError::Parse)?;
            maybe_upgrade_config(path, config)
        }
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

fn maybe_upgrade_config(path: &Path, mut config: FileConfig) -> Result<FileConfig, ConfigError> {
    let mut version = config.schema_version();
    if version == CURRENT_SCHEMA_VERSION {
        config.ensure_current_version();
        return Ok(config);
    }

    if version > CURRENT_SCHEMA_VERSION {
        return Err(ConfigError::UnsupportedSchemaVersion(version));
    }

    backup_config(path)?;

    while version < CURRENT_SCHEMA_VERSION {
        match version {
            0 => {
                // Initial migration: record schema version without changing structure.
                version = 1;
            }
            1 => {
                upgrade_profiles_to_v2(&mut config);
                version = 2;
            }
            _ => {
                return Err(ConfigError::UnsupportedSchemaVersion(version));
            }
        }
    }

    config.ensure_current_version();
    persist_config(path, &config)?;
    Ok(config)
}

fn upgrade_profiles_to_v2(config: &mut FileConfig) {
    for profile in config.profiles.values_mut() {
        upgrade_minimum(&mut profile.min_lowercase, profile.include_lowercase);
        upgrade_minimum(&mut profile.min_uppercase, profile.include_uppercase);
        upgrade_minimum(&mut profile.min_digits, profile.include_digits);
        upgrade_minimum(&mut profile.min_symbols, profile.include_symbols);
    }
}

fn upgrade_minimum(min_value: &mut usize, class_enabled: bool) {
    if class_enabled {
        if *min_value == 0 {
            *min_value = 1;
        }
    } else {
        *min_value = 0;
    }
}

fn backup_config(path: &Path) -> Result<(), ConfigError> {
    if !path.exists() {
        return Ok(());
    }

    let parent = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("passworder");

    let mut backup_path = parent.join(format!("{stem}.backup-{timestamp}.toml"));
    let mut counter = 0u32;
    while backup_path.exists() {
        counter += 1;
        backup_path = parent.join(format!("{stem}.backup-{timestamp}-{counter}.toml"));
    }

    fs::copy(path, backup_path).map_err(ConfigError::Io)?;
    Ok(())
}

pub fn list_profiles() -> Result<Vec<(String, PasswordConfig)>, ConfigError> {
    let path = config_path()?;
    let config = load_config(&path)?;
    let mut entries: Vec<_> = config.profiles.into_iter().collect();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn load_config_upgrades_unversioned_file_and_creates_backup() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");

        let old_config = r#"[profiles.default]
length = 12
allow_ambiguous = false
include_lowercase = true
include_uppercase = true
include_digits = true
include_symbols = false
"#;

        fs::write(&path, old_config).expect("write config");

        let config = load_config(&path).expect("load config");
        assert_eq!(config.schema_version(), CURRENT_SCHEMA_VERSION);

        let updated_contents = fs::read_to_string(&path).expect("read updated config");
        assert!(updated_contents.contains("schema_version = 2"));
        assert!(updated_contents.contains("min_lowercase = 1"));
        assert!(updated_contents.contains("min_uppercase = 1"));
        assert!(updated_contents.contains("min_digits = 1"));
        assert!(updated_contents.contains("min_symbols = 0"));

        let backups: Vec<_> = fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".backup-"))
            .collect();

        assert_eq!(backups.len(), 1, "expected exactly one backup file");

        let backup_contents = fs::read_to_string(backups[0].path()).expect("read backup contents");
        assert_eq!(backup_contents, old_config);
    }

    #[test]
    fn default_config_sets_schema_version() {
        let config = FileConfig::default();
        assert_eq!(config.schema_version(), CURRENT_SCHEMA_VERSION);
    }
}
