use crate::vault;
use std::collections::BTreeMap;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DevWorkflowError {
    #[error("invalid environment variable name: {0}")]
    InvalidEnvVarName(String),

    #[error("template contains unterminated placeholder")]
    UnterminatedPlaceholder,

    #[error("template references unknown variable: {0}")]
    UnknownVariable(String),
}

pub fn env_vars_for_profile(items: &[vault::VaultItemV1], profile: &str) -> BTreeMap<String, String> {
    let mut vars = BTreeMap::new();

    for item in items {
        if item.path.as_deref() != Some(profile) {
            continue;
        }
        vars.insert(item.name.clone(), item.secret.clone());
    }

    vars
}

pub fn bash_export_lines(vars: &BTreeMap<String, String>) -> Result<String, DevWorkflowError> {
    let mut out = String::new();
    for (k, v) in vars {
        if !is_valid_env_var_name(k) {
            return Err(DevWorkflowError::InvalidEnvVarName(k.clone()));
        }
        out.push_str("export ");
        out.push_str(k);
        out.push('=');
        out.push_str(&bash_single_quote(v));
        out.push('\n');
    }
    Ok(out)
}

pub fn render_template(
    template: &str,
    vars: &BTreeMap<String, String>,
) -> Result<String, DevWorkflowError> {
    let bytes = template.as_bytes();
    let mut i = 0usize;
    let mut last = 0usize;
    let mut out = String::with_capacity(template.len());

    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            out.push_str(&template[last..i]);
            i += 2;
            let start = i;
            while i < bytes.len() && bytes[i] != b'}' {
                i += 1;
            }
            if i >= bytes.len() {
                return Err(DevWorkflowError::UnterminatedPlaceholder);
            }
            let name = std::str::from_utf8(&bytes[start..i])
                .map_err(|_| DevWorkflowError::InvalidEnvVarName("<non-utf8>".to_string()))?;
            if !is_valid_env_var_name(name) {
                return Err(DevWorkflowError::InvalidEnvVarName(name.to_string()));
            }
            let value = vars
                .get(name)
                .ok_or_else(|| DevWorkflowError::UnknownVariable(name.to_string()))?;
            out.push_str(value);
            i += 1;
            last = i;
            continue;
        }

        i += 1;
    }

    out.push_str(&template[last..]);
    Ok(out)
}

pub fn write_sensitive_file_atomic(path: &Path, contents: &[u8]) -> Result<(), vault::io::VaultIoError> {
    vault::io::write_vault_bytes_atomic_unlocked(path, contents)
}

fn is_valid_env_var_name(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else { return false };
    if !(first == '_' || first.is_ascii_uppercase()) {
        return false;
    }
    chars.all(|c| c == '_' || c.is_ascii_uppercase() || c.is_ascii_digit())
}

fn bash_single_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }

    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}
