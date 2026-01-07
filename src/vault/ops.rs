use crate::vault::{crypto, format_v1, io, prompt};
use secrecy::SecretString;
use std::path::{Path, PathBuf};
use thiserror::Error;

const VAULT_ENV: &str = "PASSWORDER_VAULT";
const APP_DIR: &str = "passworder";
const DEFAULT_VAULT_FILE: &str = "vault.pwder";
const TEST_KDF_ENV: &str = "PASSWORDER_VAULT_TEST_KDF";

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("unable to determine vault directory")]
    VaultDirUnavailable,

    #[error("vault already exists at {0}")]
    AlreadyExists(String),

    #[error(transparent)]
    Io(#[from] io::VaultIoError),

    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),

    #[error(transparent)]
    Format(#[from] format_v1::VaultFormatError),

    #[error(transparent)]
    Prompt(#[from] prompt::PromptError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultStatus {
    Missing,
    Locked,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            VaultStatus::Missing => "missing",
            VaultStatus::Locked => "locked",
        }
    }
}

pub fn vault_path(override_path: Option<&Path>) -> Result<PathBuf, VaultError> {
    if let Some(path) = override_path {
        return Ok(path.to_path_buf());
    }

    if let Some(path) = std::env::var_os(VAULT_ENV) {
        return Ok(PathBuf::from(path));
    }

    let mut dir = dirs::config_dir().ok_or(VaultError::VaultDirUnavailable)?;
    dir.push(APP_DIR);
    dir.push(DEFAULT_VAULT_FILE);
    Ok(dir)
}

pub fn vault_status_v1(vault_path: &Path) -> Result<(VaultStatus, Option<u16>), VaultError> {
    if !vault_path.exists() {
        return Ok((VaultStatus::Missing, None));
    }

    let bytes = io::read_vault_bytes(vault_path)?;
    let fixed = format_v1::parse_fixed_header(&bytes)?;
    Ok((VaultStatus::Locked, Some(fixed.version)))
}

pub fn vault_init_v1(vault_path: &Path, master_password: &SecretString) -> Result<(), VaultError> {
    if vault_path.exists() {
        return Err(VaultError::AlreadyExists(vault_path.display().to_string()));
    }

    let kdf_params = if std::env::var_os(TEST_KDF_ENV).is_some() {
        crypto::KdfParams::for_tests()
    } else {
        crypto::KdfParams::recommended_macos()
    };

    let kdf_salt = crypto::random_bytes::<16>();
    let wrap_nonce = crypto::random_bytes::<{ crypto::XCHACHA_NONCE_LEN }>();
    let payload_nonce = crypto::random_bytes::<{ crypto::XCHACHA_NONCE_LEN }>();

    let kdf_out = crypto::derive_kdf_out_from_password(master_password, &kdf_salt, kdf_params)?;
    let kek = crypto::derive_kek(&kdf_out)?;
    let dek = crypto::generate_dek();

    // v1: ciphertext length is plaintext length + 16-byte Poly1305 tag.
    let wrapped_dek_len = crypto::DEK_LEN + 16;
    let placeholder_header = format_v1::VaultHeaderV1 {
        kdf_params,
        kdf_salt,
        wrap_nonce,
        wrapped_dek: vec![0u8; wrapped_dek_len],
        payload_nonce,
    };
    let aad = format_v1::encode_header_v1(&placeholder_header);
    let wrapped_dek = crypto::wrap_dek(&kek, &wrap_nonce, &aad, &dek)?;

    let header = format_v1::VaultHeaderV1 {
        wrapped_dek,
        ..placeholder_header
    };
    let header_bytes = format_v1::encode_header_v1(&header);

    let payload_plaintext = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "items": [],
    }))?;
    let payload_ciphertext = crypto::encrypt_payload(&dek, &payload_nonce, &header_bytes, &payload_plaintext)?;

    let mut vault_bytes = Vec::with_capacity(header_bytes.len() + payload_ciphertext.len());
    vault_bytes.extend_from_slice(&header_bytes);
    vault_bytes.extend_from_slice(&payload_ciphertext);

    io::write_vault_bytes_atomic(vault_path, &vault_bytes)?;
    Ok(())
}
