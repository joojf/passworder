use crate::vault::{crypto, format_v1, io, items, prompt};
use secrecy::SecretString;
use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

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

    #[error("vault is not initialized")]
    NotInitialized,

    #[error("unlock failed (wrong password or vault corrupted)")]
    AuthFailed,

    #[error("unsupported vault payload schema version {0}")]
    UnsupportedPayloadSchema(u32),

    #[error("item not found: {0}")]
    ItemNotFound(String),

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
    let payload_ciphertext = crypto::encrypt_payload(&dek, &payload_nonce, &aad, &payload_plaintext)?;

    let mut vault_bytes = Vec::with_capacity(header_bytes.len() + payload_ciphertext.len());
    vault_bytes.extend_from_slice(&header_bytes);
    vault_bytes.extend_from_slice(&payload_ciphertext);

    io::write_vault_bytes_atomic(vault_path, &vault_bytes)?;
    Ok(())
}

pub struct AddItemInput {
    pub item_type: items::VaultItemType,
    pub name: String,
    pub path: Option<String>,
    pub tags: Vec<String>,
    pub username: Option<String>,
    pub secret: String,
    pub urls: Vec<String>,
    pub notes: Option<String>,
}

pub struct EditItemInput {
    pub id: Uuid,
    pub item_type: Option<items::VaultItemType>,
    pub name: Option<String>,
    pub path: Option<String>,
    pub clear_path: bool,
    pub tags: Option<Vec<String>>,
    pub clear_tags: bool,
    pub username: Option<String>,
    pub clear_username: bool,
    pub secret: Option<String>,
    pub urls: Option<Vec<String>>,
    pub clear_urls: bool,
    pub notes: Option<String>,
    pub clear_notes: bool,
}

pub fn vault_add_item_v1(
    vault_path: &Path,
    master_password: &SecretString,
    input: AddItemInput,
) -> Result<Uuid, VaultError> {
    let _lock = io::VaultLock::acquire(
        &io::lock_path_for_vault(vault_path),
        io::LockMode::Exclusive,
    )?;

    let bytes = read_existing_vault_bytes_unlocked(vault_path)?;
    let (mut payload, header) = load_payload_v1(&bytes, master_password)?;

    let now = now_unix_seconds();
    let id = Uuid::new_v4();
    let item = items::VaultItemV1 {
        id,
        item_type: input.item_type,
        name: input.name,
        path: input.path,
        tags: normalize_tags(input.tags),
        username: input.username,
        secret: input.secret,
        urls: normalize_urls(input.urls),
        notes: input.notes,
        created_at: now,
        updated_at: now,
    };

    payload.items.push(item);
    payload.items.sort_by(item_sort_cmp);

    let new_bytes = seal_vault_v1(header.header.kdf_params, header.header.kdf_salt, master_password, &payload)?;
    io::write_vault_bytes_atomic_unlocked(vault_path, &new_bytes)?;
    Ok(id)
}

pub fn vault_get_item_v1(
    vault_path: &Path,
    master_password: &SecretString,
    id: Uuid,
) -> Result<items::VaultItemV1, VaultError> {
    let bytes = read_existing_vault_bytes(vault_path)?;
    let (payload, _) = load_payload_v1(&bytes, master_password)?;

    payload
        .items
        .into_iter()
        .find(|i| i.id == id)
        .ok_or_else(|| VaultError::ItemNotFound(id.to_string()))
}

pub fn vault_list_items_v1(
    vault_path: &Path,
    master_password: &SecretString,
) -> Result<Vec<items::VaultItemV1>, VaultError> {
    let bytes = read_existing_vault_bytes(vault_path)?;
    let (payload, _) = load_payload_v1(&bytes, master_password)?;
    Ok(payload.items)
}

pub fn vault_search_items_v1(
    vault_path: &Path,
    master_password: &SecretString,
    query: &str,
) -> Result<Vec<items::VaultItemV1>, VaultError> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return Ok(Vec::new());
    }

    let bytes = read_existing_vault_bytes(vault_path)?;
    let (payload, _) = load_payload_v1(&bytes, master_password)?;

    let matches = payload
        .items
        .into_iter()
        .filter(|item| item_matches_query(item, &q))
        .collect::<Vec<_>>();
    Ok(matches)
}

pub fn vault_edit_item_v1(
    vault_path: &Path,
    master_password: &SecretString,
    input: EditItemInput,
) -> Result<(), VaultError> {
    let _lock = io::VaultLock::acquire(
        &io::lock_path_for_vault(vault_path),
        io::LockMode::Exclusive,
    )?;

    let bytes = read_existing_vault_bytes_unlocked(vault_path)?;
    let (mut payload, header) = load_payload_v1(&bytes, master_password)?;

    let item = payload
        .items
        .iter_mut()
        .find(|i| i.id == input.id)
        .ok_or_else(|| VaultError::ItemNotFound(input.id.to_string()))?;

    if let Some(t) = input.item_type {
        item.item_type = t;
    }
    if let Some(name) = input.name {
        item.name = name;
    }
    if input.clear_path {
        item.path = None;
    } else if let Some(path) = input.path {
        item.path = Some(path);
    }
    if input.clear_tags {
        item.tags.clear();
    } else if let Some(tags) = input.tags {
        item.tags = normalize_tags(tags);
    }
    if input.clear_username {
        item.username = None;
    } else if let Some(username) = input.username {
        item.username = Some(username);
    }
    if let Some(secret) = input.secret {
        item.secret = secret;
    }
    if input.clear_urls {
        item.urls.clear();
    } else if let Some(urls) = input.urls {
        item.urls = normalize_urls(urls);
    }
    if input.clear_notes {
        item.notes = None;
    } else if let Some(notes) = input.notes {
        item.notes = Some(notes);
    }

    item.updated_at = now_unix_seconds();

    payload.items.sort_by(item_sort_cmp);
    let new_bytes = seal_vault_v1(header.header.kdf_params, header.header.kdf_salt, master_password, &payload)?;
    io::write_vault_bytes_atomic_unlocked(vault_path, &new_bytes)?;
    Ok(())
}

pub fn vault_remove_item_v1(
    vault_path: &Path,
    master_password: &SecretString,
    id: Uuid,
) -> Result<(), VaultError> {
    let _lock = io::VaultLock::acquire(
        &io::lock_path_for_vault(vault_path),
        io::LockMode::Exclusive,
    )?;

    let bytes = read_existing_vault_bytes_unlocked(vault_path)?;
    let (mut payload, header) = load_payload_v1(&bytes, master_password)?;

    let before = payload.items.len();
    payload.items.retain(|i| i.id != id);
    if payload.items.len() == before {
        return Err(VaultError::ItemNotFound(id.to_string()));
    }

    let new_bytes = seal_vault_v1(header.header.kdf_params, header.header.kdf_salt, master_password, &payload)?;
    io::write_vault_bytes_atomic_unlocked(vault_path, &new_bytes)?;
    Ok(())
}

fn read_existing_vault_bytes(vault_path: &Path) -> Result<Vec<u8>, VaultError> {
    match io::read_vault_bytes(vault_path) {
        Ok(bytes) => Ok(bytes),
        Err(io::VaultIoError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            Err(VaultError::NotInitialized)
        }
        Err(err) => Err(VaultError::Io(err)),
    }
}

fn read_existing_vault_bytes_unlocked(vault_path: &Path) -> Result<Vec<u8>, VaultError> {
    match io::read_vault_bytes_unlocked(vault_path) {
        Ok(bytes) => Ok(bytes),
        Err(io::VaultIoError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            Err(VaultError::NotInitialized)
        }
        Err(err) => Err(VaultError::Io(err)),
    }
}

fn load_payload_v1<'a>(
    vault_bytes: &'a [u8],
    master_password: &SecretString,
) -> Result<(items::VaultPayloadV1, format_v1::ParsedVaultV1<'a>), VaultError> {
    let parsed = format_v1::parse_vault_v1(vault_bytes)?;
    let aad = aad_for_v1(&parsed.header);

    let kdf_out = crypto::derive_kdf_out_from_password(
        master_password,
        &parsed.header.kdf_salt,
        parsed.header.kdf_params,
    )?;
    let kek = crypto::derive_kek(&kdf_out)?;

    let dek = crypto::unwrap_dek(
        &kek,
        &parsed.header.wrap_nonce,
        &aad,
        &parsed.header.wrapped_dek,
    )
    .map_err(|e| match e {
        crypto::CryptoError::Aead => VaultError::AuthFailed,
        other => VaultError::Crypto(other),
    })?;

    let plaintext = crypto::decrypt_payload(
        &dek,
        &parsed.header.payload_nonce,
        &aad,
        parsed.payload_ciphertext,
    )
    .map_err(|e| match e {
        crypto::CryptoError::Aead => VaultError::AuthFailed,
        other => VaultError::Crypto(other),
    })?;

    let payload: items::VaultPayloadV1 = serde_json::from_slice(&plaintext)?;
    if payload.schema_version != 1 {
        return Err(VaultError::UnsupportedPayloadSchema(payload.schema_version));
    }

    Ok((payload, parsed))
}

fn seal_vault_v1(
    kdf_params: crypto::KdfParams,
    kdf_salt: [u8; 16],
    master_password: &SecretString,
    payload: &items::VaultPayloadV1,
) -> Result<Vec<u8>, VaultError> {
    let wrap_nonce = crypto::random_bytes::<{ crypto::XCHACHA_NONCE_LEN }>();
    let payload_nonce = crypto::random_bytes::<{ crypto::XCHACHA_NONCE_LEN }>();

    let kdf_out = crypto::derive_kdf_out_from_password(master_password, &kdf_salt, kdf_params)?;
    let kek = crypto::derive_kek(&kdf_out)?;
    let dek = crypto::generate_dek();

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

    let payload_json = serde_json::to_vec(payload)?;
    let payload_ciphertext = crypto::encrypt_payload(&dek, &payload_nonce, &aad, &payload_json)?;

    let mut out = Vec::with_capacity(header_bytes.len() + payload_ciphertext.len());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&payload_ciphertext);
    Ok(out)
}

fn aad_for_v1(header: &format_v1::VaultHeaderV1) -> Vec<u8> {
    let placeholder = format_v1::VaultHeaderV1 {
        kdf_params: header.kdf_params,
        kdf_salt: header.kdf_salt,
        wrap_nonce: header.wrap_nonce,
        wrapped_dek: vec![0u8; header.wrapped_dek.len()],
        payload_nonce: header.payload_nonce,
    };
    format_v1::encode_header_v1(&placeholder)
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn item_sort_cmp(a: &items::VaultItemV1, b: &items::VaultItemV1) -> Ordering {
    let ap = a.path.as_deref().unwrap_or("");
    let bp = b.path.as_deref().unwrap_or("");
    match ap.cmp(bp) {
        Ordering::Equal => match a.name.cmp(&b.name) {
            Ordering::Equal => a.id.cmp(&b.id),
            other => other,
        },
        other => other,
    }
}

fn normalize_tags(tags: Vec<String>) -> Vec<String> {
    let mut out = tags
        .into_iter()
        .filter_map(|t| {
            let t = t.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_lowercase())
            }
        })
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    out
}

fn normalize_urls(urls: Vec<String>) -> Vec<String> {
    let mut out = urls
        .into_iter()
        .filter_map(|u| {
            let u = u.trim();
            if u.is_empty() {
                None
            } else {
                Some(u.to_string())
            }
        })
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    out
}

fn item_matches_query(item: &items::VaultItemV1, q: &str) -> bool {
    if item.name.to_lowercase().contains(q) {
        return true;
    }
    if let Some(path) = &item.path {
        if path.to_lowercase().contains(q) {
            return true;
        }
    }
    if item.tags.iter().any(|t| t.contains(q)) {
        return true;
    }
    if let Some(username) = &item.username {
        if username.to_lowercase().contains(q) {
            return true;
        }
    }
    if item
        .urls
        .iter()
        .any(|u| u.to_lowercase().contains(q))
    {
        return true;
    }
    if let Some(notes) = &item.notes {
        if notes.to_lowercase().contains(q) {
            return true;
        }
    }
    false
}
