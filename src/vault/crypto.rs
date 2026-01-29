//! Cryptographic building blocks for the local vault.
//!
//! This module intentionally provides small, composable primitives which
//! higher-level vault code can wire together according to the vault format and
//! secure defaults.
//!
//! Design notes:
//!
//! - KDF: Argon2id derives `kdf_out` from the master password + per-vault salt.
//! - Key separation: HKDF-SHA256 derives independent subkeys from `kdf_out`.
//! - Key hierarchy: a randomly generated DEK encrypts the vault payload; the
//!   DEK is wrapped (encrypted) with a KEK derived from the master password.
//! - AEAD: XChaCha20-Poly1305 provides authenticated encryption (confidentiality
//!   + integrity). Nonces must be unique per key.
//! - AAD: callers pass associated data (e.g., full header bytes) to bind
//!   ciphertexts to specific parameters/metadata. Any AAD change must fail decrypt.
//!
//! Security foot-guns to avoid:
//!
//! - Never reuse a `(key, nonce)` pair with XChaCha20-Poly1305.
//! - Do not log or print keys, plaintext payloads, or decrypted secrets.
//! - Treat all returned plaintext bytes as sensitive and keep them in memory
//!   for as short a time as possible.

use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

/// Output size (bytes) of Argon2id in v1.
pub const KDF_OUT_LEN: usize = 32;
/// Size (bytes) of the data encryption key (DEK).
pub const DEK_LEN: usize = 32;
/// Size (bytes) of XChaCha20-Poly1305 nonces.
pub const XCHACHA_NONCE_LEN: usize = 24;

/// HKDF `info` label for deriving the key-encryption-key (KEK).
///
/// This provides domain separation from other keys we may derive later.
const HKDF_INFO_KEK: &[u8] = b"passworder/vault/v1/kek";

/// Secret bytes held in memory with zeroize-on-drop semantics.
///
/// We prefer `SecretSlice<u8>` (a boxed slice) because it:
/// - can be constructed from a `Vec<u8>` via `From<Vec<u8>>`
/// - ensures the backing memory is zeroized on drop
pub type SecretBytes = SecretSlice<u8>;

/// Argon2id tuning parameters (persisted in the vault header).
///
/// These defaults are chosen to be secure-by-default for a local CLI tool on
/// macOS, but they are still policy, not truth: the vault header is the
/// source of record for a given vault file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// Recommended default parameters for macOS (interactive CLI).
    ///
    /// This should be calibrated over time; it’s intentionally centralized so
    /// callers don’t scatter “magic numbers”.
    pub fn recommended_macos() -> Self {
        Self {
            memory_kib: 256 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }

    pub fn for_tests() -> Self {
        Self {
            memory_kib: 32 * 1024,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn to_argon2_params(self, output_len: usize) -> Result<Argon2Params, CryptoError> {
        Ok(Argon2Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(output_len),
        )?)
    }
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid nonce length")]
    InvalidNonceLength,

    #[error("argon2 error")]
    Argon2(#[from] argon2::Error),

    #[error("hkdf error")]
    Hkdf,

    #[error("aead error")]
    Aead,
}

/// Generate `N` cryptographically-secure random bytes.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generate a fresh per-vault DEK (data encryption key).
pub fn generate_dek() -> SecretBytes {
    SecretBytes::from(random_bytes::<DEK_LEN>().to_vec())
}

/// Derive `kdf_out` (32 bytes) from the master password using Argon2id.
///
/// Callers are expected to:
/// - store the Argon2 params + salt in the vault header
/// - treat the returned bytes as sensitive and avoid copying them unnecessarily
pub fn derive_kdf_out(
    master_password_bytes: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<SecretBytes, CryptoError> {
    let argon2_params = params.to_argon2_params(KDF_OUT_LEN)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut out = vec![0u8; KDF_OUT_LEN];
    argon2.hash_password_into(master_password_bytes, salt, &mut out)?;
    Ok(SecretBytes::from(out))
}

/// Convenience wrapper for `derive_kdf_out` using a `SecretString`.
pub fn derive_kdf_out_from_password(
    master_password: &SecretString,
    salt: &[u8],
    params: KdfParams,
) -> Result<SecretBytes, CryptoError> {
    derive_kdf_out(master_password.expose_secret().as_bytes(), salt, params)
}

/// Derive the vault KEK (key-encryption-key) from `kdf_out` using HKDF-SHA256.
///
/// The KEK is used to wrap/unwrap the randomly generated DEK.
pub fn derive_kek(kdf_out: &SecretBytes) -> Result<SecretBytes, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, kdf_out.expose_secret());

    let mut kek = vec![0u8; 32];
    hk.expand(HKDF_INFO_KEK, &mut kek)
        .map_err(|_| CryptoError::Hkdf)?;
    Ok(SecretBytes::from(kek))
}

/// Wrap (encrypt) the DEK with the KEK using XChaCha20-Poly1305.
///
/// - `wrap_nonce` must be unique per KEK.
/// - `aad` should be the full vault header bytes (v1), to bind the wrapped DEK
///   to the header parameters.
pub fn wrap_dek(
    kek: &SecretBytes,
    wrap_nonce: &[u8; XCHACHA_NONCE_LEN],
    aad: &[u8],
    dek: &SecretBytes,
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(kek.expose_secret()).map_err(|_| CryptoError::Aead)?;
    cipher
        .encrypt(
            XNonce::from_slice(wrap_nonce),
            Payload {
                msg: dek.expose_secret(),
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

/// Unwrap (decrypt) the DEK with the KEK using XChaCha20-Poly1305.
///
/// Returns an error if authentication fails (tamper detected, wrong key, or AAD mismatch).
pub fn unwrap_dek(
    kek: &SecretBytes,
    wrap_nonce: &[u8; XCHACHA_NONCE_LEN],
    aad: &[u8],
    wrapped_dek_ct: &[u8],
) -> Result<SecretBytes, CryptoError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(kek.expose_secret()).map_err(|_| CryptoError::Aead)?;
    let dek = cipher
        .decrypt(
            XNonce::from_slice(wrap_nonce),
            Payload {
                msg: wrapped_dek_ct,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)?;
    Ok(SecretBytes::from(dek))
}

/// Encrypt the vault payload using the DEK with XChaCha20-Poly1305.
///
/// - `payload_nonce` must be unique per DEK.
/// - `aad` should match the value used for decrypt (v1: full header bytes).
pub fn encrypt_payload(
    dek: &SecretBytes,
    payload_nonce: &[u8; XCHACHA_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(dek.expose_secret()).map_err(|_| CryptoError::Aead)?;
    cipher
        .encrypt(
            XNonce::from_slice(payload_nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

/// Decrypt the vault payload using the DEK with XChaCha20-Poly1305.
///
/// Plaintext is returned wrapped in `Zeroizing<Vec<u8>>` to reduce accidental retention.
pub fn decrypt_payload(
    dek: &SecretBytes,
    payload_nonce: &[u8; XCHACHA_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(dek.expose_secret()).map_err(|_| CryptoError::Aead)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(payload_nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)?;
    Ok(Zeroizing::new(plaintext))
}

/// Parse a 24-byte XChaCha nonce from an arbitrary slice.
///
/// This is mainly useful when decoding stored nonces from the vault header.
pub fn nonce_from_slice(bytes: &[u8]) -> Result<[u8; XCHACHA_NONCE_LEN], CryptoError> {
    let bytes: &[u8; XCHACHA_NONCE_LEN] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidNonceLength)?;
    Ok(*bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_dek_roundtrip() {
        let salt = random_bytes::<16>();
        let password = b"correct horse battery staple";
        let kdf_out = derive_kdf_out(password, &salt, KdfParams::for_tests()).unwrap();
        let kek = derive_kek(&kdf_out).unwrap();

        let dek = generate_dek();
        let nonce = random_bytes::<XCHACHA_NONCE_LEN>();
        let aad = b"header-bytes";

        let ct = wrap_dek(&kek, &nonce, aad, &dek).unwrap();
        let unwrapped = unwrap_dek(&kek, &nonce, aad, &ct).unwrap();
        assert_eq!(dek.expose_secret(), unwrapped.expose_secret());
    }

    #[test]
    fn unwrap_dek_fails_on_tamper() {
        let salt = random_bytes::<16>();
        let password = b"pw";
        let kdf_out = derive_kdf_out(password, &salt, KdfParams::for_tests()).unwrap();
        let kek = derive_kek(&kdf_out).unwrap();

        let dek = SecretBytes::from(vec![42u8; DEK_LEN]);
        let nonce = random_bytes::<XCHACHA_NONCE_LEN>();
        let aad = b"header";

        let mut ct = wrap_dek(&kek, &nonce, aad, &dek).unwrap();
        ct[0] ^= 0x01;

        let err = unwrap_dek(&kek, &nonce, aad, &ct).unwrap_err();
        assert!(matches!(err, CryptoError::Aead));
    }

    #[test]
    fn decrypt_payload_fails_on_aad_mismatch() {
        let dek = generate_dek();
        let nonce = random_bytes::<XCHACHA_NONCE_LEN>();

        let aad1 = b"header-v1";
        let aad2 = b"header-v2";
        let plaintext = b"{\"k\":\"v\"}";

        let ct = encrypt_payload(&dek, &nonce, aad1, plaintext).unwrap();
        let err = decrypt_payload(&dek, &nonce, aad2, &ct).unwrap_err();
        assert!(matches!(err, CryptoError::Aead));
    }

    #[test]
    fn encrypt_decrypt_payload_roundtrip() {
        let dek = generate_dek();
        let nonce = random_bytes::<XCHACHA_NONCE_LEN>();
        let aad = b"header";
        let plaintext = b"payload";

        let ct = encrypt_payload(&dek, &nonce, aad, plaintext).unwrap();
        let pt = decrypt_payload(&dek, &nonce, aad, &ct).unwrap();
        assert_eq!(plaintext, pt.as_slice());
    }
}
