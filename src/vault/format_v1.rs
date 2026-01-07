use crate::vault::crypto;
use thiserror::Error;

pub const MAGIC: &[u8; 8] = b"PWDERVLT";
pub const VERSION_V1: u16 = 1;
pub const FIXED_HEADER_LEN: usize = 8 + 2 + 4;

const TLV_ARGON2_PARAMS: u16 = 0x0001;
const TLV_KDF_SALT: u16 = 0x0002;
const TLV_KDF_ALG: u16 = 0x0003;
const TLV_AEAD_ALG: u16 = 0x0010;
const TLV_HKDF_ALG: u16 = 0x0020;
const TLV_WRAPPED_DEK: u16 = 0x0100;
const TLV_PAYLOAD_NONCE: u16 = 0x0200;

const KDF_ALG_ARGON2ID: &[u8] = b"argon2id";
const AEAD_ALG_XCHACHA20POLY1305: &[u8] = b"xchacha20poly1305";
const HKDF_ALG_SHA256: &[u8] = b"hkdf-sha256";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedHeader {
    pub version: u16,
    pub header_len: u32,
}

#[derive(Debug, Error)]
pub enum VaultFormatError {
    #[error("vault file too small")]
    TooSmall,

    #[error("invalid magic")]
    InvalidMagic,

    #[error("unsupported vault version {0}")]
    UnsupportedVersion(u16),

    #[error("invalid header length")]
    InvalidHeaderLen,
}

pub fn parse_fixed_header(bytes: &[u8]) -> Result<FixedHeader, VaultFormatError> {
    if bytes.len() < FIXED_HEADER_LEN {
        return Err(VaultFormatError::TooSmall);
    }

    if &bytes[0..8] != MAGIC {
        return Err(VaultFormatError::InvalidMagic);
    }

    let version = u16::from_le_bytes(bytes[8..10].try_into().expect("slice is 2 bytes"));
    if version != VERSION_V1 {
        return Err(VaultFormatError::UnsupportedVersion(version));
    }

    let header_len = u32::from_le_bytes(bytes[10..14].try_into().expect("slice is 4 bytes"));
    if (header_len as usize) < FIXED_HEADER_LEN || (header_len as usize) > bytes.len() {
        return Err(VaultFormatError::InvalidHeaderLen);
    }

    Ok(FixedHeader { version, header_len })
}

pub struct VaultHeaderV1 {
    pub kdf_params: crypto::KdfParams,
    pub kdf_salt: [u8; 16],
    pub wrap_nonce: [u8; crypto::XCHACHA_NONCE_LEN],
    pub wrapped_dek: Vec<u8>,
    pub payload_nonce: [u8; crypto::XCHACHA_NONCE_LEN],
}

pub fn encode_header_v1(h: &VaultHeaderV1) -> Vec<u8> {
    let mut tlvs = Vec::new();

    let mut params = Vec::with_capacity(16);
    params.extend_from_slice(&h.kdf_params.memory_kib.to_le_bytes());
    params.extend_from_slice(&h.kdf_params.iterations.to_le_bytes());
    params.extend_from_slice(&h.kdf_params.parallelism.to_le_bytes());
    params.extend_from_slice(&(crypto::KDF_OUT_LEN as u32).to_le_bytes());
    push_tlv(&mut tlvs, TLV_ARGON2_PARAMS, &params);

    push_tlv(&mut tlvs, TLV_KDF_SALT, &h.kdf_salt);
    push_tlv(&mut tlvs, TLV_KDF_ALG, KDF_ALG_ARGON2ID);
    push_tlv(&mut tlvs, TLV_AEAD_ALG, AEAD_ALG_XCHACHA20POLY1305);
    push_tlv(&mut tlvs, TLV_HKDF_ALG, HKDF_ALG_SHA256);

    let mut wrapped = Vec::with_capacity(crypto::XCHACHA_NONCE_LEN + 4 + h.wrapped_dek.len());
    wrapped.extend_from_slice(&h.wrap_nonce);
    wrapped.extend_from_slice(&(h.wrapped_dek.len() as u32).to_le_bytes());
    wrapped.extend_from_slice(&h.wrapped_dek);
    push_tlv(&mut tlvs, TLV_WRAPPED_DEK, &wrapped);

    push_tlv(&mut tlvs, TLV_PAYLOAD_NONCE, &h.payload_nonce);

    let header_len = (FIXED_HEADER_LEN + tlvs.len()) as u32;

    let mut out = Vec::with_capacity(header_len as usize);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION_V1.to_le_bytes());
    out.extend_from_slice(&header_len.to_le_bytes());
    out.extend_from_slice(&tlvs);
    out
}

fn push_tlv(buf: &mut Vec<u8>, typ: u16, value: &[u8]) {
    buf.extend_from_slice(&typ.to_le_bytes());
    buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buf.extend_from_slice(value);
}
