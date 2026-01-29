use crate::cli::{TokenBytesArgs, TokenCommands};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use std::fmt;
use uuid::Uuid;

#[cfg(any(debug_assertions, feature = "dev-seed"))]
use rand::{SeedableRng, rngs::StdRng};

#[derive(Debug)]
pub enum TokenError {
    ByteLengthZero,
    SampleBytesFailed,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::ByteLengthZero => write!(f, "byte length must be greater than zero"),
            TokenError::SampleBytesFailed => write!(f, "failed to sample random bytes"),
        }
    }
}

impl std::error::Error for TokenError {}

pub fn handle(command: TokenCommands, seed: Option<u64>) -> Result<String, TokenError> {
    match command {
        TokenCommands::Hex(args) => hex(args, seed),
        TokenCommands::B64(args) => b64(args, seed),
        TokenCommands::Uuid => uuid(),
    }
}

fn hex(args: TokenBytesArgs, seed: Option<u64>) -> Result<String, TokenError> {
    if args.bytes == 0 {
        return Err(TokenError::ByteLengthZero);
    }

    let mut bytes = vec![0u8; args.bytes];
    fill_random(&mut bytes, seed)?;

    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn b64(args: TokenBytesArgs, seed: Option<u64>) -> Result<String, TokenError> {
    if args.bytes == 0 {
        return Err(TokenError::ByteLengthZero);
    }

    let mut bytes = vec![0u8; args.bytes];
    fill_random(&mut bytes, seed)?;

    Ok(URL_SAFE_NO_PAD.encode(&bytes))
}

fn uuid() -> Result<String, TokenError> {
    let id = Uuid::new_v4();
    Ok(id.to_string())
}

#[cfg(any(debug_assertions, feature = "dev-seed"))]
fn fill_random(bytes: &mut [u8], seed: Option<u64>) -> Result<(), TokenError> {
    if let Some(seed_value) = seed {
        let mut rng = StdRng::seed_from_u64(seed_value);
        rng.try_fill_bytes(bytes)
            .map_err(|_| TokenError::SampleBytesFailed)
    } else {
        OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| TokenError::SampleBytesFailed)
    }
}

#[cfg(not(any(debug_assertions, feature = "dev-seed")))]
fn fill_random(bytes: &mut [u8], _seed: Option<u64>) -> Result<(), TokenError> {
    OsRng
        .try_fill_bytes(bytes)
        .map_err(|_| TokenError::SampleBytesFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_length_matches() {
        let args = TokenBytesArgs { bytes: 16 };
        let token = hex(args, None).expect("hex token");
        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn b64_length_matches() {
        for bytes in [1usize, 8, 16, 32] {
            let args = TokenBytesArgs { bytes };
            let token = b64(args, None).expect("b64 token");
            assert!(!token.contains('='));
            let decoded = URL_SAFE_NO_PAD
                .decode(token.as_bytes())
                .expect("valid base64");
            assert_eq!(decoded.len(), bytes);
        }
    }

    #[test]
    fn uuid_is_v4() {
        let token = uuid().expect("uuid token");
        let parsed = Uuid::parse_str(&token).expect("parse uuid");
        assert_eq!(parsed.get_version_num(), 4);
    }

    #[test]
    fn zero_bytes_is_error() {
        for generator in [hex as fn(TokenBytesArgs, Option<u64>) -> _, b64] {
            let err = generator(TokenBytesArgs { bytes: 0 }, None).expect_err("should fail");
            assert!(matches!(err, TokenError::ByteLengthZero));
        }
    }
}
