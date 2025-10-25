use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::io::Read;

#[derive(Debug)]
pub enum EntropyError {
    Io(std::io::Error),
    InvalidUtf8,
    Serialization(serde_json::Error),
}

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EntropyError::Io(err) => write!(f, "failed to read input: {err}"),
            EntropyError::InvalidUtf8 => write!(f, "STDIN contains invalid UTF-8 data"),
            EntropyError::Serialization(err) => write!(f, "failed to serialize report: {err}"),
        }
    }
}

impl std::error::Error for EntropyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EntropyError::Io(err) => Some(err),
            EntropyError::Serialization(err) => Some(err),
            EntropyError::InvalidUtf8 => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EntropyConfig {
    pub input: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EntropyReport {
    length: usize,
    shannon_bits_estimate: f64,
}

pub fn analyze(config: EntropyConfig) -> Result<String, EntropyError> {
    let mut stdin = std::io::stdin().lock();
    analyze_with_reader(config, &mut stdin)
}

fn analyze_with_reader<R: Read>(
    config: EntropyConfig,
    reader: &mut R,
) -> Result<String, EntropyError> {
    let input = match config.input {
        Some(input) => input,
        None => read_from_reader(reader)?,
    };

    let length = input.chars().count();
    let shannon_bits = if length == 0 {
        0.0
    } else {
        calculate_shannon_bits(&input, length)
    };

    let estimate = round_to_precision(shannon_bits, 6);
    let estimate = if estimate == 0.0 { 0.0 } else { estimate };

    let report = EntropyReport {
        length,
        shannon_bits_estimate: estimate,
    };

    serde_json::to_string(&report).map_err(EntropyError::Serialization)
}

fn read_from_reader<R: Read>(reader: &mut R) -> Result<String, EntropyError> {
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).map_err(EntropyError::Io)?;
    String::from_utf8(buffer).map_err(|_| EntropyError::InvalidUtf8)
}

fn calculate_shannon_bits(input: &str, length: usize) -> f64 {
    let mut counts: HashMap<char, usize> = HashMap::new();
    for ch in input.chars() {
        *counts.entry(ch).or_insert(0) += 1;
    }

    let len = length as f64;
    let mut entropy = 0.0;
    for count in counts.values() {
        let probability = *count as f64 / len;
        entropy += probability * probability.log2();
    }

    -entropy * len
}

fn round_to_precision(value: f64, decimals: u32) -> f64 {
    let factor = 10_f64.powi(decimals as i32);
    (value * factor).round() / factor
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn analyze_with_input(input: Option<&str>) -> String {
        let config = EntropyConfig {
            input: input.map(|s| s.to_string()),
        };
        let mut cursor = Cursor::new(Vec::<u8>::new());
        analyze_with_reader(config, &mut cursor).expect("analysis to succeed")
    }

    #[test]
    fn empty_input_reports_zero() {
        let report = analyze_with_input(Some(""));
        let value: EntropyReport = serde_json::from_str(&report).unwrap();
        assert_eq!(value.length, 0);
        assert_eq!(value.shannon_bits_estimate, 0.0);
    }

    #[test]
    fn repeated_chars_have_zero_entropy() {
        let report = analyze_with_input(Some("aaaaaa"));
        let value: EntropyReport = serde_json::from_str(&report).unwrap();
        assert_eq!(value.length, 6);
        assert_eq!(value.shannon_bits_estimate, 0.0);
    }

    #[test]
    fn mixed_chars_calculate_entropy() {
        let report = analyze_with_input(Some("abcabc"));
        let value: EntropyReport = serde_json::from_str(&report).unwrap();
        assert_eq!(value.length, 6);
        // probabilities (a,b,c) = 1/3 each -> entropy per char = log2(3) ~= 1.58496
        // total bits = len * per = 6 * log2(3) ~= 9.509775
        assert!((value.shannon_bits_estimate - 9.509775).abs() < 1e-6);
    }

    #[test]
    fn stdin_invalid_utf8_errors() {
        let config = EntropyConfig { input: None };
        let mut reader = Cursor::new(vec![0xf0, 0x28, 0x8c, 0x28]); // invalid UTF-8
        let err = analyze_with_reader(config, &mut reader).unwrap_err();
        assert!(matches!(err, EntropyError::InvalidUtf8));
    }

    #[test]
    fn stdin_utf8_reads_successfully() {
        let config = EntropyConfig { input: None };
        let data = "hi".as_bytes().to_vec();
        let mut reader = Cursor::new(data);
        let result = analyze_with_reader(config, &mut reader).expect("analysis");
        let parsed: EntropyReport = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.length, 2);
    }
}
