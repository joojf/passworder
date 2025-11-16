use rand::Rng;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

#[cfg(any(debug_assertions, feature = "dev-seed"))]
use rand::{rngs::StdRng, SeedableRng};

const BUILTIN_WORDS: &[&str] = &[
    "anchor", "binary", "cobalt", "delta", "ember", "flux", "gamma", "harbor", "ion", "jolt",
    "keystone", "lumen", "matrix", "nebula", "oxide", "pixel", "quartz", "radial", "sonic",
    "tangent", "umbra", "vector", "warp", "xenon", "yonder", "zenith",
];

#[derive(Debug, Clone)]
pub struct PassphraseConfig {
    pub word_count: usize,
    pub separator: String,
    pub title_case: bool,
    pub wordlist: Option<PathBuf>,
}

#[derive(Debug)]
pub enum PassphraseError {
    WordCountZero,
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    EmptyWordList {
        path: Option<PathBuf>,
    },
}

impl fmt::Display for PassphraseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PassphraseError::WordCountZero => {
                write!(f, "word count must be greater than zero")
            }
            PassphraseError::Io { path, source } => {
                write!(
                    f,
                    "failed to read word list '{}': {}",
                    path.display(),
                    source
                )
            }
            PassphraseError::EmptyWordList { path } => match path {
                Some(path) => write!(
                    f,
                    "word list '{}' does not contain any usable words",
                    path.display()
                ),
                None => write!(f, "built-in word list is unexpectedly empty"),
            },
        }
    }
}

impl std::error::Error for PassphraseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PassphraseError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(any(debug_assertions, feature = "dev-seed"))]
pub fn generate(config: PassphraseConfig, seed: Option<u64>) -> Result<String, PassphraseError> {
    if let Some(seed_value) = seed {
        let mut rng = StdRng::seed_from_u64(seed_value);
        generate_with_rng(&mut rng, config)
    } else {
        let mut rng = OsRng;
        generate_with_rng(&mut rng, config)
    }
}

#[cfg(not(any(debug_assertions, feature = "dev-seed")))]
pub fn generate(config: PassphraseConfig, _seed: Option<u64>) -> Result<String, PassphraseError> {
    let mut rng = OsRng;
    generate_with_rng(&mut rng, config)
}

pub fn generate_with_rng<R: Rng + ?Sized>(
    rng: &mut R,
    config: PassphraseConfig,
) -> Result<String, PassphraseError> {
    if config.word_count == 0 {
        return Err(PassphraseError::WordCountZero);
    }

    let (words, source_path) = load_words(&config)?;
    let empty_list_path = source_path.clone();

    let mut chosen = Vec::with_capacity(config.word_count);
    for _ in 0..config.word_count {
        let word = words
            .choose(rng)
            .cloned()
            .ok_or_else(|| PassphraseError::EmptyWordList {
                path: empty_list_path.clone(),
            })?;

        let final_word = if config.title_case {
            title_case(&word)
        } else {
            word
        };

        chosen.push(final_word);
    }

    Ok(chosen.join(&config.separator))
}

fn load_words(
    config: &PassphraseConfig,
) -> Result<(Vec<String>, Option<PathBuf>), PassphraseError> {
    if let Some(path) = &config.wordlist {
        let path = path.clone();
        let file = File::open(&path).map_err(|source| PassphraseError::Io {
            path: path.clone(),
            source,
        })?;

        let mut reader = BufReader::new(file);
        let mut words = Vec::new();
        let mut line = String::new();

        loop {
            line.clear();
            let bytes_read = reader
                .read_line(&mut line)
                .map_err(|source| PassphraseError::Io {
                    path: path.clone(),
                    source,
                })?;

            if bytes_read == 0 {
                break;
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            words.push(trimmed.to_owned());
        }

        if words.is_empty() {
            return Err(PassphraseError::EmptyWordList {
                path: Some(path.clone()),
            });
        }

        Ok((words, Some(path)))
    } else {
        if BUILTIN_WORDS.is_empty() {
            return Err(PassphraseError::EmptyWordList { path: None });
        }

        Ok((
            BUILTIN_WORDS
                .iter()
                .map(|word| (*word).to_string())
                .collect(),
            None,
        ))
    }
}

fn title_case(word: &str) -> String {
    if word.is_empty() {
        return String::new();
    }

    let mut chars = word.chars();
    let mut result = String::new();

    if let Some(first) = chars.next() {
        result.extend(first.to_uppercase());
    }

    for ch in chars {
        result.extend(ch.to_lowercase());
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::mock::StepRng;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn base_config() -> PassphraseConfig {
        PassphraseConfig {
            word_count: 6,
            separator: "-".to_string(),
            title_case: false,
            wordlist: None,
        }
    }

    #[test]
    fn default_uses_builtin_list() {
        let config = base_config();
        let mut rng = StepRng::new(0, 1);
        let phrase = generate_with_rng(&mut rng, config).expect("passphrase to generate");

        let parts: Vec<&str> = phrase.split('-').collect();
        assert_eq!(parts.len(), 6);
        for part in parts {
            assert!(
                BUILTIN_WORDS.contains(&part),
                "word '{part}' not from built-in list"
            );
        }
    }

    #[test]
    fn title_case_transforms_words() {
        let mut plain_rng = StepRng::new(0, 1);
        let plain = generate_with_rng(&mut plain_rng, base_config()).expect("plain phrase");

        let mut titled_rng = StepRng::new(0, 1);
        let mut titled_config = base_config();
        titled_config.title_case = true;
        let titled = generate_with_rng(&mut titled_rng, titled_config).expect("titled phrase");

        for (plain_word, titled_word) in plain.split('-').zip(titled.split('-')) {
            assert_eq!(titled_word, title_case(plain_word));
        }
    }

    #[test]
    fn custom_wordlist_is_used() {
        let mut file = NamedTempFile::new().expect("temp file");
        writeln!(file, "alpha").unwrap();
        writeln!(file, "beta").unwrap();
        writeln!(file, "gamma").unwrap();
        file.flush().unwrap();

        let path = file.path().to_path_buf();
        let mut config = base_config();
        config.wordlist = Some(path);
        config.separator = " ".to_string();

        let mut rng = StepRng::new(0, 1);
        let phrase = generate_with_rng(&mut rng, config).expect("passphrase");

        for word in phrase.split(' ') {
            assert!(matches!(word, "alpha" | "beta" | "gamma"));
        }
    }

    #[test]
    fn empty_wordlist_file_is_error() {
        let file = NamedTempFile::new().expect("temp file");
        let path = file.path().to_path_buf();

        let mut config = base_config();
        config.wordlist = Some(path.clone());

        let mut rng = StepRng::new(0, 1);
        let err = generate_with_rng(&mut rng, config).expect_err("should fail");

        match err {
            PassphraseError::EmptyWordList { path: Some(p) } => assert_eq!(p, path),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn zero_word_count_is_error() {
        let mut config = base_config();
        config.word_count = 0;
        let mut rng = StepRng::new(0, 1);

        let err = generate_with_rng(&mut rng, config).expect_err("expect error");
        assert!(matches!(err, PassphraseError::WordCountZero));
    }

    #[test]
    fn custom_wordlist_trims_and_skips_blank_lines() {
        let mut file = NamedTempFile::new().expect("temp file");
        writeln!(file, "   alpha   ").unwrap();
        writeln!(file, "   ").unwrap();
        writeln!(file, "\tbeta").unwrap();
        writeln!(file, "gamma\t").unwrap();
        file.flush().unwrap();

        let path = file.path().to_path_buf();
        let mut config = base_config();
        config.wordlist = Some(path.clone());

        let (words, source) = load_words(&config).expect("wordlist to load");
        assert_eq!(source, Some(path));
        assert_eq!(
            words,
            vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()]
        );
    }
}
