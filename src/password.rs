use rand::Rng;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use std::fmt;

pub const AMBIGUOUS_CHARACTERS: &[char] = &['0', 'O', 'o', '1', 'l', 'I', '|'];

const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}<>?/\\|~";

#[derive(Debug, Clone, Copy)]
pub struct PasswordConfig {
    pub length: usize,
    pub allow_ambiguous: bool,
    pub include_lowercase: bool,
    pub include_uppercase: bool,
    pub include_digits: bool,
    pub include_symbols: bool,
}

#[derive(Debug)]
pub enum GenerationError {
    EmptyClass(&'static str),
    EmptyPool,
    LengthTooShort { required: usize, provided: usize },
    NoClassesEnabled,
}

impl fmt::Display for GenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenerationError::EmptyClass(class) => {
                write!(
                    f,
                    "character class '{class}' is empty; unable to generate password"
                )
            }
            GenerationError::EmptyPool => write!(f, "combined character pool is empty"),
            GenerationError::LengthTooShort { required, provided } => write!(
                f,
                "password length {provided} is too short; need at least {required} to cover all classes"
            ),
            GenerationError::NoClassesEnabled => {
                write!(f, "at least one character class must be enabled")
            }
        }
    }
}

impl std::error::Error for GenerationError {}

pub fn generate(config: PasswordConfig) -> Result<String, GenerationError> {
    let mut rng = OsRng;
    generate_with_rng(&mut rng, config)
}

pub fn generate_with_rng<R: Rng + ?Sized>(
    rng: &mut R,
    config: PasswordConfig,
) -> Result<String, GenerationError> {
    let char_sets = CharacterSets::new(&config)?;
    let classes = char_sets.classes();

    if config.length < classes.len() {
        return Err(GenerationError::LengthTooShort {
            required: classes.len(),
            provided: config.length,
        });
    }

    let mut password = Vec::with_capacity(config.length);

    for class in classes {
        password.push(
            class
                .sample(rng)
                .ok_or(GenerationError::EmptyClass(class.name()))?,
        );
    }

    let pool = char_sets.pool();

    for _ in password.len()..config.length {
        password.push(
            pool.choose(rng)
                .copied()
                .ok_or(GenerationError::EmptyPool)?,
        );
    }

    password.shuffle(rng);

    Ok(password.into_iter().collect())
}

struct CharacterSets {
    classes: Vec<CharClass>,
    pool: Vec<char>,
}

impl CharacterSets {
    fn new(config: &PasswordConfig) -> Result<Self, GenerationError> {
        let mut classes = Vec::new();

        if config.include_uppercase {
            let chars = filtered_chars(('A'..='Z').collect(), config.allow_ambiguous);
            if chars.is_empty() {
                return Err(GenerationError::EmptyClass("uppercase"));
            }
            classes.push(CharClass::new("uppercase", chars));
        }

        if config.include_lowercase {
            let chars = filtered_chars(('a'..='z').collect(), config.allow_ambiguous);
            if chars.is_empty() {
                return Err(GenerationError::EmptyClass("lowercase"));
            }
            classes.push(CharClass::new("lowercase", chars));
        }

        if config.include_digits {
            let chars = filtered_chars(('0'..='9').collect(), config.allow_ambiguous);
            if chars.is_empty() {
                return Err(GenerationError::EmptyClass("digits"));
            }
            classes.push(CharClass::new("digits", chars));
        }

        if config.include_symbols {
            let chars = filtered_chars(SYMBOLS.chars().collect(), config.allow_ambiguous);
            if chars.is_empty() {
                return Err(GenerationError::EmptyClass("symbols"));
            }
            classes.push(CharClass::new("symbols", chars));
        }

        if classes.is_empty() {
            return Err(GenerationError::NoClassesEnabled);
        }

        let mut pool = Vec::new();
        for class in &classes {
            pool.extend(class.chars().iter().copied());
        }

        if pool.is_empty() {
            return Err(GenerationError::EmptyPool);
        }

        Ok(Self { classes, pool })
    }

    fn classes(&self) -> &[CharClass] {
        &self.classes
    }

    fn pool(&self) -> &[char] {
        &self.pool
    }
}

struct CharClass {
    name: &'static str,
    chars: Vec<char>,
}

impl CharClass {
    fn new(name: &'static str, chars: Vec<char>) -> Self {
        Self { name, chars }
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn chars(&self) -> &[char] {
        &self.chars
    }

    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Option<char> {
        self.chars.choose(rng).copied()
    }
}

fn filtered_chars(chars: Vec<char>, allow_ambiguous: bool) -> Vec<char> {
    if allow_ambiguous {
        chars
    } else {
        chars
            .into_iter()
            .filter(|c| !AMBIGUOUS_CHARACTERS.contains(c))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::mock::StepRng;

    fn base_config() -> PasswordConfig {
        PasswordConfig {
            length: 20,
            allow_ambiguous: false,
            include_lowercase: true,
            include_uppercase: true,
            include_digits: true,
            include_symbols: true,
        }
    }

    fn class_chars<'a>(sets: &'a CharacterSets, name: &str) -> &'a [char] {
        sets.classes()
            .iter()
            .find(|class| class.name() == name)
            .map(|class| class.chars())
            .expect("class to exist")
    }

    #[test]
    fn default_generation_meets_requirements() {
        let config = base_config();
        let mut rng = StepRng::new(0, 1);
        let password = generate_with_rng(&mut rng, config).expect("password to generate");

        assert_eq!(password.len(), 20);

        let sets = CharacterSets::new(&config).expect("character sets");

        assert!(
            password
                .chars()
                .any(|c| class_chars(&sets, "uppercase").contains(&c))
        );
        assert!(
            password
                .chars()
                .any(|c| class_chars(&sets, "lowercase").contains(&c))
        );
        assert!(
            password
                .chars()
                .any(|c| class_chars(&sets, "digits").contains(&c))
        );
        assert!(
            password
                .chars()
                .any(|c| class_chars(&sets, "symbols").contains(&c))
        );

        for c in password.chars() {
            assert!(
                !AMBIGUOUS_CHARACTERS.contains(&c),
                "password contains ambiguous character {c}"
            );
        }
    }

    #[test]
    fn allows_configuring_length() {
        let mut config = base_config();
        config.length = 32;
        let mut rng = StepRng::new(0, 1);
        let password = generate_with_rng(&mut rng, config).expect("password to generate");

        assert_eq!(password.len(), 32);
    }

    #[test]
    fn rejects_insufficient_length() {
        let mut config = base_config();
        config.length = 3;
        let mut rng = StepRng::new(0, 1);
        let error = generate_with_rng(&mut rng, config).expect_err("length too short");
        let expected_required = CharacterSets::new(&base_config())
            .expect("default classes")
            .classes()
            .len();

        match error {
            GenerationError::LengthTooShort { required, provided } => {
                assert_eq!(required, expected_required);
                assert_eq!(provided, 3);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn ambiguous_characters_present_when_allowed() {
        let mut config = base_config();
        config.allow_ambiguous = true;
        let sets = CharacterSets::new(&config).expect("character sets");
        for ch in AMBIGUOUS_CHARACTERS {
            assert!(
                sets.pool().contains(ch),
                "expected ambiguous character {ch} in pool"
            );
        }
    }

    #[test]
    fn omits_lowercase_when_disabled() {
        let mut config = base_config();
        config.include_lowercase = false;
        let mut rng = StepRng::new(0, 1);
        let password = generate_with_rng(&mut rng, config).expect("password to generate");

        let lowercase_chars = filtered_chars(('a'..='z').collect(), config.allow_ambiguous);
        assert!(password.chars().all(|c| !lowercase_chars.contains(&c)));
    }

    #[test]
    fn omits_uppercase_when_disabled() {
        let mut config = base_config();
        config.include_uppercase = false;
        let mut rng = StepRng::new(0, 1);
        let password = generate_with_rng(&mut rng, config).expect("password to generate");

        let uppercase_chars = filtered_chars(('A'..='Z').collect(), config.allow_ambiguous);
        assert!(password.chars().all(|c| !uppercase_chars.contains(&c)));
    }

    #[test]
    fn omits_digits_when_disabled() {
        let mut config = base_config();
        config.include_digits = false;
        let mut rng = StepRng::new(0, 1);
        let password = generate_with_rng(&mut rng, config).expect("password to generate");

        let digit_chars = filtered_chars(('0'..='9').collect(), config.allow_ambiguous);
        assert!(password.chars().all(|c| !digit_chars.contains(&c)));
    }

    #[test]
    fn omits_symbols_when_disabled() {
        let mut config = base_config();
        config.include_symbols = false;
        let mut rng = StepRng::new(0, 1);
        let password = generate_with_rng(&mut rng, config).expect("password to generate");

        let symbol_chars = filtered_chars(SYMBOLS.chars().collect(), config.allow_ambiguous);
        assert!(password.chars().all(|c| !symbol_chars.contains(&c)));
    }

    #[test]
    fn errors_when_all_classes_disabled() {
        let mut config = base_config();
        config.include_lowercase = false;
        config.include_uppercase = false;
        config.include_digits = false;
        config.include_symbols = false;
        let mut rng = StepRng::new(0, 1);
        let error = generate_with_rng(&mut rng, config).expect_err("should fail");

        match error {
            GenerationError::NoClassesEnabled => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
