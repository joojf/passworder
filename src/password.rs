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
}

#[derive(Debug)]
pub enum GenerationError {
    EmptyClass(&'static str),
    EmptyPool,
    LengthTooShort { required: usize, provided: usize },
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
    let char_sets = CharacterSets::new(config.allow_ambiguous)?;
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
                .ok_or(GenerationError::EmptyClass(class.name))?,
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
    classes: [CharClass; 4],
    pool: Vec<char>,
}

impl CharacterSets {
    fn new(allow_ambiguous: bool) -> Result<Self, GenerationError> {
        let classes = [
            CharClass::new(
                "uppercase",
                filtered_chars(('A'..='Z').collect(), allow_ambiguous),
            ),
            CharClass::new(
                "lowercase",
                filtered_chars(('a'..='z').collect(), allow_ambiguous),
            ),
            CharClass::new(
                "digits",
                filtered_chars(('0'..='9').collect(), allow_ambiguous),
            ),
            CharClass::new(
                "symbols",
                filtered_chars(SYMBOLS.chars().collect(), allow_ambiguous),
            ),
        ];

        for class in &classes {
            if class.chars.is_empty() {
                return Err(GenerationError::EmptyClass(class.name));
            }
        }

        let mut pool = Vec::new();
        for class in &classes {
            pool.extend(class.chars.iter().copied());
        }

        if pool.is_empty() {
            return Err(GenerationError::EmptyPool);
        }

        Ok(Self { classes, pool })
    }

    fn classes(&self) -> &[CharClass; 4] {
        &self.classes
    }

    fn pool(&self) -> &[char] {
        &self.pool
    }

    #[cfg(test)]
    fn uppercase(&self) -> &[char] {
        &self.classes[0].chars
    }

    #[cfg(test)]
    fn lowercase(&self) -> &[char] {
        &self.classes[1].chars
    }

    #[cfg(test)]
    fn digits(&self) -> &[char] {
        &self.classes[2].chars
    }

    #[cfg(test)]
    fn symbols(&self) -> &[char] {
        &self.classes[3].chars
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

    #[test]
    fn default_generation_meets_requirements() {
        let config = PasswordConfig {
            length: 20,
            allow_ambiguous: false,
        };
        let mut rng = StepRng::new(0, 1);
        let password = generate_with_rng(&mut rng, config).expect("password to generate");

        assert_eq!(password.len(), 20);

        let sets = CharacterSets::new(false).expect("character sets");

        assert!(password.chars().any(|c| sets.uppercase().contains(&c)));
        assert!(password.chars().any(|c| sets.lowercase().contains(&c)));
        assert!(password.chars().any(|c| sets.digits().contains(&c)));
        assert!(password.chars().any(|c| sets.symbols().contains(&c)));

        for c in password.chars() {
            assert!(
                !AMBIGUOUS_CHARACTERS.contains(&c),
                "password contains ambiguous character {c}"
            );
        }
    }

    #[test]
    fn allows_configuring_length() {
        let config = PasswordConfig {
            length: 32,
            allow_ambiguous: false,
        };
        let mut rng = StepRng::new(0, 1);
        let password = generate_with_rng(&mut rng, config).expect("password to generate");

        assert_eq!(password.len(), 32);
    }

    #[test]
    fn rejects_insufficient_length() {
        let config = PasswordConfig {
            length: 3,
            allow_ambiguous: false,
        };
        let mut rng = StepRng::new(0, 1);
        let error = generate_with_rng(&mut rng, config).expect_err("length too short");

        match error {
            GenerationError::LengthTooShort { required, provided } => {
                assert_eq!(required, 4);
                assert_eq!(provided, 3);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn ambiguous_characters_present_when_allowed() {
        let sets = CharacterSets::new(true).expect("character sets");
        for ch in AMBIGUOUS_CHARACTERS {
            assert!(
                sets.pool().contains(ch),
                "expected ambiguous character {ch} in pool"
            );
        }
    }
}
