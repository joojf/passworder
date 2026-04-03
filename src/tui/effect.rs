#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    GeneratePassword,
    CopyGeneratedPassword,
    GeneratePassphrase,
    CopyGeneratedPassphrase,
}
