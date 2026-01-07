pub mod crypto;
pub mod io;

mod format_v1;
mod ops;
mod prompt;

pub use ops::{vault_init_v1, vault_path, vault_status_v1, VaultError};
pub use prompt::{prompt_new_master_password, PromptError};
