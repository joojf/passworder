use assert_cmd::Command;
use std::path::Path;

/// Keeps each run away from a real vault on the developer's machine.
pub fn passworder(home: &Path) -> Command {
    let mut cmd = Command::cargo_bin("passworder").expect("binary exists");
    cmd.env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env_remove("PASSWORDER_VAULT");
    cmd
}
