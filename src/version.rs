#[cfg(all(
    not(feature = "clipboard"),
    not(feature = "strength"),
    not(feature = "dev-seed")
))]
pub const SHORT: &str = env!("CARGO_PKG_VERSION");

#[cfg(all(feature = "clipboard", not(feature = "strength"), not(feature = "dev-seed")))]
pub const SHORT: &str = concat!(env!("CARGO_PKG_VERSION"), " (features: clipboard)");

#[cfg(all(not(feature = "clipboard"), feature = "strength", not(feature = "dev-seed")))]
pub const SHORT: &str = concat!(env!("CARGO_PKG_VERSION"), " (features: strength)");

#[cfg(all(not(feature = "clipboard"), not(feature = "strength"), feature = "dev-seed"))]
pub const SHORT: &str = concat!(env!("CARGO_PKG_VERSION"), " (features: dev-seed)");

#[cfg(all(feature = "clipboard", feature = "strength", not(feature = "dev-seed")))]
pub const SHORT: &str = concat!(env!("CARGO_PKG_VERSION"), " (features: clipboard,strength)");

#[cfg(all(feature = "clipboard", not(feature = "strength"), feature = "dev-seed"))]
pub const SHORT: &str = concat!(env!("CARGO_PKG_VERSION"), " (features: clipboard,dev-seed)");

#[cfg(all(not(feature = "clipboard"), feature = "strength", feature = "dev-seed"))]
pub const SHORT: &str = concat!(env!("CARGO_PKG_VERSION"), " (features: strength,dev-seed)");

#[cfg(all(feature = "clipboard", feature = "strength", feature = "dev-seed"))]
pub const SHORT: &str = concat!(env!("CARGO_PKG_VERSION"), " (features: clipboard,strength,dev-seed)");

pub const LONG: &str = SHORT;
