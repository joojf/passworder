#[cfg(all(not(feature = "strength"), not(feature = "dev-seed")))]
pub const SHORT: &str = env!("CARGO_PKG_VERSION");

#[cfg(all(feature = "strength", not(feature = "dev-seed")))]
pub const SHORT: &str = concat!(env!("CARGO_PKG_VERSION"), " (features: strength)");

#[cfg(all(not(feature = "strength"), feature = "dev-seed"))]
pub const SHORT: &str = concat!(env!("CARGO_PKG_VERSION"), " (features: dev-seed)");

#[cfg(all(feature = "strength", feature = "dev-seed"))]
pub const SHORT: &str = concat!(env!("CARGO_PKG_VERSION"), " (features: strength,dev-seed)");

pub const LONG: &str = SHORT;
