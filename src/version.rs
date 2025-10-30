#[cfg(all(feature = "clipboard", feature = "strength"))]
const FEATURES_SUFFIX: &str = " (features: clipboard,strength)";

#[cfg(all(feature = "clipboard", not(feature = "strength")))]
const FEATURES_SUFFIX: &str = " (features: clipboard)";

#[cfg(all(not(feature = "clipboard"), feature = "strength"))]
const FEATURES_SUFFIX: &str = " (features: strength)";

#[cfg(all(not(feature = "clipboard"), not(feature = "strength")))]
const FEATURES_SUFFIX: &str = "";

pub const SHORT: &str = concat!(env!("CARGO_PKG_VERSION"), FEATURES_SUFFIX);
pub const LONG: &str = SHORT;
