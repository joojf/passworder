macro_rules! short_version {
    ($suffix:literal) => {
        pub const SHORT: &str = concat!(env!("CARGO_PKG_VERSION"), $suffix);
    };
}

#[cfg(all(feature = "clipboard", not(feature = "strength")))]
short_version!(" (features: clipboard)");

#[cfg(all(not(feature = "clipboard"), feature = "strength"))]
short_version!(" (features: strength)");

#[cfg(all(not(feature = "clipboard"), not(feature = "strength")))]
short_version!("");

#[cfg(all(feature = "clipboard", feature = "strength"))]
short_version!(" (features: clipboard,strength)");

pub const LONG: &str = SHORT;
