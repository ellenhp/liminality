#[cfg(not(feature = "std"))]
pub type String = alloc::string::String;
#[cfg(feature = "std")]
pub type String = std::string::String;
