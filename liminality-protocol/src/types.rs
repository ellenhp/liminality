#[cfg(not(feature = "std"))]
pub type String = alloc::string::String;
#[cfg(feature = "std")]
pub type String = std::string::String;

#[cfg(not(feature = "std"))]
pub type Vec<T> = alloc::vec::Vec<T>;
#[cfg(feature = "std")]
pub type Vec<T> = std::vec::Vec<T>;
