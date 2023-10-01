use snafu::Snafu;

use crate::{identity::Address, types::String};

/// Common error type for the `blizzard` crate.
#[derive(Debug, Snafu)]
pub enum BlizzardError {
    /// An error occurred in the `snow` crate. This may occur during the handshake phase if handshake messages are generated while it wasn't the client's turn.
    #[snafu(display("Internal `snow` error: {}", err))]
    SnowError {
        /// The underlying `snow` error.
        err: snow::Error,
    },
    /// An error occurred while performing a cryptographic operation because the peer's public key was not known or did not match the expected value.
    #[snafu(display("Authenticity error"))]
    AuthenticityError,
    /// Attempted to parse a malformed packet.
    #[snafu(display("Malformed packet: {}", message))]
    MalformedPacket {
        /// An error message describing why the packet is malformed.
        message: String,
    },
    /// Attempted to parse a packet generated by an incompatible protocol version.
    #[snafu(display("Invalid protocol version: {}", version))]
    InvalidProtocolVersion {
        /// The detected protocol version.
        version: u8,
    },
    /// Attempted to parse a packet with an unknown packet type.
    #[snafu(display("Invalid packet type: {}", packet_type))]
    InvalidPacketType {
        /// The detected packet type.
        packet_type: u8,
    },
    /// Attempted to copy from a slice of the incorrect length. This indicates an error while performing a fixed-size copy.
    /// This error is used for some internal calls so it may indicate either a bug in blizzard or incorrect usage.
    #[snafu(display("Slice incorrect length. Expected {} but found {}", expected, actual))]
    SliceIncorrectLength {
        /// The expected length of the slice.
        expected: usize,
        /// The actual length of the slice.
        actual: usize,
    },
    /// Failed to create a binary fuse filter during the construction of an announce packet.
    /// The creation of a binary fuse filter is unfortunately not deterministic, so downstream applications should handle this error.
    #[snafu(display("BinaryFuse filter construction failed: {}", message))]
    BinaryFuseError {
        /// Human-readable message describing the error.
        message: String,
    },
    /// Failed to serialize or deserialize a struct. This is likely not a usage issue, unless the downstream application's data store was corrupted.
    #[snafu(display("(De)serializaiton failed: {}", message))]
    SerializationError {
        /// Human-readable message describing what exactly failed to deserialize.
        message: String,
    },
    /// Attempted to parse a packet with an invalid address. This is thrown when you try to decrypt a message intended for a different identity.
    /// This is entirely recoverable and should be handled by the application.
    #[snafu(display("Invalid address: {:?}", address))]
    InvalidAddress {
        /// The destination address that was detected.
        address: Address,
    },
    /// An error occurred while performing a HKDF operation. This is not a usage issue and indicates a bug inside of blizzard.
    #[snafu(display("Error in HKDF: {}", message))]
    HkdfError {
        /// Human-readable message describing the error.
        message: String,
    },
    /// Buffer size mismatch. This is an internal error that should never occur and does not indicate incorrect usage.
    #[snafu(display(
        "Incompatible buffer size. Expected at least {} but found {}",
        expected,
        actual
    ))]
    InternalBufferSizeTooSmall {
        /// The minimum buffer size for the operation attempted.
        expected: usize,
        /// The actual buffer size.
        actual: usize,
    },
    /// Attempted to copy a too-large slice into a [`crate::message::payload::Payload`].
    #[snafu(display("Slice too large. Expected at most {} but found {}", expected, actual))]
    PayloadTooLarge {
        /// The maximum size of the source slice.
        expected: usize,
        /// The actual size of the source slice.
        actual: usize,
    },
}
