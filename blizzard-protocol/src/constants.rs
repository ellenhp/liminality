/// The noise handshake protocol used in blizzard.
/// The most important part here is the handshake pattern ("IK")
///
/// `I` means the initiator sends their public key `I`mmediately, K means the responder's public key is `K`nown to the initiator.
///
/// This allows for some amount of initiator anonymity (as opposed to the IX pattern) without introducing another round trip like the XX pattern might.
/// It's not as secure as the XX pattern, but for a DTN it's very important that we don't introduce extra round trips :)
///
/// See section 7 of the noise spec: https://noiseprotocol.org/noise.html#handshake-patterns
/// Especially section 7.7 for details on the security implications of selecting the IK pattern.
pub static PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// The HKDF salt that blizzard uses to derive an address from a public key.
pub static KDF_SALT: &[u8] = "_BLIZZARD_PROTOCOL_KDF_SALT_".as_bytes();

/// The maximum size of any blizzard message.
pub const MTU: usize = 242;

/// The length of a blizzard address in bytes.
pub const ADDRESS_LEN_BYTES: usize = 8;

/// The length of a blizzard HMAC in bytes.
pub const NOISE_HMAC_LENGTH_BYTES: usize = 16;

/// The current protocol version.
pub const BLIZZARD_PROTOCOL_VERSION: u8 = 0x01;

/// Indicates a unicast blizzard message.
pub const BLIZZARD_MESSAGE_TYPE_UNICAST: u8 = 0x00;

/// Indicates an announce blizzard message.
pub const BLIZZARD_MESSAGE_TYPE_ANNOUNCE: u8 = 0x01;
