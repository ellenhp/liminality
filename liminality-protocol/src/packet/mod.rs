use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use rand::Rng;

use crate::{
    constants::{BLIZZARD_MESSAGE_TYPE_UNICAST, BLIZZARD_PROTOCOL_VERSION, MTU},
    error::BlizzardError,
};

use self::message::Message;

/// Defines the types associated with a message packet.
pub mod message;
/// Defines the types associated with a message payload.
pub mod payload;

/// A packet of data that can be sent over the wire.
pub enum Packet {
    /// A unicast message.
    Message(message::Message),
}

/// Attempts to parse a blizzard packet from a given slice.
pub fn try_parse_packet(packet: &[u8]) -> Result<Packet, BlizzardError> {
    if packet.len() < 2 {
        return Err(BlizzardError::MalformedPacket {
            message: "Packet too short. Must have at least a version and a packet type."
                .to_string(),
        });
    }
    if packet.len() > MTU {
        return Err(BlizzardError::MalformedPacket {
            message: "Packet too long.".to_string(),
        });
    }
    let version = packet[0];
    let packet_type = packet[1];
    if version != BLIZZARD_PROTOCOL_VERSION {
        return Err(BlizzardError::InvalidProtocolVersion { version });
    }
    if packet_type == BLIZZARD_MESSAGE_TYPE_UNICAST {
        Ok(Packet::Message(Message::try_from_slice(packet)?))
    } else {
        Err(BlizzardError::InvalidPacketType { packet_type })
    }
}

/// Message IDs in blizzard are a tuple (scalar, point) where the point is the session point multiplied by the scalar.
/// This invariant allows relays to multiply both the scalar and the point by a random scalar to obfuscate the message ID.
pub struct MessageId {
    raw: [u8; 64],
}

impl MessageId {
    /// Creates a new message ID from a scalar and a point.
    fn from_scalar_and_point(scalar: Scalar, point: RistrettoPoint) -> Self {
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(&scalar.as_bytes()[..]);
        raw[32..].copy_from_slice(&point.compress().to_bytes()[..]);
        Self { raw }
    }

    /// Generates a random message ID from a base point.
    pub fn random_from_base<RngType: Rng>(base: RistrettoPoint, rng: &mut RngType) -> Self {
        let (scalar, point) = {
            let rand_scalar_bytes: [u8; 32] = rng.gen();
            let scalar = curve25519_dalek::Scalar::from_bytes_mod_order(rand_scalar_bytes);
            let point = base * scalar;
            (scalar, point)
        };
        Self::from_scalar_and_point(scalar, point)
    }

    /// Rolls the message ID by multiplying it by a random scalar. This obfuscates the message ID, but does not change its ability
    /// to be verified by the recipient.
    pub fn roll<RngType: Rng>(&self, rng: &mut RngType) -> Result<MessageId, BlizzardError> {
        let rand_scalar_bytes: [u8; 32] = rng.gen();
        let scalar = curve25519_dalek::Scalar::from_bytes_mod_order(rand_scalar_bytes);
        let point = self.point()? * scalar;
        Ok(Self::from_scalar_and_point(scalar * self.scalar(), point))
    }

    /// Returns the point portion of the message ID.
    pub fn point(&self) -> Result<RistrettoPoint, BlizzardError> {
        let compressed = CompressedRistretto::from_slice(&self.raw[32..]).map_err(|_| {
            BlizzardError::CryptoError {
                message: "Unable to deserialize point.".to_string(),
            }
        });
        compressed?.decompress().map_or(
            Err(BlizzardError::CryptoError {
                message: "Unable to decompress ristretto point.".to_string(),
            }),
            |point| Ok(point),
        )
    }

    /// Returns the scalar portion of the message ID.
    pub fn scalar(&self) -> Scalar {
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&self.raw[..32]);
        Scalar::from_bytes_mod_order(scalar_bytes)
    }
}
