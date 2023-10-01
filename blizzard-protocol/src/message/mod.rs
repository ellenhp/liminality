use alloc::string::ToString;

use crate::{
    constants::{
        BLIZZARD_MESSAGE_TYPE_ANNOUNCE, BLIZZARD_MESSAGE_TYPE_UNICAST, BLIZZARD_PROTOCOL_VERSION,
        MTU,
    },
    error::BlizzardError,
};

use self::{announce::Announce, unicast::Message};

/// Announce packets.
pub mod announce;
/// Plaintext message payloads.
pub mod payload;
/// Unicast messages across the blizzard network.
pub mod unicast;

/// A blizzard packet that can be sent over the wire.
pub enum WirePacket {
    /// An announce packet.
    Announce(announce::Announce),
    /// A unicast packet.
    Unicast(unicast::Message),
}

/// Attempts to parse a blizzard packet from a slice of bytes.
/// Returns [`BlizzardError::MalformedPacket`] if the packet is too short or too long.
/// Returns [`BlizzardError::InvalidProtocolVersion`] if the packet has an unsupported protocol version.
/// Returns [`BlizzardError::InvalidPacketType`] if the packet has an unknown packet type.
pub fn try_parse_packet(packet: &[u8]) -> Result<WirePacket, BlizzardError> {
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
    if packet_type == BLIZZARD_MESSAGE_TYPE_ANNOUNCE {
        Ok(WirePacket::Announce(Announce::try_from_slice(packet)?))
    } else if packet_type == BLIZZARD_MESSAGE_TYPE_UNICAST {
        Ok(WirePacket::Unicast(Message::try_from_slice(packet)?))
    } else {
        Err(BlizzardError::InvalidPacketType { packet_type })
    }
}
