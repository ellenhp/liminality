use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint};
use rand::Rng;

use crate::{
    constants::{MESSAGE_ID_LEN_BYTES, MTU},
    error::BlizzardError,
};

use super::MessageId;

/// A message packet. Contains a message ID, a count of copies of the message, and the ciphertext.
pub struct Message {
    raw: [u8; MTU],
    len: usize,
}

impl Message {
    pub(crate) fn new() -> Self {
        Self {
            raw: [0u8; MTU],
            len: 0,
        }
    }

    /// Returns the number of copies of this message that are conveyed in this packet.
    pub fn copies(&self) -> u8 {
        self.raw[1]
    }

    pub(crate) fn message_id(&self) -> Result<MessageId, BlizzardError> {
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&self.raw[2..2 + 32]);
        let scalar = curve25519_dalek::Scalar::from_bytes_mod_order(scalar_bytes);
        let point =
            CompressedRistretto::from_slice(&self.raw[2 + 32..2 + 32 + 32]).map_err(|_| {
                BlizzardError::CryptoError {
                    message: "Invalid point".to_string(),
                }
            })?;
        Ok(MessageId::from_scalar_and_point(
            scalar,
            point.decompress().ok_or(BlizzardError::CryptoError {
                message: "Invalid point".to_string(),
            })?,
        ))
    }

    pub(crate) fn ciphertext_as_slice(&self) -> &[u8] {
        &self.raw[2 + MESSAGE_ID_LEN_BYTES..self.len]
    }

    pub(crate) fn from_parts(
        message_id: &MessageId,
        ciphertext: &[u8],
    ) -> Result<Self, BlizzardError> {
        let mut message = Self::new();
        if ciphertext.len() > MTU - MESSAGE_ID_LEN_BYTES {
            return Err(BlizzardError::InternalBufferSizeTooSmall {
                expected: MTU - MESSAGE_ID_LEN_BYTES,
                actual: ciphertext.len(),
            });
        }
        let message_id_raw = message_id.raw.clone();
        message.raw[0] = 0b0001_0000;
        message.raw[1] = 100;
        message.raw[2..2 + MESSAGE_ID_LEN_BYTES].copy_from_slice(&message_id_raw);
        message.raw[2 + MESSAGE_ID_LEN_BYTES..2 + MESSAGE_ID_LEN_BYTES + ciphertext.len()]
            .copy_from_slice(ciphertext);
        message.len = 2 + MESSAGE_ID_LEN_BYTES + ciphertext.len();
        Ok(message)
    }

    pub(crate) fn try_from_slice(slice: &[u8]) -> Result<Self, BlizzardError> {
        if slice.len() > MTU {
            return Err(BlizzardError::PayloadTooLarge {
                expected: MTU,
                actual: slice.len(),
            });
        }

        let mut message = Self::new();
        message.raw[..slice.len()].copy_from_slice(slice);
        message.len = slice.len();
        Ok(message)
    }

    pub(crate) fn confirm_message_id(
        &self,
        session_point: &RistrettoPoint,
    ) -> Result<(), BlizzardError> {
        let message_id = self.message_id()?;
        let message_point = message_id.point()?;
        let message_scalar = message_id.scalar();
        let expected_message_point = session_point * message_scalar;
        if message_point == expected_message_point {
            return Ok(());
        } else {
            return Err(BlizzardError::MessageNotPartOfChannel);
        }
    }

    /// Rolls the message ID of this message, obfuscating it to everyone who doesn't know the session point it's based on.
    pub fn rolled<RngType: Rng>(&self, rng: &mut RngType) -> Result<Message, BlizzardError> {
        Self::from_parts(&self.message_id()?.roll(rng)?, self.ciphertext_as_slice())
    }
}

impl Default for Message {
    fn default() -> Self {
        Self::new()
    }
}

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        self.raw.as_slice()
    }
}

impl AsMut<[u8]> for Message {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.raw[..self.len]
    }
}
