use crate::{
    constants::{ADDRESS_LEN_BYTES, BLIZZARD_MESSAGE_TYPE_UNICAST, BLIZZARD_PROTOCOL_VERSION, MTU},
    error::BlizzardError,
    identity::Address,
};

/// A unicast blizzard message. This is the most common type of message in blizzard.
/// It may encapsulate a payload, or it may be empty. It may be part of an ongoing session, or a request to initiate a session.
/// It does not contain any plaintext information about the sender under any circumstances.
/// Creation and decryption of [`Message`] structs are handled by the [`crate::session::BlizzardSession`] and [`crate::session::BlizzardSessionHandshake`] types.
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

    /// Returns the destination [`Address`] of this message.
    pub fn destination_address(&self) -> Result<Address, BlizzardError> {
        self.raw[2..2 + ADDRESS_LEN_BYTES].try_into()
    }

    pub(crate) fn ciphertext_as_slice(&self) -> &[u8] {
        &self.raw[2 + ADDRESS_LEN_BYTES..self.len]
    }

    pub(crate) fn from_parts(
        destination_address: &Address,
        ciphertext: &[u8],
    ) -> Result<Self, BlizzardError> {
        let mut message = Self::new();
        if ciphertext.len() > MTU - ADDRESS_LEN_BYTES {
            return Err(BlizzardError::InternalBufferSizeTooSmall {
                expected: MTU - ADDRESS_LEN_BYTES,
                actual: ciphertext.len(),
            });
        }
        let address_raw: [u8; ADDRESS_LEN_BYTES] = (*destination_address).into();
        message.raw[0] = BLIZZARD_PROTOCOL_VERSION;
        message.raw[1] = BLIZZARD_MESSAGE_TYPE_UNICAST;
        message.raw[2..2 + ADDRESS_LEN_BYTES].copy_from_slice(&address_raw);
        message.raw[2 + ADDRESS_LEN_BYTES..2 + ADDRESS_LEN_BYTES + ciphertext.len()]
            .copy_from_slice(ciphertext);
        message.len = 2 + ADDRESS_LEN_BYTES + ciphertext.len();
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

#[cfg(test)]
mod test {
    use crate::constants::NOISE_HMAC_LENGTH_BYTES;

    use super::*;

    #[test]
    fn test_large_payload() -> Result<(), BlizzardError> {
        let ciphertext_payload = [0u8; MTU - NOISE_HMAC_LENGTH_BYTES];
        let result = Message::from_parts(&[0u8; ADDRESS_LEN_BYTES].into(), &ciphertext_payload);
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_recall_address() -> Result<(), BlizzardError> {
        let ciphertext_payload = [0u8; MTU - NOISE_HMAC_LENGTH_BYTES];
        let message = Message::from_parts(&[99u8; ADDRESS_LEN_BYTES].into(), &ciphertext_payload)?;
        assert_eq!(
            message.destination_address()?,
            [99u8; ADDRESS_LEN_BYTES].into()
        );
        Ok(())
    }

    #[test]
    fn test_recall_payload() -> Result<(), BlizzardError> {
        let ciphertext_payload = [99u8; MTU - NOISE_HMAC_LENGTH_BYTES];
        let message = Message::from_parts(&[0u8; ADDRESS_LEN_BYTES].into(), &ciphertext_payload)?;
        assert_eq!(message.ciphertext_as_slice(), &ciphertext_payload);
        Ok(())
    }
}
