use crate::{
    constants::{MTU, NOISE_HMAC_LENGTH_BYTES},
    error::BlizzardError,
};

/// The payload of a blizzard [`crate::message::Message`]. This is plaintext data and shouldn't be sent over the wire in this form under any circumstances.
pub struct Payload {
    raw: [u8; MTU - NOISE_HMAC_LENGTH_BYTES],
    len: usize,
}

impl Payload {
    /// Creates a new empty payload.
    pub fn new() -> Self {
        Self {
            raw: [0u8; MTU - NOISE_HMAC_LENGTH_BYTES],
            len: 0,
        }
    }

    /// Returns the maximum number of bytes that this payload can store.
    pub fn capacity(&self) -> usize {
        self.raw.len()
    }

    /// Returns a slice of the plaintext data in this payload.
    pub fn as_plaintext_slice(&self) -> &[u8] {
        &self.raw[..self.len]
    }

    pub(crate) fn copy_from_slice(&mut self, value: &[u8]) -> Result<(), BlizzardError> {
        if value.len() > self.raw.len() {
            return Err(BlizzardError::PayloadTooLarge {
                expected: self.raw.len(),
                actual: value.len(),
            });
        }
        self.raw[..value.len()].copy_from_slice(value);
        self.len = value.len();
        Ok(())
    }
}

impl Default for Payload {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_stores_data() -> Result<(), BlizzardError> {
        let mut payload = super::Payload::new();
        payload.copy_from_slice(b"Hello, world!")?;
        assert_eq!(payload.as_plaintext_slice(), b"Hello, world!");
        Ok(())
    }

    #[test]
    fn test_size_limit() -> Result<(), BlizzardError> {
        let mut payload = super::Payload::new();
        let result = payload.copy_from_slice(&[0u8; 1024 * 1024]);
        assert!(result.is_err());
        Ok(())
    }
}
