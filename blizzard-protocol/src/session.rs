use snow::{HandshakeState, TransportState};

use crate::{
    constants::{MTU, NOISE_HMAC_LENGTH_BYTES},
    error::BlizzardError,
    identity::{pubkey_to_address, Address},
    message::{payload::Payload, unicast::Message},
};

/// A session in the process of establishing a connection.
pub struct BlizzardSessionHandshake {
    my_pubkey: [u8; 32],
    their_pubkey: [u8; 32],
    state: HandshakeState,
}

impl BlizzardSessionHandshake {
    /// Emits a handshake message to send to the remote peer.
    /// This updates the state of this handshake, so if you expect to need to retransmit this message,
    /// you should clone it first because you can't call this method again until you receive a response from the remote peer.
    /// Returns a [`BlizzardError::SnowError`] if the handshake state machine fails.
    /// This happens when you call this method more than once prior to a response from the remote peer,
    /// or when you attempt to continue the handshake after it's already finished.
    pub fn write_handshake_message(&mut self) -> Result<Message, BlizzardError> {
        let mut ciphertext = [0u8; MTU];
        let ciphertext_size = self
            .state
            .write_message(&self.my_pubkey, &mut ciphertext)
            .map_err(|err| BlizzardError::SnowError { err })?;
        let peer_address = pubkey_to_address(&self.their_pubkey)?;
        Message::from_parts(&peer_address, &ciphertext[..ciphertext_size])
    }

    /// Process a handshake message from the remote peer.
    pub fn read_handshake_message(&mut self, message: &Message) -> Result<(), BlizzardError> {
        let mut payload_buf = [0u8; MTU - 16]; // Allocate a buffer for the payload, even though it should be empty.
        self.state
            .read_message(message.ciphertext_as_slice(), &mut payload_buf)
            .map_err(|err| BlizzardError::SnowError { err })?;
        Ok(())
    }

    /// Returns true if the handshake is finished. When this returns true, you should call [BlizzardSessionHandshake::into_transport_mode()] to convert this session into a transport mode session.
    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Converts this session into a transport mode session.
    /// Returns a [`BlizzardError::SnowError`] if the session creation fails. This may happen when the handshake is not finished.
    pub fn into_transport_mode(self) -> Result<BlizzardSession, BlizzardError> {
        match self.state.get_remote_static() {
            Some(remote_static) => {
                if remote_static != &self.their_pubkey {
                    return Err(BlizzardError::AuthenticityError);
                }
            }
            None => {
                return Err(BlizzardError::AuthenticityError);
            }
        }
        let peer_address = pubkey_to_address(&self.their_pubkey)?;
        Ok(BlizzardSession {
            peer_address,
            their_pubkey_expected: self.their_pubkey,
            state: self
                .state
                .into_transport_mode()
                .map_err(|err| BlizzardError::SnowError { err })?,
        })
    }

    pub(crate) fn from_handshake_state(
        state: HandshakeState,
        my_pubkey: &[u8; 32],
        their_pubkey: &[u8; 32],
    ) -> BlizzardSessionHandshake {
        BlizzardSessionHandshake {
            state,
            my_pubkey: *my_pubkey,
            their_pubkey: *their_pubkey,
        }
    }
}

/// A session with a completed handshake that is ready to send and receive messages.
pub struct BlizzardSession {
    their_pubkey_expected: [u8; 32],
    peer_address: Address,
    state: TransportState,
}

impl BlizzardSession {
    /// Creates an encrypted message from the given [Payload].
    pub fn write_message(&mut self, payload: &Payload) -> Result<Message, BlizzardError> {
        match self.state.get_remote_static() {
            Some(remote_static) => {
                if remote_static != &self.their_pubkey_expected {
                    return Err(BlizzardError::AuthenticityError);
                }
            }
            None => return Err(BlizzardError::AuthenticityError),
        }

        let mut ciphertext = [0u8; MTU];
        let ciphertext_size = self
            .state
            .write_message(payload.as_plaintext_slice(), &mut ciphertext)
            .map_err(|err| BlizzardError::SnowError { err })?;
        Message::from_parts(&self.peer_address, &ciphertext[..ciphertext_size])
    }

    /// Decrypts a message into the given [Payload].
    pub fn read_message(
        &mut self,
        message: &Message,
        payload: &mut Payload,
    ) -> Result<(), BlizzardError> {
        let mut payload_buf = [0u8; MTU - NOISE_HMAC_LENGTH_BYTES];
        let payload_size = self
            .state
            .read_message(message.ciphertext_as_slice(), &mut payload_buf)
            .map_err(|err| BlizzardError::SnowError { err })?;
        payload.copy_from_slice(&payload_buf[..payload_size])?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::error::BlizzardError;
    use crate::identity::LocalIdentity;
    use crate::message::payload::Payload;

    #[test]
    fn establish_handshake() -> Result<(), BlizzardError> {
        let node1 = LocalIdentity::new()?;
        let node2 = LocalIdentity::new()?;
        let mut node1_handshake = node1.initiate(&node2)?;
        let msg = node1_handshake.write_handshake_message()?;
        let mut node2_handshake = node2.maybe_handshake(&msg)?;
        let msg = node2_handshake.write_handshake_message()?;

        node1_handshake.read_handshake_message(&msg)?;
        let _node1_session = node1_handshake.into_transport_mode()?;
        let _node2_session = node2_handshake.into_transport_mode()?;

        Ok(())
    }

    #[test]
    fn pass_messages() -> Result<(), BlizzardError> {
        let node1 = LocalIdentity::new()?;
        let node2 = LocalIdentity::new()?;
        let mut node1_handshake = node1.initiate(&node2)?;
        let msg = node1_handshake.write_handshake_message()?;
        let mut node2_handshake = node2.maybe_handshake(&msg)?;
        let msg = node2_handshake.write_handshake_message()?;

        node1_handshake.read_handshake_message(&msg)?;
        let mut node1_session = node1_handshake.into_transport_mode()?;
        let mut node2_session = node2_handshake.into_transport_mode()?;

        let mut node1_payload = Payload::new();
        node1_payload.copy_from_slice(b"Hello, world!")?;
        let msg = node1_session.write_message(&node1_payload)?;
        let mut node2_payload = Payload::new();
        node2_session.read_message(&msg, &mut node2_payload)?;

        assert_eq!(
            node1_payload.as_plaintext_slice(),
            node2_payload.as_plaintext_slice()
        );
        Ok(())
    }
}
