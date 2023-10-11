use blake2::{Blake2s256, Digest};
use curve25519_dalek::RistrettoPoint;
use rand::Rng;
use snow::{HandshakeState, TransportState};

use crate::{
    constants::{MTU, NOISE_HMAC_LENGTH_BYTES},
    error::BlizzardError,
    packet::{message::Message, payload::Payload, MessageId},
};

fn session_base_point(handshake_hash: &[u8]) -> RistrettoPoint {
    let mut base_point_bytes: [u8; 64] = [0u8; 64];
    let mut hasher = Blake2s256::new();
    hasher.update("BlizzardPointSalt1");
    hasher.update(handshake_hash);
    base_point_bytes[..32].copy_from_slice(&hasher.finalize()[..]);
    let mut hasher = Blake2s256::new();
    // Use a different salt for the second hash.
    hasher.update("BlizzardPointSalt2");
    // Also mix in the previous hash.
    hasher.update(&base_point_bytes[..]);
    hasher.update(&handshake_hash);
    base_point_bytes[32..].copy_from_slice(&hasher.finalize()[..]);

    let base_point = RistrettoPoint::from_uniform_bytes(&base_point_bytes);
    base_point
}

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
    pub fn write_handshake_message<RngType: Rng>(
        &mut self,
        preshared_base_point: &RistrettoPoint,
        rng: &mut RngType,
    ) -> Result<Message, BlizzardError> {
        let mut ciphertext = [0u8; MTU];
        let ciphertext_size = self
            .state
            .write_message(&self.my_pubkey, &mut ciphertext)
            .map_err(|err| BlizzardError::SnowError { err })?;
        let message_id = MessageId::random_from_base(*preshared_base_point, rng);
        Message::from_parts(&message_id, &ciphertext[..ciphertext_size])
    }

    /// Attempt to respond to an incoming handshake request.
    pub fn respond_handshake_message<RngType: Rng>(
        &mut self,
        rng: &mut RngType,
    ) -> Result<Message, BlizzardError> {
        let base_point = session_base_point(self.state.get_handshake_hash());
        let message_id = MessageId::random_from_base(base_point, rng);
        let mut ciphertext = [0u8; MTU];
        let ciphertext_size = self
            .state
            .write_message(&self.my_pubkey, &mut ciphertext)
            .map_err(|err| BlizzardError::SnowError { err })?;
        Message::from_parts(&message_id, &ciphertext[..ciphertext_size])
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
        Ok(BlizzardSession {
            handshake_hash: self.state.get_handshake_hash().to_vec(),
            num_transmitted_messages: 0,
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
    num_transmitted_messages: u32,
    state: TransportState,
    handshake_hash: crate::types::Vec<u8>,
}

impl BlizzardSession {
    /// Creates an encrypted message from the given [Payload].
    pub fn write_message<RngType: Rng>(
        &mut self,
        payload: &Payload,
        rng: &mut RngType,
    ) -> Result<Message, BlizzardError> {
        let base_point = session_base_point(&self.handshake_hash);
        let message_id = MessageId::random_from_base(base_point, rng);

        let mut ciphertext = [0u8; MTU];
        let ciphertext_size = self
            .state
            .write_message(payload.as_plaintext_slice(), &mut ciphertext)
            .map_err(|err| BlizzardError::SnowError { err })?;
        self.num_transmitted_messages += 1;
        Message::from_parts(&message_id, &ciphertext[..ciphertext_size])
    }

    /// Decrypts a message into the given [Payload].
    pub fn read_message(
        &mut self,
        message: &Message,
        payload: &mut Payload,
    ) -> Result<(), BlizzardError> {
        // Verify that the message belongs to this channel.
        message.confirm_message_id(&session_base_point(&self.handshake_hash))?;
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
    use curve25519_dalek::RistrettoPoint;
    use rand::{thread_rng, Rng};

    use crate::error::BlizzardError;
    use crate::identity::LocalIdentity;
    use crate::packet::message::Message;
    use crate::packet::payload::Payload;
    use crate::packet::MessageId;

    #[test]
    fn establish_handshake() -> Result<(), BlizzardError> {
        let node1 = LocalIdentity::new()?;
        let node2 = LocalIdentity::new()?;
        let mut preshared_key = [0u8; 64];
        thread_rng().fill(&mut preshared_key);
        let point = RistrettoPoint::from_uniform_bytes(&preshared_key);
        let mut node1_handshake = node1.initiate(&node2)?;
        let msg = node1_handshake.write_handshake_message(&point, &mut thread_rng())?;
        let mut node2_handshake = node2.maybe_handshake(&msg)?;
        let msg = node2_handshake.respond_handshake_message(&mut thread_rng())?;

        node1_handshake.read_handshake_message(&msg)?;
        let _node1_session = node1_handshake.into_transport_mode()?;
        let _node2_session = node2_handshake.into_transport_mode()?;

        Ok(())
    }

    #[test]
    fn pass_messages() -> Result<(), BlizzardError> {
        let node1 = LocalIdentity::new()?;
        let node2 = LocalIdentity::new()?;
        let mut preshared_key = [0u8; 64];
        thread_rng().fill(&mut preshared_key);
        let point = RistrettoPoint::from_uniform_bytes(&preshared_key);
        let mut node1_handshake = node1.initiate(&node2)?;
        let msg = node1_handshake.write_handshake_message(&point, &mut thread_rng())?;
        let mut node2_handshake = node2.maybe_handshake(&msg)?;
        let msg = node2_handshake.respond_handshake_message(&mut thread_rng())?;

        node1_handshake.read_handshake_message(&msg)?;
        let mut node1_session = node1_handshake.into_transport_mode()?;
        let mut node2_session = node2_handshake.into_transport_mode()?;

        let mut node1_payload = Payload::new();
        node1_payload.copy_from_slice(b"Hello, world!")?;
        let msg = node1_session.write_message(&node1_payload, &mut thread_rng())?;

        // Roll the message to simulate delivery.
        let msg = msg.rolled(&mut thread_rng())?;

        let mut node2_payload = Payload::new();
        node2_session.read_message(&msg, &mut node2_payload)?;

        assert_eq!(
            node1_payload.as_plaintext_slice(),
            node2_payload.as_plaintext_slice()
        );
        Ok(())
    }

    #[test]
    fn pass_messages_fails_recipient_check() -> Result<(), BlizzardError> {
        let node1 = LocalIdentity::new()?;
        let node2 = LocalIdentity::new()?;
        let mut preshared_key = [0u8; 64];
        thread_rng().fill(&mut preshared_key);
        let point = RistrettoPoint::from_uniform_bytes(&preshared_key);
        let mut node1_handshake = node1.initiate(&node2)?;
        let msg = node1_handshake.write_handshake_message(&point, &mut thread_rng())?;
        let mut node2_handshake = node2.maybe_handshake(&msg)?;
        let msg = node2_handshake.respond_handshake_message(&mut thread_rng())?;

        node1_handshake.read_handshake_message(&msg)?;
        let mut node1_session = node1_handshake.into_transport_mode()?;
        let mut node2_session = node2_handshake.into_transport_mode()?;

        let mut node1_payload = Payload::new();
        node1_payload.copy_from_slice(b"Hello, world!")?;
        let msg = node1_session.write_message(&node1_payload, &mut thread_rng())?;
        // Forge the message ID.
        let msg = Message::from_parts(
            &MessageId::random_from_base(
                RistrettoPoint::from_uniform_bytes(&[0u8; 64]),
                &mut thread_rng(),
            ),
            msg.ciphertext_as_slice(),
        )?;

        // Roll the message to simulate delivery.
        let msg = msg.rolled(&mut thread_rng())?;

        let mut node2_payload = Payload::new();
        let result = node2_session.read_message(&msg, &mut node2_payload);
        assert!(result.is_err());
        match result {
            Err(BlizzardError::MessageNotPartOfChannel) => {}
            _ => panic!("Failed to detect forged message ID."),
        }
        Ok(())
    }
}
