#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use snow::Keypair;

use crate::{error::BlizzardError, packet::message::Message, session::BlizzardSessionHandshake};

/// A trait for types that can be used as a Blizzard identity.
pub trait Identity {
    /// Get the public key of this identity. There's no reason to share this with a peer outside the context of a handshake,
    /// but doing so does not compromise the security or privacy properties of the protocol.
    fn pubkey(&self) -> &[u8; 32];
}

/// A local identity that can be used to initiate a handshake with a remote peer. This is a wrapper around a [`snow::Keypair`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct LocalIdentity {
    pubkey: [u8; 32],
    secret: [u8; 32],
}

impl Identity for LocalIdentity {
    fn pubkey(&self) -> &[u8; 32] {
        &self.pubkey
    }
}

impl TryFrom<Keypair> for LocalIdentity {
    type Error = BlizzardError;

    fn try_from(value: Keypair) -> Result<Self, Self::Error> {
        let pubkey = value.public.as_slice().try_into().map_err(|_err| {
            BlizzardError::SliceIncorrectLength {
                expected: 32,
                actual: value.public.len(),
            }
        })?;
        let secret = value.private.as_slice().try_into().map_err(|_err| {
            BlizzardError::SliceIncorrectLength {
                expected: 32,
                actual: value.private.len(),
            }
        })?;
        Ok(Self { pubkey, secret })
    }
}

impl LocalIdentity {
    /// Generate a new local identity with a random keypair.
    pub fn new() -> Result<Self, BlizzardError> {
        let keypair = snow::Builder::new(
            crate::constants::PATTERN
                .parse()
                .map_err(|err| BlizzardError::SnowError { err })?,
        )
        .generate_keypair()
        .map_err(|err| BlizzardError::SnowError { err })?;
        keypair.try_into()
    }

    /// Attempt to initiate a handshake with a remote peer.
    /// Returns a [`BlizzardError::SnowError`] if the handshake state machine fails.
    pub fn initiate<PeerIdentityType: Identity>(
        &self,
        remote: &PeerIdentityType,
    ) -> Result<BlizzardSessionHandshake, BlizzardError> {
        let builder = snow::Builder::new(
            crate::constants::PATTERN
                .parse()
                .map_err(|err| BlizzardError::SnowError { err })?,
        );
        let builder = builder.local_private_key(&self.secret);
        let builder = builder.remote_public_key(remote.pubkey());
        let handshake_state = builder
            .build_initiator()
            .map_err(|err| BlizzardError::SnowError { err })?;
        Ok(BlizzardSessionHandshake::from_handshake_state(
            handshake_state,
            &self.pubkey,
            remote.pubkey(),
        ))
    }

    /// Attempt to respond to an incoming handshake request.
    /// Returns a [`BlizzardError::SnowError`] if the handshake state machine fails.
    /// Returns a [`BlizzardError::SliceIncorrectLength`] if the incoming message's payload is not the exact size of a noise public key.
    pub fn maybe_handshake(
        &self,
        incoming: &Message,
    ) -> Result<BlizzardSessionHandshake, BlizzardError> {
        let builder = snow::Builder::new(
            crate::constants::PATTERN
                .parse()
                .map_err(|err| BlizzardError::SnowError { err })?,
        );
        let builder = builder.local_private_key(&self.secret);
        let mut state = builder
            .build_responder()
            .map_err(|err| BlizzardError::SnowError { err })?;
        const EXPECTED_KEYLEN: usize = 32;
        let mut payload_buf = [0u8; EXPECTED_KEYLEN];
        let size_bytes = state
            .read_message(incoming.ciphertext_as_slice(), &mut payload_buf)
            .map_err(|err| BlizzardError::SnowError { err })?;
        if size_bytes != EXPECTED_KEYLEN {
            return Err(BlizzardError::SliceIncorrectLength {
                expected: EXPECTED_KEYLEN,
                actual: size_bytes,
            });
        }
        Ok(BlizzardSessionHandshake::from_handshake_state(
            state,
            self.pubkey(),
            &payload_buf,
        ))
    }
}

/// A remote identity that can be used to represent a peer in memory. This is a wrapper around a public key.
#[derive(Clone)]
pub struct RemoteIdentity {
    pubkey: [u8; 32],
}

impl Identity for RemoteIdentity {
    fn pubkey(&self) -> &[u8; 32] {
        &self.pubkey
    }
}
