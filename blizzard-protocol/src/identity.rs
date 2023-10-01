#[cfg(not(feature = "std"))]
use sha2::{Digest, Sha256};
use snow::Keypair;

use crate::{
    constants::{ADDRESS_DERIVATION_SALT, ADDRESS_LEN_BYTES},
    error::BlizzardError,
    message::unicast::Message,
    session::BlizzardSessionHandshake,
};

/// Derive a 64-bit fingerprint of a blizzard public key.
pub fn pubkey_to_address(pubkey: &[u8]) -> Result<Address, BlizzardError> {
    let mut hasher = Sha256::new();
    hasher.update(ADDRESS_DERIVATION_SALT);
    hasher.update(pubkey);
    let digest: [u8; 32] = hasher.finalize().into();
    let address_bytes: [u8; ADDRESS_LEN_BYTES] = [
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ];
    let mut fingerprint = [0u8; ADDRESS_LEN_BYTES];
    fingerprint.copy_from_slice(&address_bytes);
    Ok(fingerprint.into())
}

/// A 64-bit fingerprint of a blizzard public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Address {
    raw: [u8; ADDRESS_LEN_BYTES],
}

impl From<[u8; ADDRESS_LEN_BYTES]> for Address {
    fn from(value: [u8; ADDRESS_LEN_BYTES]) -> Self {
        Self { raw: value }
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = BlizzardError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != ADDRESS_LEN_BYTES {
            return Err(BlizzardError::SliceIncorrectLength {
                expected: ADDRESS_LEN_BYTES,
                actual: value.len(),
            });
        }
        let mut raw = [0u8; ADDRESS_LEN_BYTES];
        raw.copy_from_slice(value);
        Ok(Self { raw })
    }
}

impl From<Address> for [u8; ADDRESS_LEN_BYTES] {
    fn from(value: Address) -> Self {
        value.raw
    }
}

/// A trait for types that can be used as a Blizzard identity.
pub trait Identity {
    /// Get the public key of this identity. There's no reason to share this with a peer outside the context of a handshake,
    /// but doing so does not compromise the security properties of the protocol.
    fn pubkey(&self) -> &[u8; 32];
    /// Returns the [`Address`] of this identity. This is an HDKF-derived fingerprint of the public key with the blizzard network salt.
    fn address(&self) -> Result<Address, BlizzardError> {
        pubkey_to_address(self.pubkey())
    }
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
    /// Returns a [`BlizzardError::InvalidAddress`] if the destination address of the incoming message does not match this identity's address.
    /// Returns a [`BlizzardError::SnowError`] if the handshake state machine fails.
    /// Returns a [`BlizzardError::SliceIncorrectLength`] if the incoming message's payload is not the exact size of a noise public key.
    pub fn maybe_handshake(
        &self,
        incoming: &Message,
    ) -> Result<BlizzardSessionHandshake, BlizzardError> {
        if self.address()? != incoming.destination_address()? {
            return Err(BlizzardError::InvalidAddress {
                address: incoming.destination_address()?,
            });
        }
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
