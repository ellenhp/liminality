use alloc::string::ToString;
use rand::Rng;
use xorf::{BinaryFuse16, Filter};

use crate::{
    constants::{
        ADDRESS_LEN_BYTES, BLIZZARD_MESSAGE_TYPE_ANNOUNCE, BLIZZARD_PROTOCOL_VERSION, MTU,
    },
    error::BlizzardError,
    identity::Address,
};

// Empirical.
const MAX_ANNOUNCE_ADDRESSES: usize = 55;

/// A blizzard announce message. This is a special type of message that is used to announce the existence of a blizzard node,
/// conveying a set of addresses that the announcer knows about. These addresses are transfered over the wire in a binary fuse filter.
/// The binary fuse filter is a probabilistic data structure that allows for efficient set membership queries. If a peer is not in the filter,
/// it is guaranteed to not be in the announce packet. If a peer is in the filter, it may or may not be known by the announcer. Internally this
/// is implemented using a [`xorf::BinaryFuse16`] filter, which has a false positive rate of 2^-16. This means that if an address appears in this filter
/// there's always a chance that the announcer does not actually know about it. Given the number of announce packets in the network, there is a near-guarantee
/// of at least one false positive in the network at any given time. This is a feature, not a bug. It allows for plausible deniability of any attacker-inferred
/// network topology without substantially increasing the amount of useless traffic (traffic destined to nodes that are incapable of delivering that traffic).
pub struct Announce {
    raw: [u8; MTU],
    len: usize,
}

impl Announce {
    fn new() -> Self {
        Self {
            raw: [0u8; MTU],
            len: 0,
        }
    }

    /// Returns the packet as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.raw[..self.len]
    }

    /// Queries whether the given address is in this filter. This is a probabilistic query, and may return false positives.
    /// See the documentation for [`xorf::BinaryFuse16`] for more details.
    pub fn contains_peer(&self, peer: &Address) -> Result<bool, BlizzardError> {
        let xorf: BinaryFuse16 = bincode::deserialize(&self.raw[2..self.len]).map_err(|err| {
            BlizzardError::SerializationError {
                message: err.to_string(),
            }
        })?;
        Ok(xorf.contains(&u64::from_be_bytes((*peer).into())))
    }

    /// Creates a new announce packet from a list of addresses. The list of peers should be at most [`MAX_ANNOUNCE_ADDRESSES`] in length. Addresses that limit
    /// may be ignored. The filter will be filled with random data if the list of peers is shorter than [`MAX_ANNOUNCE_ADDRESSES`] to help ensure plausible deniability.
    pub fn from_peer_list<RngType: Rng>(
        peers: &[Address],
        rng: &mut RngType,
    ) -> Result<Self, BlizzardError> {
        // The code here relies on addresses being 64 bits, since binary fuse filters operate on u64s.
        debug_assert_eq!(ADDRESS_LEN_BYTES, 8);
        let mut keys = [0u64; MAX_ANNOUNCE_ADDRESSES];
        for (i, key) in keys.iter_mut().enumerate() {
            *key = if let Some(peer) = peers.get(i) {
                let key_bytes = (*peer).into();
                u64::from_be_bytes(key_bytes)
            } else {
                rng.gen()
            };
        }
        let xorf = BinaryFuse16::try_from(keys[..peers.len().min(MAX_ANNOUNCE_ADDRESSES)].to_vec())
            .map_err(|err| BlizzardError::BinaryFuseError {
                message: err.to_string(),
            })?;
        let xorf_bin =
            bincode::serialize(&xorf).map_err(|err| BlizzardError::SerializationError {
                message: err.to_string(),
            })?;
        if xorf_bin.len() > MTU - 2 {
            return Err(BlizzardError::BinaryFuseError {
                message: "BinaryFuse16 filter too large. This should be reported to thie `blizzard` project.".to_string(),
            });
        }
        let mut announce = Self::new();
        announce.raw[0] = BLIZZARD_PROTOCOL_VERSION;
        announce.raw[1] = BLIZZARD_MESSAGE_TYPE_ANNOUNCE;
        announce.raw[2..2 + xorf_bin.len()].copy_from_slice(&xorf_bin);
        announce.len = 2 + xorf_bin.len();
        Ok(announce)
    }

    pub(crate) fn try_from_slice(slice: &[u8]) -> Result<Self, BlizzardError> {
        if slice.len() > MTU {
            return Err(BlizzardError::PayloadTooLarge {
                expected: MTU,
                actual: slice.len(),
            });
        }

        let mut announce = Self::new();
        announce.raw[..slice.len()].copy_from_slice(slice);
        announce.len = slice.len();
        Ok(announce)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use rand::{thread_rng, Rng};
    use std::vec::Vec;

    #[test]
    fn test_announce() -> Result<(), BlizzardError> {
        let mut rng = thread_rng();
        let announce_addresses: Vec<Address> = (0..MAX_ANNOUNCE_ADDRESSES)
            .map(|_| {
                let mut address = [0u8; ADDRESS_LEN_BYTES];
                rng.fill(&mut address);
                address.into()
            })
            .collect();
        let announce = Announce::from_peer_list(announce_addresses.as_slice(), &mut rng)?;
        // Empirical.
        assert_eq!(announce.as_slice().len(), 222);
        for address in announce_addresses {
            assert!(announce.contains_peer(&address)?);
        }
        let mut false_positives = 0;
        for _ in 0..10_000 {
            let mut address = [0u8; ADDRESS_LEN_BYTES];
            rng.fill(&mut address);
            if announce.contains_peer(&address.into())? {
                false_positives += 1;
            }
        }
        // Empirical.
        assert!(false_positives < 5);
        Ok(())
    }
}
