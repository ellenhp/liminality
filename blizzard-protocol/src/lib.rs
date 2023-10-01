//! # Blizzard
//!
//! Blizzard is a protocol for setting up authenticated and encrypted channels. It is designed to be used in
//! peer-to-peer networks where peers are not necessarily online at the same time i.e. it is a delay-tolerant protocol.
//! Unlike most other DTN protocols, it's designed to be used on a microcontroller. This crate is `no_std` compatible, but does require an allocator.
//!
//! Blizzard is built on top of a no_std-compatible fork of [snow], a modern noise protocol implementation. Blizzard uses the noise
//! protocol framework to handle encryption and authentication, meaning there are zero (or perhaps one) bespoke usages of cryptographic
//! primitives in this crate. The closest thing is the use of a key deriviation function to turn a noise public key into a 64-bit fingerprint.
//! This fingerprint is used to address messages to a specific peer.
//!
//! Blizzard does not handle any transport layer concerns. It is up to the user to send and receive messages over a transport.
//! Blizzard messages can be sent over any transport, including unreliable transports like UDP, but it is currently up to the user to
//! handle message ordering and retransmission. Noise does have facilities for handling these concerns, but Blizzard does not
//! currently use them. This may change in the future.
//!
//! Blizzard is not tolerant of sybil attacks, black-holing, or other malicious denial-of-service type behavior. Network operation
//! is predicated on the assumption that peers are honest and will not attempt to disrupt the network, however bad actors should not be capable of
//! compromising the security or anonymity guarantees of the protocol.
//!
//! ## Features
//!
//! Blizzard offers initiator anonymity, forward secrecy (each session uses ephemeral keys), AEAD channels via the noise protocol
//! framework, and some amount of plausible deniability of network topology (see [crate::message::announce::Announce] for more details).
//! Blizzard does not offer information-theoretic anonymity guarantees for the recipient of a message, meaning packets are addressed
//! to a specific peer who may be forced to reveal an association with the destination address in order to trigger delivery. Announces
//! are built in a way that intentionally obfuscates network topology, meaning it may be difficult for an attacker to determine whether
//! a node is the recipient of a message or merely a relay. This is not a guarantee of anonymity.
//!
//! The main feature of Blizzard, though, is that it's a DTN protocol that is possible for humans to understand. The entire protocol
//! as of this writing is less than 1000 lines of code, including tests and documentation. The core protocol itself is closer to 500 lines,
//! and doesn't do anything scary. Building on top of [snow] is what makes this possible.
//!
//! ## Usage
//!
//! Blizzard is not ready for general use. The API should not be considered stable. It has not been simulated. It has not been audited.
//!
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(error_in_core))]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::print_stdout)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_in_result)]
#![deny(missing_docs)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub(crate) mod types;

/// Constants used by the blizzard protocol.
pub mod constants;

/// Errors that can occur while using the blizzard protocol.
pub mod error;

/// Identity management.
pub mod identity;

/// Messages that can be sent over the blizzard protocol.
pub mod message;

/// A blizzard session.
pub mod session;
