# 🌟 Liminality 🌟

Liminality, named for the ephemeral nature of mesh networks, is a unique protocol for wireless communication in fluid and dynamic environments. The protocol takes its name from the liminoid experiences that often unfold in spaces where individuals gather in numbers and disperse. As a delay-tolerant mesh network protocol, Liminality flourishes in these environments, while other network topologies may be shut down[^1] or struggle to provide connectivity. At times other networks may provide connectivity only at the expense of privacy[^2] or, in extreme cases, physical safety[^3].

Liminality is a network layer built upon the foundation of the IEEE 802.15.4g PHY and MAC layers. By leveraging the 802.15.4g specification, Liminality benefits from a standardized packet format, enabling seamless interoperability among transceivers manufactured by different vendors. Furthermore, the 802.15.4g standard prescribes contention-handling mechanisms for crowded RF environments and offers forward error correction. Operating at layer 3, the Liminality protocol defines the state machine governing association, disassociation, data transfer, and forwarding behavior within Liminality nodes. It covers all behavior required to get raw data from A to B.

Liminality uses the [noise protocol framework](http://www.noiseprotocol.org/noise.html) to provide security guarantees, configured in the `Noise_IK_25519_ChaChaPoly_BLAKE2s` pattern. Building on top of noise enables Liminality to provide trustworthy security properties, which are often unattainable for protocols relying on bespoke usages of cryptographic primitives unless subjected to thorough audits.

[^1] http://archive.today/2013.01.30-230311/http://www.nytimes.com/2011/01/29/technology/internet/29cutoff.html?_r=0
[^3] http://archive.today/2023.09.08-125532/https://www.wsj.com/amp/articles/americans-cellphones-targeted-in-secret-u-s-spy-program-1415917533
[^2] http://archive.today/2019.12.23-235637/https://www.nytimes.com/interactive/2019/12/21/opinion/location-data-democracy-protests.html


## Features

To the best of my knowledge, Liminality offers the following properties:

1. **Simplicity**: Liminality keeps things uncomplicated with just four message types and an easily comprehensible state machine.
2. **Initiator Privacy**: Observers outside a channel remain unaware of the public key or any long-term identifiers associated with the initiator, preserving a degree of privacy.
3. **Limited Recipient Privacy**: When identifying oneself as the recipient to trigger message delivery, Liminality avoids revealing information that could be used for fingerprinting, apart from metadata about delivery, such as the time, location, and ciphertext of the radio transmission.
4. **Relay Privacy**: Delivering a message avoids disclosing information suitable for fingerprinting, limited to time, location, and message ciphertext.
5. **Forward Secrecy**: Each channel uses a new ephemeral key derived via an ECDH handshake. The handshake uses ephemeral keys for all messages except the first in a channel, which uses a recipient's static key.
6. **Low Latency**: Liminality uses a noise handshake pattern that enables 0-RTT handshakes.
7. **Efficient Bandwidth Utilization**: Liminality incorporates a modified spray-and-wait routing mechanism, allowing for efficient network bandwidth utilization.
8. **Authenticated and Encrypted Channels**: Outside observers of a channel are incapable of forging or reading messages within it.

It's critical to note that Liminality has yet to undergo a formal audit. While it offers useful properties, it may not withstand sophisticated attackers such as state actors. This is especially true of its privacy properties, which do rely on some un-audited raw operations on Curve25519, and come with some [serious caveats](#known-issues) for the time being. Consider this carefully in situations where strong guarantees are necessary to protect life, property, or safety. While it is exciting and novel that a delay-tolerant network is able to provide these security and privacy properties, an end-to-end encrypted messaging app of your choosing has similar or superior security and privacy in an information-theoretic sense, at the expense of censorship resistance and being trivially trackable through physical space. 

## Non-goals

Liminality prioritizes security and anonymity but acknowledges certain limitations. The protocol does not provide resistance against malicious denial-of-service behavior, such as Sybil attacks, flooding, or black-hole attacks. Network operation assumes that peers are honest and will not engage in disruptive activities. Addressing these issues falls outside the protocol's scope, as they pose complex challenges, primarily of academic interest. Individuals capable of launching denial-of-service attacks on a delay-tolerant network can often do so through multiple avenues, making effective prevention impractical. While protocol-level denial-of-service attacks may be mitigated through thoughtful design, determined attackers can often shift their focus to the physical layer without losing efficacy.

## Wire format

The Liminality protocol employs four distinct packet types:

1. **Message packets** carry raw data.
2. **Advertisement packets** signal that a node has messages available for distribution throughout the network.
3. **Delivery offer packets** are used to propose final message delivery. These packets use operations on Curve25519 to hide the message's identifier from everyone except its intended recipient.
4. **Message request packets** are responses to delivery offers, initiating the final delivery process.

The subsequent sections describe the functionality of each packet type.

### Conventions

While the noise protocol framework provides confidentiality and authenticity guarantees, Liminality provides its privacy guarantees through raw operations on Curve25519. This document defines "scalars" as large integers named `s`, sometimes with subscripts. Scalars are members of the prime field `𝕫` defined by the prime `ℓ=2^252+27742317777372353535851937790883648493`. This document defines points on Curve25519 as variables named `P`, sometimes with subscripts. Points in Liminality are members of the Ristretto group of Curve25519. Implementations must perform all arithmetic on scalars and Ristretto points modulo `ℓ`.

### Common features

All Liminality packets begin with a one-byte header.

| Bits | Field name | Purpose |
|---|---|---|
| 7:4 | Protocol version | Encodes the version of the specification that the implementation that constructed the packet targets. The current version is 0b0001. |
| 3:0 | Packet type | Describes the type of packet contained in all subsequent data. |

### Message packets

Message packets correspond to the packet type `0b0000` and contain a payload of the following form:

| Bytes | Field name | Purpose |
|---|---|---|
| 0:31 | Message ID scalar | Serves as the message ID in conjunction with the point. Encoded as a 32-byte big-endian integer. |
| 32:63 | Message ID point | Serves as the message ID in conjunction with the scalar. Encoded in a compressed format for Edwards |
| 64: | Payload | Contains a noise message with information from the transport layer. |

#### Message IDs

As shown in the table above, message IDs contain a 32-byte scalar `sₘ ∈ 𝕫`, encoded as a 32-byte big-endian integer, and a Ristretto point on Curve25519, encoded in a compressed 32-byte format for Edwards-form points. The message's sender derives a scalar `s₀ ∈ 𝕫` by hashing the noise handshake hash concatenated with the recipient's public key. Specifically, they must compute `s₀ = blake2s(handshake_hash ∥ public_key) % ℓ` where `blake2s` uses a 32 byte digest. After computing `s₀`, the sender will compute `P₀ = s₀ * base` where `base` is the Curve25519 base point. After generating `P₀`, the sender will choose a scalar `sₘ ∈ 𝕫` using a CPRNG and compute a point `Pₘ = P₀ * sₘ`. The 64-byte message ID is the big-endian form of `sₘ` concatenated with the compressed wire format of `Pₘ`.

### Advertisement packets

A node advertises they have copies of a message to share by emitting one or more advertisement packets. Advertisement packets use packet type `0b0001`. The first byte of an advertisement packet is a sequence byte defined identically to a message packet's sequence byte.

If the most significant bit of an advertisement packet's sequence byte is high, the byte after the *sequence byte* contains a set of bit-packed flags in an *advertisement header byte*.

|Bits|Field name|Purpose|
|---|---|---|
|7| Forwarder bit| When high, the transmitting node can forward messages, and the receiving node should advertise messages it has copies of. When low, the advertisement phase is skipped, and only delivery offers and message requests are exchanged. |
|6:0| Reserved|Reserved for future use.|

After the advertisement header byte, advertisement packets contain a flat list of 8-byte blake2s digests, each computed over a group of message packets.

### Delivery offer packets

Delivery offer packets correspond to packet type `0b0010` and exist to communicate the set of messages a peer has in its possession for final delivery. Delivery offers begin with a 2-byte big-endian integer called the sequence number, representing the number of delivery offer packets a node intends to transmit following the current one. Nodes may transmit delivery offer packets in any order as long as the *sequence number* monotonically decreases and ends at zero.

After the sequence number, delivery offer packets contain a 32-byte big-endian representation of a scalar `sₘ` and a 32-byte compressed representation of a point `Pₘ` in the Ristretto group of Curve25519. Points should be serialized and deserialized in Edwards form. Critically, delivery offers do **not** convey original message IDs verbatim.

Instead, nodes offering delivery will choose a scalar `s₀ ∈ 𝕫` using a CPRNG and compute a scalar `s = sₘ * s₀`. Then, they compute a point `P = Pₘ * s`. This computation yields a new message ID that maintains the verifiability properties of the original message ID.

#### Verification of delivery offers

For any channel `ch`, the handshake hash and the recipient's public key are known to both sender and receiver. With that information, the receiver can determine if the session point used to create the original message ID matches their session point for `ch`.

When a node receives a delivery offer, it will test the message ID against each of its open channels by following these steps:
1. It will derive `s₀` from a channel's handshake hash and its public key.
2. It will compute `s = sₘ * s₀`.
3. The node will compute `P = s * base` where `base` is the Curve25519 base point.
If `P` equals `Pₘ`, the message on offer belongs to the tested channel, and the recipient will issue a message request packet.

### Message request packets

Message request packets use packet ID `0b0011`. Following the header, each message request contains a flat list of message ID hashes. A message ID hash is computed as the 8-byte `blake2s` digest of the 64-byte message ID as transmitted by the message delivery offer.

#### Message request chaff

After receiving a sequence of delivery offer packets, a Liminality node must request at least `min(20, ceil(0.02 * offered))` messages, where `offered` is the number of delivery offer packets in the sequence. If the node has storage space available, it should store packets received as chaff to offer for delivery to other nodes, subject to the TTL.

## Spray-and-wait routing

A standard spray-and-wait system operates by proactively "spraying" a limited number of copies of a message across the network, then "waiting" for the bearer of one of those copies to come across its recipient and deliver it. Binary spray-and-wait requires that peers give away half of their "copies" of the messages they know about to each new peer they encounter until they only have one left. When a peer only has one copy left, they enter the "wait" phase for that message, waiting for a recipient to trigger delivery.

### Fingerprinting attacks against spray-and-wait

Binary spray-and-wait performs very well, even compared to other DTN routing mechanisms with inferior anonymity properties. It is, however, possible for a malicious party to track a node through the network by creating a unique message and distributing only one copy. The recipient of this unique message will be identifiable anywhere on the network because they are the only peer with a copy of this message. I refer to this as an "active fingerprinting attack" in this document.

### Mitigation of active fingerprinting attacks

Stochastic spray and wait differs in that the recipient of a message randomly adjusts the number of copies of each message they receive. This adjustment may include the recipient destroying their only copy and never advertising or delivering it. The relay never learns how the count was adjusted. This adjustment helps mitigate active fingerprinting attacks by preventing the attacker from knowing exactly how many copies of a message are on the network.

Additionally, Liminality defines a maximum TTL of 72 hours. Since nodes do not timestamp their messages at the network level, i.e., in plaintext, a node begins this TTL timer when it receives a new message for the first time. Implementations may choose a shorter TTL if desired. Shorter TTLs make the effects of an active fingerprinting attack shorter-lived.

## Routing state machine

### Authoring messages

Messages may be authored at any time by any node. When authored, a message enters a node's advertisement and delivery offer sets.

### Beaconing, association and disassociation

Each node announces an 802.15.4 network by emitting beacon packets every 180 seconds unless a user has forced the node to obey radio silence. After sending a beacon packet, a node should respond to association requests for the announced network for at least 180 seconds but no longer than 15 minutes. Nodes should rotate identifiers they use to beacon at a 15-minute interval and under no circumstances less often than one hour. When a node, Alice, detects a new network beaconed by node Bob, she may choose to connect to Bob's network to exchange data. Nodes enter and leave other nodes' networks opportunistically.

### Advertising messages

After associating to a new network, a node should advertise the messages they have copies of by transmitting one or more advertisement packets.

### Transmitting messages

A message should be transmitted after an advertisement is received missing that message, assuming the transmitting node has copies to share proactively. Messages are also transmitted in response to message requests.

A message transmitted during the spray phase is conveyed verbatim, regardless of whether the transmitting node is the author or a relay. In contrast, a message transmitted in response to a delivery request has its message ID replaced with the message ID used in its delivery offer. This replacement ensures that a passive adversary observing message delivery cannot correlate the delivered message with any of its advertisements because they will lack the correct input to the `blake2s` function used during the spray phase.

If a node receives a message via a proactive message distribution, it must continue distributing copies until it has only one remaining. Additionally, the message must remain in the recipient's delivery offer set until its TTL expires, even if the node is the recipient of that message.

### Offering delivery

Nodes offer delivery of messages after advertisements are exchanged and messages in the spray phase have been transferred. Delivery offers are constructed according to the algorithm described in the wire format section.

### Requesting messages

A peer may request after delivery offers are exchanged. Messages received via a message request must enter a node's delivery offer set regardless of whether the request is genuine or made as chaff.

### Typical message exchange

A typical encounter between Liminality peers follows:
1. Peer A beacons according to 802.15.4.
2. Peer A waits and returns to step 1 if there are no association requests.
3. Peer B associates with Peer A's network.
4. Peer B advertises the messages it has available for distribution.
4. Peer A transmits messages it has copies of that are not in Peer B's advertisement
5. Peer A advertises the messages available for delivery, omitting those it just transmitted.
6. Peer B transmits messages it has copies of that are not in Peer A's advertisement
7. Peer B transmits message delivery offers corresponding to messages in its delivery offer set.
8. Peer A responds by requesting messages belonging to one of its active channels and chaff, if applicable.
9. Peer B transmits the requested messages.
10. Peer A transmits delivery offers corresponding to messages in its delivery offer set.
11. Peer B requests messages.
12. Peer A transmits the requested messages.
13. Peer B disassociates.

## Bootstrapping a new channel

If Alice wants to talk to Bob, she must ask Bob out-of-band for a 32-byte noise public key and a 32-byte big-endian scalar value that Bob will use as `s₀` to determine if any particular message on the network is from Alice. Alice will use this `s₀` for her initial message, but each subsequent message in their channel will calculate `s₀` from their handshake hash.

## Known issues

1. If an adversary obtains a message ID belonging to a channel with known endpoints, they can replay delivery offers to any node they encounter by multiplying that message ID by a new random scalar each time. The attacker can know they will always trigger message requests from the recipient. This type of replay attack compromises recipient privacy. In larger networks, on average, the adversary will experience a false message request after offering a message for delivery to 34 nodes. Unfortunately, a malicious adversary could offer delivery of several fake packets and note that a node taking all of those packets is likely not requesting them as chaff. A future version of Liminality will include ratcheting mechanisms to reduce the time window that a fingerprinting attack like this will work.

## Implementation Gotchas

1. Each node must maintain a list of handshake hashes they've seen in the past and must not respond to any incoming handshake request with a handshake hash identical to one they've seen previously. A duplicate handshake hash would indicate a replay attack according to the note under property 3 of the [noise protocol specification, section 7.8](http://www.noiseprotocol.org/noise.html#identity-hiding).

## Feedback!

Please feel free to reach out if you have feedback. You can reach me at: `[my first name]@[my github username].me`
