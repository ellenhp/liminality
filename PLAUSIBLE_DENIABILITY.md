# Plausible Deniability of Network Topology

In the readme I talked about the concept of plausible deniability a lot, because it's one of blizzard's unique features. It comes from the fact that announces in blizzard take the form of a binary fuse filter. If you're familiar with bloom filters or xor filters, these are the same class of data structure. If you're not familiar with those things, you can think of it as a compact, probabilistic set data structure. If I insert an item into a binary fuse filter during its construction, it is guaranteed to be in the output, assuming construction is successful. Curiously, the data structure is *probabalistic* in nature which means that everything I put into the data structure will be present in the output, along with approximately 2^48 other values.

That's quite a lot of data to pack into an announce packet! At first glance it may seem like a bit of a liability, because peers will assume that I'm connected with approximately 2^48 other nodes, and I might get traffic forwarded to me that I'm incapable of delivering. While that will absolutely happen, the false-positive rate only is 2^-16 so it's not enough useless traffic to grind the network to a halt. What's very special about this announce mechanism is that annoucning these ~2^48 peer addresses happens in 222 bytes, header and all. That's on the bigger side for an announce packet. It would certainly be smaller if it was only an announce for a single public key. But the properties I'm about to dig into are worth that extra size.

## Caveat

I should mention that a binary fuse filter is not a cryptographic device. It may be possible to infer some amount of exact information about its construction parameters based on the output of the construction, though at ~32 bits of output per u64 entry I can say with some amount of certainty that at least half of the input information is lost. How much exactly is anyone's guess.

## Premise

Some attacks on DTNs rely on extracting a social graph from the network topology and using that social graph to deanonymize and target users. This can occur whenever an announcement mechanism is monitored by an adversary with enough access to the network that she's able to capture a significant portion of the announce packets emitted by her targets. Let's say "Journalist Andy" is communicating with "Source Sam" about human rights abuses, and "Investigator Irene" is monitoring Andy in an attempt to deanonymize Sam so they can be thrown in prison. In a typical DTN, Andy's device will have had recent contact with Sam's, and will readily offer to forward packets from elsewhere in the network to Sam's device for delivery.

### Attack on a typical DTN

Let's say Irene follows Andy home one night and parks outside his house, capturing a bunch of announce packets. In a DTN where recent peers are announced one-by-one, Irene now has a list of identities that she can further investigate. One of them is likely Sam's. At that point she can go wardriving to find an announce packet by Sam's device.

### Attack on blizzard

Blizzard is a bit different. Say Irene follows Andy home and captures all of those same announce packets. Each packet contains a set of approximately 2^48 addresses. If she parked outside all night she may have several of them, and if she had the computing power to perform an intersection operation between two, she'd still have a list of 2^32 addresses to go investigate. She'd have to do an intersection of 3 packets before she ended up with a small enough list to act on, which is no small feat. An intersection involves performing a lookup into each filter for every number between 0 and 2^64-1. Let's say she manages to come up with a list of 2^16 identities though, and she's pretty sure one of them is Sam. She can start wardriving, but one thing she'll run into right away is that Sam's announce packet is going to include Sam's address in the filter, but won't otherwise designate it as a special "zero-hop" destination. From Irene's perspective, Sam's announce packet will look indistinguishable from the announce packet of anyone who's recently interacted with them.

This comes with a huge downside though: Blizzard packets aren't routable past a hop or two, depending on how you're counting. I'm planning on addressing this in a future release, but for now it's a tradeoff I'm comfortable making.
