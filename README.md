# Sub-protocol data transmission, an encrypted tunnel through discv5

A sub-protocol session is used to send packets of a different protocol than discv5.

A sub-protocol session gets a different set of session keys than the discv5 session.
The trusted discv5 session is used to key-share, specifically the TALKREQ and TALKRESP.
A sub-protocol session can be used to send an arbitrary number of packets without making
the discv5 session less safe because it doesn't use the discv5 session's keys too often.

A sub-protocol session is indexed by the tuple (egress-id, ingress-id). The sub-protocol
session packet frame is (session-id, nonce, mac), in total 36 bytes. As the session-id is
unique for each session the frame doesn't need to masked. For this a sub-protocol session
frame is much lighter than a discv5 frame.

Plugged into discv5 here:
https://github.com/emhane/discv5/tree/tunnel-discv5.2
Relating to issues:
https://github.com/ethereum/devp2p/issues/229
https://github.com/ethereum/devp2p/issues/226
