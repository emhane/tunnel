# tunnel

A tunnel is used to send packets of a different protocol than discv5.

A tunnel packet passes through the same socket as a discv5 packet so it can make use of
discv5's punched NAT holes. A tunnel gets a different set of session keys than the discv5 session
used to share those keys, in TALKREQ and TALKRESP. A tunnel session can be used to send an
arbitrary number of packets without making the discv5 session less safe because it doesn't use
the discv5 session's keys too often.

A tunnel is indexed by the tuple (sr-address, connection-id). Since the connection id is a 32 byte
hash, there is no need to mask the header of a tunnel packet to protect against packet filtering.
For this a tunnel packet is much lighter than a discv5 frame.

Plugged into discv5: https://github.com/emhane/discv5/tree/tunnel-discv5.2

@emhane [@fjl](https://github.com/fjl)
