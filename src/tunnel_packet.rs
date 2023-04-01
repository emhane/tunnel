use crate::PacketError;
use std::net::SocketAddr;

/// Discv5 max packet size.
pub const MAX_PACKET_SIZE: usize = 1280;
/// Tunnel packet min size, the message is at least 1 byte.
pub const MIN_PACKET_SIZE: usize = CONNECTION_ID_LENGTH + NONCE_LENGTH + 1;
/// Length of connection id.
pub const CONNECTION_ID_LENGTH: usize = 32;
/// Length of nonce.
pub const NONCE_LENGTH: usize = 12;

/// A connection id maps to a set of session keys.
pub type ConnectionId = [u8; CONNECTION_ID_LENGTH];
/// A message nonce used in encryption.
pub type Nonce = [u8; NONCE_LENGTH];

/// An src address and tunnel packet is inbound.
pub struct InboundTunnelPacket(pub SocketAddr, pub TunnelPacket);

/// A tunnel packet is a [`TunnelPacketHeader`] and an encrypted message belonging to another
/// protocol.

pub struct TunnelPacket(pub TunnelPacketHeader, pub Vec<u8>);

/// A tunnel packet header has the information to decrypt a tunnel packet. The [`ConnectionId`]
/// maps to a set of session keys for this tunnel, shared in a discv5 TALKREQ and TALKRESP.
pub struct TunnelPacketHeader(pub ConnectionId, pub Nonce);

impl TunnelPacket {
    pub fn decode(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() > MAX_PACKET_SIZE {
            return Err(PacketError::TooLarge.into());
        }
        if data.len() < MIN_PACKET_SIZE {
            return Err(PacketError::TooSmall.into());
        }

        let mut connection_id = [0u8; CONNECTION_ID_LENGTH];
        connection_id.copy_from_slice(&data[..32]);
        let mut nonce = [0u8; NONCE_LENGTH];
        nonce.copy_from_slice(&data[32..44]);

        let header = TunnelPacketHeader(connection_id, nonce);

        // Any remaining bytes are message data
        let encrypted_data = data[44..].to_vec();

        let packet = TunnelPacket(header, encrypted_data);

        Ok(packet)
    }
}
