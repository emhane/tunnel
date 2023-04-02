use crate::{
    session::{NonceAesGcm128, NONCE_AES_GCM_128_LENGTH, TAG_AES_GCM_128_LENGTH},
    PacketError,
};
use std::net::SocketAddr;

/// Discv5 max packet size in bytes.
pub const MAX_PACKET_SIZE: usize = 1280;
/// Tunnel packet min size in bytes.
pub const MIN_PACKET_SIZE: usize = HEADER_LENGTH + MIN_ENCRYPTED_MESSAGE_LENGTH;
/// Length of the [`TunnelPacketHeader`].
pub const HEADER_LENGTH: usize = CONNECTION_ID_LENGTH + NONCE_AES_GCM_128_LENGTH;
/// Length of connection id.
pub const CONNECTION_ID_LENGTH: usize = 32;
/// Message min length in bytes.
pub const MIN_ENCRYPTED_MESSAGE_LENGTH: usize = MIN_MESSAGE_LENGTH + TAG_AES_GCM_128_LENGTH;
/// Message min length in bytes.
pub const MIN_MESSAGE_LENGTH: usize = 1;

/// A connection id maps to a set of session keys.
pub type ConnectionId = [u8; CONNECTION_ID_LENGTH];

/// An src address and tunnel packet is inbound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundTunnelPacket(pub SocketAddr, pub TunnelPacket);

/// An dst address and tunnel packet is outbound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundTunnelPacket(pub SocketAddr, pub TunnelPacket);

/// A tunnel packet is a [`TunnelPacketHeader`] and an encrypted message belonging to another
/// protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelPacket(pub TunnelPacketHeader, pub Vec<u8>);

/// A tunnel packet header has the information to decrypt a tunnel packet. The [`ConnectionId`]
/// maps to a set of session keys for this tunnel, shared in a discv5 TALKREQ and TALKRESP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelPacketHeader(pub ConnectionId, pub NonceAesGcm128);

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
        let mut nonce = [0u8; NONCE_AES_GCM_128_LENGTH];
        nonce.copy_from_slice(&data[32..44]);

        let header = TunnelPacketHeader(connection_id, nonce);

        // Any remaining bytes are message data
        let encrypted_data = data[44..].to_vec();

        if encrypted_data.len() < MIN_ENCRYPTED_MESSAGE_LENGTH {
            return Err(PacketError::TooSmall);
        }

        let packet = TunnelPacket(header, encrypted_data);

        Ok(packet)
    }
}
