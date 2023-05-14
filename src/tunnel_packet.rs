use crate::{
    session::{NonceAesGcm, SessionId, NONCE_AES_GCM_LENGTH, SESSION_ID_LENGTH, TAG_AES_GCM_ENGTH},
    PacketError,
};
use std::net::SocketAddr;

/// Discv5 max packet size in bytes.
pub const MAX_PACKET_SIZE: usize = 1280;
/// Tunnel packet min size in bytes.
pub const MIN_PACKET_SIZE: usize = HEADER_LENGTH + TAG_AES_GCM_ENGTH;
/// Length of the [`TunnelPacketHeader`].
pub const HEADER_LENGTH: usize = SESSION_ID_LENGTH + NONCE_AES_GCM_LENGTH;

/// Src address and inbound tunnel packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundTunnelPacket(pub SocketAddr, pub TunnelPacket);

/// Dst address and outbound tunnel packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundTunnelPacket(pub SocketAddr, pub TunnelPacket);

/// A tunnel packet is a [`TunnelPacketHeader`] and an encrypted message belonging to another
/// protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelPacket(pub TunnelPacketHeader, pub Vec<u8>);

/// A tunnel packet header has the information to decrypt a tunnel packet. The [`ConnectionId`]
/// maps to a set of session keys for this tunnel, shared in a discv5 TALKREQ and TALKRESP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelPacketHeader(pub SessionId, pub NonceAesGcm);

impl TunnelPacket {
    pub fn decode(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() > MAX_PACKET_SIZE {
            return Err(PacketError::TooLarge);
        }
        if data.len() < MIN_PACKET_SIZE {
            return Err(PacketError::TooSmall);
        }

        let mut session_id = [0u8; SESSION_ID_LENGTH];
        let mut nonce = [0u8; NONCE_AES_GCM_LENGTH];

        session_id.copy_from_slice(&data[..SESSION_ID_LENGTH]);
        nonce.copy_from_slice(&data[SESSION_ID_LENGTH..HEADER_LENGTH]);

        let header = TunnelPacketHeader(u64::from_be_bytes(session_id), nonce);

        // Any remaining bytes are message data
        let data = data[HEADER_LENGTH..].to_vec();

        Ok(TunnelPacket(header, data))
    }

    pub fn encode(self) -> Vec<u8> {
        let TunnelPacket(header, data) = self;
        let TunnelPacketHeader(session_id, nonce) = header;
        let mut buf = Vec::with_capacity(HEADER_LENGTH + data.len());
        buf.extend_from_slice(&session_id.to_be_bytes());
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&data);
        buf
    }
}
