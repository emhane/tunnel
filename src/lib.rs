use std::error::Error;
mod error;
mod macro_rules;
mod session;
mod tunnel_packet;

pub use error::{PacketError, SessionError, TunnelError};
pub use session::{NonceAesGcm, Session, SESSION_ID_LENGTH};
pub use tunnel_packet::{
    ConnectionId, InboundTunnelPacket, OutboundTunnelPacket, TunnelPacket, TunnelPacketHeader,
};

pub trait SubProtocol {
    type Error: Error;
    /// Send TALKREQ { initiator-secret, protocol-name }
    fn initiate_session() -> Result<Session, Self::Error>;
    fn accept_session() -> Result<Session, Self::Error>;
}
