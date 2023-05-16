use std::error::Error;
mod error;
mod macro_rules;
mod session;
mod tunnel_packet;

pub use error::{PacketError, SessionError, TunnelError};
pub use session::*;
pub use tunnel_packet::{
    InboundTunnelPacket, OutboundTunnelPacket, TunnelPacket, TunnelPacketHeader,
};

pub trait SubProtocol {
    type Error: Error;
    /// Send TALKREQ { initiator-secret, protocol-name }
    fn initiate_session() -> Result<Session, Self::Error>;
    fn accept_session() -> Result<Session, Self::Error>;
}
