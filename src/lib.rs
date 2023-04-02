use async_trait::async_trait;

mod error;
mod macro_rules;
mod session;
mod tunnel_packet;

pub use error::{PacketError, SessionError, TunnelError};
pub use session::Session;
pub use tunnel_packet::{ConnectionId, InboundTunnelPacket, TunnelPacket, TunnelPacketHeader};

#[async_trait]
pub trait Tunnel {
    /// Decrypt.
    async fn on_inbound_tunnel_packet(
        &mut self,
        packet: InboundTunnelPacket,
    ) -> Result<(), TunnelError>;
    /// Encrypt.
    async fn on_outbound_tunnel_packet(&mut self) -> Result<(), TunnelError>;
    /// The app sent a notification to close the tunnel.
    async fn on_close_tunnel(&mut self, conn_id: ConnectionId) -> Result<(), TunnelError>;
    /// Receive [`ConnectionId`] and make and share session keys.
    async fn on_talk_req(&mut self) -> Result<(), TunnelError>;
    /// Receive shared session keys.
    async fn on_talk_resp(&mut self) -> Result<(), TunnelError>;
}
