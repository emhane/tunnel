use crate::impl_from_variant_wrap;

#[derive(Debug)]
pub enum TunnelError {
    PacketError(PacketError),
}

#[derive(Debug)]
pub enum PacketError {
    TooLarge,
    TooSmall,
}

impl_from_variant_wrap!(,PacketError, TunnelError, Self::PacketError);
