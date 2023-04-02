use crate::impl_from_variant_wrap;
use aes_gcm::Error as AesGcmError;
use std::{error::Error, fmt, fmt::Display};

#[derive(Debug)]
pub enum TunnelError {
    PacketError(PacketError),
    SessionError(SessionError),
}

impl_from_variant_wrap!(,PacketError, TunnelError, Self::PacketError);
impl_from_variant_wrap!(,SessionError, TunnelError, Self::SessionError);

impl Error for TunnelError {}

impl Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketError(e) => write!(f, "tunnel error, {}", e),
            Self::SessionError(e) => write!(f, "tunnel error, {}", e),
        }
    }
}

#[derive(Debug)]
pub enum PacketError {
    TooLarge,
    TooSmall,
}

impl Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(f, "packet error, too large"),
            Self::TooSmall => write!(f, "packet error, too small"),
        }
    }
}

#[derive(Debug)]
pub enum SessionError {
    EncryptionError(AesGcmError),
}

impl_from_variant_wrap!(, AesGcmError, SessionError, Self::EncryptionError);

impl Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncryptionError(e) => write!(f, "session error, {}", e),
        }
    }
}
