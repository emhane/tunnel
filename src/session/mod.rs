use hkdf::{Hkdf, InvalidLength as HkdfError};
use rand;
use sha2::Sha256;
use std::net::SocketAddr;

mod crypto;

pub use crypto::{
    Key, NonceAesGcm, KEY_AES_GCM_128_LENGTH, NONCE_AES_GCM_LENGTH, TAG_AES_GCM_ENGTH,
};

pub const SESSION_INFO: &'static [u8] = b"discv5 sub-protocol session";
pub const SECRET_LENGTH: usize = 16;
pub const KDATA_LENGTH: usize = 48;
pub const SESSION_ID_LENGTH: usize = 8;
type Secret = [u8; SECRET_LENGTH];
type KData = [u8; KDATA_LENGTH];
type SessionId = u64;
type Initiator = (SessionId, Key);
type Recipient = (SessionId, Key);

pub type Session = (EgressSession, IngressSession);

/// A session to encrypt outgoing data.
pub struct EgressSession {
    /// Index of egress session.
    egress_id: u64,
    /// The key used to encrypt messages.
    egress_key: Key,
    /// Nonce counter. Incremented before encrypting each message and included at end of nonce in
    /// encryption.
    nonce_counter: u32,
    /// Ip socket to send packet to.
    ip: SocketAddr,
}

/// A session to decrypt incoming data.
pub struct IngressSession {
    /// Index of ingress session.
    ingress_id: u64,
    /// The key used to decrypt messages.
    ingress_key: Key,
    /// Index of matching egress session to treat sessions as invariant.
    egress_id: u64,
}

pub trait EstablishSession {
    fn initiate(
        peer_secret: Secret,
        recipient_socket: SocketAddr,
        protocol_name: &[u8],
        host_secret: Secret,
    ) -> Result<Session, HkdfError> {
        let ((ingress_id, ingress_key), (egress_id, egress_key)) =
            compute_kdata(peer_secret, protocol_name, host_secret)?;

        let session = new_session(
            egress_id,
            egress_key,
            recipient_socket,
            ingress_id,
            ingress_key,
        );

        Ok(session)
    }

    fn accept(
        peer_secret: Secret,
        initiator_socket: SocketAddr,
        protocol_name: &[u8],
    ) -> Result<(Session, Secret), HkdfError> {
        let secret: [u8; SECRET_LENGTH] = rand::random();

        let ((egress_id, egress_key), (ingress_id, ingress_key)) =
            compute_kdata(peer_secret, protocol_name, secret)?;

        let session = new_session(
            egress_id,
            egress_key,
            initiator_socket,
            ingress_id,
            ingress_key,
        );

        Ok((session, secret))
    }
}

fn compute_kdata(
    peer_secret: Secret,
    protocol_name: &[u8],
    host_secret: Secret,
) -> Result<(Initiator, Recipient), HkdfError> {
    let info = [SESSION_INFO, protocol_name].concat();
    let hk = Hkdf::<Sha256>::new(None, &[peer_secret, host_secret].concat());
    let mut kdata = [0u8; KDATA_LENGTH];
    hk.expand(&info, &mut kdata)?;

    let mut initiator_key = [0u8; KEY_AES_GCM_128_LENGTH];
    let mut recipient_key = [0u8; KEY_AES_GCM_128_LENGTH];
    let mut initiator_id = [0u8; SESSION_ID_LENGTH];
    let mut recipient_id = [0u8; SESSION_ID_LENGTH];

    initiator_key.copy_from_slice(&kdata[..KEY_AES_GCM_128_LENGTH]);
    recipient_key.copy_from_slice(&kdata[KEY_AES_GCM_128_LENGTH..KEY_AES_GCM_128_LENGTH * 2]);
    initiator_id
        .copy_from_slice(&kdata[KEY_AES_GCM_128_LENGTH * 2..KDATA_LENGTH - SESSION_ID_LENGTH]);
    recipient_id.copy_from_slice(&kdata[KDATA_LENGTH - SESSION_ID_LENGTH..]);

    let initiator_id = u64::from_be_bytes(initiator_id);
    let recipient_id = u64::from_be_bytes(recipient_id);

    Ok(((initiator_id, initiator_key), (recipient_id, recipient_key)))
}

fn new_session(
    egress_id: SessionId,
    egress_key: Key,
    remote_socket: SocketAddr,
    ingress_id: SessionId,
    ingress_key: Key,
) -> Session {
    let egress = EgressSession {
        egress_id,
        egress_key,
        nonce_counter: 0,
        ip: remote_socket,
    };
    let ingress = IngressSession {
        ingress_id,
        ingress_key,
        egress_id,
    };
    (egress, ingress)
}
