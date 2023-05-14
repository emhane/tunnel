use aes_gcm::{aead::generic_array::GenericArray, Aes128Gcm, KeyInit};
use hkdf::{Hkdf, InvalidLength as HkdfError};
use rand;
use sha2::Sha256;
use std::net::SocketAddr;

mod crypto;

pub use crypto::{NonceAesGcm, KEY_AES_GCM_128_LENGTH, NONCE_AES_GCM_LENGTH, TAG_AES_GCM_ENGTH};

pub const SESSION_INFO: &'static [u8] = b"discv5 sub-protocol session";
pub const SECRET_LENGTH: usize = 16;
pub const KDATA_LENGTH: usize = 48;
pub const SESSION_ID_LENGTH: usize = 8;
type Secret = [u8; SECRET_LENGTH];
type KData = [u8; KDATA_LENGTH];
pub type SessionId = u64;
type Initiator = (SessionId, Aes128Gcm);
type Recipient = (SessionId, Aes128Gcm);

pub type Session = (EgressSession, IngressSession);

/// A session to encrypt outgoing data.
pub struct EgressSession {
    /// Index of egress session.
    egress_id: u64,
    /// The cipher used to encrypt messages.
    egress_cipher: Aes128Gcm,
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
    /// The cipher used to decrypt messages.
    ingress_cipher: Aes128Gcm,
    /// Nonce counter used to verify integrity of ingress stream.
    nonce_counter: u32,
    /// Index of matching egress session to treat sessions as invariant.
    egress_id: u64,
}

pub trait EstablishSession {
    fn initiate(
        peer_key: Secret,
        recipient_socket: SocketAddr,
        protocol_name: &[u8],
        host_key: Secret,
    ) -> Result<Session, HkdfError> {
        let ((ingress_id, ingress_key), (egress_id, egress_key)) =
            compute_ciphers_and_ids(peer_key, protocol_name, host_key)?;

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
        peer_key: Secret,
        initiator_socket: SocketAddr,
        protocol_name: &[u8],
    ) -> Result<(Session, Secret), HkdfError> {
        let key: [u8; SECRET_LENGTH] = rand::random();

        let ((egress_id, egress_key), (ingress_id, ingress_key)) =
            compute_ciphers_and_ids(peer_key, protocol_name, key)?;

        let session = new_session(
            egress_id,
            egress_key,
            initiator_socket,
            ingress_id,
            ingress_key,
        );

        Ok((session, key))
    }
}

fn compute_ciphers_and_ids(
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

    initiator_id
        .copy_from_slice(&kdata[KEY_AES_GCM_128_LENGTH * 2..KDATA_LENGTH - SESSION_ID_LENGTH]);
    let initiator_id = u64::from_be_bytes(initiator_id);
    recipient_id.copy_from_slice(&kdata[KDATA_LENGTH - SESSION_ID_LENGTH..]);
    let recipient_id = u64::from_be_bytes(recipient_id);

    let initiator_cipher =
        Aes128Gcm::new(GenericArray::from_slice(&kdata[..KEY_AES_GCM_128_LENGTH]));
    let recipient_cipher = Aes128Gcm::new(GenericArray::from_slice(
        &kdata[KEY_AES_GCM_128_LENGTH..KEY_AES_GCM_128_LENGTH * 2],
    ));

    Ok((
        (initiator_id, initiator_cipher),
        (recipient_id, recipient_cipher),
    ))
}

fn new_session(
    egress_id: SessionId,
    egress_key: Aes128Gcm,
    remote_socket: SocketAddr,
    ingress_id: SessionId,
    ingress_key: Aes128Gcm,
) -> Session {
    let egress = EgressSession {
        egress_id,
        egress_cipher: egress_key,
        nonce_counter: 0,
        ip: remote_socket,
    };
    let ingress = IngressSession {
        ingress_id,
        ingress_cipher: ingress_key,
        nonce_counter: 0,
        egress_id,
    };
    (egress, ingress)
}
