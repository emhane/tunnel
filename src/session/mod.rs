use std::net::SocketAddr;

mod crypto;

pub use crypto::{
    AesGcmError, Cipher, Decrypt, Encrypt, GenericArray, HkdfError, Nonce, Secret, SessionId,
    KEY_LENGTH, NONCE_LENGTH, SECRET_LENGTH, SESSION_ID_LENGTH, TAG_LENGTH,
};

pub type Session = (EgressSession<Cipher>, IngressSession<Cipher>);
pub(crate) type NonceCounter = u32;

/// A session to encrypt outgoing data.
pub struct EgressSession<T> {
    /// Index of egress session.
    egress_id: SessionId,
    /// The cipher used to encrypt messages.
    egress_cipher: T,
    /// Nonce counter. Incremented before encrypting each message and included at end of nonce in
    /// encryption.
    nonce_counter: NonceCounter,
    /// Ip socket to send packet to.
    ip: SocketAddr,
}

impl EgressSession<Cipher> {
    pub fn encrypt(&mut self, msg: &[u8], aad: &[u8]) -> Result<Vec<u8>, AesGcmError> {
        <Self as Encrypt>::aes_gcm_encrypt(
            &mut self.egress_cipher,
            &mut self.nonce_counter,
            msg,
            aad,
        )
    }
}

impl Encrypt for EgressSession<Cipher> {}

/// A session to decrypt incoming data.
pub struct IngressSession<T> {
    /// Index of ingress session.
    ingress_id: SessionId,
    /// The cipher used to decrypt messages.
    ingress_cipher: T,
    /// Index of matching egress session to treat sessions as invariant.
    egress_id: SessionId,
}

impl IngressSession<Cipher> {
    pub fn decrypt(
        &mut self,
        nonce: &Nonce,
        data: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, AesGcmError> {
        <Self as Decrypt>::aes_gcm_decrypt(&mut self.ingress_cipher, nonce, data, aad)
    }
}

impl Decrypt for IngressSession<Cipher> {}

pub trait EstablishSession {
    fn initiate(
        peer_secret: Secret,
        recipient_socket: SocketAddr,
        protocol_name: &[u8],
        host_secret: Secret,
    ) -> Result<Session, HkdfError> {
        let ((ingress_id, ingress_cipher), (egress_id, egress_cipher)) =
            crypto::compute_ciphers_and_ids(peer_secret, protocol_name, host_secret)?;

        let session = new_session(
            egress_id,
            egress_cipher,
            recipient_socket,
            ingress_id,
            ingress_cipher,
        );

        Ok(session)
    }

    fn accept(
        peer_secret: Secret,
        initiator_socket: SocketAddr,
        protocol_name: &[u8],
    ) -> Result<(Session, Secret), HkdfError> {
        let key: [u8; SECRET_LENGTH] = rand::random();

        let ((egress_id, egress_cipher), (ingress_id, ingress_cipher)) =
            crypto::compute_ciphers_and_ids(peer_secret, protocol_name, key)?;

        let session = new_session(
            egress_id,
            egress_cipher,
            initiator_socket,
            ingress_id,
            ingress_cipher,
        );

        Ok((session, key))
    }
}

fn new_session(
    egress_id: SessionId,
    egress_cipher: Cipher,
    remote_socket: SocketAddr,
    ingress_id: SessionId,
    ingress_cipher: Cipher,
) -> Session {
    let egress = EgressSession {
        egress_id,
        egress_cipher,
        nonce_counter: 0,
        ip: remote_socket,
    };
    let ingress = IngressSession {
        ingress_id,
        ingress_cipher,
        egress_id,
    };
    (egress, ingress)
}
