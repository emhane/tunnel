use super::*;
use crate::{
    tunnel_packet::{CONNECTION_ID_LENGTH, HEADER_LENGTH},
    SessionError, TunnelPacket, TunnelPacketHeader,
};
use rand;

mod crypto;

pub use crypto::{
    Aad, EncryptionKey, NonceAesGcm128, NONCE_AES_GCM_128_LENGTH, TAG_AES_GCM_128_LENGTH,
};

/// A Session holds the key chain used to encrypt a [`TunnelPacket`], it uses the same encryption
/// algorithm as discv5.
pub struct Session {
    /// The key used to encrypt/decrypt messages. Upon starting a session, the key will be passed
    /// from one peer to the other in an encrypted discv5 session using the TALKREQ message.
    key: EncryptionKey,
    /// If a new session is being established using discv5 TALKREQ and TALKRESP, the older key
    /// is maintained as race conditions in the key sharing can give different views of which
    /// keys are canon. The key that worked to decrypt our last message (or are freshly
    /// established) exist in `key` and the previous key is optionally stored in `old_key`. We
    /// attempt to decrypt messages with `key` before optionally trying `old_key`.
    old_key: Option<EncryptionKey>,
    /// Number of messages sent. Used to ensure the nonce used in message encryption is always
    /// unique.
    counter: u32,
}

impl Session {
    pub fn new(keys: EncryptionKey) -> Self {
        Session {
            key: keys,
            old_key: None,
            counter: 0,
        }
    }

    /// A new session has been established. Update the session keys.
    pub fn update(&mut self, new_session: Session) {
        // Optimistically assume the new keys are canonical.
        self.old_key = Some(std::mem::replace(&mut self.key, new_session.key));
    }

    /// Uses the current `Session` to encrypt a message. Encrypt packets with the current session
    /// key if we are awaiting
    pub fn encrypt_message(
        &mut self,
        connection_id: ConnectionId,
        msg: &[u8],
    ) -> Result<TunnelPacket, SessionError> {
        self.counter += 1;

        // If the message nonce length is ever set below 4 bytes this will explode. The packet
        // size constants shouldn't be modified.
        let random_nonce: [u8; NONCE_AES_GCM_128_LENGTH - 4] = rand::random();
        let mut nonce: NonceAesGcm128 = [0u8; NONCE_AES_GCM_128_LENGTH];
        nonce[..4].copy_from_slice(&self.counter.to_be_bytes());
        nonce[4..].copy_from_slice(&random_nonce);

        // As the connection id-nonce mapping is unique for every packet, the header serves the
        // purpose of additional associated data.
        let mut aad = [0u8; HEADER_LENGTH];
        aad[..CONNECTION_ID_LENGTH].copy_from_slice(&connection_id);
        aad[CONNECTION_ID_LENGTH..].copy_from_slice(&nonce);
        let cipher_text = self.key.aes_gcm_128_encrypt(&nonce, msg, &aad)?;

        let header = TunnelPacketHeader(connection_id, nonce);

        Ok(TunnelPacket(header, cipher_text))
    }

    /// Decrypts an encrypted message. If a Session is already established, the original decryption
    /// keys are tried first, upon failure, the new keys are attempted. If the new keys succeed,
    /// the session keys are update.
    pub fn decrypt_message(
        &mut self,
        nonce: NonceAesGcm128,
        msg: &[u8],
        aad: &Aad,
    ) -> Result<Vec<u8>, SessionError> {
        // First try with the canonical keys.
        match self.key.aes_gcm_128_decrypt(&nonce, msg, aad) {
            Ok(decrypted) => Ok(decrypted),
            Err(e) => {
                // If these keys did not work, try old_keys and
                if let Some(old_keys) = self.old_key.take() {
                    let decrypted_old_keys = old_keys.aes_gcm_128_decrypt(&nonce, msg, aad)?;
                    // rotate the keys
                    self.old_key = Some(std::mem::replace(&mut self.key, old_keys));
                    return Ok(decrypted_old_keys);
                }
                return Err(SessionError::EncryptionError(e));
            }
        }
    }
}
