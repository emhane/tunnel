use crate::tunnel_packet::HEADER_LENGTH;
use aes_gcm::{
    aead::{generic_array::GenericArray, AeadMut, Payload},
    Aes128Gcm, Error as AesGcmError, KeyInit,
};
use rand;
use zeroize::Zeroize;

/// Length of [`aes_gcm::Aes128Gcm`] key in bytes.
pub const KEY_AES_GCM_128_LENGTH: usize = 32;
/// Length of [`aes_gcm::Aes128Gcm`] nonce in bytes.
pub const NONCE_AES_GCM_128_LENGTH: usize = 12;
/// Length of [`aes_gcm::Tag`], the [`aes_gcm::Aes128Gcm`] authentication data, in bytes.
pub const TAG_AES_GCM_128_LENGTH: usize = 16;

/// A message nonce used in encryption.
pub type NonceAesGcm128 = [u8; NONCE_AES_GCM_128_LENGTH];
/// Key used in [`aes_gcm::Aes128Gcm`] encryption.
pub type KeyAesGcm128 = [u8; KEY_AES_GCM_128_LENGTH];
/// Additional associated data used in authenticating the encryption of tunnel packet.
pub type Aad = [u8; HEADER_LENGTH];

/// Key used in [`aes_gcm::Aes128Gcm`] encryption.
#[derive(Zeroize, PartialEq)]
pub struct EncryptionKey(KeyAesGcm128);

impl EncryptionKey {
    pub fn new() -> Self {
        let encryption_key: [u8; KEY_AES_GCM_128_LENGTH] = rand::random();
        EncryptionKey(encryption_key)
    }

    pub fn aes_gcm_128_encrypt(
        &self,
        nonce: &NonceAesGcm128,
        msg: &[u8],
        aad: &Aad,
    ) -> Result<Vec<u8>, AesGcmError> {
        let mut cipher = Aes128Gcm::new(GenericArray::from_slice(&self.0));
        let payload = Payload { msg, aad };
        cipher.encrypt(GenericArray::from_slice(nonce), msg)
    }

    pub fn aes_gcm_128_decrypt(
        &self,
        nonce: &NonceAesGcm128,
        msg: &[u8],
        aad: &Aad,
    ) -> Result<Vec<u8>, AesGcmError> {
        let mut cipher = Aes128Gcm::new(GenericArray::from_slice(&self.0));
        let payload = Payload { msg, aad };
        cipher.decrypt(GenericArray::from_slice(&msg), payload)
    }
}
