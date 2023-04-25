use crate::tunnel_packet::HEADER_LENGTH;
use aes_gcm::{
    aead::{generic_array::GenericArray, AeadMut, Payload},
    Aes128Gcm, Error as AesGcmError, KeyInit,
};
use rand;

/// Length of [`aes_gcm::Aes128Gcm`] key in bytes.
pub const KEY_AES_GCM_128_LENGTH: usize = 32;
/// Length of [`aes_gcm::Aes128Gcm`] nonce in bytes.
pub const NONCE_AES_GCM_128_LENGTH: usize = 12;
/// Length of [`aes_gcm::Tag`], the [`aes_gcm::Aes128Gcm`] authentication data, in bytes.
pub const TAG_AES_GCM_128_LENGTH: usize = 16;

/// A message nonce used in encryption.
pub type NonceAesGcm128 = [u8; NONCE_AES_GCM_128_LENGTH];
/// Additional associated data used in authenticating the encryption of tunnel packet.
pub type Aad = [u8; HEADER_LENGTH];

/// Cipher used in [`aes_gcm::Aes128Gcm`] encryption.
pub struct Cipher(Aes128Gcm);

impl Cipher {
    pub fn new() -> Self {
        let encryption_key: [u8; KEY_AES_GCM_128_LENGTH] = rand::random();
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&encryption_key));
        Cipher(cipher)
    }

    pub fn aes_gcm_128_encrypt(
        &mut self,
        nonce: &NonceAesGcm128,
        msg: &[u8],
        aad: &Aad,
    ) -> Result<Vec<u8>, AesGcmError> {
        let payload = Payload { msg, aad };
        self.0.encrypt(GenericArray::from_slice(nonce), payload)
    }

    pub fn aes_gcm_128_decrypt(
        &mut self,
        nonce: &NonceAesGcm128,
        msg: &[u8],
        aad: &Aad,
    ) -> Result<Vec<u8>, AesGcmError> {
        let payload = Payload { msg, aad };
        self.0.decrypt(GenericArray::from_slice(nonce), payload)
    }
}
