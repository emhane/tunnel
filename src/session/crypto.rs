use aes_gcm::{
    aead::{generic_array::GenericArray, AeadMut, Payload},
    Aes128Gcm, Error as AesGcmError, KeyInit,
};
use rand;

/// Length of [`Aes128Gcm`] key in bytes.
pub const KEY_AES_GCM_128_LENGTH: usize = 16;
/// Length of [`Aes128Gcm`] nonce in bytes.
pub const NONCE_AES_GCM_LENGTH: usize = 12;
/// Length of the random bytes in a [`NonceAesGcm`].
pub const NONCE_RANDOM_LENGTH: usize = 8;
/// Length of [`aes_gcm::Tag`], the [`Aes128Gcm`] authentication data, in bytes.
pub const TAG_AES_GCM_ENGTH: usize = 2;

/// Nonce used by [`Aes128Gcm`].
pub type NonceAesGcm = [u8; NONCE_AES_GCM_LENGTH];

/// Key used for en-/decryption.
pub type Key = [u8; KEY_AES_GCM_128_LENGTH];

pub trait Encrypt {
    fn aes_gcm_128_encrypt(
        egress_key: &mut Key,
        nonce_counter: &mut u32,
        msg: &[u8],
    ) -> Result<Vec<u8>, AesGcmError> {
        let aad: &[u8; TAG_AES_GCM_ENGTH] = &rand::random();
        let payload = Payload { msg, aad };

        let nonce: [u8; NONCE_RANDOM_LENGTH] = rand::random();
        let mut nonce = nonce.to_vec();
        *nonce_counter += 1u32;
        nonce.append(&mut nonce_counter.to_be_bytes().to_vec());

        let mut cipher = Aes128Gcm::new(GenericArray::from_slice(egress_key));
        cipher.encrypt(GenericArray::from_slice(&nonce), payload)
    }
}

pub trait Decrypt {
    fn aes_gcm_128_decrypt(
        ingress_key: &Key,
        nonce: &NonceAesGcm,
        cipher_text: &[u8],
    ) -> Result<Vec<u8>, AesGcmError> {
        let offset_tag = cipher_text.len() - TAG_AES_GCM_ENGTH - 1;
        let aad = &cipher_text[offset_tag..];
        let msg = &cipher_text[..offset_tag];
        let payload = Payload { msg, aad };

        let mut cipher = Aes128Gcm::new(GenericArray::from_slice(ingress_key));

        cipher.decrypt(GenericArray::from_slice(nonce), payload)
    }
}
