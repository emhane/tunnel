use aes_gcm::{
    aead::{generic_array::GenericArray, AeadMutInPlace, Payload},
    Aes128Gcm, Error as AesGcmError,
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

pub trait Encrypt {
    fn aes_gcm_128_encrypt(
        egress_cipher: &mut Aes128Gcm,
        nonce_counter: &mut u32,
        msg: &[u8],
        aad: &[u8], // use session-id
    ) -> Result<Vec<u8>, AesGcmError> {
        *nonce_counter += 1;
        let random_nonce: [u8; NONCE_RANDOM_LENGTH] = rand::random();
        let mut nonce = random_nonce.to_vec();
        nonce.append(&mut nonce_counter.to_be_bytes().to_vec());
        let nonce = GenericArray::from_slice(&nonce);

        let mut buf = msg.to_vec();

        let tag = egress_cipher.encrypt_in_place_detached(nonce, aad, &mut buf)?;
        buf.append(&mut tag.to_vec());

        Ok(buf)
    }
}

pub trait Decrypt {
    fn aes_gcm_128_decrypt(
        ingress_cipher: &mut Aes128Gcm,
        nonce: &NonceAesGcm,
        data: &[u8],
        aad: &[u8], // use session-id
    ) -> Result<Vec<u8>, AesGcmError> {
        let offset_tag = data.len() - TAG_AES_GCM_ENGTH - 1;
        let msg = &data[..offset_tag];
        let tag = &data[offset_tag..];

        let mut buf = msg.to_vec();

        ingress_cipher.decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            aad,
            &mut buf,
            GenericArray::from_slice(tag),
        )?;

        Ok(buf)
    }
}
