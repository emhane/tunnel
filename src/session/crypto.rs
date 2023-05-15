use super::NonceCounter;
pub use aes_gcm::{
    aead::generic_array::GenericArray, aes::cipher::Unsigned, Aes128Gcm as Cipher,
    Error as AesGcmError, KeyInit,
};
use aes_gcm::{aead::AeadMutInPlace, AeadCore, KeySizeUser, Nonce as NonceAesGcm};
use hkdf::Hkdf;
pub use hkdf::InvalidLength as HkdfError;
use rand;
use sha2::Sha256;

/// Length of key in bytes.
pub const KEY_LENGTH: usize = <Cipher as KeySizeUser>::KeySize::USIZE;
/// Length of nonce in bytes.
pub const NONCE_LENGTH: usize = <Cipher as AeadCore>::NonceSize::USIZE;
/// Length of the random bytes in a [`Nonce`].
pub const NONCE_RANDOM_LENGTH: usize = NONCE_LENGTH - (NonceCounter::BITS / 8) as usize;
/// Length of mac in bytes.
pub const TAG_LENGTH: usize = <Cipher as AeadCore>::TagSize::USIZE;
/// Length of secret used to compute key data in bytes.
pub const SECRET_LENGTH: usize = 16;
/// Length of key data in bytes.
pub const KDATA_LENGTH: usize = SESSION_ID_LENGTH * 2 + KEY_LENGTH * 2;
/// Length of session id derived from key data.
pub const SESSION_ID_LENGTH: usize = 8;
/// Protocol identifier used to compute key data.
pub const SESSION_INFO: &'static [u8] = b"discv5 sub-protocol session";

/// Nonce used by [`Cipher`].
pub type Nonce = NonceAesGcm<<Cipher as AeadCore>::NonceSize>;
pub type SessionId = u64;
pub type Secret = [u8; SECRET_LENGTH];

type Initiator = (SessionId, Cipher);
type Recipient = (SessionId, Cipher);

pub trait Encrypt {
    fn aes_gcm_encrypt(
        egress_cipher: &mut Cipher,
        nonce_counter: &mut NonceCounter,
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
    fn aes_gcm_decrypt(
        ingress_cipher: &mut Cipher,
        nonce: &Nonce,
        data: &[u8],
        aad: &[u8], // use session-id
    ) -> Result<Vec<u8>, AesGcmError> {
        let offset_tag = data.len() - TAG_LENGTH - 1;
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

pub(crate) fn compute_ciphers_and_ids(
    peer_secret: Secret,
    protocol_name: &[u8],
    host_secret: Secret,
) -> Result<(Initiator, Recipient), HkdfError> {
    let info = [SESSION_INFO, protocol_name].concat();
    let hk = Hkdf::<Sha256>::new(None, &[peer_secret, host_secret].concat());
    let mut kdata = [0u8; KDATA_LENGTH];
    hk.expand(&info, &mut kdata)?;

    let initiator_cipher = Cipher::new(GenericArray::from_slice(&kdata[..KEY_LENGTH]));
    let recipient_cipher =
        Cipher::new(GenericArray::from_slice(&kdata[KEY_LENGTH..KEY_LENGTH * 2]));

    let mut initiator_id = [0u8; SESSION_ID_LENGTH];
    let mut recipient_id = [0u8; SESSION_ID_LENGTH];

    initiator_id.copy_from_slice(&kdata[KEY_LENGTH * 2..KDATA_LENGTH - SESSION_ID_LENGTH]);
    recipient_id.copy_from_slice(&kdata[KDATA_LENGTH - SESSION_ID_LENGTH..]);
    let initiator_id = SessionId::from_be_bytes(initiator_id);
    let recipient_id = SessionId::from_be_bytes(recipient_id);

    Ok((
        (initiator_id, initiator_cipher),
        (recipient_id, recipient_cipher),
    ))
}
