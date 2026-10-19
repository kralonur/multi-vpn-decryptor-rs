//! Build-899 native HMAC key derivation and authenticated encryption.

use super::{HcError, TAG_BYTES};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hex_literal::hex;
use sha2::{Digest, Sha256, block_api::compress256};

const CERTIFICATE_DIGEST: [u8; 32] =
    hex!("95dd433d7e4a0be02d55cc62553edcfc8f077fe780be5a7da7f861c2558dc181");
// SHA-256 states after the native v4 HMAC's 64-byte ipad/opad blocks.
const IPAD_STATE: [u32; 8] = [
    0x82515a9a, 0xf6ec05fc, 0xf650b6cd, 0x523f8ce6, 0xedf419ec, 0x1d6d6573, 0x66ff1b89, 0xf40a0181,
];
const OPAD_STATE: [u32; 8] = [
    0x82185b01, 0x35cb48be, 0xdb6c3846, 0xbd714ec5, 0x627728af, 0xdbaae4db, 0x463fbf8d, 0x88a24381,
];

fn finish_hmac_state(mut state: [u32; 8], data: &[u8]) -> [u8; 32] {
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&((64 + data.len()) as u64 * 8).to_be_bytes());
    compress256(&mut state, padded.as_chunks::<64>().0);
    let mut out = [0; 32];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub(super) fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    inner.update(data);
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

pub(super) fn derive_key(prefix: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut material = vec![0xe9];
    material.extend_from_slice(&CERTIFICATE_DIGEST);
    material.extend_from_slice(prefix);
    let inner = finish_hmac_state(IPAD_STATE, &material);
    let ikm = finish_hmac_state(OPAD_STATE, &inner);
    let prk = hmac(salt, &ikm);
    let mut expand = info.to_vec();
    expand.push(1);
    hmac(&prk, &expand)
}

pub(super) fn open(
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, HcError> {
    if ciphertext.len() < TAG_BYTES {
        return Err(HcError::ModernAuthentication);
    }
    let nonce = XNonce::try_from(nonce).map_err(|_| HcError::ModernAuthentication)?;
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| HcError::ModernAuthentication)
}
