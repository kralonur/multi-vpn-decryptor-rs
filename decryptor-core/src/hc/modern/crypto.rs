//! Build-899 (v4) and build-934 (v5) native HMAC key derivation and AEAD.

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
const V4_IPAD_STATE: [u32; 8] = [
    0x82515a9a, 0xf6ec05fc, 0xf650b6cd, 0x523f8ce6, 0xedf419ec, 0x1d6d6573, 0x66ff1b89, 0xf40a0181,
];
const V4_OPAD_STATE: [u32; 8] = [
    0x82185b01, 0x35cb48be, 0xdb6c3846, 0xbd714ec5, 0x627728af, 0xdbaae4db, 0x463fbf8d, 0x88a24381,
];
// SHA-256 states after the native v5 HMAC's 64-byte ipad/opad blocks.
const V5_IPAD_STATE: [u32; 8] = [
    0xaabd3a1e, 0x3d63a211, 0xe615b378, 0x46a07517, 0x11f5cab4, 0xa7aef829, 0x83c7543b, 0x2d971ab7,
];
const V5_OPAD_STATE: [u32; 8] = [
    0x423fcb79, 0xc4dd3dc8, 0x57d814ac, 0x1660ed59, 0xdbb328b7, 0xcc389261, 0x06f1803e, 0xe3130c6b,
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

fn derive_native_key(
    domain: u8,
    ipad: [u32; 8],
    opad: [u32; 8],
    prefix: &[u8],
    salt: &[u8],
    info: &[u8],
) -> [u8; 32] {
    let mut material = Vec::with_capacity(1 + CERTIFICATE_DIGEST.len() + prefix.len());
    material.push(domain);
    material.extend_from_slice(&CERTIFICATE_DIGEST);
    material.extend_from_slice(prefix);
    let inner = finish_hmac_state(ipad, &material);
    let ikm = finish_hmac_state(opad, &inner);
    hkdf_sha256_expand_one(salt, &ikm, info)
}

fn hkdf_sha256_expand_one(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hmac(salt, ikm);
    let mut expand = Vec::with_capacity(info.len() + 1);
    expand.extend_from_slice(info);
    expand.push(1);
    hmac(&prk, &expand)
}

pub(super) fn derive_key(prefix: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    derive_native_key(0xe9, V4_IPAD_STATE, V4_OPAD_STATE, prefix, salt, info)
}

pub(super) fn derive_v5_key(aad: &[u8], salt: &[u8]) -> [u8; 32] {
    derive_native_key(
        0xf1,
        V5_IPAD_STATE,
        V5_OPAD_STATE,
        aad,
        salt,
        b"hc-config-content-v12",
    )
}

pub(super) fn derive_v5_part_key(session_key: &[u8; 32], section_aad: &[u8]) -> [u8; 32] {
    hkdf_sha256_expand_one(b"hc-config-part-v12", session_key, section_aad)
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
