// Image watermark — spread-spectrum LSB across the blue channel.
//
// Frame format (96 bytes = 768 bits):
//   [0-7]   drand_round    u64 LE
//   [8-23]  drand_payload  16 bytes  (HKDF-SHA256 of drand signature)
//   [24-31] device_id       8 bytes  (SHA-256(pubkey)[0..8])
//   [32-95] Ed25519 sig    64 bytes  (signs: "signet-v3" || round || device_id || payload || pixel_hash)
//
// Robustness: each of the 768 bits is spread across every 768th pixel
// (blue channel LSB). A 12 MP image gives ~15 600 votes per bit.
// Majority-vote extraction survives JPEG Q>=90 and moderate editing.

use sha2::{Digest, Sha256};

pub const FRAME_BYTES: usize = 96;
const BITS: usize = FRAME_BYTES * 8; // 768

pub fn build_frame(
    drand_round: u64,
    drand_payload: &[u8; 16],
    device_id: &[u8; 8],
    sig: &[u8; 64],
) -> [u8; FRAME_BYTES] {
    let mut frame = [0u8; FRAME_BYTES];
    frame[0..8].copy_from_slice(&drand_round.to_le_bytes());
    frame[8..24].copy_from_slice(drand_payload);
    frame[24..32].copy_from_slice(device_id);
    frame[32..96].copy_from_slice(sig);
    frame
}

pub struct ParsedFrame {
    pub drand_round: u64,
    pub drand_payload: [u8; 16],
    pub device_id: [u8; 8],
    pub signature: [u8; 64],
}

pub fn parse_frame(frame: &[u8; FRAME_BYTES]) -> ParsedFrame {
    ParsedFrame {
        drand_round: u64::from_le_bytes(frame[0..8].try_into().unwrap()),
        drand_payload: frame[8..24].try_into().unwrap(),
        device_id:    frame[24..32].try_into().unwrap(),
        signature:    frame[32..96].try_into().unwrap(),
    }
}

/// SHA-256 of the raw pixel buffer, bound into the Ed25519 signature so a
/// frame cannot be transplanted from one image into another.
pub fn pixel_commitment(pixels: &[u8]) -> [u8; 32] {
    Sha256::digest(pixels).into()
}

fn frame_to_bits(frame: &[u8; FRAME_BYTES]) -> [u8; BITS] {
    let mut bits = [0u8; BITS];
    for (i, &byte) in frame.iter().enumerate() {
        for b in 0..8 {
            bits[i * 8 + b] = (byte >> (7 - b)) & 1;
        }
    }
    bits
}

fn bits_to_frame(bits: &[u8; BITS]) -> [u8; FRAME_BYTES] {
    let mut frame = [0u8; FRAME_BYTES];
    for (i, byte) in frame.iter_mut().enumerate() {
        for b in 0..8 {
            *byte |= bits[i * 8 + b] << (7 - b);
        }
    }
    frame
}

/// Embed a 96-byte frame into the blue-channel LSBs of flat RGB pixels.
/// `pixels`: `[R,G,B, ...]`, 3 bytes per pixel.
pub fn embed(pixels: &mut [u8], npixels: usize, frame: &[u8; FRAME_BYTES]) -> Result<(), String> {
    if npixels < BITS * 8 {
        return Err(format!("image too small: need >= {} pixels, got {}", BITS * 8, npixels));
    }
    let bits = frame_to_bits(frame);
    for (bit_idx, &bit) in bits.iter().enumerate() {
        let mut pos = bit_idx;
        while pos < npixels {
            pixels[pos * 3 + 2] = (pixels[pos * 3 + 2] & 0xFE) | bit;
            pos += BITS;
        }
    }
    Ok(())
}

/// Extract a 96-byte frame by majority-vote over blue-channel LSBs.
pub fn extract(pixels: &[u8], npixels: usize) -> Result<[u8; FRAME_BYTES], String> {
    if npixels < BITS * 8 {
        return Err(format!("image too small: need >= {} pixels, got {}", BITS * 8, npixels));
    }
    let mut bits = [0u8; BITS];
    for (bit_idx, slot) in bits.iter_mut().enumerate() {
        let mut ones: u32 = 0;
        let mut zeros: u32 = 0;
        let mut pos = bit_idx;
        while pos < npixels {
            if pixels[pos * 3 + 2] & 1 == 1 { ones += 1; } else { zeros += 1; }
            pos += BITS;
        }
        *slot = if ones > zeros { 1 } else { 0 };
    }
    Ok(bits_to_frame(&bits))
}
