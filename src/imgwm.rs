// Image watermark — spread-spectrum LSB across the blue channel.
//
// Frame format (96 bytes = 768 bits):
//   [0-7]   drand_round  u64 LE
//   [8-23]  drand_payload  16 bytes  (HKDF of drand signature)
//   [24-31] device_id    8 bytes   (SHA-256(pubkey)[0..8])
//   [32-95] Ed25519 signature  64 bytes
//           signs: "signet-v2" || round_le8 || device_id || drand_payload
//
// Robustness: each bit is spread across every 768th pixel.
// A 12 MP image gives ~15 600 votes per bit.  Majority-vote extraction
// survives JPEG compression and moderate editing.
//
// Security: without the device private key you cannot produce a valid
// Ed25519 signature, so you cannot fake a stamp from a device you do
// not control.  Production deployments should store the key in hardware
// (iOS Secure Enclave / Android StrongBox).

pub const FRAME_BYTES: usize = 96;
const BITS: usize = FRAME_BYTES * 8; // 768

// ── Frame encoding ───────────────────────────────────────────────────────────

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
    let mut round_bytes = [0u8; 8];
    round_bytes.copy_from_slice(&frame[0..8]);
    let drand_round = u64::from_le_bytes(round_bytes);

    let mut drand_payload = [0u8; 16];
    drand_payload.copy_from_slice(&frame[8..24]);

    let mut device_id = [0u8; 8];
    device_id.copy_from_slice(&frame[24..32]);

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&frame[32..96]);

    ParsedFrame { drand_round, drand_payload, device_id, signature }
}

// ── Bit packing ───────────────────────────────────────────────────────────────

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

// ── Embed / extract ───────────────────────────────────────────────────────────

/// Embed a 96-byte frame into the blue-channel LSBs of flat RGB pixels.
/// pixels: [R0,G0,B0, R1,G1,B1, ...], 3 bytes per pixel.
pub fn embed(pixels: &mut [u8], npixels: usize, frame: &[u8; FRAME_BYTES]) -> Result<(), String> {
    if npixels < BITS * 8 {
        return Err(format!(
            "image too small: need ≥ {} pixels, got {}",
            BITS * 8,
            npixels
        ));
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
        return Err(format!(
            "image too small: need ≥ {} pixels, got {}",
            BITS * 8,
            npixels
        ));
    }
    let mut bits = [0u8; BITS];
    for bit_idx in 0..BITS {
        let mut votes_1: u32 = 0;
        let mut votes_0: u32 = 0;
        let mut pos = bit_idx;
        while pos < npixels {
            if pixels[pos * 3 + 2] & 1 == 1 {
                votes_1 += 1;
            } else {
                votes_0 += 1;
            }
            pos += BITS;
        }
        bits[bit_idx] = if votes_1 > votes_0 { 1 } else { 0 };
    }
    Ok(bits_to_frame(&bits))
}
