// Invisible spread-spectrum watermark for images.
//
// The 20-byte RS payload is spread as LSBs across the blue channel of every
// pixel.  Bit b occupies pixel indices b, b+160, b+320, … so a 12 MP image
// gives ~75 000 votes per bit.  Majority-vote extraction survives JPEG at
// quality ≥ 80 and moderate cropping (>30% of pixels must survive).
//
// Binary outcome: either the embedded payload RS-decodes and matches a known
// drand round, or it does not.  No probability — just pass or fail.

const BITS: usize = 160; // 20 bytes × 8 bits

// ── bit packing helpers ─────────────────────────────────────────────────────

fn payload_to_bits(payload: &[u8; 20]) -> [u8; BITS] {
    let mut bits = [0u8; BITS];
    for (i, &byte) in payload.iter().enumerate() {
        for b in 0..8 {
            bits[i * 8 + b] = (byte >> (7 - b)) & 1;
        }
    }
    bits
}

fn bits_to_payload(bits: &[u8; BITS]) -> [u8; 20] {
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        for b in 0..8 {
            *byte |= bits[i * 8 + b] << (7 - b);
        }
    }
    out
}

// ── public API ───────────────────────────────────────────────────────────────

/// Embed `payload` into flat RGB pixels (3 bytes per pixel).
/// Modifies pixels in-place.  Image must have ≥ 1 600 pixels (trivially true
/// for any real photo).
pub fn embed(pixels: &mut [u8], npixels: usize, payload: &[u8; 20]) -> Result<(), String> {
    if npixels < BITS * 10 {
        return Err(format!(
            "image too small: need ≥ {} pixels, got {}",
            BITS * 10,
            npixels
        ));
    }
    let bits = payload_to_bits(payload);
    for (bit_idx, &bit) in bits.iter().enumerate() {
        let mut pos = bit_idx;
        while pos < npixels {
            pixels[pos * 3 + 2] = (pixels[pos * 3 + 2] & 0xFE) | bit;
            pos += BITS;
        }
    }
    Ok(())
}

/// Extract payload by majority-vote over blue-channel LSBs.
/// Returns the 20-byte raw codeword; caller must RS-decode and verify.
pub fn extract(pixels: &[u8], npixels: usize) -> Result<[u8; 20], String> {
    if npixels < BITS * 10 {
        return Err(format!(
            "image too small: need ≥ {} pixels, got {}",
            BITS * 10,
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
    Ok(bits_to_payload(&bits))
}
