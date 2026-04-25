// Near-ultrasonic AFSK modem.
//
// Continuous-phase FSK at 1000 baud, mark=19 kHz, space=18 kHz, 48 kHz sample rate.
// Frame layout: lead-in tone -> preamble -> sync word -> payload -> CRC32 -> trail.
// Demodulation uses sliding Goertzel for lead-in detection and bit sampling.

use crate::crypto::crc32;

pub const SAMPLE_RATE: u32 = 48_000;
pub const FMARK: f32 = 19_000.0; // bit = 1
pub const FSPACE: f32 = 18_000.0; // bit = 0
pub const BAUD: u32 = 1_000; // bits per second
pub const SAMPLES_PER_BIT: usize = 48; // SAMPLE_RATE / BAUD
pub const PREAMBLE_BITS: u64 = 0x5555_5555_5555_5555; // 64 bits, alternating 0/1 MSB-first
pub const PREAMBLE_LEN: usize = 64;
pub const SYNC_WORD: u32 = 0x9D2E_5B7F;
pub const SYNC_LEN: usize = 32;
pub const PAYLOAD_BITS: usize = 128;
pub const PAYLOAD_BYTES: usize = 16;
pub const CRC_BITS: usize = 32;
pub const LEAD_IN_MS: u32 = 50;
pub const GAP_MS: u32 = 50; // silence after lead-in so reverb tails decay before preamble
pub const TRAIL_MS: u32 = 50;

const AMPLITUDE: f32 = 0.7;
const TWO_PI: f64 = std::f64::consts::PI * 2.0;

#[derive(Debug)]
pub enum DecodeError {
    NoSignal,
    NoPreamble,
    NoSync,
    BadCrc,
    TooShort,
}

// -------------------- Encoding --------------------

/// Append `n_samples` of the given frequency to `out`, advancing `phase` continuously.
fn push_tone(out: &mut Vec<f32>, phase: &mut f64, freq: f32, n_samples: usize) {
    let step = TWO_PI * (freq as f64) / (SAMPLE_RATE as f64);
    for _ in 0..n_samples {
        *phase += step;
        // Keep phase bounded to avoid precision loss on long transmissions.
        if *phase > TWO_PI {
            *phase -= TWO_PI;
        }
        out.push(AMPLITUDE * (phase.sin() as f32));
    }
}

/// Append bits (MSB-first within each byte of the slice of bits). Each bit is
/// SAMPLES_PER_BIT samples at FMARK (1) or FSPACE (0).
fn push_bits_msb(out: &mut Vec<f32>, phase: &mut f64, bits: &[bool]) {
    for &b in bits {
        let f = if b { FMARK } else { FSPACE };
        push_tone(out, phase, f, SAMPLES_PER_BIT);
    }
}

fn u64_to_bits_msb(value: u64, n: usize) -> Vec<bool> {
    let mut v = Vec::with_capacity(n);
    for i in (0..n).rev() {
        v.push(((value >> i) & 1) == 1);
    }
    v
}

fn u32_to_bits_msb(value: u32, n: usize) -> Vec<bool> {
    u64_to_bits_msb(value as u64, n)
}

fn bytes_to_bits_msb(bytes: &[u8]) -> Vec<bool> {
    let mut v = Vec::with_capacity(bytes.len() * 8);
    for &byte in bytes {
        for i in (0..8).rev() {
            v.push(((byte >> i) & 1) == 1);
        }
    }
    v
}

pub fn encode(payload: &[u8; PAYLOAD_BYTES]) -> Vec<f32> {
    let lead_in_samples = (LEAD_IN_MS as usize) * (SAMPLE_RATE as usize) / 1000;
    let gap_samples = (GAP_MS as usize) * (SAMPLE_RATE as usize) / 1000;
    let trail_samples = (TRAIL_MS as usize) * (SAMPLE_RATE as usize) / 1000;
    let total_bits = PREAMBLE_LEN + SYNC_LEN + PAYLOAD_BITS + CRC_BITS;
    let total = lead_in_samples + gap_samples + total_bits * SAMPLES_PER_BIT + trail_samples;

    let mut out = Vec::with_capacity(total);
    let mut phase: f64 = 0.0;

    // 1. Lead-in: pure FMARK tone.
    push_tone(&mut out, &mut phase, FMARK, lead_in_samples);

    // 1b. Silence gap so reverb tails from the lead-in decay.
    for _ in 0..gap_samples {
        out.push(0.0);
    }
    phase = 0.0; // phase reset is fine across a silent gap.

    // 2. Preamble (64 bits, MSB-first).
    let preamble_bits = u64_to_bits_msb(PREAMBLE_BITS, PREAMBLE_LEN);
    push_bits_msb(&mut out, &mut phase, &preamble_bits);

    // 3. Sync word (32 bits, MSB-first).
    let sync_bits = u32_to_bits_msb(SYNC_WORD, SYNC_LEN);
    push_bits_msb(&mut out, &mut phase, &sync_bits);

    // 4. Payload (128 bits, byte 0 first, MSB-first per byte).
    let payload_bits = bytes_to_bits_msb(payload);
    push_bits_msb(&mut out, &mut phase, &payload_bits);

    // 5. CRC-32 of payload (MSB-first).
    let crc = crc32(payload);
    let crc_bits = u32_to_bits_msb(crc, CRC_BITS);
    push_bits_msb(&mut out, &mut phase, &crc_bits);

    // 6. Trail: silence (don't advance phase, just zeros).
    for _ in 0..trail_samples {
        out.push(0.0);
    }

    out
}

// -------------------- Goertzel --------------------

/// Run Goertzel on samples[start..start+n] for target frequency `freq` at SAMPLE_RATE.
/// Returns magnitude squared. Safe for any window; caller must ensure bounds.
fn goertzel_mag_sq(samples: &[f32], start: usize, n: usize, freq: f32) -> f32 {
    debug_assert!(start + n <= samples.len());
    let k = freq / (SAMPLE_RATE as f32);
    let w = 2.0 * std::f32::consts::PI * k;
    let coeff = 2.0 * w.cos();
    let mut s1 = 0.0f32;
    let mut s2 = 0.0f32;
    for i in 0..n {
        let x = samples[start + i];
        let s0 = x + coeff * s1 - s2;
        s2 = s1;
        s1 = s0;
    }
    // |X|^2 = s1^2 + s2^2 - coeff * s1 * s2
    s1 * s1 + s2 * s2 - coeff * s1 * s2
}

// -------------------- Decoding --------------------

/// Minimum number of samples required to contain a full frame (excluding trail).
fn min_samples() -> usize {
    let lead_in_samples = (LEAD_IN_MS as usize) * (SAMPLE_RATE as usize) / 1000;
    let gap_samples = (GAP_MS as usize) * (SAMPLE_RATE as usize) / 1000;
    let total_bits = PREAMBLE_LEN + SYNC_LEN + PAYLOAD_BITS + CRC_BITS;
    lead_in_samples + gap_samples + total_bits * SAMPLES_PER_BIT
}

/// Decode bits starting at `start` sample offset. Reads `n_bits` bits of
/// SAMPLES_PER_BIT samples each. Returns Some(bits) if enough samples exist.
fn decode_bits_at(samples: &[f32], start: usize, n_bits: usize) -> Option<Vec<bool>> {
    if start + n_bits * SAMPLES_PER_BIT > samples.len() {
        return None;
    }
    let mut bits = Vec::with_capacity(n_bits);
    for i in 0..n_bits {
        let s = start + i * SAMPLES_PER_BIT;
        let mag_mark = goertzel_mag_sq(samples, s, SAMPLES_PER_BIT, FMARK);
        let mag_space = goertzel_mag_sq(samples, s, SAMPLES_PER_BIT, FSPACE);
        bits.push(mag_mark > mag_space);
    }
    Some(bits)
}

fn bits_to_u32_msb(bits: &[bool]) -> u32 {
    let mut v: u32 = 0;
    for &b in bits {
        v = (v << 1) | (b as u32);
    }
    v
}

fn bits_to_u64_msb(bits: &[bool]) -> u64 {
    let mut v: u64 = 0;
    for &b in bits {
        v = (v << 1) | (b as u64);
    }
    v
}

fn hamming_u64(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

fn hamming_u32(a: u32, b: u32) -> u32 {
    (a ^ b).count_ones()
}

pub fn decode(samples: &[f32]) -> Result<[u8; PAYLOAD_BYTES], DecodeError> {
    if samples.len() < min_samples() {
        return Err(DecodeError::TooShort);
    }

    // ---- 1. Lead-in detection ----
    // Slide a 240-sample (5 ms) Goertzel at FMARK with 24-sample (0.5 ms) hop.
    // Threshold at 0.3x the max magnitude seen in the first 10 ms.
    const WIN: usize = 240;
    const HOP: usize = 24;

    let calib_end = (10 * (SAMPLE_RATE as usize) / 1000).min(samples.len());
    let mut max_early: f32 = 0.0;
    {
        let mut i = 0;
        while i + WIN <= calib_end {
            let m = goertzel_mag_sq(samples, i, WIN, FMARK);
            if m > max_early {
                max_early = m;
            }
            i += HOP;
        }
    }

    // If the signal is essentially silent, bail out early.
    // (Goertzel mag_sq scales like (N * amp / 2)^2; for 0.7-amp sine at N=240,
    // expect ~(0.7*240/2)^2 ~= 7056.) Use a tiny absolute floor too.
    if max_early < 1.0 {
        return Err(DecodeError::NoSignal);
    }
    let threshold = 0.3 * max_early;

    // Walk forward and find ≥30 ms of contiguous detections.
    // 30 ms at 0.5 ms hop = 60 consecutive hops above threshold.
    const REQUIRED_HOPS: usize = 60;
    let mut lead_in_start: Option<usize> = None;
    let mut run_start: Option<usize> = None;
    let mut run_len: usize = 0;
    let mut i = 0;
    while i + WIN <= samples.len() {
        let m = goertzel_mag_sq(samples, i, WIN, FMARK);
        if m >= threshold {
            if run_start.is_none() {
                run_start = Some(i);
                run_len = 1;
            } else {
                run_len += 1;
            }
            if run_len >= REQUIRED_HOPS {
                lead_in_start = run_start;
                break;
            }
        } else {
            run_start = None;
            run_len = 0;
        }
        i += HOP;
    }

    let lead_in_start = lead_in_start.ok_or(DecodeError::NoSignal)?;

    // ---- 2. Bit-boundary lock via sync word (not preamble!) ----
    //
    // We cannot anchor on the preamble: `0x5555_5555_5555_5555` is periodic with
    // period 2 bits, so Hamming distance to the expected pattern is ~0 for any
    // delta within a bit-width of the true boundary. That ambiguity is fine for
    // the preamble itself but misaligns the subsequent (non-periodic) sync word,
    // payload, and CRC — dropping frame-error-rate under 20 dB SNR dramatically.
    //
    // The sync word `0x9D2E_5B7F` is aperiodic. Minimum Hamming distance against
    // shifted reads of itself is much larger than 0, so scanning sync hamming
    // across candidate deltas produces a single clear minimum at the true
    // boundary. Anchor everything on that.
    let lead_in_samples = (LEAD_IN_MS as usize) * (SAMPLE_RATE as usize) / 1000;
    let gap_samples = (GAP_MS as usize) * (SAMPLE_RATE as usize) / 1000;
    let expected_bit0 = lead_in_start + lead_in_samples + gap_samples;
    let expected_sync_start = expected_bit0 + PREAMBLE_LEN * SAMPLES_PER_BIT;

    // Detection latency in lead-in is up to ~20 ms, so allow generous slack.
    const SYNC_SEARCH_RADIUS: i32 = 64; // samples, ~1.3 bit widths — enough to cover drift without crossing the next sync period
    let mut best_sync_hamming: u32 = u32::MAX;
    let mut best_sync_delta: i32 = 0;
    for delta in -SYNC_SEARCH_RADIUS..=SYNC_SEARCH_RADIUS {
        let s = expected_sync_start as i32 + delta;
        if s < 0 {
            continue;
        }
        let s = s as usize;
        let bits = match decode_bits_at(samples, s, SYNC_LEN) {
            Some(b) => b,
            None => continue,
        };
        let val = bits_to_u32_msb(&bits);
        let h = hamming_u32(val, SYNC_WORD);
        // Tiebreak in favor of delta closer to 0 (expected).
        if h < best_sync_hamming
            || (h == best_sync_hamming && delta.abs() < best_sync_delta.abs())
        {
            best_sync_hamming = h;
            best_sync_delta = delta;
        }
    }
    if best_sync_hamming > 6 {
        return Err(DecodeError::NoSync);
    }

    // Verify the preamble is plausibly there (lightweight sanity check, not
    // used for alignment). Reading the preamble at the position implied by the
    // sync anchor; allow generous tolerance because the preamble pattern is
    // trivially matched at many offsets.
    let frame_start = (expected_sync_start as i32 + best_sync_delta) as usize
        - PREAMBLE_LEN * SAMPLES_PER_BIT;
    if let Some(bits) = decode_bits_at(samples, frame_start, PREAMBLE_LEN) {
        let val = bits_to_u64_msb(&bits);
        let h = hamming_u64(val, PREAMBLE_BITS);
        if h > 16 {
            return Err(DecodeError::NoPreamble);
        }
    } else {
        return Err(DecodeError::TooShort);
    }

    let payload_start =
        (expected_sync_start as i32 + best_sync_delta) as usize + SYNC_LEN * SAMPLES_PER_BIT;

    // ---- 6. Payload ----
    let payload_bits = decode_bits_at(samples, payload_start, PAYLOAD_BITS)
        .ok_or(DecodeError::TooShort)?;
    let mut payload = [0u8; PAYLOAD_BYTES];
    for (i, byte) in payload.iter_mut().enumerate() {
        let mut v: u8 = 0;
        for j in 0..8 {
            v = (v << 1) | (payload_bits[i * 8 + j] as u8);
        }
        *byte = v;
    }

    // ---- 7. CRC ----
    let crc_start = payload_start + PAYLOAD_BITS * SAMPLES_PER_BIT;
    let crc_bits = decode_bits_at(samples, crc_start, CRC_BITS)
        .ok_or(DecodeError::TooShort)?;
    let received_crc = bits_to_u32_msb(&crc_bits);
    let computed_crc = crc32(&payload);
    if received_crc != computed_crc {
        return Err(DecodeError::BadCrc);
    }

    Ok(payload)
}

// -------------------- Tests --------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng};
    use rand::rngs::StdRng;

    #[test]
    fn round_trip_clean() {
        let mut rng = StdRng::seed_from_u64(0xC0FFEE_BAD_F00D);
        for trial in 0..5 {
            let mut payload = [0u8; PAYLOAD_BYTES];
            rng.fill_bytes(&mut payload);
            let samples = encode(&payload);
            let decoded = decode(&samples)
                .unwrap_or_else(|e| panic!("trial {trial} decode failed: {e:?}"));
            assert_eq!(decoded, payload, "trial {trial} payload mismatch");
        }
    }

    #[test]
    fn decode_zero_input_errors() {
        let silence = vec![0.0f32; 48_000];
        match decode(&silence) {
            Err(DecodeError::NoSignal) => {}
            other => panic!("expected NoSignal, got {other:?}"),
        }
    }

    #[test]
    fn frame_length_reasonable() {
        let payload = [0u8; PAYLOAD_BYTES];
        let samples = encode(&payload);
        let expected = 406 * (SAMPLE_RATE as usize) / 1000; // ~19488 (adds 50 ms gap)
        let low = (expected as f32 * 0.9) as usize;
        let high = (expected as f32 * 1.1) as usize;
        assert!(
            samples.len() >= low && samples.len() <= high,
            "len {} outside [{}, {}]",
            samples.len(),
            low,
            high
        );
    }

    #[test]
    fn encode_is_bounded() {
        let payload = [0xABu8; PAYLOAD_BYTES];
        let samples = encode(&payload);
        for (i, &s) in samples.iter().enumerate() {
            assert!(s.abs() <= 1.0, "sample {i} out of bounds: {s}");
        }
    }
}
