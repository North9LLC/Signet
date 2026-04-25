// Trace a full decode, printing every bit of preamble/sync/payload/CRC side by side.
use rand::{RngCore, SeedableRng};
use signet::{channel, fec, modem, crypto};

const FMARK: f32 = modem::FMARK;
const FSPACE: f32 = modem::FSPACE;
const N: usize = modem::SAMPLES_PER_BIT;

fn mag_sq(samples: &[f32], start: usize, n: usize, freq: f32) -> f32 {
    let k = freq / (modem::SAMPLE_RATE as f32);
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
    s1 * s1 + s2 * s2 - coeff * s1 * s2
}

fn read_bit(samples: &[f32], start: usize) -> (bool, f32, f32) {
    let m = mag_sq(samples, start, N, FMARK);
    let s = mag_sq(samples, start, N, FSPACE);
    (m > s, m, s)
}

fn read_bits(samples: &[f32], start: usize, n_bits: usize) -> Vec<bool> {
    (0..n_bits).map(|i| read_bit(samples, start + i * N).0).collect()
}

fn bits_to_u64(bits: &[bool]) -> u64 {
    let mut v = 0u64;
    for &b in bits { v = (v << 1) | (b as u64); }
    v
}
fn bits_to_u32(bits: &[bool]) -> u32 { bits_to_u64(bits) as u32 }

fn main() {
    let snr: f32 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(20.0);
    let seed: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(3);

    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut pay16 = [0u8; 16];
    rng.fill_bytes(&mut pay16);
    let pay20 = fec::rs_encode(&pay16);

    let clean = modem::encode(&pay20);
    let cfg = channel::ChannelCfg { snr_db: Some(snr), ..Default::default() };
    let noisy = channel::apply(&clean, &cfg, &mut rng);

    println!("seed={} snr={} dB", seed, snr);
    println!("payload16 sent: {:02x?}", pay16);
    println!("payload20 sent: {:02x?}", pay20);
    println!("CRC sent: {:08x}", crypto::crc32(&pay20));

    // Frame layout at 500 baud / 96 spb:
    //   lead_in:  0..2400   (FMARK, 50ms)
    //   gap:      2400..4800 (silence, 50ms)
    //   preamble: 4800..4800+64*96 = 4800..11136
    //   sync:     11136..11136+32*96 = 11136..14208
    //   payload:  14208..14208+160*96 = 14208..29568
    //   crc:      29568..29568+32*96 = 29568..32640
    //   trail:    32640..35040

    let lead_in_samples = (modem::LEAD_IN_MS as usize) * (modem::SAMPLE_RATE as usize) / 1000;
    let gap_samples = (modem::GAP_MS as usize) * (modem::SAMPLE_RATE as usize) / 1000;
    let bit0 = lead_in_samples + gap_samples;

    // Read preamble
    let expected_pre = modem::PREAMBLE_BITS;
    let mut best_delta: i32 = 0;
    let mut best_h: u32 = u32::MAX;
    for d in -4i32..=4 {
        let s = (bit0 as i32 + d) as usize;
        let bits = read_bits(&noisy, s, 64);
        let v = bits_to_u64(&bits);
        let h = (v ^ expected_pre).count_ones();
        if h < best_h { best_h = h; best_delta = d; }
    }
    println!("preamble best delta {:+} hamming {}", best_delta, best_h);

    let frame_start = (bit0 as i32 + best_delta) as usize;
    let sync_start = frame_start + 64 * N;
    let mut best_sync_h = u32::MAX;
    let mut best_sync_s: i32 = 0;
    for s in -2i32..=2 {
        let st = (sync_start as i32 + s) as usize;
        let bits = read_bits(&noisy, st, 32);
        let v = bits_to_u32(&bits);
        let h = (v ^ modem::SYNC_WORD).count_ones();
        println!("  sync delta={:+2} got={:08x} exp={:08x} hamming={}", s, v, modem::SYNC_WORD, h);
        if h < best_sync_h { best_sync_h = h; best_sync_s = s; }
    }

    let payload_start = (sync_start as i32 + best_sync_s) as usize + 32 * N;
    let p_bits = read_bits(&noisy, payload_start, 160); // 20 bytes
    let mut got20 = [0u8; 20];
    for i in 0..20 {
        let mut v = 0u8;
        for j in 0..8 { v = (v << 1) | (p_bits[i*8 + j] as u8); }
        got20[i] = v;
    }
    println!("payload20 got: {:02x?}", got20);
    println!("payload20 xor: {:02x?}", got20.iter().zip(pay20.iter()).map(|(a, b)| a ^ b).collect::<Vec<_>>());

    match fec::rs_decode(&got20) {
        Some(p) => println!("FEC decoded: {:02x?} {}", p,
            if p == pay16 { "MATCH" } else { "MISMATCH" }),
        None => println!("FEC: uncorrectable"),
    }

    let crc_start = payload_start + 160 * N;
    let crc_bits = read_bits(&noisy, crc_start, 32);
    let got_crc = bits_to_u32(&crc_bits);
    let exp_crc = crypto::crc32(&pay20);
    println!("crc got  : {:08x}", got_crc);
    println!("crc exp  : {:08x}", exp_crc);
    println!("crc xor  : {:08x} (Hamming {})", got_crc ^ exp_crc, (got_crc ^ exp_crc).count_ones());

    match modem::decode(&noisy) {
        Ok(raw20) => {
            println!("OFFICIAL RAW20: {:02x?}", raw20);
            match fec::rs_decode(&raw20) {
                Some(p) => println!("OFFICIAL DECODE: {:02x?} {}", p,
                    if p == pay16 { "MATCH" } else { "MISMATCH" }),
                None => println!("OFFICIAL DECODE FEC: uncorrectable"),
            }
        }
        Err(e) => println!("OFFICIAL DECODE ERR: {:?}", e),
    }
}
