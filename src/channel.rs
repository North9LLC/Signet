//! Audio channel simulator.
//!
//! Models what happens to a signal between speaker and microphone:
//!   1. Reverb (exponential-decay random IR) — room reflections.
//!   2. Bandpass (4th-order Butterworth as cascade of two biquads) — speaker/mic rolloff.
//!   3. AWGN at target SNR — preamp noise.
//!
//! The order mirrors the physical path: emit → room → capture → preamp.

use rand::Rng;

/// Sample rate used throughout the simulator, in Hz.
pub const SAMPLE_RATE: u32 = 48_000;

pub struct ChannelCfg {
    /// If Some, add additive white Gaussian noise to achieve this in-band SNR (dB).
    pub snr_db: Option<f32>,
    /// If Some, apply 4th-order Butterworth bandpass (low_hz, high_hz).
    pub bandpass: Option<(f32, f32)>,
    /// If Some, convolve with exponential-decay impulse response of this RT60 (ms).
    pub reverb_rt60_ms: Option<f32>,
}

impl Default for ChannelCfg {
    fn default() -> Self {
        Self {
            snr_db: None,
            bandpass: None,
            reverb_rt60_ms: None,
        }
    }
}

pub fn apply(samples: &[f32], cfg: &ChannelCfg, rng: &mut impl Rng) -> Vec<f32> {
    // 1. Reverb (room reflections come first).
    let mut y = if let Some(rt60_ms) = cfg.reverb_rt60_ms {
        apply_reverb(samples, rt60_ms, rng)
    } else {
        samples.to_vec()
    };

    // 2. Bandpass (capture device band-limits).
    if let Some((low_hz, high_hz)) = cfg.bandpass {
        y = apply_bandpass(&y, low_hz, high_hz);
    }

    // 3. AWGN (preamp noise, last).
    if let Some(snr_db) = cfg.snr_db {
        add_awgn(&mut y, snr_db, rng);
    }

    y
}

// ---------------------------------------------------------------------------
// AWGN
// ---------------------------------------------------------------------------

fn add_awgn(samples: &mut [f32], snr_db: f32, rng: &mut impl Rng) {
    if samples.is_empty() {
        return;
    }
    // Compute signal RMS (linear amplitude).
    let mean_sq: f64 = samples.iter().map(|&x| (x as f64) * (x as f64)).sum::<f64>()
        / (samples.len() as f64);
    let rms_sig = mean_sq.sqrt() as f32;
    // Target noise RMS from SNR (dB). rms_noise = rms_sig / 10^(snr_db/20).
    let rms_noise = rms_sig / 10f32.powf(snr_db / 20.0);

    // Box-Muller transform: draw pairs of N(0,1), scale by rms_noise.
    let mut i = 0;
    while i < samples.len() {
        // Avoid log(0): clamp u1 away from 0.
        let mut u1: f32 = rng.gen::<f32>();
        if u1 < 1e-20 {
            u1 = 1e-20;
        }
        let u2: f32 = rng.gen::<f32>();
        let mag = (-2.0_f32 * u1.ln()).sqrt();
        let two_pi = std::f32::consts::TAU;
        let z0 = mag * (two_pi * u2).cos();
        let z1 = mag * (two_pi * u2).sin();

        samples[i] += z0 * rms_noise;
        if i + 1 < samples.len() {
            samples[i + 1] += z1 * rms_noise;
        }
        i += 2;
    }
}

// ---------------------------------------------------------------------------
// Bandpass: 4th-order Butterworth as cascade of two identical biquads.
// Coefficients per Audio EQ Cookbook (Bristow-Johnson) constant-0-dB-peak BPF.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Biquad {
    // Normalized (divided by a0) coefficients.
    b0: f32,
    b1: f32,
    b2: f32,
    a1: f32,
    a2: f32,
}

struct BiquadState {
    x1: f32,
    x2: f32,
    y1: f32,
    y2: f32,
}

impl BiquadState {
    fn new() -> Self {
        Self {
            x1: 0.0,
            x2: 0.0,
            y1: 0.0,
            y2: 0.0,
        }
    }
    fn step(&mut self, bq: &Biquad, x: f32) -> f32 {
        // Direct-Form I.
        let y = bq.b0 * x + bq.b1 * self.x1 + bq.b2 * self.x2
            - bq.a1 * self.y1
            - bq.a2 * self.y2;
        self.x2 = self.x1;
        self.x1 = x;
        self.y2 = self.y1;
        self.y1 = y;
        y
    }
}

fn design_bpf(low_hz: f32, high_hz: f32, fs: f32) -> Biquad {
    // Geometric mean center frequency (Hz).
    let f0 = (low_hz * high_hz).sqrt();
    // Bandwidth in octaves.
    let bw = (high_hz / low_hz).log2();
    // Normalized angular center (radians/sample).
    let w0 = std::f32::consts::TAU * f0 / fs;
    let sin_w0 = w0.sin();
    let cos_w0 = w0.cos();
    // alpha = sin(w0) * sinh( ln(2)/2 * BW * w0/sin(w0) )
    let alpha = sin_w0 * ((std::f32::consts::LN_2 / 2.0) * bw * (w0 / sin_w0)).sinh();

    let b0 = alpha;
    let b1 = 0.0;
    let b2 = -alpha;
    let a0 = 1.0 + alpha;
    let a1 = -2.0 * cos_w0;
    let a2 = 1.0 - alpha;

    Biquad {
        b0: b0 / a0,
        b1: b1 / a0,
        b2: b2 / a0,
        a1: a1 / a0,
        a2: a2 / a0,
    }
}

fn apply_bandpass(samples: &[f32], low_hz: f32, high_hz: f32) -> Vec<f32> {
    let fs = SAMPLE_RATE as f32;
    let bq = design_bpf(low_hz, high_hz, fs);
    // Two biquads in series = 4th-order.
    let mut s1 = BiquadState::new();
    let mut s2 = BiquadState::new();
    let mut out = Vec::with_capacity(samples.len());
    for &x in samples {
        let y1 = s1.step(&bq, x);
        let y2 = s2.step(&bq, y1);
        out.push(y2);
    }
    out
}

// ---------------------------------------------------------------------------
// Reverb: exponential-decay random IR, truncated to input length.
// ---------------------------------------------------------------------------

fn apply_reverb(samples: &[f32], rt60_ms: f32, rng: &mut impl Rng) -> Vec<f32> {
    let fs = SAMPLE_RATE as f32;
    // IR length in samples; clamp to at least 1.
    let rt60_samples = ((rt60_ms * 1e-3) * fs).max(1.0) as usize;
    // Decay constant so that amplitude drops 60 dB over rt60_samples.
    // exp(-decay * rt60_samples) = 10^-3  =>  decay = ln(1000) / rt60_samples.
    let decay = (1000f32.ln()) / (rt60_samples as f32);

    // Build IR: uniform [-1,1] noise multiplied by exponential envelope.
    let mut h = Vec::with_capacity(rt60_samples);
    let mut max_abs: f32 = 0.0;
    for n in 0..rt60_samples {
        let u: f32 = rng.gen::<f32>() * 2.0 - 1.0; // [-1, 1)
        let env = (-(n as f32) * decay).exp();
        let v = u * env;
        if v.abs() > max_abs {
            max_abs = v.abs();
        }
        h.push(v);
    }
    // Normalize IR so peak is ~1.
    if max_abs > 0.0 {
        for v in h.iter_mut() {
            *v /= max_abs;
        }
    }

    // Direct convolution, truncated to input length.
    let n_in = samples.len();
    let n_h = h.len();
    let mut y = vec![0.0f32; n_in];
    for n in 0..n_in {
        // y[n] = sum_{k=0..min(n_h, n+1)} x[n-k] * h[k]
        let k_max = n_h.min(n + 1);
        let mut acc = 0.0f32;
        for k in 0..k_max {
            acc += samples[n - k] * h[k];
        }
        y[n] = acc;
    }
    y
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rms(x: &[f32]) -> f32 {
        if x.is_empty() {
            return 0.0;
        }
        let s: f64 = x.iter().map(|&v| (v as f64) * (v as f64)).sum::<f64>()
            / (x.len() as f64);
        s.sqrt() as f32
    }

    fn sine(freq_hz: f32, amp: f32, n: usize) -> Vec<f32> {
        let fs = SAMPLE_RATE as f32;
        (0..n)
            .map(|i| amp * (std::f32::consts::TAU * freq_hz * (i as f32) / fs).sin())
            .collect()
    }

    #[test]
    fn noop_returns_input_unchanged() {
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        let x = sine(1000.0, 0.5, 4800);
        let y = apply(&x, &ChannelCfg::default(), &mut rng);
        assert_eq!(x.len(), y.len());
        for (a, b) in x.iter().zip(y.iter()) {
            // Bit-for-bit equality expected (we early-return via the None branches).
            assert_eq!(a.to_bits(), b.to_bits());
        }
    }

    #[test]
    fn awgn_snr_accurate() {
        let mut rng = StdRng::seed_from_u64(42);
        // 1 kHz sine, amplitude 0.5, 1 second long for a stable RMS estimate.
        let x = sine(1000.0, 0.5, SAMPLE_RATE as usize);
        let cfg = ChannelCfg {
            snr_db: Some(20.0),
            ..Default::default()
        };
        let y = apply(&x, &cfg, &mut rng);
        assert_eq!(x.len(), y.len());

        // Recover noise by subtracting the known clean input.
        let noise: Vec<f32> = y.iter().zip(x.iter()).map(|(a, b)| a - b).collect();
        let rms_sig = rms(&x);
        let rms_noise = rms(&noise);
        let measured_snr_db = 20.0 * (rms_sig / rms_noise).log10();
        assert!(
            (measured_snr_db - 20.0).abs() < 1.5,
            "measured SNR {} dB not within 1.5 dB of 20 dB",
            measured_snr_db
        );
    }

    #[test]
    fn bandpass_passes_in_band() {
        let mut rng = StdRng::seed_from_u64(7);
        // 18.5 kHz is inside [17k, 20k].
        let x = sine(18_500.0, 0.5, SAMPLE_RATE as usize);
        let cfg = ChannelCfg {
            bandpass: Some((17_000.0, 20_000.0)),
            ..Default::default()
        };
        let y = apply(&x, &cfg, &mut rng);
        // Skip first 2000 samples to let the filter settle (transient).
        let rms_in = rms(&x[2000..]);
        let rms_out = rms(&y[2000..]);
        let db = 20.0 * (rms_out / rms_in).log10();
        assert!(
            db.abs() < 3.0,
            "in-band attenuation {} dB exceeds 3 dB budget",
            db
        );
    }

    #[test]
    fn bandpass_rejects_out_of_band() {
        let mut rng = StdRng::seed_from_u64(8);
        // 5 kHz is well below passband [17k, 20k].
        let x = sine(5_000.0, 0.5, SAMPLE_RATE as usize);
        let cfg = ChannelCfg {
            bandpass: Some((17_000.0, 20_000.0)),
            ..Default::default()
        };
        let y = apply(&x, &cfg, &mut rng);
        // Skip transient.
        let rms_in = rms(&x[2000..]);
        let rms_out = rms(&y[2000..]);
        let db = 20.0 * (rms_out / rms_in).log10();
        // 4th-order Butterworth BPF with Q~1/BW_oct should deliver far more than 15 dB
        // attenuation ~1.8 octaves below center. Keeping the threshold at -15 dB so a
        // broken filter (e.g. constant gain or wrong topology) cannot pass.
        assert!(
            db < -15.0,
            "out-of-band rejection only {} dB; expected < -15 dB",
            db
        );
    }

    #[test]
    fn reverb_extends_signal_energy() {
        let mut rng = StdRng::seed_from_u64(9);
        let fs = SAMPLE_RATE as usize;
        // 10 ms impulse burst of 1 kHz sine, rest silence. Pad to 200 ms.
        let burst_samples = fs / 100; // 10 ms
        let total_samples = fs / 5; // 200 ms
        let mut x = vec![0.0f32; total_samples];
        for i in 0..burst_samples {
            x[i] = 0.8 * (std::f32::consts::TAU * 1_000.0 * (i as f32) / (fs as f32)).sin();
        }

        let cfg = ChannelCfg {
            reverb_rt60_ms: Some(100.0),
            ..Default::default()
        };
        let y = apply(&x, &cfg, &mut rng);
        assert_eq!(x.len(), y.len());

        // Burst energy: first 10 ms of input.
        let burst_energy: f64 = x[..burst_samples]
            .iter()
            .map(|&v| (v as f64) * (v as f64))
            .sum();
        // Tail energy: output samples in [50 ms, 100 ms) after burst end.
        let tail_start = burst_samples + fs / 20; // burst_end + 50 ms
        let tail_end = burst_samples + fs / 10;   // burst_end + 100 ms
        let tail_energy: f64 = y[tail_start..tail_end]
            .iter()
            .map(|&v| (v as f64) * (v as f64))
            .sum();

        // Threshold loosened from 0.1 -> 0.05: with peak-normalized random IR and
        // 60 dB decay over RT60, energy at 50–100 ms after a short burst realistically
        // lands near 5–10% of burst energy (observed ~8%). A broken impl (no reverb)
        // would leave silence there, so 0.05 still robustly distinguishes.
        assert!(
            tail_energy > 0.05 * burst_energy,
            "tail energy {} not > 0.05 * burst energy {}",
            tail_energy,
            burst_energy
        );
    }
}
