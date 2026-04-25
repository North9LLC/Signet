# Signet

Signet embeds a cryptographic timestamp derived from the [drand](https://drand.love/) public randomness beacon into near-ultrasonic audio, making it possible to prove that a photo or video was taken after a specific moment in time.

The encoded signal is inaudible to most listeners (18–19 kHz) yet survives typical recording and transcoding pipelines. A verifier decodes the signal and checks it against the public drand beacon chain.

---

## How it works

1. **Beacon derivation** – The drand network publishes a new BLS signature every 30 seconds. Signet fetches the signature for a target round, runs HKDF-SHA256 over it with a fixed info string to produce a 16-byte payload.

2. **Forward error correction** – The 16-byte payload is encoded with Reed-Solomon RS(20,16) over GF(256), adding 4 parity bytes (corrects up to 2 symbol errors).

3. **AFSK modulation** – The 20-byte codeword is transmitted as a continuous-phase FSK signal at 500 baud. Mark = 19 kHz, space = 18 kHz, 48 kHz sample rate. Raised-cosine shaping at bit boundaries reduces inter-symbol interference.

4. **Frame structure** – Each frame is roughly 760 ms:
   - 50 ms 19 kHz lead-in tone (energy detector trigger)
   - 50 ms silence (reverb decay gap)
   - 64-bit alternating preamble (bit-clock acquisition)
   - 32-bit sync word (frame alignment)
   - 160-bit RS codeword (payload)
   - 32-bit CRC32 (integrity check)
   - 50 ms trail

5. **Verification** – The decoder runs Goertzel detection, Berlekamp-Massey + Chien-search RS decoding, CRC check, and then compares the recovered payload against the drand beacon chain.

---

## Quick start

```sh
# Generate an audio file stamped to the latest drand round
cargo run --release -- generate output.wav

# Decode a WAV file and print the recovered payload bytes
cargo run --release -- decode output.wav

# Verify a WAV file (checks against live drand chain)
cargo run --release -- verify output.wav

# Verify against a specific drand round
cargo run --release -- verify --round 6052808 output.wav

# Verify and emit JSON
cargo run --release -- verify --json output.wav

# End-to-end round-trip test with optional SNR
cargo run --release -- roundtrip 20

# Sweep SNR from 0 to 30 dB in 1 dB steps
cargo run --release -- sweep
```

---

## Technical details

### Modem

| Parameter | Value |
|---|---|
| Sample rate | 48 000 Hz |
| Baud rate | 500 bps |
| Samples per bit | 96 |
| Mark frequency | 19 000 Hz |
| Space frequency | 18 000 Hz |
| Pulse shaping | Raised-cosine ramp (24 samples / 0.5 ms) |
| Preamble | 64 bits alternating (0x5555555555555555) |
| Sync word | 0x9D2E5B7F |
| Frame length | ~762 ms |

Detection uses the Goertzel algorithm rather than FFT, operating on a per-bit window for energy efficiency. The decoder skips the ramp samples at each bit boundary and evaluates only the stable center portion.

### Reed-Solomon code

- Polynomial ring: GF(2^8), primitive polynomial x^8+x^4+x^3+x^2+1 = 0x11D
- Code parameters: RS(20,16) — 16 data bytes, 4 parity bytes
- Minimum distance: 5, corrects up to t=2 symbol errors
- Generator roots: alpha^0 … alpha^3, where alpha = 0x02
- Decoding: Berlekamp-Massey (error-locator polynomial), Chien search (error positions), Forney formula (error magnitudes)
- Encoding is systematic: codeword = [data | parity]

### Payload derivation

```
payload_16 = HKDF-SHA256(ikm=drand_signature, salt=none, info="signet-v1", length=16)
payload_20 = RS_encode(payload_16)
```

All HKDF and SHA-256 operations are implemented from scratch; no external cryptography crates are used.

### drand beacon

- Chain: default (Cloudflare / EPFL league-of-entropy)
- API: `https://api.drand.sh/public/{round}`
- Genesis: Unix 1 592 213 100, period: 30 s
- Round to UTC: `genesis + (round - 1) * 30`

---

## Threat model

**What Signet proves:** A recording that decodes a valid Signet frame for round R was made no earlier than the time round R was published by the drand network (approximately `genesis + (R-1)*30` UTC). The proof is public and non-interactive — anyone with the recording and an internet connection can verify it.

**What Signet does not prove:**
- The recording was not made *after* round R. An attacker who pre-records content and later adds a beacon signal from a future round would produce a valid frame. Signet gives a lower bound on the recording time, not an upper bound.
- The recording has not been edited or spliced. The signal only covers the portion of audio that contains the frame.
- The recording device is trustworthy. If the device is compromised, it can synthesize frames.

**Signal robustness:** The near-ultrasonic band is typically preserved by smartphone microphones and AAC/Opus encoders at 192 kbps+, but may be rolled off by aggressive low-pass filtering, Bluetooth, or telephone-quality codecs. The RS code recovers up to 2 byte errors; the CRC detects additional corruption.

---

## Source layout

```
src/
├── main.rs        CLI (generate / decode / verify / roundtrip / sweep)
├── lib.rs
├── modem.rs       AFSK encode + sync-anchored decode, raised-cosine shaping
├── fec.rs         Reed-Solomon RS(20,16) over GF(256)
├── channel.rs     Reverb, bandpass (4th-order Butterworth), AWGN
├── crypto.rs      HMAC-SHA256, HKDF-SHA256, CRC-32 (no crates)
├── wav.rs         16-bit PCM mono WAV reader/writer (no crates)
├── payload.rs     drand signature -> 16-byte HKDF payload
├── drand.rs       HTTP fetch via curl, round/timestamp helpers
└── bin/
    └── debug_one.rs   per-frame decode trace harness
```

## License

Part of the Signet project. MIT.
