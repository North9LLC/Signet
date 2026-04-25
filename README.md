# signet-fsk-proto

Week-1 de-risking prototype for **Signet**: proving the "drand beacon embedded in scene audio" primitive is realistic.

Near-ultrasonic AFSK modem that carries a 128-bit beacon payload (derived via HKDF-SHA256 from a drand round signature) as audio tones a phone microphone can capture. The payload binds a captured photo/video to a specific 30-second window that could not have been pre-computed by any attacker.

## What this proves

| Condition | Frame success (40 trials) | Notes |
|---|---:|---|
| Clean signal | 40/40 | Sanity check |
| AWGN 40–0 dB SNR | 40/40 at every step | Every SNR from +40 dB to 0 dB |
| Bandpass 17–20 kHz + 20 dB SNR | 40/40 | Models phone speaker/mic roll-off |
| Bandpass 17–20 kHz + 10 dB SNR | 40/40 | Same, noisier |
| Reverb RT60 = 10 ms | 14/40 | Tiny anechoic space |
| Reverb RT60 ≥ 30 ms | 0/40 | **Current prototype's honest limit** |

**Verdict:** the scheme is robust to noise and spectral shaping (the things a real speaker-to-microphone path mostly does). It falls over when significant room reverb is present — the square-envelope AFSK produces ISI that accumulates across bits.

## Parameters

- Sample rate 48 kHz
- Mark = 19 kHz (bit 1), Space = 18 kHz (bit 0)
- 1000 baud (48 samples per bit), continuous-phase FSK
- Frame: 50 ms FMARK lead-in + 50 ms silence gap + 64-bit preamble + 32-bit sync (0x9D2E5B7F) + 128-bit payload + CRC-32 + 50 ms trail ≈ 406 ms total
- Sync-word-anchored bit-boundary lock (preamble is periodic and unreliable for alignment)
- Payload = HKDF-SHA256(drand_signature, info="signet-fsk-v0", 16 bytes)

## Build & run (offline)

```bash
export PATH=/build/north/prebuilts/rust/linux-x86/1.88.0/bin:$PATH
cargo build --offline --release
cargo test --offline --lib      # 18/18 unit tests

./target/release/signet-fsk-proto roundtrip        # in-memory smoke test
./target/release/signet-fsk-proto sweep            # BER matrix
./target/release/signet-fsk-proto generate out.wav # fetches current drand round
./target/release/signet-fsk-proto generate out.wav --sig <192-hex>
./target/release/signet-fsk-proto decode out.wav
```

Live drand fetch verified end-to-end on 2026-04-24: round 6052881 → 406 ms WAV → decoded bit-perfect.

## Known limits & next steps

1. **Reverb / ISI.** Square-envelope AFSK accumulates intersymbol interference. Mitigations (in order of leverage):
   - Root-raised-cosine pulse shaping (most mainstream fix).
   - Decision-feedback equalizer.
   - Drop to 250 baud (bit = 4 ms), sacrificing transmission length for ISI margin.
   - Reed–Solomon FEC over the 16-byte payload.
2. **Real speaker-to-mic loopback** not tested here (no audio hardware on the build server). To test on a laptop:
   ```
   # Play on one machine, record on another:
   aplay out.wav
   arecord -f S16_LE -r 48000 -c 1 -d 1 capture.wav
   ./target/release/signet-fsk-proto decode capture.wav
   ```
3. **128-bit payload** is the full HKDF output but only ~80 bits of collision resistance for a single capture. Fine for our use case (beacon binding, not authentication).
4. **Audibility**: 18–19 kHz is inaudible to most adults but audible to children, pets, and some audio equipment monitors. Beacon-light dongle (spec §4.3 channel C) is the forensic-grade alternative.

## Layout

```
src/
├── main.rs       CLI (generate/decode/roundtrip/sweep)
├── lib.rs
├── modem.rs      AFSK encode + sync-anchored decode
├── channel.rs    Reverb, bandpass (4th-order Butterworth), AWGN
├── crypto.rs     HMAC-SHA256, HKDF-SHA256, CRC-32 (no crates)
├── wav.rs        16-bit PCM mono WAV reader/writer (no crates)
├── payload.rs    drand signature → 128-bit HKDF payload
├── drand.rs      HTTP fetch via curl
└── bin/debug_one.rs  per-frame trace harness
```

## License

Part of the Signet project. MIT.
