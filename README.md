# Signet

Signet invisibly embeds a cryptographic timestamp into images (and audio) at the moment they are captured, so anyone can later verify they are real.

The stamp is derived from the [drand](https://drand.love/) public randomness beacon — a decentralized network that publishes a new unforgeable signature every 30 seconds. A Signet-stamped image contains that signature encoded across its pixels. Verification is public and non-interactive: either the cryptographic proof checks out, or it does not.

**There is no probability, no score, no model.** The output is binary: `VERIFIED` or `NOT VERIFIED`.

---

## How it works

1. **Capture + stamp** — When you take a photo, run `signet stamp photo.jpg`. Signet fetches the current drand round, derives a 16-byte payload via HKDF-SHA256, encodes it with Reed-Solomon FEC, and spreads the 160-bit codeword invisibly across every pixel's blue channel LSB. The change is invisible to the human eye.

2. **Spread-spectrum embedding** — Each of the 160 bits is written to every 160th pixel, giving a 12 MP image ~75 000 votes per bit. Even aggressive JPEG compression or minor editing cannot flip enough votes to destroy the signal — the RS code corrects any remaining errors.

3. **Verify** — Anyone with the image can run `signet verify photo.png`. Signet reads the blue-channel LSBs, majority-votes each bit position, RS-decodes the 16-byte payload, and checks it against the live drand chain. If the signature matches a known round, the image is `VERIFIED` with the exact UTC timestamp it was stamped.

4. **Binary outcome** — If the watermark is intact and the cryptographic check passes: `VERIFIED`. If there is no watermark, the watermark is broken, or the payload does not match any drand round: `NOT VERIFIED`. No gray area.

---

## Quick start

```sh
# Stamp a photo (output is always PNG to preserve the watermark losslessly)
signet stamp photo.jpg
# → photo_stamped.png

# Stamp with a custom output path
signet stamp photo.jpg --out certified.png

# Verify a stamped image
signet verify certified.png
# → VERIFIED: round=6052808 time=2026-04-25 06:00:00 UTC

# Verify and get JSON output (for tooling)
signet verify certified.png --json
# → {"verified":true,"round":6052808,"time":"2026-04-25 06:00:00"}

# Verify against a specific drand round
signet verify certified.png --round 6052808

# Verify an image that was not stamped
signet verify unknown.jpg
# → NOT VERIFIED: no valid Signet watermark found
```

---

## Why this is court-ready

- **Cryptographic proof, not a model.** There is no classifier, no threshold, no confidence score. The drand signature is mathematically verifiable and publicly auditable.
- **Decentralized beacon.** Drand is operated by a league-of-entropy coalition (Cloudflare, EPFL, Protocol Labs). No single party can retroactively forge a round signature.
- **Non-interactive verification.** Anyone with the image and an internet connection can verify. No proprietary API, no account, no black box.
- **Tamper-evident.** Editing the image (cropping, color adjustments, AI inpainting) disrupts enough pixel votes that the watermark fails to decode. The RS code distinguishes minor transmission noise from intentional modification.

**What Signet proves:** This image was processed by Signet software no earlier than the timestamp of the embedded drand round.

**What Signet does not prove:** Images without a Signet watermark are not necessarily AI-generated — older cameras and software do not embed it. Signet is a positive certification standard, not a universal AI detector.

---

## Technical details

### Watermark embedding

| Parameter | Value |
|---|---|
| Payload | 16-byte HKDF-SHA256 of drand signature |
| FEC | RS(20,16) over GF(256) — corrects up to 2 symbol errors |
| Embedded bits | 160 (20 bytes × 8) |
| Channel | Blue channel LSB of RGB8 pixels |
| Spread | Bit b → pixels b, b+160, b+320, … |
| Votes per bit (12 MP) | ~75 000 |
| Output format | PNG (lossless) |

### drand beacon

| Parameter | Value |
|---|---|
| Network | League of Entropy (Cloudflare / EPFL / Protocol Labs) |
| API | `https://api.drand.sh/public/{round}` |
| Round period | 30 seconds |
| Genesis | 2020-06-15 18:25:00 UTC |

### Audio watermarking (legacy)

Signet also supports near-ultrasonic audio watermarking (18–19 kHz AFSK) for video recordings where you cannot embed directly into the image bytes. See `signet generate` and `signet verify <file.wav>`.

---

## Source layout

```
src/
├── main.rs        CLI (stamp / verify / generate / decode / roundtrip / sweep)
├── lib.rs
├── imgwm.rs       Image watermark embed + majority-vote extract
├── modem.rs       AFSK encode + sync-anchored decode, raised-cosine shaping
├── fec.rs         Reed-Solomon RS(20,16) over GF(256)
├── channel.rs     Reverb, bandpass, AWGN (audio simulation)
├── crypto.rs      HMAC-SHA256, HKDF-SHA256, CRC-32
├── wav.rs         16-bit PCM mono WAV reader/writer
├── payload.rs     drand signature → 16-byte HKDF payload
└── drand.rs       HTTP fetch, round/timestamp helpers
```

## License

MIT.
