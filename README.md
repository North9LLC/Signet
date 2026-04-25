# Signet

A cryptographic watermarking SDK that camera apps embed to certify photos are real.

The stamp happens **inside the camera app, at the moment the shutter fires** — before the image is encoded or saved. There is no post-processing step. A Signet-certified photo carries an unforgeable cryptographic proof derived from the [drand](https://drand.love/) public randomness beacon (operated by Cloudflare, EPFL, Protocol Labs). Verification is binary, public, and non-interactive: either the math checks out or it doesn't.

---

## How it works

```
┌─────────────────────────────────────────────────────────────────┐
│  Camera App                                                     │
│                                                                 │
│  1. [Background thread, every 25s]                              │
│     signet_prefetch_round() → cache drand signature             │
│                                                                 │
│  2. [Shutter press — synchronous, < 5 ms]                       │
│     signet_stamp_pixels(raw_pixels, sig)                        │
│     ↓ invisible LSB watermark embedded                          │
│                                                                 │
│  3. [Normal encode path]                                        │
│     Encode stamped pixels → JPEG/HEIC/PNG → save to disk        │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  Verifier (anyone, anywhere)                                    │
│                                                                 │
│  signet_verify_pixels(pixels) → VERIFIED (round + timestamp)   │
│                              or NOT VERIFIED                    │
└─────────────────────────────────────────────────────────────────┘
```

**Why pre-fetch?** drand publishes a new round every 30 seconds. The app caches the signature in the background so shutter press is instant — no network round-trip during capture.

**Why inside the app?** Post-processing after capture creates a window where an AI-generated image could be submitted for stamping. Embedding at capture time inside a trusted app closes that window. The stamp certifies: *these raw pixels existed at this moment inside this software*.

---

## SDK integration

### iOS

```swift
// AppDelegate or CameraViewController setup
SignetSDK.shared.start()  // begins background prefetch

// Inside your AVCapturePhotoCaptureDelegate
func photoOutput(_ output: AVCapturePhotoOutput,
                 didFinishProcessingPhoto photo: AVCapturePhoto,
                 error: Error?) {
    guard let pixelBuffer = photo.pixelBuffer else { return }
    SignetSDK.shared.stamp(pixelBuffer: pixelBuffer)  // < 5 ms
    // ... encode and save as normal
}

// Verify any image
if let result = SignetSDK.verify(pixelBuffer: pixelBuffer) {
    print("VERIFIED: \(result.dateString)")  // e.g. "2026-04-25T06:00:00Z"
} else {
    print("NOT VERIFIED")
}
```

See `sdk/ios/SignetSDK.swift`.

### Android

```kotlin
// In your Application or Camera setup
SignetSDK.start()

// In your ImageCapture.OnImageCapturedCallback
val bitmap = imageProxy.toBitmap()
SignetSDK.stamp(bitmap)  // < 5 ms, modifies in-place
// ... encode and save

// Verify any image
val result = SignetSDK.verify(bitmap)
if (result != null) {
    println("VERIFIED: ${result.isoTime}")
} else {
    println("NOT VERIFIED")
}
```

See `sdk/android/SignetSDK.kt`.

### C / C++ (any platform)

```c
#include "signet.h"

// Background thread — call every 25 s
char sig_hex[512];
uint64_t round;
signet_prefetch_round(&round, sig_hex, sizeof(sig_hex));

// At shutter press — synchronous, no network
signet_stamp_pixels(pixels_rgb, width, height, sig_hex);

// Verification
uint64_t verified_round, unix_time;
int ok = signet_verify_pixels(pixels_rgb, width, height, &verified_round, &unix_time);
// ok == 1 → VERIFIED, ok == 0 → NOT VERIFIED
```

See `include/signet.h`.

---

## Building the library

```sh
# Shared library (.so / .dylib)
cargo build --release
# → target/release/libsignet.so  (Linux)
# → target/release/libsignet.dylib  (macOS)

# Static library (.a) — for embedding into iOS/Android NDK builds
cargo build --release
# → target/release/libsignet.a

# iOS XCFramework (arm64 device + x86_64 simulator)
cargo build --release --target aarch64-apple-ios
cargo build --release --target x86_64-apple-ios
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libsignet.a \
  -library target/x86_64-apple-ios/release/libsignet.a \
  -output Signet.xcframework

# Android NDK
cargo build --release --target aarch64-linux-android
cargo build --release --target armv7-linux-androideabi
```

---

## CLI reference tool

The CLI is a reference implementation and developer tool — not the end-user product.

```sh
# Stamp a photo (for testing; real apps stamp inside the pipeline)
signet stamp photo.jpg
# → photo_stamped.png

# Verify
signet verify photo_stamped.png
# → VERIFIED: round=6052808 time=2026-04-25 06:00:00 UTC

# JSON output (for tooling)
signet verify photo_stamped.png --json
# → {"verified":true,"round":6052808,"time":"2026-04-25 06:00:00"}

# Unstamped or AI-generated image
signet verify suspect.jpg
# → NOT VERIFIED: no valid Signet watermark found
```

---

## Security model

**Stamps from the CLI tool are development-grade only.** The device key is stored at `~/.signet/device.key` as plaintext software. A rooted device or stolen backup exposes the key. Production requires hardware-backed keys:

- **iOS:** Secure Enclave integration (not yet implemented; see TODO in `sdk/ios/SignetSDK.swift`)
- **Android:** StrongBox integration (not yet implemented; see TODO in `sdk/android/SignetSDK.kt`)

**Device enrollment requires out-of-band registry submission.** The CLI prints your public key and registry URL. You must submit the key to `https://registry.signet.dev` (placeholder) for verifiers to trust your stamps. No auto-enrollment from `signet enroll`. Unregistered devices are rejected at verify time.

**Drand signatures are verified.** Each stamped image references a drand round. Verification confirms that `SHA-256(drand_signature) == randomness_field` to ensure the beacon data was not tampered with.

---

## Why this is court-ready

- **No model, no score.** The drand BLS signature either matches or it doesn't. Binary.
- **Decentralized beacon.** No single entity controls drand. Past round signatures cannot be forged retroactively.
- **Non-interactive verification.** Anyone with the image and internet access can verify. No proprietary API.
- **Tamper-evident.** Meaningful edits (cropping, inpainting, compositing) destroy enough pixel votes that FEC fails to decode.
- **Open standard.** The watermarking algorithm, payload derivation, and drand chain are all public.

**What Signet proves:** These pixels existed, unmodified, inside Signet-integrated software at the stated drand round.

**Limitation:** Signet certifies enrolled cameras and apps. Images without a valid watermark are unverified — not proven AI. Adoption is the key driver: the more apps embed Signet, the stronger the signal.

---

## Technical details

| Parameter | Value |
|---|---|
| Payload | 16-byte HKDF-SHA256(drand signature, "signet-v1") |
| FEC | RS(20,16) over GF(256) — 4 parity bytes, corrects ≤ 2 symbol errors |
| Embedded bits | 160 (20 bytes × 8) |
| Embedding channel | Blue channel LSB of RGB8 |
| Spread | Bit b → pixels b, b+160, b+320, … |
| Votes per bit (12 MP) | ~75 000 |
| Min image size | 1 600 pixels |
| drand network | League of Entropy — `https://api.drand.sh/public/{round}` |
| Round period | 30 seconds |

## Source layout

```
include/
└── signet.h              C header (FFI API)
sdk/
├── ios/SignetSDK.swift    iOS drop-in integration
└── android/SignetSDK.kt  Android drop-in integration
src/
├── main.rs               CLI reference tool
├── lib.rs                Library root + C FFI exports
├── imgwm.rs              Spread-spectrum embed + majority-vote extract
├── fec.rs                Reed-Solomon RS(20,16) over GF(256)
├── crypto.rs             HKDF-SHA256, CRC-32
├── payload.rs            drand signature → 16-byte payload
├── drand.rs              HTTP fetch, round/timestamp helpers
├── modem.rs              Audio AFSK (legacy)
└── wav.rs                WAV I/O (legacy)
```

## License

MIT.
