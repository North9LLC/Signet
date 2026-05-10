// Device identity and signing.
//
// KEY SECURITY GUARANTEES (and their limits):
//
//   1. Content binding  — the signature covers pixel_hash, so a frame
//      extracted from image A cannot be transplanted into image B.
//
//   2. Device binding   — the signature covers device_id; only the holder
//      of the matching Ed25519 private key can produce a valid stamp.
//
//   3. Time binding     — the signature covers drand_round and drand_payload;
//      both are checked against the live drand chain at verify time, and
//      stamps older than MAX_STAMP_AGE_SECS are rejected.
//
// KNOWN LIMITATIONS:
//
//   Software key  — the key is stored at ~/.signet/device.key (mode 0600).
//                   A rooted phone or a stolen backup can extract it.
//                   Production must use iOS Secure Enclave or Android
//                   StrongBox so the key is hardware-bound and unextractable.
//
//   Local registry — trusted_devices.json is a local file.  Anyone on the
//                    same machine can add their own key with `signet enroll`.
//                    Production must query a remote, append-only registry
//                    that requires hardware attestation for enrollment
//                    (Apple DeviceCheck / Android Play Integrity).
//                    Verification output explicitly warns when local-only.
//
// SIGN MESSAGE:
//   "signet-v3" || round_le8 || device_id_16 || drand_payload_16 || pixel_hash_32
//   = 9 + 8 + 16 + 16 + 32 = 81 bytes

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::fs;
use std::path::PathBuf;

const SIGN_DOMAIN: &[u8] = b"signet-v3";


// ── Key storage ──────────────────────────────────────────────────────────────

fn key_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".signet").join("device.key")
}

fn trusted_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".signet").join("trusted_devices.json")
}

/// Load the device signing key, creating one if none exists.
pub fn load_or_create_key() -> Result<SigningKey, String> {
    let path = key_path();
    if path.exists() {
        let bytes = fs::read(&path).map_err(|e| format!("read key: {}", e))?;
        if bytes.len() != 32 {
            return Err("device.key corrupt (expected 32 bytes)".into());
        }
        let seed: [u8; 32] = bytes.try_into().unwrap();
        Ok(SigningKey::from_bytes(&seed))
    } else {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| format!("rng: {}", e))?;
        let key = SigningKey::from_bytes(&seed);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir: {}", e))?;
        }
        fs::write(&path, seed).map_err(|e| format!("write key: {}", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("chmod: {}", e))?;
        }
        println!("generated new device key at {}", path.display());
        Ok(key)
    }
}

// ── Device ID ────────────────────────────────────────────────────────────────

/// First 8 bytes of SHA-256(public_key).
/// 64 bits: collision probability negligible at any realistic device count.
pub fn device_id(vk: &VerifyingKey) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(vk.as_bytes());
    hash[..8].try_into().unwrap()
}

// ── Signing ───────────────────────────────────────────────────────────────────

/// Sign a stamp.  pixel_hash binds the signature to specific image content —
/// the same frame cannot be transplanted into a different image.
pub fn sign_stamp(
    key: &SigningKey,
    drand_round: u64,
    dev_id: &[u8; 8],
    drand_payload: &[u8; 16],
    pixel_hash: &[u8; 32],
) -> [u8; 64] {
    let msg = build_sign_msg(drand_round, dev_id, drand_payload, pixel_hash);
    key.sign(&msg).to_bytes()
}

/// Verify a stamp signature.
pub fn verify_stamp(
    vk: &VerifyingKey,
    sig_bytes: &[u8; 64],
    drand_round: u64,
    dev_id: &[u8; 8],
    drand_payload: &[u8; 16],
    pixel_hash: &[u8; 32],
) -> bool {
    let msg = build_sign_msg(drand_round, dev_id, drand_payload, pixel_hash);
    let sig = Signature::from_bytes(sig_bytes);
    vk.verify(&msg, &sig).is_ok()
}

fn build_sign_msg(
    drand_round: u64,
    dev_id: &[u8; 8],
    drand_payload: &[u8; 16],
    pixel_hash: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SIGN_DOMAIN.len() + 8 + 8 + 16 + 32);
    msg.extend_from_slice(SIGN_DOMAIN);
    msg.extend_from_slice(&drand_round.to_le_bytes());
    msg.extend_from_slice(dev_id);
    msg.extend_from_slice(drand_payload);
    msg.extend_from_slice(pixel_hash);
    msg
}

// ── Freshness check ───────────────────────────────────────────────────────────

/// Check whether `submitted_round` is suspiciously older than `latest_round`.
///
/// Backdating attack: attacker uses a round from years ago to make a
/// recently-generated AI image appear historical.  We reject rounds that
/// are more than MAX_BACKDATING_ROUNDS behind the live latest.
///
/// We compare against the live latest (not wall clock) so that a legitimately
/// stale drand API head is never falsely flagged.
pub const MAX_BACKDATING_ROUNDS: u64 = 10; // 10 × 30s = 5 minutes

pub fn check_backdating(submitted_round: u64, latest_round: u64) -> Result<(), String> {
    if submitted_round > latest_round + 2 {
        return Err(format!(
            "round {} is {} rounds ahead of current ({}) — possible clock skew",
            submitted_round,
            submitted_round - latest_round,
            latest_round
        ));
    }
    if latest_round > submitted_round + MAX_BACKDATING_ROUNDS {
        let lag = latest_round - submitted_round;
        return Err(format!(
            "round {} is {} rounds ({} minutes) behind the latest ({}) — \
             backdating rejected; use the current drand round",
            submitted_round,
            lag,
            lag / 2,
            latest_round
        ));
    }
    Ok(())
}

// ── Trusted device registry ───────────────────────────────────────────────────
//
// ⚠ LOCAL REGISTRY — DEVELOPMENT ONLY ⚠
//
// This JSON file is writable by any process running as this user.  An
// attacker with local access can self-enroll and then verify their own
// forged stamps.  Production MUST replace `lookup_device` with a call to
// a remote, append-only registry that enforces hardware attestation during
// enrollment.

pub enum TrustSource {
    Local,
    // Remote(String),  -- future: add server-verified registry
}

pub struct TrustLookup {
    pub verifying_key: VerifyingKey,
    pub source: TrustSource,
}

/// Register a device in the local trusted list (dev mode only).
pub fn trust_device(dev_id: &[u8; 8], vk: &VerifyingKey) -> Result<(), String> {
    let mut map = load_trusted_map();
    map.insert(hex(dev_id), hex(vk.as_bytes()));
    let json = serde_json::to_string_pretty(&map)
        .map_err(|e| format!("serialize: {}", e))?;
    let path = trusted_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir: {}", e))?;
    }
    fs::write(&path, json).map_err(|e| format!("write trusted: {}", e))?;
    Ok(())
}

/// Look up a device from the remote registry (via SIGNET_REGISTRY_URL env var).
/// If SIGNET_REGISTRY_URL is unset or the registry is unreachable, returns None.
pub fn lookup_device(dev_id: &[u8; 8]) -> Option<TrustLookup> {
    let registry_url = std::env::var("SIGNET_REGISTRY_URL")
        .ok()
        .filter(|s| !s.is_empty())?;

    let dev_id_hex = hex(dev_id);
    let url = format!("{}/devices/{}", registry_url, dev_id_hex);

    let result = std::process::Command::new("curl")
        .args(["-s", "--max-time", "5", &url])
        .output();

    if result.is_err() {
        return None;
    }

    let output = result.unwrap();
    if !output.status.success() {
        return None;
    }

    let body = std::str::from_utf8(&output.stdout).ok()?;
    let pk_hex: String = serde_json::from_str(body)
        .ok()
        .and_then(|v: serde_json::Value| v.get("public_key")?.as_str().map(|s| s.to_string()))?;

    let pk_bytes = unhex(&pk_hex)?;
    let arr: [u8; 32] = pk_bytes.try_into().ok()?;
    let vk = VerifyingKey::from_bytes(&arr).ok()?;
    Some(TrustLookup { verifying_key: vk, source: TrustSource::Local })
}

fn load_trusted_map() -> std::collections::HashMap<String, String> {
    let path = trusted_path();
    if !path.exists() {
        return std::collections::HashMap::new();
    }
    serde_json::from_str(&fs::read_to_string(&path).unwrap_or_default())
        .unwrap_or_default()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
