// Device identity and signing.
//
// Each Signet-enabled device generates an Ed25519 keypair once, stored at
// ~/.signet/device.key (32-byte seed).  The device_id is the first 8 bytes
// of SHA-256(public_key) — short enough to embed in the watermark, unique
// enough to look up from a registry.
//
// Security model:
//   Software key: harder to fake than no key, but a rooted device can extract it.
//   Production:   key should live in hardware secure enclave (iOS SEP / Android
//                 StrongBox) so it is physically unextractable.  The SDK wrappers
//                 in sdk/ios and sdk/android show where to call the SE APIs.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::fs;
use std::path::PathBuf;

const SIGN_DOMAIN: &[u8] = b"signet-v2";

// ── Key storage ──────────────────────────────────────────────────────────────

fn key_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".signet").join("device.key")
}

fn trusted_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".signet").join("trusted_devices.json")
}

/// Load the device signing key, creating a new one if none exists.
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
        // Generate a fresh keypair
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| format!("rng: {}", e))?;
        let key = SigningKey::from_bytes(&seed);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir: {}", e))?;
        }
        fs::write(&path, &seed).map_err(|e| format!("write key: {}", e))?;
        // Restrict permissions on Unix
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
pub fn device_id(vk: &VerifyingKey) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(vk.as_bytes());
    hash[..8].try_into().unwrap()
}

// ── Signing ──────────────────────────────────────────────────────────────────

/// Sign a stamp: domain || drand_round || device_id || drand_payload
pub fn sign_stamp(
    key: &SigningKey,
    drand_round: u64,
    dev_id: &[u8; 8],
    drand_payload: &[u8; 16],
) -> [u8; 64] {
    let mut msg = Vec::with_capacity(SIGN_DOMAIN.len() + 8 + 8 + 16);
    msg.extend_from_slice(SIGN_DOMAIN);
    msg.extend_from_slice(&drand_round.to_le_bytes());
    msg.extend_from_slice(dev_id);
    msg.extend_from_slice(drand_payload);
    key.sign(&msg).to_bytes()
}

/// Verify a stamp signature.
pub fn verify_stamp(
    vk: &VerifyingKey,
    sig_bytes: &[u8; 64],
    drand_round: u64,
    dev_id: &[u8; 8],
    drand_payload: &[u8; 16],
) -> bool {
    let mut msg = Vec::with_capacity(SIGN_DOMAIN.len() + 8 + 8 + 16);
    msg.extend_from_slice(SIGN_DOMAIN);
    msg.extend_from_slice(&drand_round.to_le_bytes());
    msg.extend_from_slice(dev_id);
    msg.extend_from_slice(drand_payload);
    let sig = Signature::from_bytes(sig_bytes);
    vk.verify(&msg, &sig).is_ok()
}

// ── Trusted device registry ──────────────────────────────────────────────────

/// Register a device as trusted locally.  In production this would be a
/// call to the Signet PKI server.
pub fn trust_device(dev_id: &[u8; 8], vk: &VerifyingKey) -> Result<(), String> {
    let mut map = load_trusted_map();
    let id_hex = hex(dev_id);
    let pk_hex = hex(vk.as_bytes());
    map.insert(id_hex, pk_hex);
    let json = serde_json::to_string_pretty(&map)
        .map_err(|e| format!("serialize: {}", e))?;
    let path = trusted_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir: {}", e))?;
    }
    fs::write(&path, json).map_err(|e| format!("write trusted: {}", e))?;
    Ok(())
}

/// Look up a device public key by device_id.  Returns None if not enrolled.
pub fn lookup_device(dev_id: &[u8; 8]) -> Option<VerifyingKey> {
    let map = load_trusted_map();
    let id_hex = hex(dev_id);
    let pk_hex = map.get(&id_hex)?;
    let pk_bytes = unhex(pk_hex)?;
    let arr: [u8; 32] = pk_bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

fn load_trusted_map() -> std::collections::HashMap<String, String> {
    let path = trusted_path();
    if !path.exists() {
        return std::collections::HashMap::new();
    }
    let s = fs::read_to_string(&path).unwrap_or_default();
    serde_json::from_str(&s).unwrap_or_default()
}

// ── Helpers ───────────────────────────────────────────────────────���──────────

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
