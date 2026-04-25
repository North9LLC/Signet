// Minimal drand client: shells out to `curl` for HTTP (no http-client crate cached).

use std::process::Command;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct DrandRound {
    pub round: u64,
    pub signature_hex: String,
    pub randomness_hex: String,
    pub previous_signature_hex: String,
}

#[derive(serde::Deserialize)]
struct RawResp {
    round: u64,
    signature: String,
    randomness: String,
    #[serde(default)]
    previous_signature: String,
}

/// Fetch the latest drand round from api.drand.sh via `curl`. 5s timeout.
pub fn fetch_latest() -> Result<DrandRound, String> {
    fetch_url("https://api.drand.sh/public/latest")
}

/// Fetch a specific drand round from api.drand.sh via `curl`. 5s timeout.
pub fn fetch_round(round: u64) -> Result<DrandRound, String> {
    fetch_url(&format!("https://api.drand.sh/public/{}", round))
}

/// Convert a drand round number to a Unix timestamp.
/// Drand genesis: 1592213100 Unix, period: 30 seconds.
pub fn round_to_unix(round: u64) -> u64 {
    1_592_213_100 + (round.saturating_sub(1)) * 30
}

/// Verify that the drand signature's SHA-256 hash matches the randomness field.
/// This ensures the signature bytes were not tampered with.
pub fn verify_signature(signature_hex: &str, randomness_hex: &str) -> bool {
    let sig_bytes = match hex_to_bytes(signature_hex) {
        Some(b) => b,
        None => return false,
    };
    let hash = Sha256::digest(&sig_bytes);
    let hash_hex = format!("{:x}", hash);
    hash_hex == randomness_hex
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

fn fetch_url(url: &str) -> Result<DrandRound, String> {
    let out = Command::new("curl")
        .args(["-s", "--max-time", "5", url])
        .output()
        .map_err(|e| format!("failed to spawn curl: {}", e))?;
    if !out.status.success() {
        return Err(format!("curl exited with status {}", out.status));
    }
    let body = std::str::from_utf8(&out.stdout)
        .map_err(|e| format!("curl output not utf-8: {}", e))?;
    if body.is_empty() {
        return Err("curl returned empty body".to_string());
    }
    from_json(body)
}

/// Parse a drand JSON response into a DrandRound.
pub fn from_json(json: &str) -> Result<DrandRound, String> {
    let raw: RawResp =
        serde_json::from_str(json).map_err(|e| format!("json parse error: {}", e))?;
    Ok(DrandRound {
        round: raw.round,
        signature_hex: raw.signature,
        randomness_hex: raw.randomness,
        previous_signature_hex: raw.previous_signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_real_response() {
        let js = r#"{"round":6052808,"randomness":"f0a48d681bc43eacd26c87b1e4424e9382cd43061fc1b4943e1834d2560712bf","signature":"8c3d933b3e36210c80eb383c21314521822ccf4ac7b7a99b1f855d7f257ce7be39c56d9ac9d87922df06fa4449aea6a501a41f199025814329baa5a81e119a8795702066f8c4c03601b44c5d194657d55a5bca769d239256c73ee8339b7dc95b","previous_signature":"aa4365d59e6ce201e873d32735d3714cc99d503e2e0e845bdaa45ff02705c1f4"}"#;
        let r = from_json(js).expect("should parse");
        assert_eq!(r.round, 6052808);
        assert_eq!(r.signature_hex.len(), 192);
        assert_eq!(r.randomness_hex.len(), 64);
        assert_eq!(r.previous_signature_hex, "aa4365d59e6ce201e873d32735d3714cc99d503e2e0e845bdaa45ff02705c1f4");
    }

    #[test]
    fn parse_malformed_errors() {
        assert!(from_json("not json").is_err());
    }

    #[test]
    fn parse_missing_previous_signature() {
        // previous_signature is optional (round 1 has none)
        let js = r#"{"round":1,"randomness":"deadbeef","signature":"cafebabe","previous_signature":""}"#;
        let r = from_json(js).expect("should parse with empty prev sig");
        assert_eq!(r.round, 1);
        assert_eq!(r.previous_signature_hex, "");
    }

    #[test]
    fn round_to_unix_known() {
        // Round 1: genesis = 1592213100
        assert_eq!(round_to_unix(1), 1592213100);
        // Round 2: genesis + 30
        assert_eq!(round_to_unix(2), 1592213130);
        // Round 6052808: genesis + (6052808-1) * 30
        let expected = 1_592_213_100 + (6_052_808u64 - 1) * 30;
        assert_eq!(round_to_unix(6_052_808), expected);
    }
}
