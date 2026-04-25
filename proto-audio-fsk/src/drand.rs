// Minimal drand client: shells out to `curl` for HTTP (no http-client crate cached).

use std::process::Command;

#[derive(Debug, Clone)]
pub struct DrandRound {
    pub round: u64,
    pub signature_hex: String,
    pub randomness_hex: String,
}

#[derive(serde::Deserialize)]
struct RawResp {
    round: u64,
    signature: String,
    randomness: String,
}

/// Fetch the latest drand round from api.drand.sh via `curl`. 5s timeout.
pub fn fetch_latest() -> Result<DrandRound, String> {
    let out = Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "5",
            "https://api.drand.sh/public/latest",
        ])
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
    }

    #[test]
    fn parse_malformed_errors() {
        assert!(from_json("not json").is_err());
    }
}
