// Payload derivation from a drand beacon signature.

/// Derive the 128-bit payload embedded in the audio beacon from a drand round's signature.
///
/// The drand signature is a BLS signature, hex-encoded (96 bytes when decoded).
/// We run it through HKDF-SHA256 with info="signet-fsk-v0" and take the first 16 bytes.
pub fn derive_from_drand_signature(sig_hex: &str) -> Result<[u8; 16], String> {
    let sig_bytes = hex_decode(sig_hex)?;
    let okm = crate::crypto::hkdf_sha256(b"", &sig_bytes, b"signet-fsk-v0", 16);
    let mut out = [0u8; 16];
    out.copy_from_slice(&okm);
    Ok(out)
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("hex string has odd length: {}", s.len()));
    }
    let nyb = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(format!("non-hex character '{}'", c as char)),
        }
    };
    let b = s.as_bytes();
    let mut result = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) {
        result.push((nyb(b[i])? << 4) | nyb(b[i + 1])?);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed 192-hex-char (96-byte) signature used as a regression fixture.
    const FIXED_SIG: &str = "8c3d933b3e36210c80eb383c21314521822ccf4ac7b7a99b1f855d7f257ce7be39c56d9ac9d87922df06fa4449aea6a501a41f199025814329baa5a81e119a8795702066f8c4c03601b44c5d194657d55a5bca769d239256c73ee8339b7dc95b";

    #[test]
    fn derive_is_deterministic() {
        let a = derive_from_drand_signature(FIXED_SIG).unwrap();
        let b = derive_from_drand_signature(FIXED_SIG).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn derive_known_vector() {
        // Regression: if this changes, HKDF parameters or hex decoding changed.
        let got = derive_from_drand_signature(FIXED_SIG).unwrap();
        let expected: [u8; 16] = [
            0x37, 0x78, 0xff, 0x56, 0x30, 0x0f, 0xb4, 0x67,
            0xf3, 0x3c, 0x37, 0x74, 0xd2, 0x58, 0x2c, 0x0e,
        ];
        assert_eq!(got, expected, "got {:02x?}", got);
    }

    #[test]
    fn derive_differs_with_different_input() {
        let other = "aa4365d59e6ce201e873d32735d3714cc99d503e2e0e845bdaa45ff02705c1f4aa4365d59e6ce201e873d32735d3714cc99d503e2e0e845bdaa45ff02705c1f4aa4365d59e6ce201e873d32735d3714cc99d503e2e0e845bdaa45ff02705c1f4";
        let a = derive_from_drand_signature(FIXED_SIG).unwrap();
        let b = derive_from_drand_signature(other).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn hex_decode_mixed_case() {
        assert_eq!(hex_decode("AbCd01").unwrap(), vec![0xab, 0xcd, 0x01]);
    }

    #[test]
    fn hex_decode_odd_length_errors() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn hex_decode_invalid_char_errors() {
        assert!(hex_decode("zz").is_err());
    }

    #[test]
    fn derive_invalid_hex_errors() {
        assert!(derive_from_drand_signature("not-hex").is_err());
    }
}
