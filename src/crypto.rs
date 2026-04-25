// Minimal HMAC-SHA256, HKDF-SHA256, and CRC-32. No external crates beyond sha2.

use sha2::{Digest, Sha256};

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let d = Sha256::digest(key);
        k[..32].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(ih);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let prk = hmac_sha256(salt, ikm);
    let mut out = Vec::with_capacity(out_len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < out_len {
        let mut msg = Vec::with_capacity(t.len() + info.len() + 1);
        msg.extend_from_slice(&t);
        msg.extend_from_slice(info);
        msg.push(counter);
        let ti = hmac_sha256(&prk, &msg);
        out.extend_from_slice(&ti);
        t = ti.to_vec();
        counter += 1;
    }
    out.truncate(out_len);
    out
}

// CRC-32 IEEE 802.3 (reflected, poly 0xEDB88320, init 0xFFFFFFFF, xorout 0xFFFFFFFF).
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_rfc4231_case1() {
        // RFC 4231 Test Case 1
        let key = [0x0b; 20];
        let msg = b"Hi There";
        let expected = hex_decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(hmac_sha256(&key, msg).to_vec(), expected);
    }

    #[test]
    fn hkdf_rfc5869_case1() {
        // RFC 5869 Test Case 1
        let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_decode("000102030405060708090a0b0c");
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
        let expected = hex_decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );
        assert_eq!(hkdf_sha256(&salt, &ikm, &info, 42), expected);
    }

    #[test]
    fn crc32_known() {
        // CRC-32("123456789") = 0xCBF43926
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
