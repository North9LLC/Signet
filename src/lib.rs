#![allow(clippy::not_unsafe_ptr_arg_deref)]
pub mod channel;
pub mod crypto;
pub mod device;
pub mod drand;
pub mod fec;
pub mod imgwm;
pub mod modem;
pub mod payload;
pub mod wav;

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

/// Fetch the current drand round.  `out_sig_hex` must be ≥ 385 bytes.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn signet_prefetch_round(
    out_round: *mut u64,
    out_sig_hex: *mut c_char,
    hex_buf_len: c_int,
) -> c_int {
    if out_round.is_null() || out_sig_hex.is_null() || hex_buf_len < 385 {
        return -1;
    }
    match drand::fetch_latest() {
        Ok(r) => {
            let hex = r.signature_hex;
            if hex.len() + 1 > hex_buf_len as usize {
                return -1;
            }
            unsafe {
                *out_round = r.round;
                let buf = std::slice::from_raw_parts_mut(
                    out_sig_hex as *mut u8,
                    hex_buf_len as usize,
                );
                buf[..hex.len()].copy_from_slice(hex.as_bytes());
                buf[hex.len()] = 0;
            }
            0
        }
        Err(_) => -1,
    }
}

/// Stamp raw RGB pixels in-place.
///
/// The pixel commitment (SHA-256 of content bits) is computed before signing,
/// so the signature is bound to this specific image.  Transplanting this frame
/// into a different image will fail signature verification.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn signet_stamp_pixels(
    pixels_rgb: *mut u8,
    width: c_int,
    height: c_int,
    sig_hex: *const c_char,
    drand_round: u64,
) -> c_int {
    if pixels_rgb.is_null() || sig_hex.is_null() || width <= 0 || height <= 0 {
        return -1;
    }
    let sig = unsafe {
        match CStr::from_ptr(sig_hex).to_str() {
            Ok(s) => s.to_owned(),
            Err(_) => return -1,
        }
    };
    let pay16 = match payload::derive_from_drand_signature(&sig) {
        Ok(p) => p,
        Err(_) => return -1,
    };
    // Fetch round data to verify the signature and check backdating
    let round_data = match drand::fetch_round(drand_round) {
        Ok(r) => r,
        Err(_) => return -1,
    };
    // Verify the drand signature is authentic by checking SHA-256(sig) == randomness
    if !drand::verify_signature(&round_data.signature_hex, &round_data.randomness_hex) {
        return -1;
    }
    let latest = match drand::fetch_latest() {
        Ok(r) => r.round,
        Err(_) => return -1,
    };
    if device::check_backdating(drand_round, latest).is_err() {
        return -1;
    }
    let signing_key = match device::load_or_create_key() {
        Ok(k) => k,
        Err(_) => return -1,
    };
    let npixels = match (width as i64)
        .checked_mul(height as i64)
        .filter(|&n| n > 0 && n <= 100_000_000)
        .map(|n| n as usize)
    {
        Some(n) => n,
        None => return -1,
    };
    let pixels = unsafe { std::slice::from_raw_parts_mut(pixels_rgb, npixels * 3) };
    // Compute pixel commitment BEFORE modifying pixels
    let pix_hash = imgwm::pixel_commitment(pixels);
    let vk = signing_key.verifying_key();
    let dev_id = device::device_id(&vk);
    let sig_bytes = device::sign_stamp(&signing_key, drand_round, &dev_id, &pay16, &pix_hash);
    let frame = imgwm::build_frame(drand_round, &pay16, &dev_id, &sig_bytes);
    match imgwm::embed(pixels, npixels, &frame) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Verify a Signet watermark.
///
/// Checks (in order):
///   1. drand_round freshness — rejects backdated stamps
///   2. device_id in local trusted registry
///   3. Ed25519 signature including pixel commitment — proves image not modified
///      and frame not transplanted from another image
///   4. drand payload matches live chain
///
/// Returns 1 if VERIFIED, 0 otherwise.
#[no_mangle]
pub extern "C" fn signet_verify_pixels(
    pixels_rgb: *const u8,
    width: c_int,
    height: c_int,
    out_round: *mut u64,
    out_unix_time: *mut u64,
) -> c_int {
    if pixels_rgb.is_null() || width <= 0 || height <= 0 {
        return 0;
    }
    let npixels = match (width as i64)
        .checked_mul(height as i64)
        .filter(|&n| n > 0 && n <= 100_000_000)
        .map(|n| n as usize)
    {
        Some(n) => n,
        None => return 0,
    };
    let pixels = unsafe { std::slice::from_raw_parts(pixels_rgb, npixels * 3) };

    let raw_frame = match imgwm::extract(pixels, npixels) {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let parsed = imgwm::parse_frame(&raw_frame);

    // Device trust
    let trust = match device::lookup_device(&parsed.device_id) {
        Some(t) => t,
        None => return 0,
    };

    // Pixel commitment + signature
    let pix_hash = imgwm::pixel_commitment(pixels);
    if !device::verify_stamp(
        &trust.verifying_key,
        &parsed.signature,
        parsed.drand_round,
        &parsed.device_id,
        &parsed.drand_payload,
        &pix_hash,
    ) {
        return 0;
    }

    // drand chain
    let round_data = match drand::fetch_round(parsed.drand_round) {
        Ok(r) => r,
        Err(_) => return 0,
    };
    if !drand::verify_signature(&round_data.signature_hex, &round_data.randomness_hex) {
        return 0;
    }
    let expected = match payload::derive_from_drand_signature(&round_data.signature_hex) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    if expected != parsed.drand_payload {
        return 0;
    }

    if !out_round.is_null() {
        unsafe { *out_round = parsed.drand_round };
    }
    if !out_unix_time.is_null() {
        unsafe { *out_unix_time = drand::round_to_unix(parsed.drand_round) };
    }
    1
}
