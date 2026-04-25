pub mod channel;
pub mod crypto;
pub mod drand;
pub mod fec;
pub mod imgwm;
pub mod modem;
pub mod payload;
pub mod wav;

// ── C FFI ────────────────────────────────────────────────────────────────────
//
// Camera apps call these three functions:
//
//   1. signet_prefetch_round() — call every 25 s in a background thread.
//      Fetches the latest drand round and caches the signature in the
//      provided buffer.  Zero network cost at shutter press.
//
//   2. signet_stamp_pixels()   — call synchronously at shutter press.
//      Embeds the cached signature into raw RGB pixels before the app
//      encodes or saves the image.  Pure CPU, < 5 ms on any modern phone.
//
//   3. signet_verify_pixels()  — call to verify any image later.
//      Binary result: 1 = verified, 0 = not verified.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

/// Fetch the current drand round.
///
/// # Arguments
/// - `out_round`   — filled with the round number on success
/// - `out_sig_hex` — filled with the hex-encoded BLS signature (384 chars + NUL)
/// - `hex_buf_len` — must be ≥ 385
///
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
                let buf =
                    std::slice::from_raw_parts_mut(out_sig_hex as *mut u8, hex_buf_len as usize);
                buf[..hex.len()].copy_from_slice(hex.as_bytes());
                buf[hex.len()] = 0;
            }
            0
        }
        Err(_) => -1,
    }
}

/// Stamp raw RGB pixels in-place using a drand signature.
///
/// Call this at shutter press, before encoding/saving the image.
/// `pixels_rgb` is a flat buffer of `width * height * 3` bytes (R, G, B order).
///
/// # Arguments
/// - `pixels_rgb` — mutable RGB pixel buffer (modified in-place)
/// - `width`, `height` — image dimensions
/// - `sig_hex`     — hex drand signature from `signet_prefetch_round`
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn signet_stamp_pixels(
    pixels_rgb: *mut u8,
    width: c_int,
    height: c_int,
    sig_hex: *const c_char,
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
    let pay20 = fec::rs_encode(&pay16);
    let npixels = (width * height) as usize;
    let pixels = unsafe { std::slice::from_raw_parts_mut(pixels_rgb, npixels * 3) };
    match imgwm::embed(pixels, npixels, &pay20) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Verify a Signet watermark in raw RGB pixels.
///
/// # Arguments
/// - `pixels_rgb`    — RGB pixel buffer (read-only)
/// - `width`, `height` — image dimensions
/// - `out_round`     — filled with the matching drand round on success
/// - `out_unix_time` — filled with the UTC Unix timestamp on success
///
/// Returns 1 if verified, 0 if not verified or on error.
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
    let npixels = (width * height) as usize;
    let pixels = unsafe { std::slice::from_raw_parts(pixels_rgb, npixels * 3) };

    let raw20 = match imgwm::extract(pixels, npixels) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let decoded = match fec::rs_decode(&raw20) {
        Some(p) => p,
        None => return 0,
    };

    // Try latest round ±10 rounds (~5 min window)
    let latest = match drand::fetch_latest() {
        Ok(r) => r,
        Err(_) => return 0,
    };
    for delta in -10i64..=10 {
        let r = latest.round as i64 + delta;
        if r <= 0 {
            continue;
        }
        let round_num = r as u64;
        let round_data = match drand::fetch_round(round_num) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let expected = match payload::derive_from_drand_signature(&round_data.signature_hex) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if expected == decoded {
            if !out_round.is_null() {
                unsafe { *out_round = round_num };
            }
            if !out_unix_time.is_null() {
                unsafe { *out_unix_time = drand::round_to_unix(round_num) };
            }
            return 1;
        }
    }
    0
}
