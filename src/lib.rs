pub mod channel;
pub mod crypto;
pub mod device;
pub mod drand;
pub mod fec;
pub mod imgwm;
pub mod modem;
pub mod payload;
pub mod wav;

// ── C FFI ────────────────────────────────────────────────────────────────────
//
// Three functions for camera app integration:
//
//   signet_prefetch_round()  — background thread, every 25 s
//   signet_stamp_pixels()    — at shutter press, synchronous, < 5 ms
//   signet_verify_pixels()   — returns 1=verified+trusted, 0=not verified
//
// The stamp is now signed with the device Ed25519 key.  Without that key
// no-one can produce a valid stamp, even knowing the algorithm.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

/// Fetch the current drand round and cache its signature.
/// `out_sig_hex` must be ≥ 385 bytes.
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

/// Stamp raw RGB pixels with the device key + drand round.
///
/// `sig_hex` is the hex drand signature from `signet_prefetch_round`.
/// `key_path` is the path to the device key file (NULL = default ~/.signet/device.key).
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
    let signing_key = match device::load_or_create_key() {
        Ok(k) => k,
        Err(_) => return -1,
    };
    let vk = signing_key.verifying_key();
    let dev_id = device::device_id(&vk);
    let sig_bytes = device::sign_stamp(&signing_key, drand_round, &dev_id, &pay16);
    let frame = imgwm::build_frame(drand_round, &pay16, &dev_id, &sig_bytes);
    let npixels = (width * height) as usize;
    let pixels = unsafe { std::slice::from_raw_parts_mut(pixels_rgb, npixels * 3) };
    match imgwm::embed(pixels, npixels, &frame) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Verify a Signet watermark in raw RGB pixels.
/// Returns 1 if VERIFIED (valid drand + trusted device signature), 0 otherwise.
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

    let raw_frame = match imgwm::extract(pixels, npixels) {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let parsed = imgwm::parse_frame(&raw_frame);

    // Verify device signature first — this is what prevents faking
    let vk = match device::lookup_device(&parsed.device_id) {
        Some(k) => k,
        None => return 0, // unknown / untrusted device
    };
    if !device::verify_stamp(
        &vk,
        &parsed.signature,
        parsed.drand_round,
        &parsed.device_id,
        &parsed.drand_payload,
    ) {
        return 0;
    }

    // Verify drand payload against the chain
    let round_data = match drand::fetch_round(parsed.drand_round) {
        Ok(r) => r,
        Err(_) => return 0,
    };
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
