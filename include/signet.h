#ifndef SIGNET_H
#define SIGNET_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fetch the latest drand round and cache its signature.
 *
 * Call this every 25 seconds in a background thread.
 * The cached sig_hex is what you pass to signet_stamp_pixels() at shutter press —
 * so there is zero network latency at capture time.
 *
 * @param out_round    Filled with the drand round number.
 * @param out_sig_hex  Buffer filled with the hex BLS signature (NUL-terminated).
 *                     Must be at least 385 bytes.
 * @param hex_buf_len  Size of out_sig_hex buffer. Must be >= 385.
 * @return 0 on success, -1 on error.
 */
int signet_prefetch_round(uint64_t *out_round, char *out_sig_hex, int hex_buf_len);

/**
 * Embed a Signet watermark into raw RGB pixels at capture time.
 *
 * Call this synchronously inside your camera pipeline, on the raw pixel
 * data, BEFORE encoding to JPEG/PNG or writing to disk.
 *
 * The modification is invisible: only the LSB of the blue channel is
 * touched, spread across every pixel. On a 12 MP image this is
 * ~75 000 redundant votes per bit — robust against JPEG compression
 * and minor edits.
 *
 * @param pixels_rgb  Flat RGB buffer: [R0,G0,B0, R1,G1,B1, ...].
 *                    Modified in-place.
 * @param width       Image width in pixels.
 * @param height      Image height in pixels.
 * @param sig_hex     NUL-terminated hex drand signature from signet_prefetch_round().
 * @return 0 on success, -1 on error.
 */
int signet_stamp_pixels(uint8_t *pixels_rgb, int width, int height, const char *sig_hex);

/**
 * Verify the Signet watermark in raw RGB pixels.
 *
 * Extracts the embedded payload, RS-decodes it, and checks it against
 * the live drand chain. Binary result — no scores, no thresholds.
 *
 * @param pixels_rgb    Flat RGB buffer (read-only).
 * @param width         Image width in pixels.
 * @param height        Image height in pixels.
 * @param out_round     If non-NULL, filled with the matching drand round.
 * @param out_unix_time If non-NULL, filled with the UTC Unix timestamp.
 * @return 1 if VERIFIED, 0 if NOT VERIFIED.
 */
int signet_verify_pixels(const uint8_t *pixels_rgb, int width, int height,
                         uint64_t *out_round, uint64_t *out_unix_time);

#ifdef __cplusplus
}
#endif

#endif /* SIGNET_H */
