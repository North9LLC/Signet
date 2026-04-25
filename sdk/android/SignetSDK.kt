package ing.paperclip.signet

import android.graphics.Bitmap
import android.graphics.Color
import androidx.camera.core.ImageProxy
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * SignetSDK — drop this file into any Android camera app.
 *
 * Usage:
 *   1. Add libsignet.so to your jniLibs/ folder.
 *   2. Call SignetSDK.start() when your CameraX session starts.
 *      This begins prefetching the drand beacon every 25 seconds.
 *   3. In your ImageCapture.OnImageCapturedCallback or ImageAnalysis.Analyzer,
 *      call stamp(bitmap) on the raw Bitmap BEFORE encoding or saving.
 *   4. Save as PNG or JPEG quality >= 90.
 *
 * Verification:
 *   SignetSDK.verify(bitmap) returns a VerifyResult with the drand round
 *   and UTC timestamp, or null if no valid watermark is present.
 */
object SignetSDK {

    // Load the Signet native library
    init {
        System.loadLibrary("signet")
    }

    // ── Native declarations ───────────────────────────────────────────────────

    @JvmStatic private external fun prefetchRound(sigHexBuf: ByteArray): Long
    @JvmStatic private external fun stampPixels(
        pixelsRgb: ByteArray, width: Int, height: Int, sigHex: String
    ): Int
    @JvmStatic private external fun verifyPixels(
        pixelsRgb: ByteArray, width: Int, height: Int,
        outRound: LongArray, outUnixTime: LongArray
    ): Int

    // ── State ─────────────────────────────────────────────────────────────────

    @Volatile private var cachedSigHex: String? = null
    private val executor = Executors.newSingleThreadScheduledExecutor()
    private var prefetchJob: ScheduledFuture<*>? = null

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /** Start background beacon prefetch. Call when the camera session opens. */
    fun start() {
        prefetchJob = executor.scheduleAtFixedRate(::prefetchNow, 0, 25, TimeUnit.SECONDS)
    }

    /** Stop background prefetch. Call when the camera session closes. */
    fun stop() {
        prefetchJob?.cancel(false)
    }

    // ── Stamp ─────────────────────────────────────────────────────────────────

    /**
     * Stamp a Bitmap with the current drand watermark.
     *
     * Call this inside your photo capture pipeline, before encoding or saving.
     * The bitmap must be in ARGB_8888 format (Android default).
     *
     * Returns true if the stamp was applied. Returns false if no beacon is
     * cached yet (call start() before opening the camera).
     */
    fun stamp(bitmap: Bitmap): Boolean {
        val sig = cachedSigHex ?: return false
        val width = bitmap.width
        val height = bitmap.height
        val rgb = bitmapToRgb(bitmap)
        if (stampPixels(rgb, width, height, sig) != 0) return false
        rgbToBitmap(rgb, bitmap)
        return true
    }

    // ── Verify ────────────────────────────────────────────────────────────────

    data class VerifyResult(val round: Long, val unixTime: Long) {
        val isoTime: String get() {
            val date = java.util.Date(unixTime * 1000)
            return java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'",
                java.util.Locale.US).apply {
                timeZone = java.util.TimeZone.getTimeZone("UTC")
            }.format(date)
        }
    }

    /**
     * Verify the Signet watermark in a Bitmap.
     * Returns null if no valid watermark is found.
     */
    fun verify(bitmap: Bitmap): VerifyResult? {
        val rgb = bitmapToRgb(bitmap)
        val outRound = LongArray(1)
        val outTime = LongArray(1)
        val ok = verifyPixels(rgb, bitmap.width, bitmap.height, outRound, outTime)
        return if (ok == 1) VerifyResult(outRound[0], outTime[0]) else null
    }

    // ── Private ───────────────────────────────────────────────────────────────

    private fun prefetchNow() {
        val buf = ByteArray(512)
        val round = prefetchRound(buf)
        if (round > 0) {
            cachedSigHex = buf.takeWhile { it != 0.toByte() }
                .toByteArray().toString(Charsets.US_ASCII)
        }
    }

    private fun bitmapToRgb(bitmap: Bitmap): ByteArray {
        val w = bitmap.width
        val h = bitmap.height
        val buf = ByteArray(w * h * 3)
        val pixels = IntArray(w * h)
        bitmap.getPixels(pixels, 0, w, 0, 0, w, h)
        for (i in pixels.indices) {
            val p = pixels[i]
            buf[i * 3 + 0] = Color.red(p).toByte()
            buf[i * 3 + 1] = Color.green(p).toByte()
            buf[i * 3 + 2] = Color.blue(p).toByte()
        }
        return buf
    }

    private fun rgbToBitmap(rgb: ByteArray, bitmap: Bitmap) {
        val w = bitmap.width
        val h = bitmap.height
        val pixels = IntArray(w * h)
        bitmap.getPixels(pixels, 0, w, 0, 0, w, h)
        for (i in pixels.indices) {
            val r = rgb[i * 3 + 0].toInt() and 0xFF
            val g = rgb[i * 3 + 1].toInt() and 0xFF
            val b = rgb[i * 3 + 2].toInt() and 0xFF
            val a = Color.alpha(pixels[i])
            pixels[i] = Color.argb(a, r, g, b)
        }
        bitmap.setPixels(pixels, 0, w, 0, 0, w, h)
    }
}
