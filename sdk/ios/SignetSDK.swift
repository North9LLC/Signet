import Foundation
import CoreImage
import AVFoundation

// SignetSDK — drop this file into any iOS camera app.
//
// Usage:
//   1. Call SignetSDK.shared.start() when the camera session starts.
//      This begins prefetching the drand beacon every 25 seconds.
//   2. In your AVCapturePhotoCaptureDelegate or photo processing pipeline,
//      call stamp(pixelBuffer:) on the raw CVPixelBuffer BEFORE encoding.
//   3. Save the modified buffer as PNG (lossless) or JPEG at quality ≥ 0.9.
//
// Verification:
//   SignetSDK.verify(pixelBuffer:) returns a VerifyResult with the drand
//   round and UTC timestamp, or nil if the image has no valid watermark.

public final class SignetSDK {
    public static let shared = SignetSDK()

    private var cachedSigHex: String?
    private var cachedRound: UInt64 = 0
    private var prefetchTimer: Timer?
    private let sigBuf = UnsafeMutablePointer<CChar>.allocate(capacity: 512)

    private init() {}

    deinit {
        sigBuf.deallocate()
    }

    // MARK: - Lifecycle

    /// Start background beacon prefetch. Call when the camera session opens.
    public func start() {
        prefetchNow()
        prefetchTimer = Timer.scheduledTimer(withTimeInterval: 25, repeats: true) { [weak self] _ in
            self?.prefetchNow()
        }
    }

    /// Stop background prefetch. Call when the camera session closes.
    public func stop() {
        prefetchTimer?.invalidate()
        prefetchTimer = nil
    }

    // MARK: - Stamp

    /// Stamp a CVPixelBuffer with the current drand watermark.
    ///
    /// Call this inside your photo capture pipeline, on the raw pixels,
    /// before encoding or saving. The buffer must be kCVPixelFormatType_32BGRA
    /// or kCVPixelFormatType_24RGB.
    ///
    /// TODO: hardware attestation required for production. The device's public key
    /// certificate must be obtained from the Secure Enclave and passed to the C API
    /// so that verifiers can confirm the stamp came from a hardware-backed key.
    ///
    /// Returns true if the stamp was applied, false if no beacon is cached yet.
    @discardableResult
    public func stamp(pixelBuffer: CVPixelBuffer) -> Bool {
        guard let sig = cachedSigHex else { return false }
        CVPixelBufferLockBaseAddress(pixelBuffer, [])
        defer { CVPixelBufferUnlockBaseAddress(pixelBuffer, []) }

        guard let base = CVPixelBufferGetBaseAddress(pixelBuffer) else { return false }
        let width = CVPixelBufferGetWidth(pixelBuffer)
        let height = CVPixelBufferGetHeight(pixelBuffer)

        // Convert BGRA → contiguous RGB scratch buffer, stamp, write back
        let npixels = width * height
        var rgb = [UInt8](repeating: 0, count: npixels * 3)
        let src = base.assumingMemoryBound(to: UInt8.self)
        let bytesPerRow = CVPixelBufferGetBytesPerRow(pixelBuffer)

        for y in 0..<height {
            for x in 0..<width {
                let srcIdx = y * bytesPerRow + x * 4
                let dstIdx = (y * width + x) * 3
                rgb[dstIdx + 0] = src[srcIdx + 2] // R (from BGRA)
                rgb[dstIdx + 1] = src[srcIdx + 1] // G
                rgb[dstIdx + 2] = src[srcIdx + 0] // B
            }
        }

        let result = sig.withCString { sigPtr in
            signet_stamp_pixels(&rgb, Int32(width), Int32(height), sigPtr)
        }
        guard result == 0 else { return false }

        // Write stamped blue channel back into the pixel buffer
        for y in 0..<height {
            for x in 0..<width {
                let srcIdx = (y * width + x) * 3
                let dstIdx = y * bytesPerRow + x * 4
                src[dstIdx + 0] = rgb[srcIdx + 2] // B back to BGRA
            }
        }
        return true
    }

    // MARK: - Verify

    public struct VerifyResult {
        public let round: UInt64
        public let unixTime: UInt64
        /// Human-readable UTC timestamp
        public var dateString: String {
            let date = Date(timeIntervalSince1970: TimeInterval(unixTime))
            let fmt = ISO8601DateFormatter()
            return fmt.string(from: date)
        }
    }

    /// Verify the Signet watermark in a CVPixelBuffer.
    /// Returns nil if no valid watermark is found.
    public static func verify(pixelBuffer: CVPixelBuffer) -> VerifyResult? {
        CVPixelBufferLockBaseAddress(pixelBuffer, .readOnly)
        defer { CVPixelBufferUnlockBaseAddress(pixelBuffer, .readOnly) }

        guard let base = CVPixelBufferGetBaseAddress(pixelBuffer) else { return nil }
        let width = CVPixelBufferGetWidth(pixelBuffer)
        let height = CVPixelBufferGetHeight(pixelBuffer)
        let bytesPerRow = CVPixelBufferGetBytesPerRow(pixelBuffer)
        let npixels = width * height
        var rgb = [UInt8](repeating: 0, count: npixels * 3)
        let src = base.assumingMemoryBound(to: UInt8.self)

        for y in 0..<height {
            for x in 0..<width {
                let srcIdx = y * bytesPerRow + x * 4
                let dstIdx = (y * width + x) * 3
                rgb[dstIdx + 0] = src[srcIdx + 2]
                rgb[dstIdx + 1] = src[srcIdx + 1]
                rgb[dstIdx + 2] = src[srcIdx + 0]
            }
        }

        var outRound: UInt64 = 0
        var outTime: UInt64 = 0
        let verified = signet_verify_pixels(&rgb, Int32(width), Int32(height), &outRound, &outTime)
        guard verified == 1 else { return nil }
        return VerifyResult(round: outRound, unixTime: outTime)
    }

    // MARK: - Private

    private func prefetchNow() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            var round: UInt64 = 0
            let ret = signet_prefetch_round(&round, self.sigBuf, 512)
            if ret == 0 {
                self.cachedRound = round
                self.cachedSigHex = String(cString: self.sigBuf)
            }
        }
    }
}
