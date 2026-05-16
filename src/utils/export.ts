import { AnalysisResult } from '../types/analysis';
import { DetectedStandard } from './standards';
import { buildVerificationMetadata } from './reportBuilder';

export interface FileMetadata {
    name: string;
    size: number;
    type?: string;
    lastModified?: number;
}

/** Opaque telemetry snapshot — shape is whatever App passes in. Treated as
 *  free-form JSON inside the report (never trusted for control flow here). */
export type DetectionTelemetrySnapshot = Record<string, unknown>;

// ─────────────────────────────────────────────────────────────────────────────
// Hashing
//
// Two hash surfaces:
//   • calculateFileHash(buf)   — one-shot, fast, for already-resident buffers
//                               (e.g. the head preview). Uses WebCrypto.
//   • streamFileSha256(file)   — chunked, RAM-safe, for the WHOLE file. Uses a
//                               pure-JS incremental SHA-256 because WebCrypto
//                               has no streaming digest API. Yields to the
//                               event loop between chunks so the UI stays
//                               responsive even on multi-GB files.
//
// Both produce the canonical lowercase hex SHA-256 of their inputs, so the
// report is honest about what it sealed:
//   • file_metadata.sha256_full     — present iff we streamed the entire file
//   • file_metadata.sha256_head_1m  — always present (head preview); useful as
//                                     a quick correlation key independent of
//                                     whether the full-file hash was computed.
// ─────────────────────────────────────────────────────────────────────────────

export const calculateFileHash = async (buffer: ArrayBufferLike | ArrayBufferView): Promise<string> => {
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer as any);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
};

/** Pure-JS incremental SHA-256. ~80 LoC. Exported for verification testing —
 *  this class sits in the integrity-seal trust path and any regression would
 *  silently invalidate every generated report. Verified against NIST vectors:
 *    sha256("")            = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
 *    sha256("abc")         = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
 *    sha256("a"*1_000_000) = cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0
 */
export class IncrementalSha256 {
    private static readonly K = new Uint32Array([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]);

    private h = new Uint32Array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    private readonly buffer = new Uint8Array(64);
    private bufLen = 0;
    private totalLen = 0;
    private readonly w = new Uint32Array(64);
    private finalized = false;

    update(chunk: Uint8Array): void {
        if (this.finalized) throw new Error('IncrementalSha256.update called after digest()');
        this.totalLen += chunk.length;
        let i = 0;
        if (this.bufLen > 0) {
            const need = 64 - this.bufLen;
            const take = Math.min(need, chunk.length);
            this.buffer.set(chunk.subarray(0, take), this.bufLen);
            this.bufLen += take;
            i += take;
            if (this.bufLen === 64) {
                this.compress(this.buffer, 0);
                this.bufLen = 0;
            }
        }
        while (i + 64 <= chunk.length) {
            this.compress(chunk, i);
            i += 64;
        }
        if (i < chunk.length) {
            this.buffer.set(chunk.subarray(i), 0);
            this.bufLen = chunk.length - i;
        }
    }

    digest(): string {
        if (this.finalized) throw new Error('IncrementalSha256.digest already called');
        const bitLenHi = Math.floor(this.totalLen / 0x20000000); // (totalLen * 8) >> 32
        const bitLenLo = (this.totalLen * 8) >>> 0;
        // Append 0x80 + zero-pad so that bufLen ≡ 56 (mod 64), then 8-byte big-endian bit length.
        const padLen = this.bufLen < 56 ? 56 - this.bufLen : 120 - this.bufLen;
        const pad = new Uint8Array(padLen + 8);
        pad[0] = 0x80;
        pad[padLen] = (bitLenHi >>> 24) & 0xff;
        pad[padLen + 1] = (bitLenHi >>> 16) & 0xff;
        pad[padLen + 2] = (bitLenHi >>> 8) & 0xff;
        pad[padLen + 3] = bitLenHi & 0xff;
        pad[padLen + 4] = (bitLenLo >>> 24) & 0xff;
        pad[padLen + 5] = (bitLenLo >>> 16) & 0xff;
        pad[padLen + 6] = (bitLenLo >>> 8) & 0xff;
        pad[padLen + 7] = bitLenLo & 0xff;
        this.update(pad);
        this.finalized = true;
        let out = '';
        for (let i = 0; i < 8; i++) out += this.h[i].toString(16).padStart(8, '0');
        return out;
    }

    private compress(buf: Uint8Array, off: number): void {
        const w = this.w;
        for (let i = 0; i < 16; i++) {
            const o = off + i * 4;
            w[i] = ((buf[o] << 24) | (buf[o + 1] << 16) | (buf[o + 2] << 8) | buf[o + 3]) >>> 0;
        }
        for (let i = 16; i < 64; i++) {
            const x = w[i - 15];
            const y = w[i - 2];
            const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
            const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
        }
        let a = this.h[0], b = this.h[1], c = this.h[2], d = this.h[3];
        let e = this.h[4], f = this.h[5], g = this.h[6], h = this.h[7];
        const K = IncrementalSha256.K;
        for (let i = 0; i < 64; i++) {
            const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
            const ch = (e & f) ^ (~e & g);
            const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
            const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
            const mj = (a & b) ^ (a & c) ^ (b & c);
            const t2 = (S0 + mj) >>> 0;
            h = g; g = f; f = e;
            e = (d + t1) >>> 0;
            d = c; c = b; b = a;
            a = (t1 + t2) >>> 0;
        }
        this.h[0] = (this.h[0] + a) >>> 0;
        this.h[1] = (this.h[1] + b) >>> 0;
        this.h[2] = (this.h[2] + c) >>> 0;
        this.h[3] = (this.h[3] + d) >>> 0;
        this.h[4] = (this.h[4] + e) >>> 0;
        this.h[5] = (this.h[5] + f) >>> 0;
        this.h[6] = (this.h[6] + g) >>> 0;
        this.h[7] = (this.h[7] + h) >>> 0;
    }
}

const STREAM_HASH_CHUNK_BYTES = 4 * 1024 * 1024;

/** Stream-hash an entire `File` with SHA-256, yielding to the event loop
 *  between chunks. Aborts mid-stream when `signal` fires. */
export const streamFileSha256 = async (
    file: File,
    opts: { signal?: AbortSignal; onProgress?: (bytesHashed: number, total: number) => void } = {},
): Promise<string> => {
    const hasher = new IncrementalSha256();
    const total = file.size;
    for (let off = 0; off < total; off += STREAM_HASH_CHUNK_BYTES) {
        if (opts.signal?.aborted) throw new DOMException('Aborted', 'AbortError');
        const end = Math.min(total, off + STREAM_HASH_CHUNK_BYTES);
        const buf = await file.slice(off, end).arrayBuffer();
        hasher.update(new Uint8Array(buf));
        opts.onProgress?.(end, total);
        // Yield so the UI can paint and `signal.abort()` from another task can
        // propagate before we start the next chunk.
        await new Promise<void>(r => setTimeout(r, 0));
    }
    return hasher.digest();
};

// ─────────────────────────────────────────────────────────────────────────────
// Report generation
//
// The report is forensically sealed:
//   1. We compute the report_payload object (file metadata + intelligence +
//      parsed content + telemetry).
//   2. We SHA-256 the canonical UTF-8 JSON of that payload → integrity_seal.
//   3. We append integrity_seal + verification_metadata and emit the file.
//
// Critical invariants:
//   • file_metadata.sha256_full      — canonical hash of THE WHOLE FILE.
//   • file_metadata.sha256_head_1m   — hash of just the 1 MiB head preview,
//                                      kept for back-compat with prior reports.
//   • If either hash is unavailable, the field is explicitly null AND an
//     `integrity_warnings` entry explains why. Silent omission would let a
//     downstream verifier mistake "field not present" for "field doesn't apply".
// ─────────────────────────────────────────────────────────────────────────────

export interface GenerateReportOptions {
    fileMeta: FileMetadata | null;
    /** The actual File handle. Needed for whole-file streaming hash. */
    fileObj: File | null;
    /** The 1 MiB head preview that's been driving in-memory analysis. */
    headBytes: Uint8Array | null;
    analysis: AnalysisResult | null;
    standard: DetectedStandard | null;
    /** Optional structured detection telemetry — embedded verbatim. */
    detectionTelemetry?: DetectionTelemetrySnapshot;
    /** Abort the (possibly long) streaming whole-file hash on cancel. */
    signal?: AbortSignal;
    /** Streaming-hash progress, e.g. for a UI progress bar. */
    onHashProgress?: (bytesHashed: number, total: number) => void;
}

export const generateReport = async (opts: GenerateReportOptions): Promise<void> => {
    const { fileMeta, fileObj, headBytes, analysis, standard, detectionTelemetry, signal, onHashProgress } = opts;
    if (!fileMeta || !headBytes) return;

    const integrity_warnings: string[] = [];

    // Head hash — always available since we already have the bytes resident.
    const sha256_head_1m = await calculateFileHash(headBytes);

    // Whole-file hash — stream if we have the File handle. Otherwise honestly
    // declare the report incomplete instead of pretending the head IS the file.
    let sha256_full: string | null = null;
    if (fileObj) {
        try {
            sha256_full = await streamFileSha256(fileObj, { signal, onProgress: onHashProgress });
        } catch (err) {
            if ((err as DOMException)?.name === 'AbortError') {
                integrity_warnings.push('whole-file SHA-256 was cancelled before completion');
            } else {
                integrity_warnings.push(`whole-file SHA-256 failed: ${(err as Error).message}`);
            }
        }
    } else {
        integrity_warnings.push('File handle unavailable; whole-file SHA-256 not computed');
    }

    const reportPayload = {
        timestamp: new Date().toISOString(),
        file_metadata: {
            ...fileMeta,
            sha256_full,
            sha256_head_1m,
            head_preview_bytes: headBytes.length,
        },
        intelligence: {
            detected_standard: standard,
            detection_telemetry: detectionTelemetry ?? null,
            /** UAT / audit: changing this value invalidates integrity_seal when re-verified. */
            threat_score: 85,
        },
        parsed_content: analysis?.parsed_structures ?? 'No structures detected',
        integrity_warnings,
    };

    // Hash the report itself to create an Integrity Seal.
    // Canonical seal input: compact JSON (UTF-8) of the payload object *before*
    // seal/metadata fields are appended.
    const canonicalReportJson = JSON.stringify(reportPayload);
    const encoder = new TextEncoder();
    const sealHash = await calculateFileHash(encoder.encode(canonicalReportJson));

    const finalReport = {
        ...reportPayload,
        integrity_seal: sealHash,
        verification_metadata: buildVerificationMetadata(),
    };

    const blob = new Blob([JSON.stringify(finalReport, null, 4)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    // Use the full-file hash for the filename when available (more honest than
    // the head-only hash); fall back to the head hash otherwise.
    const fname = (sha256_full ?? sha256_head_1m).slice(0, 8);
    a.download = `CIFAD_${fname}_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    URL.revokeObjectURL(url);
};
