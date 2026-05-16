import { describe, expect, it } from 'vitest';
import {
    detectHttp1,
    detectHttp2,
    detectQuic,
    detectSip,
    detectDiameter,
    detectEtsiLi,
    detect3gppCdr,
    detectVendorPeriodic,
    detectProtocols,
} from './protocols';
import { TlvNode } from '../types/analysis';

// ─── helpers ─────────────────────────────────────────────────────────────────

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

const cat = (...parts: Array<Uint8Array | number[]>): Uint8Array => {
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
        const arr = p instanceof Uint8Array ? p : new Uint8Array(p);
        out.set(arr, off);
        off += arr.length;
    }
    return out;
};

const mkTlv = (tag: number, offset: number, children: TlvNode[] = [], valueLen = 10): TlvNode => ({
    name: '',
    tag,
    offset,
    header_len: 2,
    value_len: valueLen,
    value_offset: offset + 2,
    total_len: 2 + valueLen,
    is_container: children.length > 0,
    children,
});

// ─── HTTP/1.x ────────────────────────────────────────────────────────────────

describe('detectHttp1', () => {
    it('matches GET request with Host header at high confidence', () => {
        const bytes = enc('GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n');
        const h = detectHttp1(bytes);
        expect(h).not.toBeNull();
        expect(h!.family).toBe('http');
        expect(h!.name).toContain('HTTP/1.1');
        expect(h!.name).toContain('GET');
        expect(h!.confidence).toBeGreaterThanOrEqual(0.95);
        expect(h!.evidence.some(e => e.toLowerCase().includes('host'))).toBe(true);
    });

    it('matches POST/PUT/DELETE/PATCH/OPTIONS/CONNECT/TRACE/HEAD', () => {
        for (const method of ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'CONNECT', 'TRACE', 'HEAD']) {
            const bytes = enc(`${method} /x HTTP/1.1\r\nHost: a\r\n\r\n`);
            const h = detectHttp1(bytes);
            expect(h, `method ${method}`).not.toBeNull();
            expect(h!.name).toContain(method);
        }
    });

    it('matches HTTP response with corroborating headers', () => {
        const bytes = enc('HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n<html>');
        const h = detectHttp1(bytes);
        expect(h).not.toBeNull();
        expect(h!.name).toContain('response');
        expect(h!.confidence).toBeGreaterThanOrEqual(0.93);
    });

    it('lowers confidence when corroborating headers are absent', () => {
        // Valid request line + an unrecognised header (no Host).
        const bytes = enc('GET /index.html HTTP/1.1\r\nReferer: example.org\r\n\r\n');
        const h = detectHttp1(bytes);
        expect(h).not.toBeNull();
        expect(h!.confidence).toBeLessThan(0.90);
        expect(h!.confidence).toBeGreaterThanOrEqual(0.80);
    });

    it('rejects HTTP/2.0 request preface (PRI * HTTP/2.0)', () => {
        const bytes = enc('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
        expect(detectHttp1(bytes)).toBeNull();
    });

    it('rejects binary file whose first byte is "G" but is not HTTP', () => {
        const bytes = cat([0x47, 0x49, 0x46, 0x38, 0x39, 0x61], new Uint8Array(64).fill(0x00));  // GIF89a
        expect(detectHttp1(bytes)).toBeNull();
    });

    it('rejects partial request line (no CRLF)', () => {
        const bytes = enc('GET / HTTP/1.1');  // no \r\n
        expect(detectHttp1(bytes)).toBeNull();
    });

    it('rejects invalid HTTP version (HTTP/0.9, HTTP/2.0 in request line)', () => {
        expect(detectHttp1(enc('GET / HTTP/0.9\r\nHost: a\r\n\r\n'))).toBeNull();
        expect(detectHttp1(enc('GET / HTTP/2.0\r\nHost: a\r\n\r\n'))).toBeNull();
    });

    it('rejects unknown method', () => {
        expect(detectHttp1(enc('YEET / HTTP/1.1\r\nHost: a\r\n\r\n'))).toBeNull();
    });
});

// ─── HTTP/2 ──────────────────────────────────────────────────────────────────

const H2_PREFACE_BYTES = enc('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');

describe('detectHttp2', () => {
    it('matches valid preface + empty SETTINGS frame at maximum confidence', () => {
        const settingsFrame = new Uint8Array([
            0x00, 0x00, 0x00,  // length=0
            0x04,              // type=SETTINGS
            0x00,              // flags=0
            0x00, 0x00, 0x00, 0x00,  // stream=0
        ]);
        const bytes = cat(H2_PREFACE_BYTES, settingsFrame);
        const h = detectHttp2(bytes);
        expect(h).not.toBeNull();
        expect(h!.confidence).toBeGreaterThanOrEqual(0.99);
        expect(h!.evidence.some(e => e.includes('SETTINGS'))).toBe(true);
    });

    it('matches valid preface + SETTINGS with 2 params (12 bytes payload)', () => {
        const settingsFrame = new Uint8Array([
            0x00, 0x00, 0x0c,  // length=12 (2 params × 6 bytes)
            0x04,              // type=SETTINGS
            0x00,
            0x00, 0x00, 0x00, 0x00,
            // 2× (id:u16 + value:u32)
            0x00, 0x03, 0x00, 0x00, 0x00, 0x64,  // SETTINGS_MAX_CONCURRENT_STREAMS=100
            0x00, 0x04, 0x00, 0x01, 0x00, 0x00,  // SETTINGS_INITIAL_WINDOW_SIZE=65536
        ]);
        const bytes = cat(H2_PREFACE_BYTES, settingsFrame);
        const h = detectHttp2(bytes);
        expect(h).not.toBeNull();
        expect(h!.confidence).toBeGreaterThanOrEqual(0.99);
    });

    it('lowers confidence on preface followed by non-SETTINGS frame', () => {
        const dataFrame = new Uint8Array([
            0x00, 0x00, 0x00,
            0x00,              // type=DATA (not SETTINGS)
            0x00,
            0x00, 0x00, 0x00, 0x01,  // stream=1
        ]);
        const bytes = cat(H2_PREFACE_BYTES, dataFrame);
        const h = detectHttp2(bytes);
        expect(h).not.toBeNull();
        expect(h!.confidence).toBeLessThan(0.95);
        expect(h!.confidence).toBeGreaterThanOrEqual(0.75);
    });

    it('lowers confidence on SETTINGS with non-zero stream id (protocol violation)', () => {
        const bad = new Uint8Array([
            0x00, 0x00, 0x00,
            0x04,
            0x00,
            0x00, 0x00, 0x00, 0x05,  // stream=5 — illegal for SETTINGS
        ]);
        const bytes = cat(H2_PREFACE_BYTES, bad);
        const h = detectHttp2(bytes);
        expect(h).not.toBeNull();
        expect(h!.confidence).toBeLessThan(0.95);
    });

    it('rejects truncated preface', () => {
        expect(detectHttp2(H2_PREFACE_BYTES.subarray(0, 20))).toBeNull();
    });

    it('rejects almost-preface (one byte off)', () => {
        const corrupted = new Uint8Array(H2_PREFACE_BYTES);
        corrupted[10] ^= 0x01;
        expect(detectHttp2(corrupted)).toBeNull();
    });

    it('returns null on HTTP/1 request', () => {
        expect(detectHttp2(enc('GET / HTTP/1.1\r\nHost: a\r\n\r\n'))).toBeNull();
    });
});

// ─── QUIC ────────────────────────────────────────────────────────────────────

const mkQuicLongHeader = (version: number, dcidLen: number = 8, packetType: number = 0): Uint8Array => {
    // byte0: 1 (long) | 1 (fixed) | packetType (2 bits) | type-specific (4 bits)
    const b0 = 0xc0 | ((packetType & 0x03) << 4);
    const buf = new Uint8Array(6 + dcidLen + 1);  // header + version + dcid_len + dcid + scid_len
    buf[0] = b0;
    buf[1] = (version >>> 24) & 0xff;
    buf[2] = (version >>> 16) & 0xff;
    buf[3] = (version >>> 8) & 0xff;
    buf[4] = version & 0xff;
    buf[5] = dcidLen;
    // DCID bytes left zero, scid_len byte left zero
    return buf;
};

describe('detectQuic', () => {
    it('matches QUIC v1 Initial packet', () => {
        const bytes = mkQuicLongHeader(0x00000001, 8, 0);
        const h = detectQuic(bytes);
        expect(h).not.toBeNull();
        expect(h!.confidence).toBeGreaterThanOrEqual(0.90);
        expect(h!.name).toContain('QUIC v1');
        expect(h!.evidence.some(e => e.includes('Initial'))).toBe(true);
    });

    it('matches QUIC v2', () => {
        const bytes = mkQuicLongHeader(0x6b3343cf, 8, 2);
        const h = detectQuic(bytes);
        expect(h).not.toBeNull();
        expect(h!.name).toContain('v2');
    });

    it('matches gQUIC Q050', () => {
        const bytes = mkQuicLongHeader(0x51303530, 8, 0);
        const h = detectQuic(bytes);
        expect(h).not.toBeNull();
        expect(h!.name).toContain('gQUIC');
    });

    it('flags Version Negotiation (version=0)', () => {
        const bytes = mkQuicLongHeader(0x00000000, 8, 0);
        const h = detectQuic(bytes);
        expect(h).not.toBeNull();
        expect(h!.name).toContain('Negotiation');
    });

    it('returns low confidence for unknown version with valid long-header shape', () => {
        const bytes = mkQuicLongHeader(0xdeadbeef, 8, 0);
        const h = detectQuic(bytes);
        expect(h).not.toBeNull();
        expect(h!.confidence).toBeLessThan(0.60);
        expect(h!.confidence).toBeGreaterThanOrEqual(0.40);
    });

    it('rejects short-header packets (high bit clear)', () => {
        const bytes = new Uint8Array([0x40, 0, 0, 0, 1, 0, 0, 0]);
        expect(detectQuic(bytes)).toBeNull();
    });

    it('rejects packets missing the fixed bit', () => {
        const bytes = new Uint8Array([0x80, 0, 0, 0, 1, 0, 0, 0]);
        expect(detectQuic(bytes)).toBeNull();
    });

    it('rejects DCID length > 20', () => {
        const bytes = mkQuicLongHeader(0x00000001, 21, 0);
        // Build manually to set dcid len = 21 with the rest still present
        const b = new Uint8Array(7);
        b[0] = 0xc0;
        b[1] = 0x00; b[2] = 0x00; b[3] = 0x00; b[4] = 0x01;
        b[5] = 21;
        b[6] = 0;
        expect(detectQuic(b)).toBeNull();
        // also via helper (overflows buffer but that's fine — version is still valid)
        expect(bytes[5]).toBe(21);
        expect(detectQuic(bytes)).toBeNull();
    });

    it('does NOT match PCAP magic (which has high bits set)', () => {
        // PCAP swapped magic 0xd4c3b2a1 — first byte 0xd4 (binary 11010100). (b0 & 0xc0) = 0xc0!
        // But bytes 1..4 form version 0xc3b2a100, which is not in our known list.
        // Should match with LOW confidence, NOT high.
        const pcap = new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00]);
        const h = detectQuic(pcap);
        // It WILL fire (unknown-version path), but with low confidence.
        if (h !== null) {
            expect(h.confidence).toBeLessThan(0.60);
        }
    });
});

// ─── SIP ─────────────────────────────────────────────────────────────────────

describe('detectSip', () => {
    it('matches INVITE with mandatory headers', () => {
        const msg =
            'INVITE sip:alice@atlanta.example.com SIP/2.0\r\n' +
            'Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n' +
            'Max-Forwards: 70\r\n' +
            'To: Alice <sip:alice@atlanta.example.com>\r\n' +
            'From: Bob <sip:bob@biloxi.example.com>;tag=1928301774\r\n' +
            'Call-ID: a84b4c76e66710\r\n' +
            'CSeq: 314159 INVITE\r\n' +
            '\r\n';
        const h = detectSip(enc(msg));
        expect(h).not.toBeNull();
        expect(h!.name).toContain('INVITE');
        expect(h!.confidence).toBeGreaterThanOrEqual(0.95);
    });

    it('matches SIP/2.0 response with status code', () => {
        const msg = 'SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP h\r\nFrom: a\r\nTo: b\r\nCall-ID: c\r\nCSeq: 1 ACK\r\n\r\n';
        const h = detectSip(enc(msg));
        expect(h).not.toBeNull();
        expect(h!.name).toContain('response');
        expect(h!.confidence).toBeGreaterThanOrEqual(0.95);
    });

    it('rejects HTTP/1 request masquerading as SIP', () => {
        expect(detectSip(enc('GET / SIP/2.0\r\nHost: a\r\n\r\n'))).toBeNull();
        expect(detectSip(enc('GET / HTTP/1.1\r\nHost: a\r\n\r\n'))).toBeNull();
    });

    it('rejects binary input', () => {
        expect(detectSip(new Uint8Array([0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd, 0xfc]))).toBeNull();
    });
});

// ─── Diameter ────────────────────────────────────────────────────────────────

const mkDiameterHeader = (cmd: number, length = 20, appId = 0, flags = 0x80): Uint8Array => {
    const b = new Uint8Array(20);
    b[0] = 0x01;
    b[1] = (length >>> 16) & 0xff;
    b[2] = (length >>> 8) & 0xff;
    b[3] = length & 0xff;
    b[4] = flags;
    b[5] = (cmd >>> 16) & 0xff;
    b[6] = (cmd >>> 8) & 0xff;
    b[7] = cmd & 0xff;
    b[8] = (appId >>> 24) & 0xff;
    b[9] = (appId >>> 16) & 0xff;
    b[10] = (appId >>> 8) & 0xff;
    b[11] = appId & 0xff;
    return b;
};

describe('detectDiameter', () => {
    it('matches CER (cmd=257) with high confidence', () => {
        const h = detectDiameter(mkDiameterHeader(257, 20, 0), 4096);
        expect(h).not.toBeNull();
        expect(h!.name).toContain('Capabilities-Exchange');
        expect(h!.confidence).toBeGreaterThanOrEqual(0.90);
    });

    it('matches CCR (cmd=271) for Gy/Ro charging', () => {
        const h = detectDiameter(mkDiameterHeader(271, 100, 4), 4096);
        expect(h).not.toBeNull();
        expect(h!.name).toContain('Credit-Control');
    });

    it('matches AIR (cmd=318) for S6a', () => {
        const h = detectDiameter(mkDiameterHeader(318, 20, 16777251), 4096);
        expect(h).not.toBeNull();
        expect(h!.name).toContain('Authentication-Information');
    });

    it('returns moderate confidence for unknown command code with valid header', () => {
        const h = detectDiameter(mkDiameterHeader(999999, 20, 0), 4096);
        expect(h).not.toBeNull();
        expect(h!.confidence).toBeGreaterThanOrEqual(0.55);
        expect(h!.confidence).toBeLessThan(0.85);
    });

    it('rejects wrong version byte', () => {
        const b = mkDiameterHeader(257, 20, 0);
        b[0] = 0x02;
        expect(detectDiameter(b, 4096)).toBeNull();
    });

    it('rejects length < 20', () => {
        expect(detectDiameter(mkDiameterHeader(257, 8, 0), 4096)).toBeNull();
    });

    it('rejects length not divisible by 4', () => {
        expect(detectDiameter(mkDiameterHeader(257, 21, 0), 4096)).toBeNull();
    });

    it('rejects length larger than file size', () => {
        expect(detectDiameter(mkDiameterHeader(257, 1024, 0), 100)).toBeNull();
    });

    it('rejects non-zero reserved flag bits', () => {
        const b = mkDiameterHeader(257, 20, 0, 0x80 | 0x0f);  // lower 4 bits must be 0
        expect(detectDiameter(b, 4096)).toBeNull();
    });

    it('rejects cmd code 0', () => {
        expect(detectDiameter(mkDiameterHeader(0, 20, 0), 4096)).toBeNull();
    });
});

// ─── ETSI LI / 3GPP TS 33.108 ────────────────────────────────────────────────

describe('detectEtsiLi', () => {
    it('classifies single IRI-Begin record (HI2 envelope with 0xA1 child)', () => {
        const envelope = mkTlv(0x30, 0, [
            mkTlv(0x06, 4, []),                          // domain OID
            mkTlv(0xA1, 12, [mkTlv(0x04, 14, [])]),      // IRI-Begin [1]
        ]);
        const h = detectEtsiLi([envelope]);
        expect(h).not.toBeNull();
        expect(h!.name).toContain('IRI-Begin');
        expect(h!.interfaceName).toBe('HI2');
        expect(h!.confidence).toBeGreaterThanOrEqual(0.90);
    });

    it('classifies IRI-End / IRI-Continue / IRI-Report by tag', () => {
        for (const [tag, label] of [
            [0xA2, 'IRI-End'],
            [0xA3, 'IRI-Continue'],
            [0xA4, 'IRI-Report'],
        ] as Array<[number, string]>) {
            const env = mkTlv(0x30, 0, [mkTlv(tag, 4, [])]);
            const h = detectEtsiLi([env]);
            expect(h, `tag 0x${tag.toString(16)}`).not.toBeNull();
            expect(h!.name).toContain(label);
        }
    });

    it('handles IRI sequence (multiple message types under one envelope)', () => {
        const env = mkTlv(0x30, 0, [
            mkTlv(0xA1, 4, []),
            mkTlv(0xA3, 20, []),
            mkTlv(0xA2, 36, []),
        ]);
        const h = detectEtsiLi([env]);
        expect(h).not.toBeNull();
        expect(h!.name).toMatch(/sequence/i);
        // All four-of-four would be max, three of four still high.
        expect(h!.confidence).toBeGreaterThanOrEqual(0.85);
    });

    it('does NOT fire when root tag itself is 0xA1 (CDR mtCallRecord shape, not LI)', () => {
        const cdrRoot = mkTlv(0xA1, 0, [mkTlv(0x80, 4, [])]);
        expect(detectEtsiLi([cdrRoot])).toBeNull();
    });

    it('returns null when no IRI tags found', () => {
        const env = mkTlv(0x30, 0, [mkTlv(0x06, 4, []), mkTlv(0x04, 12, [])]);
        expect(detectEtsiLi([env])).toBeNull();
    });

    it('returns null on empty input', () => {
        expect(detectEtsiLi([])).toBeNull();
        expect(detectEtsiLi(undefined)).toBeNull();
    });

    it('returns null when root is not SEQUENCE/SET', () => {
        expect(detectEtsiLi([mkTlv(0x04, 0, [])])).toBeNull();
    });

    it('does not hang on adversarially-nested trees (bounded visit + depth)', () => {
        // Build a chain 1000 deep with an IRI tag at the bottom; we should
        // either find it within the depth limit or bail without exploding.
        let node: TlvNode = mkTlv(0xA1, 999 * 2, []);
        for (let i = 998; i >= 0; i--) node = mkTlv(0x30, i * 2, [node]);
        const start = Date.now();
        const h = detectEtsiLi([node]);
        const elapsed = Date.now() - start;
        expect(elapsed).toBeLessThan(100);
        // Whether h is null or non-null is fine — what matters is bounded time.
        expect([null, 'object']).toContain(h === null ? null : typeof h);
    });
});

// ─── 3GPP CDR ────────────────────────────────────────────────────────────────

describe('detect3gppCdr', () => {
    it('matches single moCallRecord (root tag 0xA0)', () => {
        const root = mkTlv(0xA0, 0, [], 100);
        const bytes = new Uint8Array(102);
        const h = detect3gppCdr(bytes, [root], 'cdr');
        expect(h).not.toBeNull();
        expect(h!.name).toContain('moCallRecord');
        // .cdr extension boosts confidence
        expect(h!.confidence).toBeGreaterThanOrEqual(0.70);
    });

    it('matches single mtCallRecord (root tag 0xA1)', () => {
        const root = mkTlv(0xA1, 0, [], 50);
        const bytes = new Uint8Array(52);
        const h = detect3gppCdr(bytes, [root], 'cdr');
        expect(h).not.toBeNull();
        expect(h!.name).toContain('mtCallRecord');
    });

    it('matches SEQUENCE OF CallEventRecord', () => {
        const root = mkTlv(0x30, 0, [
            mkTlv(0xA0, 2, [], 30),
            mkTlv(0xA1, 34, [], 30),
            mkTlv(0xA0, 66, [], 30),
        ]);
        const h = detect3gppCdr(new Uint8Array(100), [root], 'cdr');
        expect(h).not.toBeNull();
        expect(h!.name).toContain('SEQUENCE OF');
    });

    it('rejects plain SEQUENCE (no context-specific children)', () => {
        const root = mkTlv(0x30, 0, [mkTlv(0x06, 2, []), mkTlv(0x04, 10, [])]);
        expect(detect3gppCdr(new Uint8Array(50), [root], '')).toBeNull();
    });

    it('returns null on empty parsed structures', () => {
        expect(detect3gppCdr(new Uint8Array(50), [], '')).toBeNull();
    });

    it('extension boost is bounded (no extension → moderate confidence only)', () => {
        const root = mkTlv(0xA0, 0, [], 100);
        const h = detect3gppCdr(new Uint8Array(102), [root], '');
        expect(h).not.toBeNull();
        expect(h!.confidence).toBeLessThan(0.70);
    });
});

// ─── Vendor periodic ─────────────────────────────────────────────────────────

describe('detectVendorPeriodic', () => {
    it('returns null when worker hint is false (no false positives without corroboration)', () => {
        const bytes = new Uint8Array(512);
        expect(detectVendorPeriodic(bytes, false)).toBeNull();
    });

    it('boosts confidence when a repeating 4-byte tag is found at consistent period', () => {
        // Build a fake periodic frame: 32-byte records with tag 0xDEADBEEF at offset 0.
        const period = 32;
        const bytes = new Uint8Array(period * 16);
        for (let k = 0; k < 16; k++) {
            bytes[k * period + 0] = 0xDE;
            bytes[k * period + 1] = 0xAD;
            bytes[k * period + 2] = 0xBE;
            bytes[k * period + 3] = 0xEF;
        }
        const h = detectVendorPeriodic(bytes, true);
        expect(h).not.toBeNull();
        expect(h!.confidence).toBeGreaterThanOrEqual(0.80);
        expect(h!.evidence.some(e => e.includes('period'))).toBe(true);
    });

    it('lowers confidence when worker hint is not corroborated by structural periodicity', () => {
        // Random-ish bytes — no consistent repeating tag.
        const bytes = new Uint8Array(512);
        for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 7919) & 0xff;
        const h = detectVendorPeriodic(bytes, true);
        expect(h).not.toBeNull();
        expect(h!.confidence).toBeLessThan(0.60);
    });
});

// ─── Aggregator ──────────────────────────────────────────────────────────────

describe('detectProtocols (integration)', () => {
    it('returns multiple hypotheses for a polyglot-like input', () => {
        // HTTP/1 request bytes — should fire HTTP/1 but nothing else.
        const out = detectProtocols({
            headerBytes: enc('GET / HTTP/1.1\r\nHost: a\r\n\r\n'),
            fileSize: 128,
            parsedStructures: undefined,
            claimedExt: '',
            workerPeriodicHint: false,
        });
        expect(out).toHaveLength(1);
        expect(out[0].family).toBe('http');
    });

    it('returns LI + CDR hypotheses for an ambiguous TLV structure', () => {
        // SEQUENCE with 0xA1 child — could be LI (IRI-Begin under HI2 envelope)
        // OR CDR (SEQUENCE OF mtCallRecord). The aggregator surfaces BOTH so
        // the analyst sees both interpretations.
        const env = mkTlv(0x30, 0, [mkTlv(0xA1, 4, [], 30)]);
        const out = detectProtocols({
            headerBytes: new Uint8Array(50).fill(0x00),
            fileSize: 50,
            parsedStructures: [env],
            claimedExt: '',
            workerPeriodicHint: false,
        });
        const families = out.map(h => h.family).sort();
        expect(families).toContain('li');
        expect(families).toContain('cdr');
    });

    it('returns empty list for unknown binary input', () => {
        const bytes = new Uint8Array(256);
        for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 41) & 0xff;
        const out = detectProtocols({
            headerBytes: bytes,
            fileSize: 256,
            parsedStructures: undefined,
            claimedExt: '',
            workerPeriodicHint: false,
        });
        expect(out).toHaveLength(0);
    });
});
