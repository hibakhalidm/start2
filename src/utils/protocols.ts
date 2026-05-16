import { TlvNode } from '../types/analysis';

// ─────────────────────────────────────────────────────────────────────────────
// Protocol-decoding module.
//
// Pure, deterministic detectors for application-layer protocols relevant to
// CIFAD's telecom / lawful-interception / charging-record domain:
//
//   • HTTP/1.x   — request OR response framing + corroborating headers
//   • HTTP/2     — connection preface + first-frame SETTINGS structural validation
//   • HTTP/3     — QUIC long header + known version table + DCID sanity
//   • SIP        — IMS application layer (request OR status line + mandatory headers)
//   • Diameter   — RFC 6733 header with command-code dictionary (IMS/charging)
//   • ETSI LI    — HI2 IRI-Begin/End/Continue/Report record classification
//                  (ETSI TS 101 671 / 3GPP TS 33.108)
//   • 3GPP CDR   — TS 32.298 CallEventRecord (CHOICE or SEQUENCE OF)
//   • Vendor     — periodic-frame corroboration (with worker hint)
//
// Each detector returns a `ProtocolHypothesis` with numeric confidence and
// per-decoder evidence strings. The aggregator `detectProtocols` runs them all
// and lets the caller (fuseDetection in App.tsx) decide how to rank and fuse
// them with other signal sources.
//
// All decoders are designed to MINIMISE FALSE POSITIVES on adversarial near-
// misses: every match either requires multiple independent structural checks
// (preface + frame, header + body) or validates a length/range field that is
// hard to satisfy by coincidence.
// ─────────────────────────────────────────────────────────────────────────────

export type ProtocolFamily = 'http' | 'quic' | 'sip' | 'diameter' | 'li' | 'cdr' | 'vendor';

export interface ProtocolHypothesis {
    /** Stable identifier, used for de-dup and reporting. */
    id: string;
    /** Human-readable name. */
    name: string;
    family: ProtocolFamily;
    /** Confidence in [0, 1]. */
    confidence: number;
    /** Human-readable evidence strings (one per corroborating signal). */
    evidence: string[];
    /** Absolute file offsets where matches were anchored. */
    matchedOffsets: number[];
    /** Display color. */
    color: string;
    /** Standards reference (RFC / ETSI / 3GPP TS number). */
    standard?: string;
    /** For LI / Diameter: interface name (HI2, HI3, Rf, Sx, etc.). */
    interfaceName?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP/1.x
// ─────────────────────────────────────────────────────────────────────────────

// Anchored at offset 0; CRLF-terminated; method whitelist; version 1.0 or 1.1.
const HTTP1_REQUEST_RE =
    /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+\S+\s+HTTP\/1\.(0|1)\r\n/;
// HTTP responses: "HTTP/1.x SP CODE [SP reason] CRLF".
const HTTP1_RESPONSE_RE = /^HTTP\/1\.(0|1)\s+\d{3}(?:\s+[^\r\n]*)?\r\n/;
const HTTP1_REQUEST_HEADER_CORROBORATION = /\r\nHost:\s/i;
const HTTP1_RESPONSE_HEADER_CORROBORATION = /\r\n(?:Server|Content-Type|Content-Length|Date):\s/i;

export function detectHttp1(bytes: Uint8Array): ProtocolHypothesis | null {
    const scanLen = Math.min(8192, bytes.length);
    if (scanLen < 18) return null;

    // Hard ASCII gate on the first line — any non-printable, non-CRLF byte in
    // the first 64 bytes disqualifies. This kills false-positives on binary
    // files whose first byte happens to be 'G' (0x47) etc.
    const gateLen = Math.min(64, scanLen);
    for (let i = 0; i < gateLen; i++) {
        const b = bytes[i];
        // Allow: TAB (0x09), LF (0x0A), CR (0x0D), printable ASCII (0x20..0x7E).
        if (b !== 0x09 && b !== 0x0A && b !== 0x0D && (b < 0x20 || b > 0x7E)) return null;
    }

    let text: string;
    try {
        text = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, scanLen));
    } catch { return null; }

    const evidence: string[] = [];
    let confidence = 0;
    let kind: 'request' | 'response' | null = null;
    let method = '';
    let version = '1.1';

    const reqMatch = HTTP1_REQUEST_RE.exec(text);
    if (reqMatch) {
        kind = 'request';
        method = reqMatch[1];
        version = `1.${reqMatch[2]}`;
        evidence.push(`request-line matched: ${method} ... HTTP/${version}`);
        confidence = 0.85;
        if (HTTP1_REQUEST_HEADER_CORROBORATION.test(text)) {
            evidence.push('mandatory Host: header present (RFC 9112 §3.2)');
            confidence = 0.97;
        }
    } else {
        const respMatch = HTTP1_RESPONSE_RE.exec(text);
        if (respMatch) {
            kind = 'response';
            version = `1.${respMatch[1]}`;
            evidence.push(`status-line matched: HTTP/${version} <code>`);
            confidence = 0.78;
            if (HTTP1_RESPONSE_HEADER_CORROBORATION.test(text)) {
                evidence.push('Server / Content-* / Date header(s) present');
                confidence = 0.94;
            }
        }
    }

    if (!kind) return null;

    return {
        id: `http1.${version}.${kind}`,
        name: `HTTP/${version} ${kind}${method ? ` (${method})` : ''}`,
        family: 'http',
        confidence,
        evidence,
        matchedOffsets: [0],
        color: '#00f0ff',
        standard: 'RFC 9110 / RFC 9112',
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP/2
// ─────────────────────────────────────────────────────────────────────────────

// "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" — RFC 9113 §3.4, exactly 24 bytes.
const H2_PREFACE = new Uint8Array([
    0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30,
    0x0d, 0x0a, 0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a,
]);
const H2_FRAME_SETTINGS = 0x04;

export function detectHttp2(bytes: Uint8Array): ProtocolHypothesis | null {
    if (bytes.length < H2_PREFACE.length) return null;
    for (let i = 0; i < H2_PREFACE.length; i++) {
        if (bytes[i] !== H2_PREFACE[i]) return null;
    }

    const evidence: string[] = ['client connection preface matched at offset 0 (RFC 9113 §3.4)'];
    let confidence = 0.95;

    // Validate the immediately-following SETTINGS frame:
    //   3 bytes length (uint24 BE), payload must be multiple of 6
    //   1 byte type = 0x04 (SETTINGS)
    //   1 byte flags (bit 0 = ACK; typically 0 in the initial preface)
    //   4 bytes stream identifier (top bit reserved, must be 0; SETTINGS stream id MUST be 0)
    if (bytes.length >= H2_PREFACE.length + 9) {
        const off = H2_PREFACE.length;
        const length = (bytes[off] << 16) | (bytes[off + 1] << 8) | bytes[off + 2];
        const type = bytes[off + 3];
        const flags = bytes[off + 4];
        const streamId =
            (((bytes[off + 5] << 24) >>> 0) |
                ((bytes[off + 6] << 16) >>> 0) |
                ((bytes[off + 7] << 8) >>> 0) |
                (bytes[off + 8] >>> 0)) &
            0x7fffffff;

        if (type === H2_FRAME_SETTINGS && streamId === 0 && length % 6 === 0 && length <= 0x4000) {
            evidence.push(`first frame is SETTINGS (len=${length}, flags=0x${flags.toString(16).padStart(2, '0')}, stream=0)`);
            confidence = 0.99;
        } else {
            evidence.push(
                `post-preface frame type=0x${type.toString(16).padStart(2, '0')} stream=${streamId} len=${length} — ` +
                `expected SETTINGS(0x04) on stream 0 with length%6==0`,
            );
            // Preface alone is already strong, but a missing/invalid first frame
            // is suspicious — knock confidence down so the analyst sees a flag.
            confidence = 0.80;
        }
    }

    return {
        id: 'http2',
        name: 'HTTP/2',
        family: 'http',
        confidence,
        evidence,
        matchedOffsets: [0],
        color: '#00f0ff',
        standard: 'RFC 9113',
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// QUIC / HTTP/3
// ─────────────────────────────────────────────────────────────────────────────

// Known QUIC version numbers (big-endian uint32).
const QUIC_VERSIONS: ReadonlyMap<number, string> = new Map([
    [0x00000000, 'QUIC Version Negotiation'],
    [0x00000001, 'QUIC v1 (RFC 9000)'],
    [0x6b3343cf, 'QUIC v2 (RFC 9369)'],
    [0xff00001d, 'QUIC draft-29'],
    [0xff00001e, 'QUIC draft-30'],
    [0xff00001f, 'QUIC draft-31'],
    [0xff000020, 'QUIC draft-32'],
    [0xff000022, 'QUIC draft-34'],
    [0xfaceb002, 'QUIC mvfst (Facebook)'],
    [0x709a50c4, 'QUIC v2 draft-00'],
    [0x51303530, 'gQUIC Q050'],
    [0x51303436, 'gQUIC Q046'],
]);

export function detectQuic(bytes: Uint8Array): ProtocolHypothesis | null {
    // Need at least byte0 + version(4) + dcid_len(1) + 1 byte DCID = 7.
    if (bytes.length < 7) return null;
    const b0 = bytes[0];
    // Long header form: (b0 & 0x80) === 0x80 AND fixed bit (b0 & 0x40) === 0x40.
    // Combined: (b0 & 0xc0) === 0xc0.
    if ((b0 & 0xc0) !== 0xc0) return null;

    const version =
        (((bytes[1] << 24) >>> 0) |
            ((bytes[2] << 16) >>> 0) |
            ((bytes[3] << 8) >>> 0) |
            (bytes[4] >>> 0)) >>>
        0;
    const versionName = QUIC_VERSIONS.get(version);

    // DCID length is bounded to 20 by RFC 9000 §17.2.
    const dcidLen = bytes[5];
    if (dcidLen > 20) return null;
    // Need to fit DCID + at least 1 byte of SCID-length within available data.
    if (6 + dcidLen + 1 > bytes.length) return null;

    const evidence: string[] = [];
    let confidence: number;

    if (versionName) {
        evidence.push(
            `QUIC long header at offset 0; version 0x${version.toString(16).padStart(8, '0')} (${versionName})`,
        );
        confidence = 0.94;
    } else if (version === 0) {
        evidence.push('QUIC Version Negotiation packet (version=0)');
        confidence = 0.80;
    } else {
        // Unknown version bytes — could be a future QUIC version or a
        // coincidental long-header-shaped binary file. Keep confidence low.
        evidence.push(`QUIC-shaped long header but unknown version 0x${version.toString(16).padStart(8, '0')}`);
        confidence = 0.45;
    }

    evidence.push(`DCID length=${dcidLen} (RFC 9000 limit 20)`);
    const pktType = (b0 >> 4) & 0x03;
    const pktTypeName = ['Initial', '0-RTT', 'Handshake', 'Retry'][pktType];
    evidence.push(`long-header packet type: ${pktTypeName}`);

    return {
        id: 'quic',
        name: versionName ?? 'QUIC (long header, unknown version)',
        family: 'quic',
        confidence,
        evidence,
        matchedOffsets: [0],
        color: '#00f0ff',
        standard: 'RFC 9000 (transport) / RFC 9114 (HTTP/3)',
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// SIP (IMS)
// ─────────────────────────────────────────────────────────────────────────────

const SIP_REQUEST_RE =
    /^(INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|INFO|NOTIFY|SUBSCRIBE|REFER|MESSAGE|PRACK|UPDATE|PUBLISH)\s+\S+\s+SIP\/2\.0\r\n/;
const SIP_RESPONSE_RE = /^SIP\/2\.0\s+\d{3}(?:\s+[^\r\n]*)?\r\n/;
const SIP_MANDATORY_HEADER_RE = /\r\n(?:Via|From|To|Call-ID|CSeq|Contact|Max-Forwards):\s/i;

export function detectSip(bytes: Uint8Array): ProtocolHypothesis | null {
    const scanLen = Math.min(4096, bytes.length);
    if (scanLen < 12) return null;
    // ASCII gate on first 64 bytes.
    const gateLen = Math.min(64, scanLen);
    for (let i = 0; i < gateLen; i++) {
        const b = bytes[i];
        if (b !== 0x09 && b !== 0x0A && b !== 0x0D && (b < 0x20 || b > 0x7E)) return null;
    }
    let text: string;
    try {
        text = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, scanLen));
    } catch { return null; }

    let kind: 'request' | 'response' | null = null;
    let method = '';
    const r = SIP_REQUEST_RE.exec(text);
    if (r) { kind = 'request'; method = r[1]; }
    else if (SIP_RESPONSE_RE.test(text)) kind = 'response';
    if (!kind) return null;

    const evidence: string[] = [];
    let confidence = 0.85;
    if (kind === 'request') evidence.push(`SIP request-line: ${method} ... SIP/2.0`);
    else evidence.push('SIP status-line: SIP/2.0 <code>');

    if (SIP_MANDATORY_HEADER_RE.test(text)) {
        evidence.push('mandatory SIP headers present (Via/From/To/Call-ID/CSeq)');
        confidence = 0.97;
    }

    return {
        id: 'sip',
        name: `SIP/2.0 ${kind === 'request' ? `${method} request` : 'response'}`,
        family: 'sip',
        confidence,
        evidence,
        matchedOffsets: [0],
        color: '#00ff9d',
        standard: 'RFC 3261 / 3GPP TS 24.229 (IMS)',
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Diameter (RFC 6733)
// ─────────────────────────────────────────────────────────────────────────────

// Subset of well-known Diameter command codes, biased toward IMS / charging.
const DIAMETER_COMMANDS: ReadonlyMap<number, string> = new Map([
    [257, 'Capabilities-Exchange (CER/CEA)'],
    [258, 'Re-Auth (RAR/RAA)'],
    [265, 'AA (AAR/AAA, Rx)'],
    [271, 'Credit-Control (CCR/CCA, Gy/Ro)'],
    [272, 'Authentication-Information (AIR/AIA, S6a)'],
    [274, 'Abort-Session (ASR/ASA)'],
    [275, 'Session-Termination (STR/STA)'],
    [280, 'Device-Watchdog (DWR/DWA)'],
    [282, 'Disconnect-Peer (DPR/DPA)'],
    [301, 'Server-Assignment (SAR/SAA, Cx)'],
    [302, 'Multimedia-Auth (MAR/MAA, Cx)'],
    [303, 'Registration-Termination (RTR/RTA, Cx)'],
    [304, 'Push-Profile (PPR/PPA, Cx/Sh)'],
    [305, 'User-Authorization (UAR/UAA, Cx)'],
    [306, 'User-Data (UDR/UDA, Sh)'],
    [307, 'Profile-Update (PUR/PUA, Sh)'],
    [308, 'Subscribe-Notifications (SNR/SNA, Sh)'],
    [309, 'Push-Notification (PNR/PNA, Sh)'],
    [316, 'Update-Location (ULR/ULA, S6a)'],
    [317, 'Cancel-Location (CLR/CLA, S6a)'],
    [318, 'Authentication-Information (AIR/AIA, S6a)'],
    [319, 'Insert-Subscriber-Data (IDR/IDA, S6a)'],
    [320, 'Delete-Subscriber-Data (DSR/DSA, S6a)'],
    [321, 'Purge-UE (PUR/PUA, S6a)'],
    [322, 'Reset (RSR/RSA, S6a)'],
    [323, 'Notify (NOR/NOA, S6a)'],
    [8388620, 'Spending-Limit (SLR/SLA, Sy)'],
    [8388622, 'Update-Location (ULR/ULA, S6d)'],
]);

export function detectDiameter(bytes: Uint8Array, fileSize: number): ProtocolHypothesis | null {
    // RFC 6733 header is exactly 20 bytes.
    if (bytes.length < 20) return null;
    if (bytes[0] !== 0x01) return null;

    const length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    // Length must be at least the fixed header (20) and divisible by 4 (RFC 6733 §3).
    if (length < 20 || (length & 0x03) !== 0) return null;
    // Length must fit in the file (when known) and within a sane ceiling.
    if (fileSize > 0 && length > fileSize) return null;
    if (length > 16 * 1024 * 1024) return null;

    const flags = bytes[4];
    // Lower 4 bits of flags are reserved and MUST be 0.
    if ((flags & 0x0f) !== 0) return null;

    const cmdCode = (bytes[5] << 16) | (bytes[6] << 8) | bytes[7];
    // Reasonable upper bound (24-bit field, but real commands are well under this).
    if (cmdCode === 0 || cmdCode > 0xffffff) return null;

    const appId =
        (((bytes[8] << 24) >>> 0) |
            ((bytes[9] << 16) >>> 0) |
            ((bytes[10] << 8) >>> 0) |
            (bytes[11] >>> 0)) >>>
        0;

    const cmdName = DIAMETER_COMMANDS.get(cmdCode) ?? null;

    const evidence: string[] = [
        `Diameter header: ver=1, length=${length}, cmd=${cmdCode}${cmdName ? ` (${cmdName})` : ''}, appId=${appId}`,
        `flags=0x${flags.toString(16).padStart(2, '0')} ` +
            `(R=${(flags >> 7) & 1}, P=${(flags >> 6) & 1}, E=${(flags >> 5) & 1}, T=${(flags >> 4) & 1})`,
    ];

    // Confidence ladder: known command codes get high confidence; unknown codes
    // with a structurally valid header still warrant a moderate signal.
    const confidence = cmdName ? 0.92 : 0.62;

    return {
        id: `diameter.${cmdCode}`,
        name: cmdName ? `Diameter — ${cmdName}` : `Diameter (unknown cmd ${cmdCode})`,
        family: 'diameter',
        confidence,
        evidence,
        matchedOffsets: [0],
        color: '#00f0ff',
        standard: 'RFC 6733 / 3GPP TS 29.x',
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// ETSI / 3GPP Lawful Interception — HI2 IRI message classification
//
// Per ETSI TS 101 671 / 3GPP TS 33.108, the IRIsContent CHOICE uses
// context-specific constructed tags for the four message types:
//
//   iRI-Begin-record     [1]  → 0xA1
//   iRI-End-record       [2]  → 0xA2
//   iRI-Continue-record  [3]  → 0xA3
//   iRI-Report-record    [4]  → 0xA4
//
// The outer envelope is typically a SEQUENCE/SET (root tag 0x30 / 0x31) holding
// the domainID OID, lawfulInterceptionIdentifier and the iRIsContent CHOICE.
// ─────────────────────────────────────────────────────────────────────────────

const ETSI_LI_IRI_TAGS: ReadonlyMap<number, { name: string; messageType: string }> = new Map([
    [0xA1, { name: 'IRI-Begin', messageType: 'iRI-Begin-record [1]' }],
    [0xA2, { name: 'IRI-End', messageType: 'iRI-End-record [2]' }],
    [0xA3, { name: 'IRI-Continue', messageType: 'iRI-Continue-record [3]' }],
    [0xA4, { name: 'IRI-Report', messageType: 'iRI-Report-record [4]' }],
]);

const ETSI_LI_TREE_VISIT_LIMIT = 256;
const ETSI_LI_TREE_MAX_DEPTH = 6;

export function detectEtsiLi(rootTlv: TlvNode[] | undefined): ProtocolHypothesis | null {
    if (!rootTlv || rootTlv.length === 0) return null;
    const root = rootTlv[0];

    // Root MUST be SEQUENCE or SET. If the root is itself a context-specific
    // tag (0xA0..0xBF), this is much more likely a 3GPP CDR record than an LI
    // envelope — defer to the CDR detector.
    if (root.tag !== 0x30 && root.tag !== 0x31) return null;

    // BFS over the tree with bounded depth and node budget. Bounded so a
    // pathological TLV (deeply nested adversarial input) cannot hang detection.
    const found: Array<{ tag: number; name: string; messageType: string; offset: number; depth: number }> = [];
    interface QueueEntry { node: TlvNode; depth: number; }
    const queue: QueueEntry[] = [{ node: root, depth: 0 }];
    let visited = 0;
    while (queue.length > 0 && visited < ETSI_LI_TREE_VISIT_LIMIT) {
        const { node, depth } = queue.shift()!;
        visited++;
        const info = ETSI_LI_IRI_TAGS.get(node.tag);
        if (info && depth > 0) {
            // depth > 0: only count IRI tags BELOW the root; an IRI tag AT the
            // root is most likely a CDR CallEventRecord, not LI.
            found.push({ tag: node.tag, ...info, offset: node.offset, depth });
        }
        if (node.children && depth < ETSI_LI_TREE_MAX_DEPTH) {
            for (const child of node.children) queue.push({ node: child, depth: depth + 1 });
        }
    }

    if (found.length === 0) return null;

    const uniqueTags = new Set(found.map(f => f.tag));
    const types = Array.from(uniqueTags)
        .sort((a, b) => a - b)
        .map(t => ETSI_LI_IRI_TAGS.get(t)!.name)
        .join(', ');
    const offsetMin = Math.min(...found.map(f => f.offset));

    const evidence: string[] = [
        `root tag 0x${root.tag.toString(16).padStart(2, '0')} (SEQUENCE/SET) — HI2 envelope`,
        `IRI message-type tag(s) found: ${types}`,
        `${found.length} occurrence(s); first at offset ${offsetMin}`,
    ];

    let confidence: number;
    let name: string;
    if (uniqueTags.size === 1) {
        const single = found[0];
        confidence = 0.93;
        name = `ETSI HI2 ${single.name} (${single.messageType})`;
    } else {
        confidence = 0.90;
        name = `ETSI HI2 IRI sequence (${types})`;
    }

    return {
        id: 'etsi.li.hi2.iri',
        name,
        family: 'li',
        confidence,
        evidence,
        matchedOffsets: found.map(f => f.offset),
        color: '#00ff9d',
        standard: 'ETSI TS 101 671 / 3GPP TS 33.108',
        interfaceName: 'HI2',
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// 3GPP TS 32.298 CDR (Charging Data Record)
//
// Two common shapes:
//   1. Single CallEventRecord — root tag is a context-specific CHOICE alternative
//      (0xA0..0xBF), e.g. moCallRecord[0], mtCallRecord[1], roamingRecord[2]…
//   2. Concatenated sequence — root is SEQUENCE OF CallEventRecord (0x30 + children
//      all context-specific). Used by mediation systems for batch files.
// ─────────────────────────────────────────────────────────────────────────────

// 3GPP TS 32.298 §5.1.1 — CallEventRecord alternative tag map (subset).
const CDR_RECORD_TYPE_NAMES: ReadonlyMap<number, string> = new Map([
    [0xA0, 'moCallRecord [0]'],
    [0xA1, 'mtCallRecord [1]'],
    [0xA2, 'roamingRecord [2]'],
    [0xA3, 'incGatewayRecord [3]'],
    [0xA4, 'outGatewayRecord [4]'],
    [0xA5, 'transitCallRecord [5]'],
    [0xA6, 'moSMSRecord [6]'],
    [0xA7, 'mtSMSRecord [7]'],
    [0xA8, 'moSMSIWRecord [8]'],
    [0xA9, 'mtSMSGWRecord [9]'],
    [0xAA, 'ssActionRecord [10]'],
    [0xAB, 'hlrIntRecord [11]'],
    [0xAC, 'locationUpdateRecord [12]'],
    [0xAD, 'commonEquipmentRecord [13]'],
    [0xAE, 'moTraceRecord [14]'],
    [0xAF, 'mtTraceRecord [15]'],
    [0xBF, 'extension/proprietary'],
]);

const CDR_EXTENSION_HINTS: ReadonlySet<string> = new Set(['cdr', 'asn', 'asn1', 'ber']);

export function detect3gppCdr(
    bytes: Uint8Array,
    parsedStructures: TlvNode[] | undefined,
    claimedExt: string,
): ProtocolHypothesis | null {
    if (!parsedStructures || parsedStructures.length === 0) return null;
    const root = parsedStructures[0];

    const isCdrChoice = root.tag >= 0xA0 && root.tag <= 0xBF;
    const isSeqOfRecords =
        root.tag === 0x30 &&
        root.children.length > 0 &&
        root.children.every(c => c.tag >= 0xA0 && c.tag <= 0xBF);

    if (!isCdrChoice && !isSeqOfRecords) return null;

    const evidence: string[] = [];
    let confidence: number;
    let name: string;

    if (isCdrChoice) {
        const typeName = CDR_RECORD_TYPE_NAMES.get(root.tag) ?? `context-specific [${root.tag - 0xA0}]`;
        evidence.push(`root is CallEventRecord CHOICE alternative: ${typeName}`);
        confidence = 0.58;
        name = `3GPP CDR — ${typeName}`;
    } else {
        const childTags = root.children.map(c => c.tag);
        const distinct = Array.from(new Set(childTags));
        const distinctNames = distinct
            .map(t => CDR_RECORD_TYPE_NAMES.get(t) ?? `[${t - 0xA0}]`)
            .join(', ');
        evidence.push(
            `root SEQUENCE OF ${root.children.length} CallEventRecord(s); types: ${distinctNames}`,
        );
        confidence = 0.65;
        name = `3GPP CDR — SEQUENCE OF (${root.children.length} records)`;
    }

    if (CDR_EXTENSION_HINTS.has(claimedExt)) {
        evidence.push(`filename extension ".${claimedExt}" consistent with CDR`);
        confidence = Math.min(0.88, confidence + 0.18);
    }

    // ASN.1 outer-length sanity: for single-record files, total_len should
    // approximately match the captured size.
    const totalLen = root.header_len + root.value_len;
    if (totalLen > 0 && bytes.length > 0) {
        const ratio = totalLen / bytes.length;
        if (ratio >= 0.98 && ratio <= 1.02) {
            evidence.push('outer ASN.1 length matches captured size (well-framed)');
            confidence = Math.min(0.92, confidence + 0.05);
        }
    }

    return {
        id: '3gpp.cdr',
        name,
        family: 'cdr',
        confidence,
        evidence,
        matchedOffsets: [root.offset],
        color: '#00ff9d',
        standard: '3GPP TS 32.298',
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Vendor periodic frame format
//
// The worker emits a `VENDOR_PERIODIC_DETECTED` signature when its autocorrelation
// lag analysis spots a repeating header outside the AES/DES lag positions. We
// corroborate that hint here by searching the head for an actual repeating
// 4-byte tag at consistent periodicity. Both signals are required; either alone
// is too noisy.
// ─────────────────────────────────────────────────────────────────────────────

export function detectVendorPeriodic(
    bytes: Uint8Array,
    workerPeriodicHint: boolean,
): ProtocolHypothesis | null {
    if (!workerPeriodicHint) return null;

    const evidence: string[] = [
        'worker reported VENDOR_PERIODIC_DETECTED (autocorrelation lag spike outside crypto-aligned positions)',
    ];

    // Search for a repeating 4-byte tag at periods 8..256 in the first 4 KiB.
    const scan = bytes.subarray(0, Math.min(4096, bytes.length));
    let bestPeriod = 0;
    let bestScore = 0;
    if (scan.length >= 128) {
        for (let p = 8; p <= 256; p++) {
            const maxIter = Math.min(16, Math.floor(scan.length / p) - 1);
            if (maxIter < 4) continue;
            let matches = 0;
            for (let k = 1; k <= maxIter; k++) {
                const a = k * p;
                if (
                    scan[0] === scan[a] &&
                    scan[1] === scan[a + 1] &&
                    scan[2] === scan[a + 2] &&
                    scan[3] === scan[a + 3]
                ) {
                    matches++;
                }
            }
            const score = matches / maxIter;
            if (score > bestScore) { bestScore = score; bestPeriod = p; }
        }
    }

    let confidence = 0.50;
    if (bestScore >= 0.75 && bestPeriod > 0) {
        evidence.push(
            `repeating 4-byte tag at period ${bestPeriod} bytes (match ratio ${bestScore.toFixed(2)})`,
        );
        confidence = 0.82;
    } else if (bestScore >= 0.40 && bestPeriod > 0) {
        evidence.push(
            `partial repeating tag at period ${bestPeriod} bytes (match ratio ${bestScore.toFixed(2)})`,
        );
        confidence = 0.65;
    } else {
        evidence.push('no consistent repeating tag found within first 4 KiB (worker hint not corroborated)');
        confidence = 0.40;
    }

    return {
        id: 'vendor.periodic',
        name: 'Vendor periodic frame format',
        family: 'vendor',
        confidence,
        evidence,
        matchedOffsets: [0],
        color: '#ffaa00',
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Aggregator
// ─────────────────────────────────────────────────────────────────────────────

export interface DetectProtocolsInput {
    headerBytes: Uint8Array;
    fileSize: number;
    parsedStructures?: TlvNode[];
    claimedExt: string;
    /** Set to true when worker reported "VENDOR (Periodic / repeating header)". */
    workerPeriodicHint: boolean;
}

export function detectProtocols(input: DetectProtocolsInput): ProtocolHypothesis[] {
    const out: ProtocolHypothesis[] = [];
    const push = (h: ProtocolHypothesis | null) => { if (h) out.push(h); };

    // Order: most specific / least overlapping first. Each detector is
    // independent; aggregator does no de-dup — the caller fuses.
    push(detectHttp2(input.headerBytes));
    push(detectHttp1(input.headerBytes));
    push(detectQuic(input.headerBytes));
    push(detectSip(input.headerBytes));
    push(detectDiameter(input.headerBytes, input.fileSize));
    push(detectEtsiLi(input.parsedStructures));
    push(detect3gppCdr(input.headerBytes, input.parsedStructures, input.claimedExt));
    push(detectVendorPeriodic(input.headerBytes, input.workerPeriodicHint));

    return out;
}
