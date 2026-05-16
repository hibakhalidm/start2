// ─────────────────────────────────────────────────────────────────────────────
// ASN.1 BER/DER value decoder.
//
// The WASM `parse_file_structure` produces the TLV *framing* (tag, length,
// offset, hierarchy). This module decodes the actual VALUE bytes of each node
// per the ASN.1 universal-tag semantics, plus telecom/LI-aware context tags
// and a friendly-name dictionary for the most common OIDs (PKI, ETSI HI, 3GPP).
//
// Design goals:
//   • Pure, deterministic — easy to unit-test, no DOM dependencies.
//   • Defensive on length: a malformed/truncated value should produce a
//     `complete: false` result, never throw.
//   • One canonical short string in `primary` for copy/export.
//   • Optional `secondary` for the friendly name or extra context.
//   • Numeric `kind` so the UI can color/style consistently.
// ─────────────────────────────────────────────────────────────────────────────

export type TlvDecodedKind =
    | 'boolean'
    | 'integer'
    | 'enumerated'
    | 'bitstring'
    | 'octetstring'
    | 'null'
    | 'oid'
    | 'string'
    | 'datetime'
    | 'real'
    | 'container'
    | 'context'
    | 'binary'
    | 'unknown';

export interface TlvDecodedValue {
    /** Canonical short representation, suitable for copy/export. */
    primary: string;
    /** Optional human-readable enrichment (e.g. OID friendly name). */
    secondary?: string;
    /** UI-level type bucket for color/style decisions. */
    kind: TlvDecodedKind;
    /** True if `primary` is human-readable text (not hex). */
    isText: boolean;
    /** True if the decoder consumed the value cleanly (no malformation). */
    complete: boolean;
    /** Optional notes / warnings (e.g. "value truncated", "unused bits = 4"). */
    notes?: string[];
}

export interface TlvDecodeContext {
    /** When true, context-specific tags 0xA1..0xA4 at depth > 0 are interpreted
     *  as ETSI/3GPP HI2 IRI message types. */
    hi2Envelope?: boolean;
    /** Optional depth-from-root hint, useful for context-tag interpretation. */
    depth?: number;
    /** Optional number of children for container nodes; the WASM parser already
     *  knows this and we just echo it in `primary` so the inspector doesn't
     *  need to do its own counting. */
    childCount?: number;
}

// Universal-tag short names — used for `kind` selection and primary fallbacks.
const UNIVERSAL_TAG_NAMES: Readonly<Record<number, string>> = {
    0x01: 'BOOLEAN',
    0x02: 'INTEGER',
    0x03: 'BIT STRING',
    0x04: 'OCTET STRING',
    0x05: 'NULL',
    0x06: 'OBJECT IDENTIFIER',
    0x07: 'ObjectDescriptor',
    0x09: 'REAL',
    0x0A: 'ENUMERATED',
    0x0C: 'UTF8String',
    0x10: 'SEQUENCE',
    0x11: 'SET',
    // Canonical BER/DER encodings of SEQUENCE / SET have the constructed bit (0x20)
    // set, so the on-the-wire tag bytes are 0x30 / 0x31. Include both forms so
    // describeTag works regardless of which the parser surfaces.
    0x30: 'SEQUENCE',
    0x31: 'SET',
    0x12: 'NumericString',
    0x13: 'PrintableString',
    0x14: 'T61String',
    0x15: 'VideotexString',
    0x16: 'IA5String',
    0x17: 'UTCTime',
    0x18: 'GeneralizedTime',
    0x19: 'GraphicString',
    0x1A: 'VisibleString',
    0x1B: 'GeneralString',
    0x1C: 'UniversalString',
    0x1E: 'BMPString',
};

// ── OID friendly-name dictionary (telecom / PKI / IMS / LI) ──────────────────
//
// This is deliberately tight and curated, not exhaustive. The entries focus on
// the OIDs CIFAD analysts most often see in evidence: PKCS / X.509 chains,
// hash and signature algorithms, X.520 directory attributes, ETSI HI domain
// identifiers, and 3GPP series prefixes.

const KNOWN_OIDS: Readonly<Record<string, string>> = {
    // Hash algorithms
    '1.2.840.113549.2.5': 'MD5',
    '1.3.14.3.2.26': 'SHA-1',
    '2.16.840.1.101.3.4.2.1': 'SHA-256',
    '2.16.840.1.101.3.4.2.2': 'SHA-384',
    '2.16.840.1.101.3.4.2.3': 'SHA-512',
    // RSA signature algorithms
    '1.2.840.113549.1.1.1': 'rsaEncryption',
    '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
    '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
    '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
    // ECDSA
    '1.2.840.10045.4.1': 'ecdsa-with-SHA1',
    '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
    '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
    '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
    // PKCS#7 content types
    '1.2.840.113549.1.7.1': 'PKCS#7 data',
    '1.2.840.113549.1.7.2': 'PKCS#7 signedData',
    '1.2.840.113549.1.7.3': 'PKCS#7 envelopedData',
    '1.2.840.113549.1.7.4': 'PKCS#7 signedAndEnvelopedData',
    '1.2.840.113549.1.7.5': 'PKCS#7 digestedData',
    '1.2.840.113549.1.7.6': 'PKCS#7 encryptedData',
    // PKCS#9 attributes
    '1.2.840.113549.1.9.1': 'PKCS#9 emailAddress',
    '1.2.840.113549.1.9.3': 'PKCS#9 contentType',
    '1.2.840.113549.1.9.4': 'PKCS#9 messageDigest',
    '1.2.840.113549.1.9.5': 'PKCS#9 signingTime',
    '1.2.840.113549.1.9.16.1.4': 'PKCS#9 tstInfo',
    // X.520 directory attributes (Distinguished Name components)
    '2.5.4.3': 'commonName (CN)',
    '2.5.4.4': 'surname',
    '2.5.4.5': 'serialNumber',
    '2.5.4.6': 'countryName (C)',
    '2.5.4.7': 'localityName (L)',
    '2.5.4.8': 'stateOrProvinceName (ST)',
    '2.5.4.9': 'streetAddress',
    '2.5.4.10': 'organizationName (O)',
    '2.5.4.11': 'organizationalUnitName (OU)',
    '2.5.4.12': 'title',
    '2.5.4.42': 'givenName',
    // ETSI HI (Lawful Interception) domain identifiers
    '0.4.0.2.0': 'ETSI HI1 domain',
    '0.4.0.2.1': 'ETSI HI2 domain',
    '0.4.0.2.2': 'ETSI HI3 domain',
    '0.4.0.2.3': 'ETSI LI dynamic-trigger',
    // 3GPP series prefixes (CDR / charging-record OIDs)
    '0.4.0.832.1': '3GPP TS 33.108 HI2/HI3',
    '0.4.0.1028': '3GPP CDR (TS 32.298)',
};

// ── Public decoder ───────────────────────────────────────────────────────────

export function decodeTlvValue(
    tag: number,
    isConstructed: boolean,
    valueBytes: Uint8Array,
    ctx: TlvDecodeContext = {},
): TlvDecodedValue {
    // Constructed types (containers) — short-circuit. The value bytes belong
    // to children that the WASM parser already extracted, so we never look
    // inside them here.
    if (isConstructed) {
        const childCount = ctx.childCount ?? null;
        const tagName = describeTag(tag, ctx);
        // Special-case: HI2 IRI message-type tags at depth > 0 inside a SEQUENCE/SET envelope.
        if (ctx.hi2Envelope && (ctx.depth ?? 0) > 0 && HI2_IRI_TAGS[tag]) {
            return {
                primary: HI2_IRI_TAGS[tag],
                secondary: childCount !== null ? `${childCount} field(s)` : undefined,
                kind: 'context',
                isText: true,
                complete: true,
            };
        }
        return {
            primary: childCount !== null ? `[${tagName}] ${childCount} field(s)` : `[${tagName}]`,
            kind: 'container',
            isText: true,
            complete: true,
        };
    }

    // Primitive types — class is the top 2 bits.
    const tagClass = tag & 0xC0; // 0x00 universal, 0x40 application, 0x80 context, 0xC0 private
    const tagNumber = tag & 0x1F; // for non-universal classes

    if (tagClass !== 0x00) {
        // Non-universal primitive — we don't know the schema, so we surface
        // a best-effort hex preview and a class label.
        const classLabel = tagClass === 0x40 ? 'Application' : tagClass === 0x80 ? 'Context' : 'Private';
        return {
            primary: previewHex(valueBytes, 32),
            secondary: `${classLabel} [${tagNumber}] · ${valueBytes.length} byte(s)`,
            kind: 'context',
            isText: false,
            complete: true,
        };
    }

    switch (tag) {
        case 0x01: return decodeBoolean(valueBytes);
        case 0x02: return decodeInteger(valueBytes, 'integer');
        case 0x03: return decodeBitString(valueBytes);
        case 0x04: return decodeOctetString(valueBytes);
        case 0x05: return decodeNull(valueBytes);
        case 0x06: return decodeOid(valueBytes);
        case 0x0A: return decodeInteger(valueBytes, 'enumerated');
        case 0x0C: return decodeStringUtf8(valueBytes, 'UTF8String');
        case 0x12: return decodeStringPrintable(valueBytes, 'NumericString', /^[0-9 ]*$/);
        case 0x13: return decodeStringPrintable(valueBytes, 'PrintableString', /^[A-Za-z0-9 '()+,\-./:=?]*$/);
        case 0x14: return decodeStringLatin1(valueBytes, 'T61String');
        case 0x16: return decodeStringPrintable(valueBytes, 'IA5String', /^[\x00-\x7E]*$/);
        case 0x17: return decodeUtcTime(valueBytes);
        case 0x18: return decodeGeneralizedTime(valueBytes);
        case 0x19: return decodeStringPrintable(valueBytes, 'GraphicString', /^[\x20-\x7E]*$/);
        case 0x1A: return decodeStringPrintable(valueBytes, 'VisibleString', /^[\x20-\x7E]*$/);
        case 0x1B: return decodeStringPrintable(valueBytes, 'GeneralString', /^[\x00-\x7E]*$/);
        case 0x1E: return decodeStringBmp(valueBytes);
        default: {
            const name = UNIVERSAL_TAG_NAMES[tag] ?? `UNIVERSAL[0x${tag.toString(16)}]`;
            return {
                primary: previewHex(valueBytes, 32),
                secondary: `${name} (${valueBytes.length}B, decoder unimplemented)`,
                kind: 'binary',
                isText: false,
                complete: false,
            };
        }
    }
}

// ─── per-type decoders ───────────────────────────────────────────────────────

function decodeBoolean(b: Uint8Array): TlvDecodedValue {
    if (b.length !== 1) {
        return {
            primary: b.length === 0 ? '(empty)' : previewHex(b, 16),
            secondary: 'BOOLEAN must be exactly 1 byte (BER/DER §8.2)',
            kind: 'boolean',
            isText: false,
            complete: false,
        };
    }
    const v = b[0];
    return {
        primary: v === 0 ? 'FALSE' : 'TRUE',
        secondary: v === 0 || v === 0xFF ? undefined : `non-canonical TRUE (0x${v.toString(16).padStart(2, '0')}; DER requires 0xFF)`,
        kind: 'boolean',
        isText: true,
        complete: true,
        notes: v !== 0 && v !== 0xFF ? ['non-canonical DER encoding'] : undefined,
    };
}

function decodeInteger(b: Uint8Array, kind: 'integer' | 'enumerated'): TlvDecodedValue {
    if (b.length === 0) {
        return { primary: '(empty)', kind, isText: false, complete: false };
    }
    // Two's-complement decode using BigInt. Top bit of first byte = sign.
    let n: bigint;
    if ((b[0] & 0x80) === 0) {
        n = 0n;
        for (let i = 0; i < b.length; i++) n = (n << 8n) | BigInt(b[i]);
    } else {
        // Negative: invert and add 1, take negative.
        const inv = new Uint8Array(b.length);
        for (let i = 0; i < b.length; i++) inv[i] = b[i] ^ 0xff;
        let pos = 0n;
        for (let i = 0; i < inv.length; i++) pos = (pos << 8n) | BigInt(inv[i]);
        n = -(pos + 1n);
    }
    // Range hint (signed 64-bit) for analyst convenience.
    const fitsI64 = n >= -(1n << 63n) && n < (1n << 63n);
    const decimal = n.toString(10);
    const hex = (n < 0n ? '-' : '') + (n < 0n ? (-n) : n).toString(16);
    return {
        primary: decimal,
        secondary: b.length <= 16
            ? `0x${hex}${fitsI64 ? '' : ' · arbitrary-precision'} · ${b.length} byte(s)`
            : `${b.length} byte(s) · arbitrary-precision`,
        kind,
        isText: true,
        complete: true,
    };
}

function decodeBitString(b: Uint8Array): TlvDecodedValue {
    if (b.length === 0) {
        return { primary: '(empty)', kind: 'bitstring', isText: false, complete: false };
    }
    const unused = b[0];
    if (unused > 7) {
        return {
            primary: previewHex(b, 32),
            secondary: `invalid unused-bits byte 0x${unused.toString(16)} (must be 0..7)`,
            kind: 'bitstring',
            isText: false,
            complete: false,
        };
    }
    const data = b.subarray(1);
    const bitCount = data.length * 8 - unused;
    return {
        primary: previewHex(data, 32),
        secondary: `${bitCount} bit(s), unused trailing bits = ${unused}`,
        kind: 'bitstring',
        isText: false,
        complete: true,
    };
}

function decodeOctetString(b: Uint8Array): TlvDecodedValue {
    // Smart: if the bytes are clean ASCII/UTF-8 text, show as text; otherwise hex.
    const asText = tryDecodeAscii(b);
    if (asText !== null && asText.length > 0) {
        return {
            primary: truncate(asText, 256),
            secondary: `OCTET STRING · ${b.length} byte(s) (interpretable as ASCII)`,
            kind: 'octetstring',
            isText: true,
            complete: true,
        };
    }
    return {
        primary: previewHex(b, 48),
        secondary: `OCTET STRING · ${b.length} byte(s)`,
        kind: 'octetstring',
        isText: false,
        complete: true,
    };
}

function decodeNull(b: Uint8Array): TlvDecodedValue {
    return {
        primary: 'NULL',
        secondary: b.length === 0 ? undefined : `NULL must be 0 bytes; got ${b.length} (malformed)`,
        kind: 'null',
        isText: true,
        complete: b.length === 0,
    };
}

function decodeOid(b: Uint8Array): TlvDecodedValue {
    if (b.length === 0) {
        return { primary: '(empty OID)', kind: 'oid', isText: false, complete: false };
    }
    const parts: string[] = [];
    // First byte → first two arcs.
    const first = b[0];
    const arc1 = first < 80 ? Math.floor(first / 40) : 2;
    const arc2 = first < 80 ? first % 40 : first - 80;
    parts.push(String(arc1), String(arc2));

    // Subsequent: base-128, high bit = "more bytes follow". Use BigInt so large
    // sub-identifiers (e.g. Microsoft / private OIDs) don't overflow.
    let acc = 0n;
    let i = 1;
    let inProgress = false;
    while (i < b.length) {
        const byte = b[i];
        acc = (acc << 7n) | BigInt(byte & 0x7f);
        inProgress = true;
        if ((byte & 0x80) === 0) {
            parts.push(acc.toString(10));
            acc = 0n;
            inProgress = false;
        }
        i++;
    }
    const complete = !inProgress;
    const dotted = parts.join('.');
    const friendly = KNOWN_OIDS[dotted];
    return {
        primary: dotted,
        secondary: friendly ?? (complete ? undefined : 'truncated — last sub-identifier incomplete'),
        kind: 'oid',
        isText: true,
        complete,
    };
}

function decodeStringUtf8(b: Uint8Array, label: string): TlvDecodedValue {
    try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(b);
        return {
            primary: truncate(text, 256),
            secondary: `${label} · ${b.length} byte(s)`,
            kind: 'string',
            isText: true,
            complete: true,
        };
    } catch {
        return {
            primary: previewHex(b, 32),
            secondary: `${label} · invalid UTF-8`,
            kind: 'string',
            isText: false,
            complete: false,
        };
    }
}

function decodeStringPrintable(b: Uint8Array, label: string, allowed: RegExp): TlvDecodedValue {
    let text: string;
    try {
        text = new TextDecoder('latin1').decode(b);
    } catch {
        return {
            primary: previewHex(b, 32),
            secondary: `${label} · undecodable`,
            kind: 'string',
            isText: false,
            complete: false,
        };
    }
    const ok = allowed.test(text);
    return {
        primary: truncate(text, 256),
        secondary: ok ? `${label} · ${b.length} byte(s)` : `${label} · contains out-of-charset characters`,
        kind: 'string',
        isText: true,
        complete: ok,
    };
}

function decodeStringLatin1(b: Uint8Array, label: string): TlvDecodedValue {
    try {
        const text = new TextDecoder('latin1').decode(b);
        return {
            primary: truncate(text, 256),
            secondary: `${label} · ${b.length} byte(s) (decoded as Latin-1)`,
            kind: 'string',
            isText: true,
            complete: true,
        };
    } catch {
        return {
            primary: previewHex(b, 32),
            secondary: `${label} · undecodable`,
            kind: 'string',
            isText: false,
            complete: false,
        };
    }
}

function decodeStringBmp(b: Uint8Array): TlvDecodedValue {
    if ((b.length & 1) !== 0) {
        return {
            primary: previewHex(b, 32),
            secondary: 'BMPString length must be even (2 bytes per code point)',
            kind: 'string',
            isText: false,
            complete: false,
        };
    }
    let out = '';
    for (let i = 0; i < b.length; i += 2) {
        const cp = (b[i] << 8) | b[i + 1];
        out += String.fromCharCode(cp);
    }
    return {
        primary: truncate(out, 256),
        secondary: `BMPString · ${b.length / 2} code point(s)`,
        kind: 'string',
        isText: true,
        complete: true,
    };
}

// UTCTime format: YYMMDDhhmm[ss]Z  or  YYMMDDhhmm[ss]±hhmm
function decodeUtcTime(b: Uint8Array): TlvDecodedValue {
    const text = safeAscii(b);
    if (text === null) {
        return { primary: previewHex(b, 32), secondary: 'UTCTime · undecodable', kind: 'datetime', isText: false, complete: false };
    }
    const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})$/.exec(text);
    if (!m) {
        return {
            primary: text,
            secondary: 'UTCTime · does not match YYMMDDhhmm[ss]Z',
            kind: 'datetime',
            isText: true,
            complete: false,
        };
    }
    const [, yy, mm, dd, hh, mi, ss = '00', tz] = m;
    const yearNum = parseInt(yy, 10);
    const year = (yearNum < 50 ? 2000 + yearNum : 1900 + yearNum).toString().padStart(4, '0');
    const offset = tz === 'Z' ? 'Z' : `${tz.slice(0, 3)}:${tz.slice(3)}`;
    const iso = `${year}-${mm}-${dd}T${hh}:${mi}:${ss}${offset}`;
    return {
        primary: iso,
        secondary: `UTCTime · raw="${text}"`,
        kind: 'datetime',
        isText: true,
        complete: true,
    };
}

// GeneralizedTime format: YYYYMMDDhhmm[ss][.fff][Z|±hhmm]
function decodeGeneralizedTime(b: Uint8Array): TlvDecodedValue {
    const text = safeAscii(b);
    if (text === null) {
        return { primary: previewHex(b, 32), secondary: 'GeneralizedTime · undecodable', kind: 'datetime', isText: false, complete: false };
    }
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(\.\d+)?(Z|[+-]\d{4})?$/.exec(text);
    if (!m) {
        return {
            primary: text,
            secondary: 'GeneralizedTime · does not match YYYYMMDDhhmm[ss][.fff][Z|±hhmm]',
            kind: 'datetime',
            isText: true,
            complete: false,
        };
    }
    const [, y, mo, d, h, mi, ss = '00', frac = '', tz = ''] = m;
    const offset = tz === '' ? '' : tz === 'Z' ? 'Z' : `${tz.slice(0, 3)}:${tz.slice(3)}`;
    const iso = `${y}-${mo}-${d}T${h}:${mi}:${ss}${frac}${offset}`;
    return {
        primary: iso,
        secondary: `GeneralizedTime · raw="${text}"`,
        kind: 'datetime',
        isText: true,
        complete: true,
    };
}

// ─── helpers ─────────────────────────────────────────────────────────────────

function previewHex(b: Uint8Array, maxBytes: number): string {
    const len = Math.min(b.length, maxBytes);
    let out = '';
    for (let i = 0; i < len; i++) {
        if (i > 0) out += ' ';
        out += b[i].toString(16).padStart(2, '0').toUpperCase();
    }
    if (b.length > maxBytes) out += ` … (+${b.length - maxBytes}B)`;
    return out;
}

function truncate(s: string, max: number): string {
    return s.length <= max ? s : s.slice(0, max) + `… (+${s.length - max} chars)`;
}

function safeAscii(b: Uint8Array): string | null {
    for (let i = 0; i < b.length; i++) {
        const x = b[i];
        if (x < 0x20 || x > 0x7E) return null;
    }
    try {
        return new TextDecoder('ascii').decode(b);
    } catch {
        try { return new TextDecoder('latin1').decode(b); } catch { return null; }
    }
}

function tryDecodeAscii(b: Uint8Array): string | null {
    if (b.length === 0) return null;
    let printableRatio = 0;
    for (let i = 0; i < b.length; i++) {
        const x = b[i];
        // Printable ASCII OR TAB / LF / CR — common in plain text.
        if ((x >= 0x20 && x <= 0x7E) || x === 0x09 || x === 0x0A || x === 0x0D) printableRatio++;
    }
    if (printableRatio / b.length < 0.95) return null;
    try {
        return new TextDecoder('ascii').decode(b);
    } catch {
        return null;
    }
}

// HI2 IRI message-type tag → friendly name (used when hi2Envelope is true).
const HI2_IRI_TAGS: Readonly<Record<number, string>> = {
    0xA1: 'IRI-Begin (iRI-Begin-record [1])',
    0xA2: 'IRI-End (iRI-End-record [2])',
    0xA3: 'IRI-Continue (iRI-Continue-record [3])',
    0xA4: 'IRI-Report (iRI-Report-record [4])',
};

// ─────────────────────────────────────────────────────────────────────────────
// Header byte segmentation (Tag · Length · Value)
//
// Splits the raw bytes of a TLV node into its three encoded segments so the UI
// can color-code them. We trust `headerLen` and `valueLen` from the WASM parser
// as authoritative; this helper just locates the BOUNDARY between the tag and
// length sub-segments inside the header by re-parsing the BER/DER encoding.
// ─────────────────────────────────────────────────────────────────────────────

export type LengthEncoding = 'short' | 'long' | 'indefinite' | 'unknown';

export interface TlvByteSegments {
    tagBytes: Uint8Array;
    lengthBytes: Uint8Array;
    valueBytes: Uint8Array;
    /** True if our internal re-parse matched the parser-reported headerLen and
     *  there were enough bytes in `fileBytes` to satisfy headerLen + valueLen. */
    complete: boolean;
    lengthEncoding: LengthEncoding;
    /** Decoded length value from the length bytes. For indefinite form this is
     *  reported as -1; for normal forms it should match `valueLen`. */
    decodedLength: number;
    /** Number of bytes consumed by the tag identifier (≥ 1). */
    tagByteCount: number;
    /** Number of bytes consumed by the length encoding (≥ 1). */
    lengthByteCount: number;
}

export function splitTlvHeader(
    fileBytes: Uint8Array,
    nodeOffset: number,
    headerLen: number,
    valueLen: number,
): TlvByteSegments {
    const empty: TlvByteSegments = {
        tagBytes: new Uint8Array(0),
        lengthBytes: new Uint8Array(0),
        valueBytes: new Uint8Array(0),
        complete: false,
        lengthEncoding: 'unknown',
        decodedLength: -1,
        tagByteCount: 0,
        lengthByteCount: 0,
    };

    if (
        nodeOffset < 0 ||
        nodeOffset >= fileBytes.length ||
        headerLen < 2 ||
        nodeOffset + headerLen > fileBytes.length
    ) {
        return empty;
    }

    // ── Tag byte count ──────────────────────────────────────────────────────
    // Single-byte tag unless low 5 bits of byte 0 == 0x1F (high-tag-number form),
    // in which case continuation bytes follow with bit 7 set; the LAST byte of
    // the tag has bit 7 clear. Bounded so we always leave at least 1 byte for
    // the length field within headerLen.
    let tagByteCount = 1;
    if ((fileBytes[nodeOffset] & 0x1F) === 0x1F) {
        const tagCountMax = headerLen - 1; // need ≥ 1 length byte
        while (tagByteCount < tagCountMax) {
            const justRead = fileBytes[nodeOffset + tagByteCount];
            tagByteCount++;
            if ((justRead & 0x80) === 0) break;
        }
    }

    // ── Length encoding ─────────────────────────────────────────────────────
    let lengthEncoding: LengthEncoding = 'unknown';
    let lengthByteCount = 0;
    let decodedLength = -1;
    const lengthByte0 = fileBytes[nodeOffset + tagByteCount];

    if (lengthByte0 < 0x80) {
        lengthEncoding = 'short';
        lengthByteCount = 1;
        decodedLength = lengthByte0;
    } else if (lengthByte0 === 0x80) {
        // Indefinite form — the value is terminated by a 0x00 0x00 marker.
        // We don't compute the length from the header alone in this case.
        lengthEncoding = 'indefinite';
        lengthByteCount = 1;
        decodedLength = -1;
    } else {
        const n = lengthByte0 & 0x7F;
        lengthByteCount = 1 + n;
        lengthEncoding = 'long';
        if (n === 0 || n > 8 || tagByteCount + lengthByteCount > headerLen) {
            // Malformed: reserved (0xFF), too-long count, or doesn't fit in headerLen.
            lengthEncoding = 'unknown';
        } else {
            decodedLength = 0;
            for (let i = 0; i < n; i++) {
                decodedLength = (decodedLength * 256) + fileBytes[nodeOffset + tagByteCount + 1 + i];
            }
        }
    }

    // ── Sanity vs. parser-reported headerLen ────────────────────────────────
    const internalHeaderLen = tagByteCount + lengthByteCount;
    let complete = internalHeaderLen === headerLen;
    // For non-indefinite forms, decodedLength should match valueLen.
    if (complete && lengthEncoding !== 'indefinite' && decodedLength !== valueLen) {
        complete = false;
    }
    // If our reparse disagrees but the parser says headerLen is N, trust the
    // parser for slicing — we just flag complete=false.
    const effectiveTagCount = Math.min(tagByteCount, headerLen);
    const effectiveLengthCount = Math.max(0, headerLen - effectiveTagCount);

    const tagBytes = fileBytes.slice(nodeOffset, nodeOffset + effectiveTagCount);
    const lengthBytes = fileBytes.slice(nodeOffset + effectiveTagCount, nodeOffset + headerLen);
    const valueEnd = Math.min(fileBytes.length, nodeOffset + headerLen + valueLen);
    const valueBytes = fileBytes.slice(nodeOffset + headerLen, valueEnd);
    // If the buffer can't satisfy the full value length, flag incomplete.
    if (valueBytes.length < valueLen) complete = false;

    return {
        tagBytes,
        lengthBytes,
        valueBytes,
        complete,
        lengthEncoding,
        decodedLength,
        tagByteCount: effectiveTagCount,
        lengthByteCount: effectiveLengthCount,
    };
}

// Tag-class label for the inspector.
export function describeTag(tag: number, ctx: TlvDecodeContext = {}): string {
    if (ctx.hi2Envelope && (ctx.depth ?? 0) > 0 && HI2_IRI_TAGS[tag]) {
        return HI2_IRI_TAGS[tag];
    }
    if ((tag & 0xC0) === 0x00) return UNIVERSAL_TAG_NAMES[tag] ?? `UNIVERSAL[0x${tag.toString(16)}]`;
    if ((tag & 0xC0) === 0x40) return `Application [${tag & 0x1F}]`;
    if ((tag & 0xC0) === 0x80) return `Context [${tag & 0x1F}]`;
    return `Private [${tag & 0x1F}]`;
}
