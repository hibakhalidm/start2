import { describe, expect, it } from 'vitest';
import { decodeTlvValue, describeTag, splitTlvHeader } from './tlvDecode';

const u8 = (...x: number[]): Uint8Array => new Uint8Array(x);
const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

// ─── BOOLEAN (0x01) ──────────────────────────────────────────────────────────

describe('decodeTlvValue: BOOLEAN', () => {
    it('decodes canonical FALSE / TRUE', () => {
        expect(decodeTlvValue(0x01, false, u8(0x00))).toMatchObject({ primary: 'FALSE', kind: 'boolean', complete: true });
        expect(decodeTlvValue(0x01, false, u8(0xFF))).toMatchObject({ primary: 'TRUE', kind: 'boolean', complete: true });
    });

    it('flags non-canonical TRUE (any non-zero byte != 0xFF)', () => {
        const r = decodeTlvValue(0x01, false, u8(0x01));
        expect(r.primary).toBe('TRUE');
        expect(r.notes?.[0]).toMatch(/non-canonical/);
    });

    it('rejects multi-byte BOOLEAN as incomplete', () => {
        const r = decodeTlvValue(0x01, false, u8(0x00, 0x01));
        expect(r.complete).toBe(false);
    });
});

// ─── INTEGER (0x02) ──────────────────────────────────────────────────────────

describe('decodeTlvValue: INTEGER', () => {
    it('decodes small positive', () => {
        expect(decodeTlvValue(0x02, false, u8(0x00)).primary).toBe('0');
        expect(decodeTlvValue(0x02, false, u8(0x7F)).primary).toBe('127');
        expect(decodeTlvValue(0x02, false, u8(0x00, 0x80)).primary).toBe('128');
    });

    it('decodes negative two\'s-complement correctly', () => {
        expect(decodeTlvValue(0x02, false, u8(0xFF)).primary).toBe('-1');
        expect(decodeTlvValue(0x02, false, u8(0x80)).primary).toBe('-128');
        expect(decodeTlvValue(0x02, false, u8(0xFF, 0x7F)).primary).toBe('-129');
    });

    it('handles arbitrary-precision integers (> 8 bytes) — the old decoder lost data here', () => {
        // 16-byte value: 0x01 followed by 15 zero bytes = 2^120
        const bytes = u8(0x01, ...new Array(15).fill(0x00));
        const r = decodeTlvValue(0x02, false, bytes);
        expect(r.complete).toBe(true);
        expect(r.primary).toBe((1n << 120n).toString());
        expect(r.secondary).toMatch(/arbitrary-precision|16 byte/);
    });

    it('marks empty INTEGER as incomplete', () => {
        expect(decodeTlvValue(0x02, false, u8()).complete).toBe(false);
    });
});

// ─── BIT STRING (0x03) ───────────────────────────────────────────────────────

describe('decodeTlvValue: BIT STRING', () => {
    it('decodes valid bit string with unused bits', () => {
        const r = decodeTlvValue(0x03, false, u8(0x04, 0xF0, 0xC0));
        expect(r.complete).toBe(true);
        expect(r.secondary).toMatch(/12 bit\(s\)/);
        expect(r.secondary).toMatch(/unused trailing bits = 4/);
    });

    it('rejects invalid unused-bits byte (> 7)', () => {
        const r = decodeTlvValue(0x03, false, u8(0x09, 0xAA));
        expect(r.complete).toBe(false);
    });
});

// ─── OCTET STRING (0x04) ─────────────────────────────────────────────────────

describe('decodeTlvValue: OCTET STRING', () => {
    it('renders printable bytes as text', () => {
        const r = decodeTlvValue(0x04, false, enc('Hello'));
        expect(r.primary).toBe('Hello');
        expect(r.isText).toBe(true);
    });

    it('renders binary bytes as hex preview', () => {
        const r = decodeTlvValue(0x04, false, u8(0x00, 0xFF, 0xFE, 0xFD));
        expect(r.isText).toBe(false);
        expect(r.primary).toMatch(/^00 FF FE FD/);
    });
});

// ─── NULL (0x05) ─────────────────────────────────────────────────────────────

describe('decodeTlvValue: NULL', () => {
    it('decodes empty NULL', () => {
        const r = decodeTlvValue(0x05, false, u8());
        expect(r).toMatchObject({ primary: 'NULL', complete: true, kind: 'null' });
    });
    it('flags non-empty NULL as malformed', () => {
        const r = decodeTlvValue(0x05, false, u8(0x00));
        expect(r.complete).toBe(false);
    });
});

// ─── OID (0x06) ──────────────────────────────────────────────────────────────

describe('decodeTlvValue: OID', () => {
    it('decodes 1.2.840.113549.1.7.2 (PKCS#7 signedData) and gives friendly name', () => {
        // Encoding: 2A 86 48 86 F7 0D 01 07 02
        const bytes = u8(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02);
        const r = decodeTlvValue(0x06, false, bytes);
        expect(r.primary).toBe('1.2.840.113549.1.7.2');
        expect(r.secondary).toBe('PKCS#7 signedData');
        expect(r.complete).toBe(true);
    });

    it('decodes 2.16.840.1.101.3.4.2.1 (SHA-256)', () => {
        // 60 86 48 01 65 03 04 02 01
        const bytes = u8(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01);
        const r = decodeTlvValue(0x06, false, bytes);
        expect(r.primary).toBe('2.16.840.1.101.3.4.2.1');
        expect(r.secondary).toBe('SHA-256');
    });

    it('decodes commonName OID (2.5.4.3)', () => {
        const r = decodeTlvValue(0x06, false, u8(0x55, 0x04, 0x03));
        expect(r.primary).toBe('2.5.4.3');
        expect(r.secondary).toMatch(/commonName/);
    });

    it('decodes ETSI HI2 domain OID (0.4.0.2.1)', () => {
        // arc1=0, arc2=4 → first byte = 0*40 + 4 = 0x04
        const r = decodeTlvValue(0x06, false, u8(0x04, 0x00, 0x02, 0x01));
        expect(r.primary).toBe('0.4.0.2.1');
        expect(r.secondary).toBe('ETSI HI2 domain');
    });

    it('flags truncated OID (last sub-id missing its terminator byte)', () => {
        // The trailing 0x86 has the high bit set, indicating "more bytes follow" — but none do.
        const r = decodeTlvValue(0x06, false, u8(0x2A, 0x86));
        expect(r.complete).toBe(false);
    });
});

// ─── ENUMERATED (0x0A) ───────────────────────────────────────────────────────

describe('decodeTlvValue: ENUMERATED', () => {
    it('decodes like INTEGER but with kind=enumerated', () => {
        const r = decodeTlvValue(0x0A, false, u8(0x03));
        expect(r.primary).toBe('3');
        expect(r.kind).toBe('enumerated');
    });
});

// ─── Strings ─────────────────────────────────────────────────────────────────

describe('decodeTlvValue: Strings', () => {
    it('UTF8String decodes Unicode', () => {
        // "Héllo" in UTF-8
        const r = decodeTlvValue(0x0C, false, enc('Héllo'));
        expect(r.primary).toBe('Héllo');
        expect(r.complete).toBe(true);
    });

    it('UTF8String flags invalid UTF-8', () => {
        const r = decodeTlvValue(0x0C, false, u8(0xC3, 0x28));
        expect(r.complete).toBe(false);
    });

    it('PrintableString accepts canonical chars and rejects out-of-charset', () => {
        expect(decodeTlvValue(0x13, false, enc('Alice')).complete).toBe(true);
        expect(decodeTlvValue(0x13, false, enc('alice@x.com')).complete).toBe(false); // '@' not in PrintableString
    });

    it('IA5String accepts 7-bit ASCII including @', () => {
        expect(decodeTlvValue(0x16, false, enc('alice@example.com')).complete).toBe(true);
    });

    it('BMPString decodes UCS-2 BE', () => {
        // "Hi" in BMPString: 00 48 00 69
        const r = decodeTlvValue(0x1E, false, u8(0x00, 0x48, 0x00, 0x69));
        expect(r.primary).toBe('Hi');
        expect(r.complete).toBe(true);
    });

    it('BMPString flags odd-length input', () => {
        const r = decodeTlvValue(0x1E, false, u8(0x00, 0x48, 0x00));
        expect(r.complete).toBe(false);
    });
});

// ─── UTCTime / GeneralizedTime ───────────────────────────────────────────────

describe('decodeTlvValue: dates', () => {
    it('UTCTime parses to ISO with century rollover (yy < 50 → 20yy)', () => {
        const r = decodeTlvValue(0x17, false, enc('230509142500Z'));
        expect(r.primary).toBe('2023-05-09T14:25:00Z');
        expect(r.complete).toBe(true);
    });

    it('UTCTime parses pre-2000 (yy >= 50 → 19yy)', () => {
        const r = decodeTlvValue(0x17, false, enc('970509142500Z'));
        expect(r.primary).toBe('1997-05-09T14:25:00Z');
    });

    it('UTCTime accepts ±hhmm offset', () => {
        const r = decodeTlvValue(0x17, false, enc('230509142500+0200'));
        expect(r.primary).toBe('2023-05-09T14:25:00+02:00');
    });

    it('UTCTime flags malformed', () => {
        const r = decodeTlvValue(0x17, false, enc('not-a-date'));
        expect(r.complete).toBe(false);
    });

    it('GeneralizedTime parses 4-digit year + fractional seconds', () => {
        const r = decodeTlvValue(0x18, false, enc('20230509142500.123Z'));
        expect(r.primary).toBe('2023-05-09T14:25:00.123Z');
    });

    it('GeneralizedTime parses without timezone (local time)', () => {
        const r = decodeTlvValue(0x18, false, enc('20230509142500'));
        expect(r.primary).toBe('2023-05-09T14:25:00');
    });
});

// ─── Container / context tags ───────────────────────────────────────────────

describe('decodeTlvValue: containers and context tags', () => {
    it('SEQUENCE constructed returns container with child count', () => {
        const r = decodeTlvValue(0x30, true, u8(), { childCount: 3 });
        expect(r.kind).toBe('container');
        expect(r.primary).toMatch(/SEQUENCE.*3 field/);
    });

    it('Context-specific constructed at depth > 0 in HI2 envelope maps to IRI message type', () => {
        const r = decodeTlvValue(0xA1, true, u8(), { hi2Envelope: true, depth: 1, childCount: 5 });
        expect(r.primary).toMatch(/IRI-Begin/);
        expect(r.kind).toBe('context');
    });

    it('Context-specific constructed at depth 0 (root) is NOT interpreted as IRI (likely CDR)', () => {
        const r = decodeTlvValue(0xA1, true, u8(), { hi2Envelope: true, depth: 0, childCount: 5 });
        expect(r.primary).not.toMatch(/IRI-Begin/);
    });

    it('Context-specific primitive shows hex + class label', () => {
        const r = decodeTlvValue(0x82, false, u8(0xDE, 0xAD, 0xBE, 0xEF));
        expect(r.primary).toMatch(/DE AD BE EF/);
        expect(r.secondary).toMatch(/Context \[2\]/);
    });
});

// ─── splitTlvHeader ──────────────────────────────────────────────────────────

const hexToBytes = (...nums: number[]): Uint8Array => new Uint8Array(nums);

describe('splitTlvHeader', () => {
    it('short-form length: 1 tag byte + 1 length byte + value', () => {
        // 0x02 0x03 0x01 0x02 0x03 — INTEGER length 3, value [01 02 03]
        const buf = hexToBytes(0x02, 0x03, 0x01, 0x02, 0x03);
        const s = splitTlvHeader(buf, 0, 2, 3);
        expect(s.complete).toBe(true);
        expect(Array.from(s.tagBytes)).toEqual([0x02]);
        expect(Array.from(s.lengthBytes)).toEqual([0x03]);
        expect(Array.from(s.valueBytes)).toEqual([0x01, 0x02, 0x03]);
        expect(s.lengthEncoding).toBe('short');
        expect(s.decodedLength).toBe(3);
        expect(s.tagByteCount).toBe(1);
        expect(s.lengthByteCount).toBe(1);
    });

    it('long-form length (1 length count byte): 0x82 0x01 0x00 → 256-byte value', () => {
        // OCTET STRING with long-form 2-byte length encoding 0x82 0x01 0x00 = 256
        const header = hexToBytes(0x04, 0x82, 0x01, 0x00);
        const value = new Uint8Array(256);
        const buf = new Uint8Array(header.length + value.length);
        buf.set(header, 0);
        buf.set(value, header.length);
        const s = splitTlvHeader(buf, 0, 4, 256);
        expect(s.complete).toBe(true);
        expect(Array.from(s.tagBytes)).toEqual([0x04]);
        expect(Array.from(s.lengthBytes)).toEqual([0x82, 0x01, 0x00]);
        expect(s.valueBytes.length).toBe(256);
        expect(s.lengthEncoding).toBe('long');
        expect(s.decodedLength).toBe(256);
    });

    it('multi-byte (high-tag-number) tag: 0x1F 0x82 0x05 + length', () => {
        // High-tag-number form: first byte low 5 bits = 0x1F, then continuation
        // bytes with bit 7 set until last byte with bit 7 clear.
        // Tag bytes 0x1F 0x82 0x05 → headerLen=4 (3 tag + 1 length).
        const buf = hexToBytes(0x1F, 0x82, 0x05, 0x02, 0xAA, 0xBB);
        const s = splitTlvHeader(buf, 0, 4, 2);
        expect(s.complete).toBe(true);
        expect(Array.from(s.tagBytes)).toEqual([0x1F, 0x82, 0x05]);
        expect(Array.from(s.lengthBytes)).toEqual([0x02]);
        expect(Array.from(s.valueBytes)).toEqual([0xAA, 0xBB]);
        expect(s.tagByteCount).toBe(3);
        expect(s.lengthByteCount).toBe(1);
    });

    it('indefinite-form length (0x80 marker) flagged distinctly', () => {
        // BER allows indefinite form for constructed types. headerLen=2 here.
        const buf = hexToBytes(0x30, 0x80, 0x01, 0x02, 0x00, 0x00);
        const s = splitTlvHeader(buf, 0, 2, 2);
        expect(s.lengthEncoding).toBe('indefinite');
        expect(s.decodedLength).toBe(-1);
        expect(Array.from(s.lengthBytes)).toEqual([0x80]);
    });

    it('flags incomplete when our reparse disagrees with parser-reported headerLen', () => {
        // headerLen says 3 but the bytes only justify 2 (1 tag + 1 short length).
        const buf = hexToBytes(0x02, 0x03, 0x01, 0x02, 0x03);
        const s = splitTlvHeader(buf, 0, 3, 3);
        expect(s.complete).toBe(false);
    });

    it('flags incomplete when decodedLength does not match valueLen', () => {
        const buf = hexToBytes(0x02, 0x03, 0x01, 0x02, 0x03);
        // Parser claims valueLen=2 but the length byte says 3 → mismatch.
        const s = splitTlvHeader(buf, 0, 2, 2);
        expect(s.complete).toBe(false);
    });

    it('handles non-zero node offsets correctly', () => {
        // Junk bytes before the node, then a real TLV at offset 4.
        const buf = hexToBytes(0xff, 0xff, 0xff, 0xff, 0x06, 0x02, 0x2A, 0x03);
        const s = splitTlvHeader(buf, 4, 2, 2);
        expect(s.complete).toBe(true);
        expect(Array.from(s.tagBytes)).toEqual([0x06]);
        expect(Array.from(s.lengthBytes)).toEqual([0x02]);
        expect(Array.from(s.valueBytes)).toEqual([0x2A, 0x03]);
    });

    it('returns partial value bytes (and complete=false) when value is truncated', () => {
        // Header fits (2 bytes) but the buffer is too small for the claimed value.
        const buf = hexToBytes(0x04, 0x0A, 0xAA, 0xBB);
        const s = splitTlvHeader(buf, 0, 2, 10);
        expect(s.complete).toBe(false);
        expect(Array.from(s.tagBytes)).toEqual([0x04]);
        expect(Array.from(s.lengthBytes)).toEqual([0x0A]);
        expect(Array.from(s.valueBytes)).toEqual([0xAA, 0xBB]); // partial value
    });

    it('returns empty segments when the header itself does not fit in the buffer', () => {
        const buf = hexToBytes(0x04);
        const s = splitTlvHeader(buf, 0, 2, 0);
        expect(s.complete).toBe(false);
        expect(s.tagBytes.length).toBe(0);
        expect(s.lengthBytes.length).toBe(0);
        expect(s.valueBytes.length).toBe(0);
    });
});

// ─── describeTag ─────────────────────────────────────────────────────────────

describe('describeTag', () => {
    it('names universal tags', () => {
        expect(describeTag(0x02)).toBe('INTEGER');
        expect(describeTag(0x06)).toBe('OBJECT IDENTIFIER');
        expect(describeTag(0x30)).toBe('SEQUENCE');
    });
    it('names context tags by index', () => {
        expect(describeTag(0x80)).toBe('Context [0]');
        expect(describeTag(0xA3)).toBe('Context [3]');
    });
    it('maps HI2 IRI tags when in HI2 envelope context', () => {
        expect(describeTag(0xA1, { hi2Envelope: true, depth: 1 })).toMatch(/IRI-Begin/);
        expect(describeTag(0xA4, { hi2Envelope: true, depth: 1 })).toMatch(/IRI-Report/);
    });
});
