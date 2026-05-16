import { describe, expect, it } from 'vitest';
import { IncrementalSha256 } from './export';

// These are NIST FIPS-180-4 test vectors plus a couple of well-known
// reference cases. The IncrementalSha256 class is in the integrity-seal
// trust path for every CIFAD report, so we lock it down explicitly.

const sha256OneShot = (bytes: Uint8Array): string => {
    const h = new IncrementalSha256();
    h.update(bytes);
    return h.digest();
};

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

describe('IncrementalSha256', () => {
    it('matches NIST vector: empty input', () => {
        expect(sha256OneShot(new Uint8Array(0)))
            .toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('matches NIST vector: "abc"', () => {
        expect(sha256OneShot(enc('abc')))
            .toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    });

    it('matches NIST vector: 448-bit length boundary', () => {
        // sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        expect(sha256OneShot(enc('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')))
            .toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
    });

    it('matches NIST vector: 896-bit length boundary (1 million "a")', () => {
        const buf = new Uint8Array(1_000_000);
        buf.fill(0x61); // 'a'
        expect(sha256OneShot(buf))
            .toBe('cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');
    });

    it('produces identical digest for chunked vs one-shot updates', () => {
        // Pseudo-random-ish but deterministic data that crosses multiple 64-byte blocks.
        const data = new Uint8Array(4096 + 17); // odd length to stress trailing-byte handling
        for (let i = 0; i < data.length; i++) data[i] = (i * 1103515245 + 12345) & 0xff;

        const expected = sha256OneShot(data);
        // Chunk at every awkward boundary we can think of: 1, 63, 64, 65, 127, 128, 1024.
        for (const chunkSize of [1, 63, 64, 65, 127, 128, 1024]) {
            const h = new IncrementalSha256();
            for (let off = 0; off < data.length; off += chunkSize) {
                h.update(data.subarray(off, Math.min(off + chunkSize, data.length)));
            }
            expect(h.digest()).toBe(expected);
        }
    });

    it('rejects double-digest / update-after-digest', () => {
        const h = new IncrementalSha256();
        h.update(enc('abc'));
        h.digest();
        expect(() => h.digest()).toThrow();
        expect(() => h.update(enc('xyz'))).toThrow();
    });
});
