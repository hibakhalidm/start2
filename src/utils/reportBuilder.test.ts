import { describe, expect, it } from 'vitest';
import { buildVerificationMetadata } from './reportBuilder';

describe('buildVerificationMetadata', () => {
    it('returns SHA-256 and canonical JSON + UTF-8 rules for integrity seal reproduction', () => {
        const meta = buildVerificationMetadata();

        expect(meta.hashing_algorithm).toBe('SHA-256');

        expect(meta.canonicalization.format).toBe('application/json');
        expect(meta.canonicalization.encoding).toBe('UTF-8');
        expect(meta.canonicalization.serialization).toContain('JSON.stringify');
        expect(meta.canonicalization.serialization.toLowerCase()).toContain('compact');

        expect(meta.canonicalization.notes.length).toBeGreaterThan(0);
        expect(meta.canonicalization.notes.some((n) => n.toLowerCase().includes('integrity_seal'))).toBe(true);
        expect(meta.canonicalization.notes.some((n) => n.toLowerCase().includes('utf-8'))).toBe(true);

        expect(meta.integrity_seal_computation.input.toLowerCase()).toContain('utf-8');
        expect(meta.integrity_seal_computation.input.toLowerCase()).toContain('json.stringify');
        expect(meta.integrity_seal_computation.output.toLowerCase()).toContain('sha-256');
        expect(meta.integrity_seal_computation.output.toLowerCase()).toContain('hex');
    });
});
