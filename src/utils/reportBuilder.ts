export type VerificationMetadata = {
    hashing_algorithm: 'SHA-256';
    canonicalization: {
        format: 'application/json';
        serialization: 'JSON.stringify (standard ECMAScript JSON serialization; compact, no whitespace)';
        encoding: 'UTF-8';
        notes: string[];
    };
    integrity_seal_computation: {
        input: 'UTF-8 bytes of JSON.stringify(report_payload) using the exact object shape and key order shown in report_payload';
        output: 'lowercase hex string of SHA-256 digest (64 hex chars)';
    };
};

export function buildVerificationMetadata(): VerificationMetadata {
    return {
        hashing_algorithm: 'SHA-256',
        canonicalization: {
            format: 'application/json',
            serialization: 'JSON.stringify (standard ECMAScript JSON serialization; compact, no whitespace)',
            encoding: 'UTF-8',
            notes: [
                'integrity_seal is computed over UTF-8(JSON.stringify(report_payload)) where report_payload is the object BEFORE integrity_seal and verification_metadata fields are appended.',
                'Reproducers must match the same JSON object shape and property insertion order as emitted by this exporter (post-JSON.parse, pre-seal).',
                'Pretty-printed JSON in the downloaded file is for human readability only; it is NOT the canonical input to the seal unless you re-serialize identically.'
            ]
        },
        integrity_seal_computation: {
            input: 'UTF-8 bytes of JSON.stringify(report_payload) using the exact object shape and key order shown in report_payload',
            output: 'lowercase hex string of SHA-256 digest (64 hex chars)'
        }
    };
}
