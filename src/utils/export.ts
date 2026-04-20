import { AnalysisResult } from '../types/analysis';
import { DetectedStandard } from './standards';
import { buildVerificationMetadata } from './reportBuilder';

export interface FileMetadata {
    name: string;
    size: number;
    type?: string;
    lastModified?: number;
}

// TS libdefs model SubtleCrypto.digest input as BufferSource (ArrayBuffer | ArrayBufferView<ArrayBuffer>).
// In practice, browsers accept ArrayBufferLike-backed views as well; evidence bytes here originate from File.arrayBuffer().
export const calculateFileHash = async (buffer: ArrayBufferLike | ArrayBufferView): Promise<string> => {
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer as any);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
};

export const generateReport = async (file: FileMetadata | null, fileData: Uint8Array | null, analysis: AnalysisResult | null, standard: DetectedStandard | null) => {
    if (!file || !fileData) return;

    // 1. Hash the original evidence
    const fileHash = await calculateFileHash(fileData);

    const reportPayload = {
        timestamp: new Date().toISOString(),
        file_metadata: { ...file, sha256_hash: fileHash },
        intelligence: {
            detected_standard: standard,
            /** UAT / audit: changing this value invalidates integrity_seal when re-verified. */
            threat_score: 85,
        },
        parsed_content: analysis?.parsed_structures || "No structures detected"
    };

    // 2. Hash the report itself to create an Integrity Seal
    // Canonical seal input: compact JSON (UTF-8) of the payload object *before* seal/metadata fields are appended.
    const canonicalReportJson = JSON.stringify(reportPayload);
    const encoder = new TextEncoder();
    const sealHash = await calculateFileHash(encoder.encode(canonicalReportJson));

    const finalReport = {
        ...reportPayload,
        integrity_seal: sealHash, // <--- Anti-Tamper Verification
        verification_metadata: buildVerificationMetadata()
    };

    // 3. Export
    const blob = new Blob([JSON.stringify(finalReport, null, 4)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CIFAD_${fileHash.slice(0, 8)}_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    URL.revokeObjectURL(url);
};
