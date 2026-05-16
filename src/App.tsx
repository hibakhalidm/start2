import React, { useState, useRef, useMemo, useEffect, useCallback } from 'react';
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels';
import { useAnalysisEngine } from './hooks/useAnalysisEngine';
import { HilbertCurve } from './utils/hilbert';
import { detectStandard, DetectedStandard } from './utils/standards';
import { FileMetadata, generateReport, DetectionTelemetrySnapshot } from './utils/export';
import { detectProtocols, ProtocolHypothesis } from './utils/protocols';
import { Download, HardDrive, Activity, MousePointer2, FileType, AlertTriangle, ShieldCheck } from 'lucide-react';

import Radar from './components/Radar';
import HexView, { HexViewRef } from './components/HexView';
import SemanticScrollbar from './components/SemanticScrollbar';
import AutocorrelationGraph from './components/AutocorrelationGraph';
import FileTree from './components/FileTree';
import StructureInspector from './components/StructureInspector';
import TransformationPipeline from './components/TransformationPipeline';
import { TlvNode, AnalysisResult } from './types/analysis';
import './App.css';

// ─────────────────────────────────────────────────────────────────────────────
// DETECTION-ENGINEERING CORE
//
// This module-scope section implements layered, race-safe, explainable
// detection orchestration. It deliberately lives next to the UI so the React
// shell can stay thin while the heavy correctness invariants (run tokens,
// evidence atomicity, anomaly fusion) are pure functions, testable in
// isolation. None of the helpers below capture component state.
// ─────────────────────────────────────────────────────────────────────────────

/** Bytes of file head we *always* keep in memory for signature + UI preview. */
const HEAD_PREVIEW_BYTES = 1024 * 1024;          // 1 MiB
/** Bytes of file tail we keep in memory specifically for trailer-marker detection
 *  (ZIP EOCD, PDF %%EOF, OLE2 chains, RAR/7z trailers, MP4 moov-at-end, etc.). */
const TAIL_PREVIEW_BYTES = 256 * 1024;           // 256 KiB
/** Number of evenly-spaced sparse probes taken from the middle of the file
 *  (between head end and tail start). Each probe is `SPARSE_PROBE_SIZE_BYTES`.
 *  These defeat "hide between head and tail" evasion without paying for a
 *  full-file scan. */
const SPARSE_PROBE_COUNT = 6;
const SPARSE_PROBE_SIZE_BYTES = 4 * 1024;        // 4 KiB
/** Hard cap on bytes loaded for a user selection. Selection-driven local
 *  analyses past this point are EXPLICITLY surfaced as anomalies; never
 *  silently truncated. */
const SELECTION_HARD_CAP_BYTES = 1024 * 1024;    // 1 MiB
/** Sample budget for local autocorrelation (defeats quadratic blow-up on
 *  multi-MB selections). */
const LOCAL_AUTOCORR_SAMPLE_BUDGET = 8 * 1024;   // 8 KiB
/** Maximum lag computed against the sample. */
const LOCAL_AUTOCORR_MAX_LAG = 128;
/** Soft timeout: emit anomaly + send cooperative cancel to the worker. */
const WORKER_TIMEOUT_SOFT_MS = 60_000;
/** Hard timeout: terminate-and-respawn the worker. Reserved for genuinely
 *  wedged synchronous WASM calls that cooperative cancel cannot reach. */
const WORKER_TIMEOUT_HARD_MS = 180_000;
/** Confidence floor before we badge a TYPE in the status bar. Anything below
 *  this is shown as "RAW BINARY" with a separate "weak signal" tooltip. */
const PRIMARY_CONFIDENCE_FLOOR = 0.45;
/** Ring-buffer capacity for the per-session detection telemetry log. Bounded
 *  so a long analyst session can't OOM the page. */
const TELEMETRY_LOG_CAPACITY = 50;

type DetectionCategory =
    | 'network' | 'archive' | 'document' | 'executable'
    | 'media' | 'crypto' | 'protocol' | 'unknown';

type EvidenceSource =
    | 'magic-head' | 'magic-tail' | 'magic-sparse'
    | 'structure' | 'extension' | 'mime' | 'entropy'
    | 'crypto-heuristic' | 'protocol-heuristic'
    | 'protocol-decode'
    | 'fusion';

interface DetectionHypothesis {
    id: string;
    name: string;
    category: DetectionCategory;
    confidence: number;          // 0..1
    evidence: string[];          // human-readable reasons
    matchedOffsets: number[];    // absolute file offsets where evidence was found
    source: EvidenceSource;
    color: string;
}

interface DetectionAnomaly {
    severity: 'info' | 'warn' | 'critical';
    code:
        | 'ext_mime_magic_mismatch' | 'polyglot'
        | 'tail_only_magic' | 'sparse_only_magic' | 'embedded_executable'
        | 'selection_truncated'
        | 'worker_timeout_soft' | 'worker_timeout_hard'
        | 'stale_result_attribution'
        | 'evidence_load_error' | 'high_entropy_unstructured';
    message: string;
}

interface DetectionReport {
    token: number;
    fingerprint: string;
    primary: DetectionHypothesis | null;
    hypotheses: DetectionHypothesis[];
    anomalies: DetectionAnomaly[];
    generatedAt: number;
    costMs: number;
}

interface SparseProbe {
    offset: number;             // absolute file offset
    bytes: Uint8Array;
}

interface FileEvidence {
    token: number;
    name: string;
    size: number;
    lastModified: number;
    claimedMime: string;        // browser-supplied — UNTRUSTED, used only for cross-check
    claimedExt: string;         // from filename — UNTRUSTED, used only for cross-check
    head: Uint8Array;           // up to HEAD_PREVIEW_BYTES
    tail: Uint8Array;           // up to TAIL_PREVIEW_BYTES (empty if size <= head)
    tailOffset: number;         // absolute file offset where `tail` starts
    sparseProbes: SparseProbe[];// evenly spaced middle probes (anti-evasion)
    fingerprint: string;        // sha256(head || size-LE-u64 || tail || probes) — cache key
    capturedAt: number;         // performance.now()
    loadCostMs: number;
}

// ── Pure helpers (module scope, tree-shake friendly) ─────────────────────────

const CRYPTO_SUBTLE: SubtleCrypto | null =
    typeof crypto !== 'undefined' && crypto.subtle ? crypto.subtle : null;

async function sha256Hex(parts: Uint8Array[]): Promise<string> {
    const total = parts.reduce((n, p) => n + p.byteLength, 0);
    const joined = new Uint8Array(total);
    let cursor = 0;
    for (const p of parts) { joined.set(p, cursor); cursor += p.byteLength; }
    if (!CRYPTO_SUBTLE) {
        // Deterministic FNV-1a fallback — collision-prone but stable for caching only.
        let h = 0x811c9dc5;
        for (let i = 0; i < joined.length; i++) {
            h ^= joined[i];
            h = Math.imul(h, 0x01000193) >>> 0;
        }
        return `fnv1a:${h.toString(16).padStart(8, '0')}`;
    }
    const buf = await CRYPTO_SUBTLE.digest('SHA-256', joined as unknown as ArrayBuffer);
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function extractExt(name: string): string {
    const dot = name.lastIndexOf('.');
    if (dot <= 0 || dot === name.length - 1) return '';
    return name.slice(dot + 1).toLowerCase();
}

function toExclusiveEnd(inclusive: { start: number; end: number }): { start: number; endExclusive: number } {
    // Canonical conversion. Our external contract is end-INCLUSIVE; slice math is exclusive.
    return { start: inclusive.start, endExclusive: Math.max(inclusive.start, inclusive.end) + 1 };
}

interface MagicRule {
    id: string;
    name: string;
    category: DetectionCategory;
    /** Bytes to match. */
    match: number[];
    /** Where the magic is expected: head only, tail only, or either. */
    window: 'head' | 'tail' | 'any';
    /** Base confidence for an isolated head/tail hit. */
    baseConfidence: number;
    color: string;
}

const m = (...b: number[]) => b;

const MAGIC_LIBRARY: ReadonlyArray<MagicRule> = [
    // network
    { id: 'pcap-le',     name: 'PCAP',                 category: 'network',    match: m(0xa1, 0xb2, 0xc3, 0xd4), window: 'head', baseConfidence: 0.95, color: '#ff0055' },
    { id: 'pcap-be',     name: 'PCAP (swapped)',       category: 'network',    match: m(0xd4, 0xc3, 0xb2, 0xa1), window: 'head', baseConfidence: 0.95, color: '#ff0055' },
    { id: 'pcap-ns-le',  name: 'PCAP (nanosec)',       category: 'network',    match: m(0xa1, 0xb2, 0x3c, 0x4d), window: 'head', baseConfidence: 0.90, color: '#ff0055' },
    { id: 'pcap-ns-be',  name: 'PCAP (nanosec, swap)', category: 'network',    match: m(0x4d, 0x3c, 0xb2, 0xa1), window: 'head', baseConfidence: 0.90, color: '#ff0055' },
    { id: 'pcapng',      name: 'PCAP-NG',              category: 'network',    match: m(0x0a, 0x0d, 0x0d, 0x0a), window: 'head', baseConfidence: 0.95, color: '#ff00aa' },
    // archives / containers
    { id: 'zip-lfh',     name: 'ZIP (local header)',   category: 'archive',    match: m(0x50, 0x4b, 0x03, 0x04), window: 'head', baseConfidence: 0.70, color: '#ffaa00' },
    { id: 'zip-eocd',    name: 'ZIP (EOCD trailer)',   category: 'archive',    match: m(0x50, 0x4b, 0x05, 0x06), window: 'tail', baseConfidence: 0.90, color: '#ffaa00' },
    { id: 'rar5',        name: 'RAR5',                 category: 'archive',    match: m(0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00), window: 'head', baseConfidence: 0.97, color: '#ffaa00' },
    { id: '7z',          name: '7-Zip',                category: 'archive',    match: m(0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c), window: 'head', baseConfidence: 0.97, color: '#ffaa00' },
    { id: 'gz',          name: 'gzip',                 category: 'archive',    match: m(0x1f, 0x8b), window: 'head', baseConfidence: 0.65, color: '#ffaa00' },
    { id: 'xz',          name: 'xz',                   category: 'archive',    match: m(0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00), window: 'head', baseConfidence: 0.95, color: '#ffaa00' },
    // documents
    { id: 'pdf',         name: 'PDF',                  category: 'document',   match: m(0x25, 0x50, 0x44, 0x46, 0x2d), window: 'head', baseConfidence: 0.93, color: '#00ff9d' },
    { id: 'pdf-eof',     name: 'PDF (%%EOF trailer)',  category: 'document',   match: m(0x25, 0x25, 0x45, 0x4f, 0x46), window: 'tail', baseConfidence: 0.55, color: '#00ff9d' },
    { id: 'ole2',        name: 'OLE2 (MS Office)',     category: 'document',   match: m(0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1), window: 'head', baseConfidence: 0.97, color: '#00ff9d' },
    // executables
    { id: 'pe-mz',       name: 'PE (MZ stub)',         category: 'executable', match: m(0x4d, 0x5a), window: 'head', baseConfidence: 0.55, color: '#ff5577' },
    { id: 'elf',         name: 'ELF',                  category: 'executable', match: m(0x7f, 0x45, 0x4c, 0x46), window: 'head', baseConfidence: 0.95, color: '#ff5577' },
    { id: 'macho-64',    name: 'Mach-O 64',            category: 'executable', match: m(0xcf, 0xfa, 0xed, 0xfe), window: 'head', baseConfidence: 0.92, color: '#ff5577' },
    { id: 'macho-32',    name: 'Mach-O 32',            category: 'executable', match: m(0xce, 0xfa, 0xed, 0xfe), window: 'head', baseConfidence: 0.90, color: '#ff5577' },
    // media
    { id: 'png',         name: 'PNG',                  category: 'media',      match: m(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a), window: 'head', baseConfidence: 0.98, color: '#aa66ff' },
    { id: 'jpg',         name: 'JPEG',                 category: 'media',      match: m(0xff, 0xd8, 0xff), window: 'head', baseConfidence: 0.85, color: '#aa66ff' },
    { id: 'gif',         name: 'GIF',                  category: 'media',      match: m(0x47, 0x49, 0x46, 0x38), window: 'head', baseConfidence: 0.92, color: '#aa66ff' },
    // crypto / structure
    { id: 'asn1-seq',    name: 'ASN.1 SEQUENCE (DER)', category: 'crypto',     match: m(0x30, 0x82), window: 'head', baseConfidence: 0.45, color: '#00f0ff' },
];

/** Extension → expected category. Used ONLY for anti-evasion cross-check, never as primary signal. */
const EXT_CATEGORY: Readonly<Record<string, DetectionCategory>> = {
    pcap: 'network', pcapng: 'network', cap: 'network',
    zip: 'archive', rar: 'archive', '7z': 'archive', gz: 'archive', xz: 'archive', tar: 'archive', tgz: 'archive',
    pdf: 'document', doc: 'document', docx: 'archive' /* OOXML is a zip */, xls: 'document', xlsx: 'archive', ppt: 'document', pptx: 'archive',
    exe: 'executable', dll: 'executable', sys: 'executable', so: 'executable', dylib: 'executable', elf: 'executable',
    png: 'media', jpg: 'media', jpeg: 'media', gif: 'media', webp: 'media', bmp: 'media',
};

/** MIME prefix → expected category. */
function categoryFromMime(mime: string): DetectionCategory | null {
    if (!mime) return null;
    if (mime.startsWith('image/')) return 'media';
    if (mime.startsWith('video/')) return 'media';
    if (mime.startsWith('audio/')) return 'media';
    if (mime === 'application/pdf') return 'document';
    if (mime === 'application/zip' || mime === 'application/x-zip-compressed') return 'archive';
    if (mime === 'application/x-7z-compressed') return 'archive';
    if (mime === 'application/x-rar-compressed' || mime === 'application/vnd.rar') return 'archive';
    if (mime === 'application/gzip' || mime === 'application/x-gzip') return 'archive';
    if (mime === 'application/vnd.tcpdump.pcap') return 'network';
    if (mime === 'application/x-msdownload' || mime === 'application/x-dosexec') return 'executable';
    return null;
}

function matchAt(buf: Uint8Array, offset: number, pattern: number[]): boolean {
    if (offset < 0 || offset + pattern.length > buf.length) return false;
    for (let i = 0; i < pattern.length; i++) if (buf[offset + i] !== pattern[i]) return false;
    return true;
}

/** Scan a window for magic occurrences.
 *  - `'head'` side: only head-anchored rules (offset 0).
 *  - `'tail'` side: only tail-window rules, scanned across the whole window.
 *  - `'sparse'` side: any non-head rule (treated as unanchored scan); used for
 *    middle probes where we have no anchor to rely on.
 *  Early-out on first hit per rule to keep cost bounded. */
function scanMagics(
    window: Uint8Array,
    absoluteBase: number,
    side: 'head' | 'tail' | 'sparse',
): Array<{ rule: MagicRule; absoluteOffset: number }> {
    const out: Array<{ rule: MagicRule; absoluteOffset: number }> = [];
    for (const rule of MAGIC_LIBRARY) {
        if (side === 'head') {
            if (rule.window !== 'head') continue;
            if (matchAt(window, 0, rule.match)) out.push({ rule, absoluteOffset: absoluteBase });
        } else if (side === 'tail') {
            if (rule.window !== 'tail' && rule.window !== 'any') continue;
            const limit = window.length - rule.match.length;
            for (let i = 0; i <= limit; i++) {
                if (matchAt(window, i, rule.match)) { out.push({ rule, absoluteOffset: absoluteBase + i }); break; }
            }
        } else {
            // sparse: scan everywhere EXCEPT pure head-anchored rules (the
            // probe isn't anchored, so a head-rule match somewhere in the
            // middle is suspicious — keep it but penalise via the caller).
            const limit = window.length - rule.match.length;
            for (let i = 0; i <= limit; i++) {
                if (matchAt(window, i, rule.match)) { out.push({ rule, absoluteOffset: absoluteBase + i }); break; }
            }
        }
    }
    return out;
}

/** Local byte-rank autocorrelation over a capped sample. Returns |r| in [0, 1]
 *  per lag in 1..maxLag. Pure, deterministic, no dependencies. */
function localByteAutocorrelation(bytes: Uint8Array): number[] {
    if (!bytes || bytes.length < 4) return [];
    const N = Math.min(bytes.length, LOCAL_AUTOCORR_SAMPLE_BUDGET);
    // Mean
    let mean = 0;
    for (let i = 0; i < N; i++) mean += bytes[i];
    mean /= N;
    // Denominator (variance × N)
    let denom = 0;
    for (let i = 0; i < N; i++) { const d = bytes[i] - mean; denom += d * d; }
    if (denom < 1e-9) return new Array(Math.min(LOCAL_AUTOCORR_MAX_LAG, Math.floor(N / 4))).fill(0);
    const maxLag = Math.min(LOCAL_AUTOCORR_MAX_LAG, Math.floor(N / 4));
    const out = new Array<number>(maxLag);
    for (let lag = 1; lag <= maxLag; lag++) {
        let num = 0;
        const upper = N - lag;
        for (let i = 0; i < upper; i++) {
            num += (bytes[i] - mean) * (bytes[i + lag] - mean);
        }
        // Normalize against denom (matches Pearson at lag 0 = 1)
        const r = num / denom;
        out[lag - 1] = Math.max(0, Math.min(1, Math.abs(r)));
    }
    return out;
}

function confidenceTier(c: number): 'HIGH' | 'MEDIUM' | 'LOW' {
    if (c >= 0.80) return 'HIGH';
    if (c >= 0.55) return 'MEDIUM';
    return 'LOW';
}

/** Map ProtocolFamily → DetectionCategory for fusion-engine ranking. */
function protocolFamilyToCategory(p: ProtocolHypothesis): DetectionCategory {
    switch (p.family) {
        case 'http':
        case 'quic':
        case 'sip':
        case 'diameter':
        case 'li':
        case 'cdr':
            return 'protocol';
        case 'vendor':
            return 'protocol';
        default:
            return 'unknown';
    }
}

/** Bridge our internal hypothesis to the legacy `DetectedStandard` shape so
 *  downstream components (FileTree, StructureInspector, generateReport) keep
 *  working without prop changes. */
function hypothesisToStandard(h: DetectionHypothesis | null, category: string): DetectedStandard | null {
    if (!h) return null;
    return {
        name: h.name,
        description: `${h.evidence[0] ?? 'signal fusion'} · conf=${h.confidence.toFixed(2)}`,
        category: category.toUpperCase(),
        confidence: confidenceTier(h.confidence),
        color: h.color,
    };
}

/** Layered detection fusion. Pure. Deterministic per (evidence, result) pair.
 *
 *  Layers, in order:
 *    A. Structural (existing detectStandard over head + parsed TLV).
 *    B. Magic-head scan — anchored byte signatures at offset 0.
 *    C. Magic-tail scan — trailer-marker signatures over the tail window.
 *    D. Magic-sparse scan — middle-of-file probes (anti-evasion).
 *    E. Crypto/protocol heuristics from the WASM worker (fusion sources).
 *    F. Extension / MIME / detected-category cross-check.
 *    G. Polyglot detection.
 *    H. High-entropy fallback (only when nothing else fired). */
function fuseDetection(
    evidence: FileEvidence,
    parsedStructures: TlvNode[] | undefined,
    legacyStructural: DetectedStandard | null,
    workerCryptoMode: 'AES-128/256' | 'DES/3DES' | null,
    workerProtocolGuess: string | null,
): DetectionReport {
    const t0 = performance.now();
    const hypotheses: DetectionHypothesis[] = [];
    const anomalies: DetectionAnomaly[] = [];

    // ── Layer A: structural ──────────────────────────────────────────────────
    if (legacyStructural) {
        const conf = legacyStructural.confidence === 'HIGH' ? 0.92
                   : legacyStructural.confidence === 'MEDIUM' ? 0.65 : 0.35;
        hypotheses.push({
            id: `legacy:${legacyStructural.name}`,
            name: legacyStructural.name,
            category: (legacyStructural.category.toLowerCase() as DetectionCategory) || 'unknown',
            confidence: conf,
            evidence: [`structural detector matched (${legacyStructural.confidence})`, legacyStructural.description],
            matchedOffsets: [0],
            source: 'structure',
            color: legacyStructural.color,
        });
    }
    if (parsedStructures && parsedStructures.length > 0) {
        const root = parsedStructures[0];
        if (root.tag === 0x30 || root.tag === 0x31) {
            const hasEtsi = parsedStructures.some(n => n.tag === 0xA1 || n.tag === 0xA2);
            hypotheses.push({
                id: 'tlv:asn1',
                name: hasEtsi ? 'ETSI TS 101 671' : 'ASN.1 / BER',
                category: hasEtsi ? 'protocol' : 'crypto',
                confidence: hasEtsi ? 0.90 : 0.60,
                evidence: [
                    `root tag 0x${root.tag.toString(16)} at offset ${root.offset}`,
                    hasEtsi ? 'ETSI HI2/HI3 IRI tags present (0xA1/0xA2)' : 'DER/BER SEQUENCE root',
                ],
                matchedOffsets: [root.offset],
                source: 'structure',
                color: hasEtsi ? '#00ff9d' : '#00f0ff',
            });
        }
    }

    // ── Layer B + C: magic scans (head + tail) ───────────────────────────────
    const headHits = scanMagics(evidence.head, 0, 'head');
    const tailHits = evidence.tail.length > 0
        ? scanMagics(evidence.tail, evidence.tailOffset, 'tail')
        : [];
    for (const { rule, absoluteOffset } of headHits) {
        hypotheses.push({
            id: `magic:${rule.id}`,
            name: rule.name,
            category: rule.category,
            confidence: rule.baseConfidence,
            evidence: [`magic ${rule.id} matched at offset 0x${absoluteOffset.toString(16)}`],
            matchedOffsets: [absoluteOffset],
            source: 'magic-head',
            color: rule.color,
        });
    }
    for (const { rule, absoluteOffset } of tailHits) {
        const paired = headHits.some(h => h.rule.category === rule.category);
        const conf = paired ? rule.baseConfidence : Math.max(0.35, rule.baseConfidence - 0.15);
        hypotheses.push({
            id: `magic-tail:${rule.id}`,
            name: rule.name,
            category: rule.category,
            confidence: conf,
            evidence: [
                `trailer ${rule.id} matched at offset 0x${absoluteOffset.toString(16)}`,
                paired ? 'paired with head signature (corroborating)' : 'unpaired trailer (lower confidence)',
            ],
            matchedOffsets: [absoluteOffset],
            source: 'magic-tail',
            color: rule.color,
        });
        if (!paired) {
            anomalies.push({
                severity: 'info',
                code: 'tail_only_magic',
                message: `${rule.name} signature found only at the tail (offset 0x${absoluteOffset.toString(16)}) without a head counterpart — possible appended payload.`,
            });
        }
    }

    // ── Layer D: sparse middle probes ────────────────────────────────────────
    // Hits in the middle of the file are NEVER the primary classification (no
    // anchor), but they're strong evidence of embedding/concatenation. We emit
    // them as `magic-sparse` hypotheses with low base confidence AND raise
    // anomalies so the analyst notices.
    const sparseHitsByRule = new Set<string>();
    const headCategoriesEarly = new Set(headHits.map(h => h.rule.category));
    for (const probe of evidence.sparseProbes) {
        const hits = scanMagics(probe.bytes, probe.offset, 'sparse');
        for (const { rule, absoluteOffset } of hits) {
            if (sparseHitsByRule.has(rule.id)) continue; // dedupe across probes
            sparseHitsByRule.add(rule.id);
            const insideKnownHead = headCategoriesEarly.has(rule.category);
            const conf = insideKnownHead
                ? Math.max(0.25, rule.baseConfidence - 0.35) // probably just a substructure of the head's format
                : Math.max(0.30, rule.baseConfidence - 0.25);
            hypotheses.push({
                id: `magic-sparse:${rule.id}`,
                name: rule.name,
                category: rule.category,
                confidence: conf,
                evidence: [`probe match for ${rule.id} at offset 0x${absoluteOffset.toString(16)} (middle of file)`],
                matchedOffsets: [absoluteOffset],
                source: 'magic-sparse',
                color: rule.color,
            });
            if (!insideKnownHead) {
                // Embedded executable inside a non-executable container is a
                // classic IOC. Surface it loudly.
                if (rule.category === 'executable') {
                    anomalies.push({
                        severity: 'critical',
                        code: 'embedded_executable',
                        message: `Executable signature (${rule.name}) found embedded at offset 0x${absoluteOffset.toString(16)}, outside any matching head signature.`,
                    });
                } else {
                    anomalies.push({
                        severity: 'warn',
                        code: 'sparse_only_magic',
                        message: `${rule.name} signature found mid-file at offset 0x${absoluteOffset.toString(16)} with no head/tail counterpart.`,
                    });
                }
            }
        }
    }

    // ── Layer E: crypto / protocol heuristics from worker (multi-signal fusion) ──
    if (workerCryptoMode) {
        hypotheses.push({
            id: `crypto:${workerCryptoMode}`,
            name: workerCryptoMode,
            category: 'crypto',
            confidence: 0.55,
            evidence: [`autocorrelation lag spike consistent with ${workerCryptoMode}`],
            matchedOffsets: [0],
            source: 'crypto-heuristic',
            color: '#00f0ff',
        });
    }

    // ── Layer E.5: explicit protocol decoders (HTTP/1, HTTP/2, QUIC, SIP, Diameter,
    //               ETSI HI2 IRI, 3GPP CDR, vendor periodic). These are STRUCTURALLY
    //               validated and outrank the worker's protocol_guess heuristic. ──
    const workerSaysVendorPeriodic = !!workerProtocolGuess && /^VENDOR\b/i.test(workerProtocolGuess);
    const protocolHits = detectProtocols({
        headerBytes: evidence.head,
        fileSize: evidence.size,
        parsedStructures: parsedStructures,
        claimedExt: evidence.claimedExt,
        workerPeriodicHint: workerSaysVendorPeriodic,
    });
    for (const p of protocolHits) {
        hypotheses.push({
            id: `protocol:${p.id}`,
            name: p.name,
            category: protocolFamilyToCategory(p),
            confidence: p.confidence,
            evidence: [...p.evidence, ...(p.standard ? [`standard: ${p.standard}`] : []), ...(p.interfaceName ? [`interface: ${p.interfaceName}`] : [])],
            matchedOffsets: p.matchedOffsets,
            source: 'protocol-decode',
            color: p.color,
        });
    }

    // Worker's protocol_guess is now a SECONDARY source. Suppress it when an
    // explicit decoder already produced a stronger HTTP/QUIC hypothesis to
    // avoid double-counting; keep it otherwise (e.g. legacy vendor hint).
    const haveExplicitHttpOrQuic = protocolHits.some(p => p.family === 'http' || p.family === 'quic');
    const workerSaysHttp = !!workerProtocolGuess && /^H[123]\b/.test(workerProtocolGuess);
    if (workerProtocolGuess && !(workerSaysHttp && haveExplicitHttpOrQuic)) {
        hypotheses.push({
            id: `proto:${workerProtocolGuess}`,
            name: workerProtocolGuess,
            category: 'protocol',
            confidence: workerProtocolGuess.startsWith('H2') ? 0.85
                     : workerProtocolGuess.startsWith('H1') ? 0.65
                     : 0.50,
            evidence: [`worker protocol heuristic: ${workerProtocolGuess}`],
            matchedOffsets: [0],
            source: 'protocol-heuristic',
            color: '#00f0ff',
        });
    }

    // ── Layer F: cross-check extension / MIME / detected category ────────────
    const detectedCategories = new Set<DetectionCategory>(
        hypotheses.filter(h => h.source === 'magic-head' || h.source === 'magic-tail').map(h => h.category),
    );
    const extCat = EXT_CATEGORY[evidence.claimedExt] ?? null;
    const mimeCat = categoryFromMime(evidence.claimedMime);
    if (extCat && detectedCategories.size > 0 && !detectedCategories.has(extCat)) {
        anomalies.push({
            severity: 'critical',
            code: 'ext_mime_magic_mismatch',
            message: `Extension ".${evidence.claimedExt}" suggests ${extCat} but magic signatures indicate ${Array.from(detectedCategories).join('/')}.`,
        });
    }
    if (mimeCat && detectedCategories.size > 0 && !detectedCategories.has(mimeCat)) {
        anomalies.push({
            severity: 'warn',
            code: 'ext_mime_magic_mismatch',
            message: `Browser-claimed MIME "${evidence.claimedMime}" (${mimeCat}) does not match detected magic (${Array.from(detectedCategories).join('/')}).`,
        });
    }

    // ── Layer G: polyglot ────────────────────────────────────────────────────
    const headCategories = new Set(headHits.map(h => h.rule.category));
    if (headCategories.size >= 2) {
        anomalies.push({
            severity: 'critical',
            code: 'polyglot',
            message: `Polyglot suspected: head matches multiple format families (${Array.from(headCategories).join(', ')}).`,
        });
    }

    // ── Layer H: high-entropy fallback ONLY if nothing else fired ────────────
    const hasNonHeuristicHypothesis = hypotheses.some(
        h => h.source !== 'crypto-heuristic' && h.source !== 'protocol-heuristic',
    );
    if (!hasNonHeuristicHypothesis && evidence.head.length > 512) {
        const seen = new Uint8Array(256);
        const sample = Math.min(evidence.head.length, 4096);
        let distinct = 0;
        for (let i = 0; i < sample; i++) { const b = evidence.head[i]; if (!seen[b]) { seen[b] = 1; distinct++; } }
        const distinctRatio = distinct / 256;
        if (distinctRatio > 0.85) {
            hypotheses.push({
                id: 'entropy:high',
                name: 'ENCRYPTED / COMPRESSED',
                category: 'unknown',
                confidence: 0.30,
                evidence: [`distinct-byte ratio ${distinctRatio.toFixed(2)} on first ${sample} bytes — no readable header`],
                matchedOffsets: [0],
                source: 'entropy',
                color: '#ffaa00',
            });
            anomalies.push({
                severity: 'info',
                code: 'high_entropy_unstructured',
                message: 'No known magic; high distinct-byte ratio suggests encrypted, compressed, or random data.',
            });
        }
    }

    // ── Multi-signal corroboration boost ─────────────────────────────────────
    // Count "strong" sources per category (excludes sparse hits, which are
    // already low-confidence by design and shouldn't bootstrap themselves).
    const strongSources: ReadonlySet<EvidenceSource> = new Set([
        'magic-head', 'magic-tail', 'structure',
        'protocol-decode',
        'crypto-heuristic', 'protocol-heuristic',
    ]);
    const categoryBoosts = new Map<DetectionCategory, number>();
    for (const h of hypotheses) {
        if (strongSources.has(h.source)) {
            categoryBoosts.set(h.category, (categoryBoosts.get(h.category) ?? 0) + 1);
        }
    }
    for (const h of hypotheses) {
        const n = categoryBoosts.get(h.category) ?? 1;
        if (n > 1 && strongSources.has(h.source)) {
            const boost = Math.min(0.10 * (n - 1), 0.18);
            h.confidence = Math.min(0.99, h.confidence + boost);
            h.evidence.push(`+${(boost * 100).toFixed(0)}% multi-signal corroboration (${n} strong signals in ${h.category})`);
        }
    }

    const sourceRank: Record<EvidenceSource, number> = {
        'magic-head': 6,
        'protocol-decode': 6,  // structurally validated decoders are as strong as magic-head
        'structure': 5,
        'magic-tail': 4,
        'protocol-heuristic': 3, 'crypto-heuristic': 3,
        'magic-sparse': 2, 'mime': 2, 'extension': 1, 'entropy': 0, 'fusion': 0,
    };
    hypotheses.sort((a, b) => {
        if (b.confidence !== a.confidence) return b.confidence - a.confidence;
        return sourceRank[b.source] - sourceRank[a.source];
    });

    const primary = hypotheses.length > 0 && hypotheses[0].confidence >= PRIMARY_CONFIDENCE_FLOOR
        ? hypotheses[0]
        : null;

    return {
        token: evidence.token,
        fingerprint: evidence.fingerprint,
        primary,
        hypotheses,
        anomalies,
        generatedAt: Date.now(),
        costMs: performance.now() - t0,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// COMPONENT
// ─────────────────────────────────────────────────────────────────────────────

function App() {
    const { isReady, analyzeFile, cancelAnalysis, hardCancel, result, isAnalyzing } = useAnalysisEngine();

    // Atomic per-load identifier. EVERY async path captures this and refuses to
    // commit unless it still matches `runTokenRef.current`. This is THE primary
    // race defense for cross-file contamination of analysis results.
    const runTokenRef = useRef(0);
    // Incremented whenever `result` changes identity, so we can attribute it to
    // the correct kickoff. Defeats stale-result attribution when file B's load
    // intercepts file A's worker callback.
    const resultRevisionRef = useRef(0);
    // The revision number at the moment we kicked off the *current* token. A
    // result is considered "fresh" only when resultRevisionRef.current > kickoff.
    const analysisKickoffRevRef = useRef(0);
    const analysisStartedAtRef = useRef<number | null>(null);
    // Abort current evidence load when a new file arrives.
    const evidenceAbortRef = useRef<AbortController | null>(null);
    const selectionAbortRef = useRef<AbortController | null>(null);
    // Abort the current worker analysis (signals → hook → worker cancel message).
    const workerAbortRef = useRef<AbortController | null>(null);
    // Abort an in-flight streaming whole-file hash on file change or user cancel.
    const reportAbortRef = useRef<AbortController | null>(null);
    // In-memory de-dup of evidence by content fingerprint (head+size+tail+probes).
    const evidenceCacheRef = useRef<Map<string, FileEvidence>>(new Map());
    // Bounded telemetry ring buffer of per-load detection reports for audit.
    const telemetryLogRef = useRef<DetectionReport[]>([]);

    const [fileMeta, setFileMeta] = useState<FileMetadata | null>(null);
    const [fileObj, setFileObj] = useState<File | null>(null);
    const [evidence, setEvidence] = useState<FileEvidence | null>(null);
    const [detection, setDetection] = useState<DetectionReport | null>(null);
    const [analysisError, setAnalysisError] = useState<string | null>(null);
    const [softTimeoutHit, setSoftTimeoutHit] = useState(false);
    const [hardTimeoutHit, setHardTimeoutHit] = useState(false);
    const [hashProgress, setHashProgress] = useState<{ done: number; total: number } | null>(null);

    const [inspectorContext, setInspectorContext] = useState<'file' | 'node' | 'trailing'>('file');
    const [isDragging, setIsDragging] = useState(false);

    const [showHilbert, setShowHilbert] = useState(true);
    const [showHeatmap, setShowHeatmap] = useState(true);
    const [showInspector, setShowInspector] = useState(true);
    const [showPipeline, setShowPipeline] = useState(true);

    const [hoveredOffset] = useState<number | null>(null);
    const [selectionRange, setSelectionRange] = useState<{ start: number; end: number } | null>(null);
    const [hoverRange, setHoverRange] = useState<{ start: number; end: number } | null>(null);
    const [selectedNode, setSelectedNode] = useState<TlvNode | null>(null);
    const [currentScrollOffset, setCurrentScrollOffset] = useState(0);

    const [hexStride] = useState(16);
    const [hilbert] = useState(() => new HilbertCurve(9));
    const hexViewRef = useRef<HexViewRef>(null);

    // `fileData` is preserved as the head buffer for backward compatibility with
    // downstream components (StructureInspector, exports). The richer `evidence`
    // bundle is what drives detection.
    const fileData = evidence?.head ?? null;

    // ── Track result identity revision (for stale-attribution defense) ───────
    useEffect(() => {
        resultRevisionRef.current += 1;
        if (analysisStartedAtRef.current !== null) {
            analysisStartedAtRef.current = null;
            setSoftTimeoutHit(false);
            setHardTimeoutHit(false);
        }
    }, [result]);

    // ── Worker watchdog: SOFT → cooperative cancel; HARD → terminate+respawn. ──
    // Cooperative cancel reaches the worker between awaits and is enough for
    // most timeouts. If the worker is wedged in a synchronous WASM call,
    // hard cancel re-spawns it after a longer grace period.
    useEffect(() => {
        if (!isAnalyzing) return;
        analysisStartedAtRef.current = performance.now();
        setSoftTimeoutHit(false);
        setHardTimeoutHit(false);
        const softTimer = window.setTimeout(() => {
            setSoftTimeoutHit(true);
            workerAbortRef.current?.abort();
            try { cancelAnalysis(); } catch { /* swallow */ }
        }, WORKER_TIMEOUT_SOFT_MS);
        const hardTimer = window.setTimeout(() => {
            setHardTimeoutHit(true);
            try { hardCancel(); } catch { /* swallow */ }
        }, WORKER_TIMEOUT_HARD_MS);
        return () => { window.clearTimeout(softTimer); window.clearTimeout(hardTimer); };
    }, [isAnalyzing, cancelAnalysis, hardCancel]);

    // ── File ingest: atomic, token-guarded, abort-safe ───────────────────────
    const processFile = useCallback(async (file: File) => {
        // Bump token first. Anything in flight from the previous load is now
        // implicitly invalid even before we await anything.
        const token = ++runTokenRef.current;
        evidenceAbortRef.current?.abort();
        const ac = new AbortController();
        evidenceAbortRef.current = ac;

        // Cancel any prior worker analysis and report-hash that may still be
        // running for the previous file. These are real cancellations now,
        // not just suppressed attributions.
        workerAbortRef.current?.abort();
        const workerAc = new AbortController();
        workerAbortRef.current = workerAc;
        reportAbortRef.current?.abort();
        reportAbortRef.current = null;
        setHashProgress(null);

        // Reset per-file analyst state immediately so the UI never shows stale
        // selections/inspector context against a new file.
        setSelectionRange(null);
        setSelectedNode(null);
        setInspectorContext('file');
        setAnalysisError(null);
        setDetection(null);

        setFileObj(file);
        setFileMeta({ name: file.name, size: file.size, type: file.type, lastModified: file.lastModified });

        try {
            const tStart = performance.now();

            // Head + tail in parallel.
            const headLen = Math.min(HEAD_PREVIEW_BYTES, file.size);
            const headBufP = file.slice(0, headLen).arrayBuffer();

            const wantTail = file.size > HEAD_PREVIEW_BYTES;
            const tailStart = wantTail ? Math.max(headLen, file.size - TAIL_PREVIEW_BYTES) : file.size;
            const tailBufP: Promise<ArrayBuffer> = wantTail
                ? file.slice(tailStart, file.size).arrayBuffer()
                : Promise.resolve(new ArrayBuffer(0));

            // Sparse middle probes — evenly spaced between head end and tail start.
            // Each probe is small (4 KiB) so the total extra I/O is bounded
            // (~24 KiB for the default 6 probes) even on multi-GB files.
            const probeWindowStart = headLen;
            const probeWindowEnd = wantTail ? tailStart : file.size;
            const probePromises: Array<Promise<SparseProbe>> = [];
            if (probeWindowEnd - probeWindowStart > SPARSE_PROBE_SIZE_BYTES * 2) {
                const span = probeWindowEnd - probeWindowStart - SPARSE_PROBE_SIZE_BYTES;
                for (let i = 0; i < SPARSE_PROBE_COUNT; i++) {
                    const off = Math.floor(probeWindowStart + (span * (i + 1)) / (SPARSE_PROBE_COUNT + 1));
                    const end = off + SPARSE_PROBE_SIZE_BYTES;
                    probePromises.push(
                        file.slice(off, end).arrayBuffer().then(buf => ({ offset: off, bytes: new Uint8Array(buf) })),
                    );
                }
            }

            const [headBuf, tailBuf, probes] = await Promise.all([
                headBufP,
                tailBufP,
                Promise.all(probePromises),
            ]);
            if (ac.signal.aborted || runTokenRef.current !== token) return;

            const head = new Uint8Array(headBuf);
            const tail = new Uint8Array(tailBuf);

            // Fingerprint: SHA-256(head || size-LE-u64 || tail || concat(probe.bytes)).
            // Probes are included so cache equivalence considers the same regions
            // we actually scanned. NOT the forensic file hash — that's the
            // whole-file stream hash in generateReport.
            const sizeBytes = new Uint8Array(8);
            let s = file.size;
            for (let i = 0; i < 8; i++) { sizeBytes[i] = s & 0xff; s = Math.floor(s / 256); }
            const fingerprintParts: Uint8Array[] = [head, sizeBytes, tail, ...probes.map(p => p.bytes)];
            const fingerprint = await sha256Hex(fingerprintParts);
            if (ac.signal.aborted || runTokenRef.current !== token) return;

            const cached = evidenceCacheRef.current.get(fingerprint);
            const ev: FileEvidence = cached && cached.size === file.size && cached.name === file.name
                ? { ...cached, token }
                : {
                    token,
                    name: file.name,
                    size: file.size,
                    lastModified: file.lastModified,
                    claimedMime: file.type ?? '',
                    claimedExt: extractExt(file.name),
                    head,
                    tail,
                    tailOffset: tailStart,
                    sparseProbes: probes,
                    fingerprint,
                    capturedAt: performance.now(),
                    loadCostMs: performance.now() - tStart,
                };
            evidenceCacheRef.current.set(fingerprint, ev);
            setEvidence(ev);

            // Record the revision at kickoff so we can later distinguish "the
            // result we are seeing was produced AFTER this kickoff" from "this
            // is leftover state from a previous file".
            analysisKickoffRevRef.current = resultRevisionRef.current;
            // Pass the worker abort signal so timeout / file-change really kills
            // the in-flight analysis instead of merely ignoring its eventual result.
            analyzeFile(file, { signal: workerAc.signal });
        } catch (err) {
            if (ac.signal.aborted || runTokenRef.current !== token) return;
            setAnalysisError(`Evidence load failed: ${(err as Error).message}`);
        }
    }, [analyzeFile]);

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const f = e.target.files?.[0];
        if (f) void processFile(f);
    };

    const handleDragOver = (e: React.DragEvent) => { e.preventDefault(); setIsDragging(true); };
    const handleDragLeave = () => setIsDragging(false);
    const handleDrop = async (e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(false);
        const f = e.dataTransfer.files?.[0];
        if (f) await processFile(f);
    };

    // Selection ranges are end-INCLUSIVE at the external contract (status bar,
    // child components). All internal slice math goes through toExclusiveEnd
    // to eliminate F6 off-by-one bleed.
    const handleJumpTo = useCallback((offset: number, length: number = 16) => {
        const safeLen = Math.max(1, Math.floor(length));
        setSelectionRange({ start: offset, end: offset + safeLen - 1 });
        hexViewRef.current?.scrollToOffset(offset);
    }, []);

    const handleScrollUpdate = (off: number) => setCurrentScrollOffset(off);

    // ── Detection fusion ─────────────────────────────────────────────────────
    // Runs only when (a) we have an evidence bundle, (b) the token matches the
    // currently-loaded file, and (c) the worker result we are seeing was
    // produced AFTER the current evidence was kicked off — otherwise we'd be
    // fusing the new file's bytes with the previous file's TLV tree.
    useEffect(() => {
        if (!evidence) { setDetection(null); return; }
        if (evidence.token !== runTokenRef.current) return;

        const haveFreshResult = resultRevisionRef.current > analysisKickoffRevRef.current;
        const parsed = haveFreshResult ? result?.parsed_structures : undefined;
        const cryptoMode = haveFreshResult ? (result?.crypto_mode ?? null) : null;
        const protocolGuess = haveFreshResult ? (result?.protocol_guess ?? null) : null;
        const legacy = detectStandard(parsed, evidence.head);
        const report = fuseDetection(evidence, parsed, legacy, cryptoMode, protocolGuess);

        if (!haveFreshResult && (result?.parsed_structures?.length ?? 0) > 0) {
            report.anomalies.unshift({
                severity: 'warn',
                code: 'stale_result_attribution',
                message: 'Worker result from a previous file is still in memory; structural layer is suppressed until the new analysis completes.',
            });
        }
        if (softTimeoutHit) {
            report.anomalies.push({
                severity: 'warn',
                code: 'worker_timeout_soft',
                message: `Worker analysis exceeded ${(WORKER_TIMEOUT_SOFT_MS / 1000).toFixed(0)}s; cooperative cancel issued, structural detection disabled.`,
            });
        }
        if (hardTimeoutHit) {
            report.anomalies.push({
                severity: 'critical',
                code: 'worker_timeout_hard',
                message: `Worker did not respond to cooperative cancel within ${(WORKER_TIMEOUT_HARD_MS / 1000).toFixed(0)}s; worker was terminated and respawned.`,
            });
        }
        setDetection(report);

        // Telemetry ring buffer (bounded). One entry per (token, fingerprint)
        // pair; we don't dedupe across fingerprint because re-analysis is a
        // legitimately separate event.
        const log = telemetryLogRef.current;
        log.push(report);
        if (log.length > TELEMETRY_LOG_CAPACITY) log.splice(0, log.length - TELEMETRY_LOG_CAPACITY);
    }, [evidence, result, softTimeoutHit, hardTimeoutHit]);

    // ── Selection bytes: abortable, capped, anomaly-surfacing ────────────────
    const [selectedBytes, setSelectedBytes] = useState<Uint8Array | null>(null);
    const [selectionTruncated, setSelectionTruncated] = useState(false);
    useEffect(() => {
        // Abort any in-flight selection read on every change.
        selectionAbortRef.current?.abort();
        if (!fileObj || !selectionRange) {
            setSelectedBytes(null);
            setSelectionTruncated(false);
            return;
        }
        const ac = new AbortController();
        selectionAbortRef.current = ac;
        const tokenAtKickoff = runTokenRef.current;

        const load = async () => {
            const { start, endExclusive } = toExclusiveEnd(selectionRange);
            const safeStart = Math.max(0, Math.min(fileObj.size, start));
            const requestedLen = Math.max(0, Math.min(fileObj.size, endExclusive) - safeStart);
            const truncated = requestedLen > SELECTION_HARD_CAP_BYTES;
            const effectiveLen = Math.min(requestedLen, SELECTION_HARD_CAP_BYTES);
            try {
                const buf = await fileObj.slice(safeStart, safeStart + effectiveLen).arrayBuffer();
                if (ac.signal.aborted || runTokenRef.current !== tokenAtKickoff) return;
                setSelectedBytes(new Uint8Array(buf));
                setSelectionTruncated(truncated);
            } catch (err) {
                if (ac.signal.aborted) return;
                console.warn('Selection load failed:', err);
                setSelectedBytes(null);
            }
        };
        void load();
        return () => ac.abort();
    }, [fileObj, selectionRange]);

    // ── Local autocorrelation (real implementation, finally wired in) ────────
    const liveAutocorrelation = useMemo(() => {
        if (!selectedBytes || selectedBytes.length < 4) return [];
        return localByteAutocorrelation(selectedBytes);
    }, [selectedBytes]);

    // Pass the local series to the graph when a selection is active; otherwise
    // fall back to the worker's global series. This finally surfaces region-
    // local structural signals (F3).
    const autocorrSeries = liveAutocorrelation.length > 0
        ? liveAutocorrelation
        : (result?.autocorrelation_graph ?? []);

    const currentViewPercent = fileMeta ? currentScrollOffset / Math.max(1, fileMeta.size) : 0;
    const showCrunchingOverlay = !!fileObj && isAnalyzing && !softTimeoutHit && !hardTimeoutHit;

    const showStructureInspector = showInspector && !!fileObj && !!fileData;

    // Bridge to legacy `DetectedStandard` shape — downstream components are unchanged.
    const standardForDownstream: DetectedStandard | null = useMemo(
        () => hypothesisToStandard(detection?.primary ?? null, detection?.primary?.category ?? 'unknown'),
        [detection],
    );

    // Anomaly aggregation for the status bar.
    const anomalies = detection?.anomalies ?? [];
    const maxSeverity: 'info' | 'warn' | 'critical' | null = anomalies.length === 0
        ? null
        : anomalies.some(a => a.severity === 'critical') ? 'critical'
        : anomalies.some(a => a.severity === 'warn') ? 'warn' : 'info';
    const anomalyColor = maxSeverity === 'critical' ? '#ff3355'
        : maxSeverity === 'warn' ? '#ffaa00'
        : maxSeverity === 'info' ? '#00f0ff' : '#444';

    // Token-coherent report generation. We re-validate at click time AND pass
    // only the currently-attributed `result` (gated by revision freshness).
    // The whole-file SHA-256 is streamed; abort signal propagates on file
    // change or explicit cancel.
    const handleReport = useCallback(() => {
        if (!fileMeta || !evidence) return;
        if (evidence.token !== runTokenRef.current) return;
        const haveFreshResult = resultRevisionRef.current > analysisKickoffRevRef.current;
        const safeResult: AnalysisResult | null = haveFreshResult ? result : null;

        reportAbortRef.current?.abort();
        const ac = new AbortController();
        reportAbortRef.current = ac;
        setHashProgress({ done: 0, total: fileMeta.size });

        const telemetry: DetectionTelemetrySnapshot | undefined = detection
            ? {
                fingerprint: detection.fingerprint,
                primary: detection.primary ? {
                    id: detection.primary.id,
                    name: detection.primary.name,
                    category: detection.primary.category,
                    confidence: detection.primary.confidence,
                    source: detection.primary.source,
                    evidence: detection.primary.evidence,
                    matchedOffsets: detection.primary.matchedOffsets,
                } : null,
                hypotheses: detection.hypotheses.map(h => ({
                    name: h.name, category: h.category, confidence: h.confidence,
                    source: h.source, evidence: h.evidence, matchedOffsets: h.matchedOffsets,
                })),
                anomalies: detection.anomalies,
                cost_ms: detection.costMs,
                generated_at: detection.generatedAt,
                session_log: telemetryLogRef.current.slice(-10).map(r => ({
                    fingerprint: r.fingerprint,
                    primary: r.primary?.name ?? null,
                    confidence: r.primary?.confidence ?? null,
                    anomaly_count: r.anomalies.length,
                    cost_ms: r.costMs,
                    generated_at: r.generatedAt,
                })),
            }
            : undefined;

        void generateReport({
            fileMeta,
            fileObj,
            headBytes: evidence.head,
            analysis: safeResult,
            standard: standardForDownstream,
            detectionTelemetry: telemetry,
            signal: ac.signal,
            onHashProgress: (done, total) => setHashProgress({ done, total }),
        }).finally(() => {
            if (reportAbortRef.current === ac) reportAbortRef.current = null;
            setHashProgress(null);
        });
    }, [fileMeta, fileObj, evidence, result, standardForDownstream, detection]);

    const primary = detection?.primary;
    const typeBadge = primary
        ? `${primary.name}  ${(primary.confidence * 100).toFixed(0)}%`
        : (detection && detection.hypotheses.length > 0)
            ? `WEAK (${detection.hypotheses[0].name} ${(detection.hypotheses[0].confidence * 100).toFixed(0)}%)`
            : 'RAW BINARY';

    return (
        <div
            className={`app-container ${isDragging ? 'drop-active' : ''}`}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            style={{ height: '100vh', display: 'flex', flexDirection: 'column', background: 'var(--bg-deep)' }}
        >
            {/* TOOLBAR */}
            <div className="toolbar" style={{ height: '40px', borderBottom: '1px solid #333', display: 'flex', alignItems: 'center', padding: '0 20px', flexShrink: 0, justifyContent: 'space-between', background: '#0a0a0a' }}>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                    <span className="logo" style={{ color: 'var(--accent-cyan)', fontWeight: 'bold', letterSpacing: '1px' }}>CIFAD</span>
                    <span style={{ margin: '0 10px', color: '#333' }}>|</span>
                    <input type="file" onChange={handleFileChange} style={{ fontSize: '12px', color: '#888' }} />
                </div>

                <div style={{ display: 'flex', gap: '15px', alignItems: 'center' }}>
                    <div className={!fileData ? 'disabled-toolbar' : ''} style={{ display: 'flex', gap: '2px', background: '#111', padding: '2px', borderRadius: '4px', border: '1px solid #333' }}>
                        <ToggleButton label="RADAR" active={showHilbert} onClick={() => setShowHilbert(!showHilbert)} />
                        <ToggleButton label="HEATMAP" active={showHeatmap} onClick={() => setShowHeatmap(!showHeatmap)} />
                        <span style={{ width: '1px', background: '#333', margin: '0 4px' }} />
                        <ToggleButton label="DETAILS" active={showInspector} onClick={() => setShowInspector(!showInspector)} />
                        <ToggleButton label="PIPELINE" active={showPipeline} onClick={() => setShowPipeline(!showPipeline)} />
                    </div>

                    <button
                        onClick={handleReport}
                        disabled={!result || !evidence}
                        style={{
                            background: result ? 'rgba(0, 240, 255, 0.1)' : '#222',
                            color: result ? 'var(--accent-cyan)' : '#555',
                            border: result ? '1px solid var(--accent-cyan)' : '1px solid #333',
                            padding: '4px 12px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold', cursor: result ? 'pointer' : 'not-allowed',
                            display: 'flex', alignItems: 'center', gap: '6px'
                        }}
                    >
                        <Download size={14} /> GEN INTEL REPORT
                    </button>
                </div>
            </div>

            <div style={{ flex: 1, minHeight: 0, position: 'relative' }}>
                {showCrunchingOverlay && (
                    <div className="crunching-matrix-overlay" aria-live="polite" aria-busy="true">
                        <div className="crunching-matrix-backdrop" />
                        <div className="crunching-matrix-card">
                            <div className="crunching-matrix-spinner" aria-hidden="true" />
                            <div className="crunching-matrix-title">Crunching Matrix…</div>
                            <div className="crunching-matrix-sub">Worker thread — UI stays responsive</div>
                        </div>
                    </div>
                )}
                {analysisError && (
                    <div style={{ position: 'absolute', top: 8, right: 8, background: 'rgba(255,51,85,0.12)', border: '1px solid #ff3355', color: '#ff8899', padding: '6px 10px', fontSize: 11, borderRadius: 4, zIndex: 5 }}>
                        {analysisError}
                    </div>
                )}
                {!fileObj ? (
                    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: '#444' }}>
                        <div style={{ width: '100px', height: '100px', border: '2px dashed #333', borderRadius: '20px', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '20px', animation: 'pulse-border 2s infinite' }}>
                            <Download size={40} color="#666" />
                        </div>
                        <h2 style={{ color: '#eee', marginBottom: '8px', letterSpacing: '1px' }}>DROP FILE TO BEGIN</h2>
                    </div>
                ) : (
                    <PanelGroup direction="horizontal">
                        <Panel defaultSize={20} minSize={10} className="bg-panel cyber-border-right">
                            <FileTree
                                file={fileMeta}
                                fileSize={fileMeta?.size}
                                structures={result?.parsed_structures}
                                standard={standardForDownstream}
                                trailingArtifacts={result?.trailing_artifacts}
                                selectionOffset={selectionRange?.start ?? null}
                                inspectorContext={inspectorContext}
                                onSelectRange={(s, e) => handleJumpTo(s, e - s)}
                                onHoverRange={setHoverRange}
                                onNodeSelect={(node) => { setSelectedNode(node); setInspectorContext('node'); }}
                                onSelectFileRoot={() => { setSelectedNode(null); setInspectorContext('file'); }}
                                onSelectTrailingArtifacts={() => { setSelectedNode(null); setInspectorContext('trailing'); }}
                            />
                        </Panel>
                        <PanelResizeHandle className="resize-handle" />

                        <Panel minSize={30}>
                            <PanelGroup direction="vertical">
                                {showHilbert && (
                                    <>
                                        <Panel defaultSize={40} minSize={22}>
                                            <div style={{ height: '100%', minHeight: 0, display: 'flex', flexDirection: 'column' }}>
                                                {isReady && result && fileMeta ? (
                                                    <div style={{ flex: 1, minHeight: 0, display: 'flex', justifyContent: 'center', background: '#0a0a0a', overflow: 'hidden' }}>
                                                        <div style={{ width: 'min(512px, 100%)', height: 'min(400px, 100%)', maxHeight: '400px' }}>
                                                            <Radar
                                                                matrix={result.hilbert_matrix}
                                                                entropyMap={result.entropy_map}
                                                                highlightOffset={hoveredOffset}
                                                                selectionRange={selectionRange}
                                                                hilbert={hilbert}
                                                                fileSize={fileMeta.size}
                                                                cryptoMode={result.crypto_mode ?? null}
                                                                highEntropyRadarIndices={result.high_entropy_radar_indices ?? []}
                                                                onJumpToOffset={(off) => handleJumpTo(off)}
                                                            />
                                                        </div>
                                                    </div>
                                                ) : (
                                                    <div style={{ flex: 1, minHeight: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#555' }}>
                                                        AWAITING ANALYSIS…
                                                    </div>
                                                )}
                                            </div>
                                        </Panel>
                                        <PanelResizeHandle className="resize-handle-horizontal" />
                                    </>
                                )}

                                <Panel defaultSize={15} minSize={10} collapsible={true}>
                                    <AutocorrelationGraph
                                        fileData={fileData}
                                        fileSize={fileMeta?.size ?? 0}
                                        autocorrelationGraph={autocorrSeries}
                                        onJumpToOffset={(off) => handleJumpTo(off)}
                                    />
                                </Panel>
                                <PanelResizeHandle className="resize-handle-horizontal" />

                                <Panel minSize={20}>
                                    <div style={{ display: 'flex', height: '100%' }}>
                                        <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                                            <div className="panel-header">RAW MATRIX</div>
                                            <div style={{ flex: 1 }}>
                                                {fileObj && fileMeta && (
                                                    <HexView
                                                        ref={hexViewRef}
                                                        file={fileObj}
                                                        fileSize={fileMeta.size}
                                                        stride={hexStride}
                                                        selectionRange={selectionRange}
                                                        hoverRange={hoverRange}
                                                        onSelect={(s, e) => { setSelectionRange({ start: s, end: e }); }}
                                                        onScroll={handleScrollUpdate}
                                                    />
                                                )}
                                            </div>
                                        </div>
                                        {showHeatmap && (
                                            <div style={{ width: '24px', height: '100%', alignSelf: 'stretch', display: 'flex' }}>
                                                {result ? (
                                                    <SemanticScrollbar
                                                        entropyMap={result.entropy_map}
                                                        currentPercent={currentViewPercent}
                                                        onScroll={(p) => fileMeta && handleJumpTo(Math.floor(fileMeta.size * p))}
                                                    />
                                                ) : (
                                                    <div style={{ width: '100%', height: '100%', background: '#050505', borderLeft: '1px solid #333' }} title="Heatmap pending analysis" />
                                                )}
                                            </div>
                                        )}
                                    </div>
                                </Panel>
                            </PanelGroup>
                        </Panel>

                        {(showInspector || showPipeline) && (
                            <>
                                <PanelResizeHandle className="resize-handle" />
                                <Panel defaultSize={28} minSize={18} className="bg-panel cyber-border-left">
                                    <div className="panel-header">DECODE &amp; DETAILS</div>
                                    <div style={{ padding: '15px', display: 'flex', flexDirection: 'column', height: 'calc(100% - 30px)', gap: '15px', overflowY: 'auto', minHeight: 0 }}>

                                        {showStructureInspector && (
                                            <div style={{ flexShrink: 0 }}>
                                                <StructureInspector
                                                    node={selectedNode}
                                                    fileData={fileData}
                                                    fileMeta={fileMeta}
                                                    inspectorContext={inspectorContext}
                                                    trailingArtifacts={result?.trailing_artifacts}
                                                    cryptoMode={result?.crypto_mode ?? null}
                                                    protocolGuess={result?.protocol_guess ?? null}
                                                    standard={standardForDownstream}
                                                    onFocus={(s, e) => handleJumpTo(s, e - s + 1)}
                                                />
                                            </div>
                                        )}

                                        {/* DETECTION HYPOTHESES — explainable surface */}
                                        {detection && detection.hypotheses.length > 0 && (
                                            <div style={{ flexShrink: 0, border: '1px solid #222', borderRadius: 4, padding: 10, background: '#070707' }}>
                                                <div style={{ fontSize: 10, color: '#666', letterSpacing: 1, marginBottom: 8 }}>DETECTION HYPOTHESES</div>
                                                {detection.hypotheses.slice(0, 4).map((h, idx) => (
                                                    <div key={h.id} style={{ marginBottom: 6, opacity: idx === 0 ? 1 : 0.7 }}>
                                                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                                                            <span style={{ color: h.color, fontWeight: 600 }}>{h.name}</span>
                                                            <span style={{ color: '#888' }}>{(h.confidence * 100).toFixed(0)}% · {h.source}</span>
                                                        </div>
                                                        <div style={{ fontSize: 10, color: '#666', marginTop: 2 }}>
                                                            {h.evidence[0]}
                                                        </div>
                                                    </div>
                                                ))}
                                                {detection.anomalies.length > 0 && (
                                                    <div style={{ borderTop: '1px solid #222', marginTop: 8, paddingTop: 8 }}>
                                                        <div style={{ fontSize: 10, color: '#888', letterSpacing: 1, marginBottom: 4 }}>ANOMALIES</div>
                                                        {detection.anomalies.slice(0, 4).map((a, i) => (
                                                            <div key={i} style={{
                                                                fontSize: 10,
                                                                color: a.severity === 'critical' ? '#ff7788' : a.severity === 'warn' ? '#ffcc66' : '#88ddff',
                                                                marginBottom: 3,
                                                            }}>
                                                                · {a.message}
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}
                                            </div>
                                        )}

                                        {showPipeline && (
                                            <div style={{ flex: 1, borderTop: showInspector ? '1px solid #333' : 'none', paddingTop: showInspector ? '15px' : '0' }}>
                                                <div style={{ fontSize: '10px', color: '#666', marginBottom: '10px' }}>
                                                    TRANSFORMATION PIPELINE
                                                    {selectionTruncated && (
                                                        <span style={{ color: '#ffaa00', marginLeft: 8 }}>
                                                            ⚠ selection truncated to {Math.floor(SELECTION_HARD_CAP_BYTES / 1024)} KiB
                                                        </span>
                                                    )}
                                                </div>
                                                <TransformationPipeline selectedBytes={selectedBytes} />
                                            </div>
                                        )}
                                    </div>
                                </Panel>
                            </>
                        )}
                    </PanelGroup>
                )}
            </div>

            {/* STATUS BAR — confidence-weighted, anomaly-aware */}
            <div style={{
                height: '28px', background: '#0a0a0a', borderTop: '1px solid #333',
                display: 'flex', alignItems: 'center', padding: '0 15px',
                fontSize: '11px', color: '#888', gap: '20px', fontFamily: 'monospace'
            }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <HardDrive size={12} color="var(--accent-blue)" />
                    <span>SIZE: {fileMeta ? (fileMeta.size / 1024).toFixed(2) + ' KB' : 'N/A'}</span>
                </div>
                <div style={{ width: '1px', height: '12px', background: '#333' }} />

                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <MousePointer2 size={12} color={selectionRange ? 'var(--accent-cyan)' : '#555'} />
                    <span>
                        SEL: {selectionRange
                            ? `0x${selectionRange.start.toString(16).toUpperCase()} (+${selectionRange.end - selectionRange.start + 1})`
                            : 'NONE'}
                    </span>
                </div>
                <div style={{ width: '1px', height: '12px', background: '#333' }} />

                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <FileType size={12} color={primary ? primary.color : '#555'} />
                    <span style={{ color: primary ? primary.color : 'inherit' }} title={primary?.evidence.join(' · ')}>
                        TYPE: {typeBadge}
                    </span>
                </div>
                <div style={{ width: '1px', height: '12px', background: '#333' }} />

                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }} title={anomalies.map(a => `[${a.severity}] ${a.message}`).join('\n') || 'No anomalies detected'}>
                    {maxSeverity ? <AlertTriangle size={12} color={anomalyColor} /> : <ShieldCheck size={12} color="#00ff9d" />}
                    <span style={{ color: maxSeverity ? anomalyColor : '#00ff9d' }}>
                        {anomalies.length > 0 ? `ANOMALIES: ${anomalies.length}` : 'CLEAN'}
                    </span>
                </div>

                {hashProgress && (
                    <>
                        <div style={{ width: '1px', height: '12px', background: '#333' }} />
                        <div
                            style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}
                            title="Click to cancel whole-file hash"
                            onClick={() => reportAbortRef.current?.abort()}
                        >
                            <Download size={12} color="#00f0ff" />
                            <span>
                                HASH: {((hashProgress.done / Math.max(1, hashProgress.total)) * 100).toFixed(0)}%
                                <span style={{ color: '#555', marginLeft: 6 }}>(click to cancel)</span>
                            </span>
                        </div>
                    </>
                )}

                <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Activity size={12} color={
                        hardTimeoutHit ? '#ff3355'
                        : softTimeoutHit ? '#ffaa00'
                        : showCrunchingOverlay ? '#ffff00' : '#00ff9d'
                    } />
                    <span>
                        {hardTimeoutHit ? 'WORKER KILLED (HARD)'
                         : softTimeoutHit ? 'WORKER CANCEL ISSUED'
                         : showCrunchingOverlay ? 'CRUNCHING MATRIX…' : 'READY'}
                    </span>
                </div>
            </div>
        </div>
    );
}

const ToggleButton = ({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) => (
    <button
        onClick={onClick}
        style={{
            background: active ? 'var(--accent-cyan)' : 'transparent',
            color: active ? '#000' : '#666',
            border: 'none', borderRadius: '2px', padding: '4px 8px', fontSize: '10px', fontWeight: 'bold', cursor: 'pointer',
            transition: 'all 0.2s'
        }}
    >
        {label}
    </button>
);

export default App;
