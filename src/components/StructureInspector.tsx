import React, { useMemo, useState } from 'react';
import { Terminal, Copy, Check } from 'lucide-react';
import { TlvNode, CryptoMode } from '../types/analysis';
import { getTagInfo } from '../utils/tag_dictionary';
import { FileMetadata } from '../utils/export';
import type { DetectedStandard } from '../utils/standards';
import { decodeTlvValue, describeTag, splitTlvHeader, TlvDecodedKind } from '../utils/tlvDecode';

// TLV segment palette — chosen to be mutually distinguishable in the dark
// theme and to align with the rest of the inspector's color language:
//   • TAG    → cyan  (matches the existing "TAG: 0x…" accent)
//   • LEN    → amber (warning-ish but not error; signals "metadata header")
//   • VALUE  → tinted per-kind via KIND_COLORS (see below)
const SEGMENT_COLORS = {
    tag:    { fg: '#00f0ff', label: '#00f0ff', bg: 'rgba(0,240,255,0.10)',  border: 'rgba(0,240,255,0.45)'  },
    length: { fg: '#ffd966', label: '#ffd966', bg: 'rgba(255,217,102,0.10)', border: 'rgba(255,217,102,0.45)' },
} as const;

interface Props {
    node: TlvNode | null;
    fileData: Uint8Array | null;
    fileMeta?: FileMetadata | null;
    inspectorContext?: 'file' | 'node' | 'trailing';
    trailingArtifacts?: string[];
    cryptoMode?: CryptoMode | null;
    protocolGuess?: string | null;
    standard?: DetectedStandard | null;
    onFocus?: (start: number, end: number) => void;
}

const ProtocolGuessBadge = ({ label }: { label: string }) => (
    <div
        style={{
            border: '2px solid rgba(0, 240, 255, 0.65)',
            borderRadius: '8px',
            padding: '10px 14px',
            marginBottom: '4px',
            background: 'linear-gradient(135deg, rgba(0, 40, 50, 0.6), rgba(0, 15, 25, 0.85))',
            boxShadow: '0 0 14px rgba(0, 240, 255, 0.2)',
        }}
    >
        <div style={{ fontSize: '0.62rem', color: 'var(--accent-cyan, #00f0ff)', letterSpacing: '0.18em', fontWeight: 700 }}>
            WEB PROTOCOL (HEURISTIC)
        </div>
        <div style={{ fontSize: '0.95rem', fontWeight: 800, color: '#fff', marginTop: '6px', letterSpacing: '0.03em' }}>{label}</div>
    </div>
);

const ProtocolGuessFallbackBadge = () => (
    <div
        style={{
            border: '1px solid rgba(0, 240, 255, 0.25)',
            borderRadius: '8px',
            padding: '10px 14px',
            marginBottom: '4px',
            background: 'rgba(0, 15, 25, 0.55)',
        }}
    >
        <div style={{ fontSize: '0.62rem', color: '#555', letterSpacing: '0.18em', fontWeight: 700 }}>
            WEB PROTOCOL (HEURISTIC)
        </div>
        <div style={{ fontSize: '0.9rem', fontWeight: 800, color: '#888', marginTop: '6px', letterSpacing: '0.03em' }}>
            UNKNOWN
        </div>
    </div>
);

function cryptoBadgeHeadline(mode: CryptoMode): string {
    if (mode === 'AES-128/256') return 'AES (16-byte Block Cipher Detected)';
    return 'DES/3DES (64-bit Block Cipher Suspected)';
}

const CryptoOverviewBadge = ({ mode }: { mode: CryptoMode }) => (
    <div
        style={{
            border: '2px solid #ff2a2a',
            borderRadius: '8px',
            padding: '12px 14px',
            marginBottom: '4px',
            background: 'linear-gradient(135deg, rgba(80, 0, 0, 0.55), rgba(20, 0, 0, 0.75))',
            boxShadow: '0 0 20px rgba(255, 42, 42, 0.25)',
        }}
    >
        <div style={{ fontSize: '0.62rem', color: '#ff2a2a', letterSpacing: '0.2em', fontWeight: 700 }}>CRYPTOGRAPHIC MODE</div>
        <div style={{ fontSize: '1.05rem', fontWeight: 800, color: '#fff', marginTop: '8px', letterSpacing: '0.03em', lineHeight: 1.25 }}>
            {cryptoBadgeHeadline(mode)}
        </div>
        <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#ffb4b4', marginTop: '6px' }}>{mode}</div>
        <div style={{ fontSize: '0.72rem', color: '#999', marginTop: '8px', lineHeight: 1.4 }}>
            Lag-profile heuristic (e.g. spike at lag 16 for AES). Use Autocorrelation + Hex jump to correlate.
        </div>
    </div>
);

const StandardGuessBadge = ({ standard }: { standard: DetectedStandard }) => (
    <div
        style={{
            border: `2px solid ${standard.color ?? 'rgba(0, 255, 157, 0.65)'}`,
            borderRadius: '8px',
            padding: '10px 14px',
            marginBottom: '4px',
            background: 'linear-gradient(135deg, rgba(0, 30, 22, 0.55), rgba(0, 10, 8, 0.85))',
            boxShadow: '0 0 14px rgba(0, 255, 157, 0.12)',
        }}
    >
        <div style={{ fontSize: '0.62rem', color: '#00ff9d', letterSpacing: '0.18em', fontWeight: 700 }}>
            LIKELY FORMAT / VENDOR
        </div>
        <div style={{ fontSize: '0.95rem', fontWeight: 800, color: '#fff', marginTop: '6px', letterSpacing: '0.03em' }}>
            {standard.name}
        </div>
        <div style={{ fontSize: '0.72rem', color: '#777', marginTop: '6px', lineHeight: 1.35 }}>
            {standard.category} · {standard.confidence}
        </div>
    </div>
);

const StandardGuessFallbackBadge = () => (
    <div
        style={{
            border: '1px solid rgba(0, 255, 157, 0.25)',
            borderRadius: '8px',
            padding: '10px 14px',
            marginBottom: '4px',
            background: 'rgba(0, 10, 8, 0.55)',
        }}
    >
        <div style={{ fontSize: '0.62rem', color: '#555', letterSpacing: '0.18em', fontWeight: 700 }}>
            LIKELY FORMAT / VENDOR
        </div>
        <div style={{ fontSize: '0.9rem', fontWeight: 800, color: '#888', marginTop: '6px', letterSpacing: '0.03em' }}>
            RAW / UNKNOWN
        </div>
    </div>
);

const StructureInspector: React.FC<Props> = ({
    node,
    fileData,
    fileMeta,
    inspectorContext = 'node',
    trailingArtifacts,
    cryptoMode = null,
    protocolGuess = null,
    standard = null,
    onFocus,
}) => {
    const [copied, setCopied] = useState<string | null>(null);

    const resyncEvents = useMemo(() => {
        if (!trailingArtifacts || trailingArtifacts.length === 0) return [];
        return trailingArtifacts.filter((a) => typeof a === 'string' && a.includes('Resync Event'));
    }, [trailingArtifacts]);

    const nonResyncArtifacts = useMemo(() => {
        if (!trailingArtifacts || trailingArtifacts.length === 0) return [];
        return trailingArtifacts.filter((a) => typeof a === 'string' && !a.includes('Resync Event'));
    }, [trailingArtifacts]);

    const showTrailingAlerts = useMemo(() => {
        const has = !!(trailingArtifacts && trailingArtifacts.length > 0);
        if (!has) return false;
        return inspectorContext === 'file' || inspectorContext === 'trailing';
    }, [inspectorContext, trailingArtifacts]);

    if (!node || !fileData) {
        return (
            <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {standard ? <StandardGuessBadge standard={standard} /> : <StandardGuessFallbackBadge />}
                {protocolGuess ? <ProtocolGuessBadge label={protocolGuess} /> : <ProtocolGuessFallbackBadge />}
                {cryptoMode && <CryptoOverviewBadge mode={cryptoMode} />}
                {showTrailingAlerts && (
                    <div style={{ border: '1px solid rgba(255, 42, 42, 0.35)', background: 'rgba(255, 42, 42, 0.08)', padding: '12px', borderRadius: '6px' }}>
                        <div style={{ fontSize: '0.65rem', color: '#ff2a2a', letterSpacing: '1px', marginBottom: '8px' }}>SECURITY ALERT</div>
                        <div style={{ fontSize: '0.75rem', color: '#eee', marginBottom: '10px' }}>
                            Trailing artifacts detected on <span style={{ color: '#fff' }}>{fileMeta?.name ?? 'evidence'}</span>
                        </div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                            {nonResyncArtifacts.map((a) => (
                                <span key={a} style={{
                                    fontSize: '0.65rem',
                                    padding: '4px 8px',
                                    borderRadius: '999px',
                                    border: '1px solid rgba(255, 42, 42, 0.55)',
                                    color: '#ffb4b4',
                                    background: 'rgba(0,0,0,0.35)'
                                }}>
                                    {a}
                                </span>
                            ))}
                        </div>
                    </div>
                )}

                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '12px', textAlign: 'center' }}>
                    <Terminal size={32} strokeWidth={1} style={{ opacity: 0.35 }} />
                    <div style={{ marginTop: 12, fontSize: '0.72rem', letterSpacing: '0.08em', color: '#888', fontWeight: 600 }}>TLV DECODE</div>
                    <div style={{ marginTop: 8, fontSize: '0.7rem', color: '#555', maxWidth: '220px', lineHeight: 1.45 }}>
                        Choose a structure in the left file tree to view decoded fields and copy-safe export.
                    </div>
                </div>

                {resyncEvents.length > 0 && (
                    <details
                        style={{
                            marginTop: '6px',
                            border: '1px solid #222',
                            background: '#0a0a0a',
                            borderRadius: '8px',
                            padding: '10px 12px',
                            color: '#bbb',
                        }}
                    >
                        <summary style={{ cursor: 'pointer', listStyle: 'none', color: '#ffb4b4', fontSize: '0.75rem', fontWeight: 700 }}>
                            ⚠️ Parser Recovery Logs ({resyncEvents.length} events)
                        </summary>
                        <div style={{ marginTop: '10px', fontSize: '0.7rem', color: '#777', lineHeight: 1.45, maxHeight: '180px', overflow: 'auto', paddingRight: '6px' }}>
                            {resyncEvents.slice(0, 200).map((e, i) => (
                                <div key={`${i}-${e}`} style={{ padding: '3px 0', borderBottom: '1px dotted #1f1f1f' }}>
                                    {e}
                                </div>
                            ))}
                            {resyncEvents.length > 200 && (
                                <div style={{ paddingTop: '8px', color: '#555' }}>
                                    … truncated (showing first 200)
                                </div>
                            )}
                        </div>
                    </details>
                )}
            </div>
        );
    }

    const info = getTagInfo(node.tag);

    // Split the node's raw bytes into Tag · Length · Value sub-segments so we
    // can color-code them. We trust the WASM parser for the authoritative
    // header/value lengths; splitTlvHeader only locates the boundary between
    // the tag and length sub-segments inside the header.
    const headerLen = Math.max(0, node.value_offset - node.offset);
    const segments = splitTlvHeader(fileData, node.offset, headerLen, node.value_len);
    const tagBytes = segments.tagBytes;
    const lengthBytes = segments.lengthBytes;
    const valueBytes = segments.valueBytes;

    // Treat the inspector context as an HI2 envelope when the detected standard
    // is ETSI / 3GPP LI — this enables IRI-Begin/End/Continue/Report naming on
    // context-specific tags below the root.
    const hi2Envelope =
        !!standard && /ETSI|HI2|33\.108/.test(`${standard.name} ${standard.category} ${standard.description}`);

    const decoded = decodeTlvValue(node.tag, node.is_container, valueBytes, {
        hi2Envelope,
        depth: 1, // we don't know the true depth here, but >0 is the relevant signal
        childCount: node.children.length,
    });
    const decodedValue = decoded.primary;
    const isText = decoded.isText;

    const handleCopy = async () => {
        const ok = window.confirm(
            [
                'OPSEC WARNING: Clipboard Copy',
                '',
                'You are about to copy decoded evidence bytes to the system clipboard.',
                'Clipboard data can be read by other applications, browser extensions, and remote-desktop tooling.',
                '',
                'Proceed ONLY if you accept the risk of sensitive data exfiltration.',
            ].join('\n')
        );
        if (!ok) return;

        try {
            await navigator.clipboard.writeText(decodedValue);
            setCopied('dec');
            setTimeout(() => setCopied(null), 2000);
        } catch {
            window.alert('Clipboard write failed. Your browser may have blocked clipboard access.');
        }
    };

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', height: '100%' }}>
            {standard ? <StandardGuessBadge standard={standard} /> : <StandardGuessFallbackBadge />}
            {protocolGuess ? <ProtocolGuessBadge label={protocolGuess} /> : <ProtocolGuessFallbackBadge />}
            {cryptoMode && <CryptoOverviewBadge mode={cryptoMode} />}
            {showTrailingAlerts && (
                <div style={{ border: '1px solid rgba(255, 42, 42, 0.35)', background: 'rgba(255, 42, 42, 0.08)', padding: '12px', borderRadius: '6px' }}>
                    <div style={{ fontSize: '0.65rem', color: '#ff2a2a', letterSpacing: '1px', marginBottom: '8px' }}>SECURITY ALERT</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                        {nonResyncArtifacts.map((a) => (
                            <span key={a} style={{
                                fontSize: '0.65rem',
                                padding: '4px 8px',
                                borderRadius: '999px',
                                border: '1px solid rgba(255, 42, 42, 0.55)',
                                color: '#ffb4b4',
                                background: 'rgba(0,0,0,0.35)'
                            }}>
                                {a}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* MINIMAL HEADER */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
                        <div style={{ fontSize: '1.1rem', color: '#fff', letterSpacing: '-0.5px' }}>
                            {describeTag(node.tag, { hi2Envelope, depth: 1 })}
                        </div>
                        <KindBadge kind={decoded.kind} />
                    </div>
                    <div style={{ display: 'flex', gap: '10px', marginTop: '6px', fontSize: '0.7rem', color: '#666', flexWrap: 'wrap' }}>
                        <span>TAG: <span style={{ color: SEGMENT_COLORS.tag.fg }}>0x{node.tag.toString(16).toUpperCase()}</span></span>
                        <span>OFFSET: <span style={{ color: '#aaa' }}>0x{node.offset.toString(16).toUpperCase()}</span></span>
                        <span>
                            LEN: <span style={{ color: SEGMENT_COLORS.length.fg }}>{node.value_len}B</span>
                            <span style={{ color: '#555', marginLeft: 4 }}>
                                ({segments.lengthEncoding}{segments.lengthByteCount > 0 ? `, ${segments.lengthByteCount}B enc` : ''})
                            </span>
                        </span>
                        <span>CLASS: <span style={{ color: '#aaa' }}>{info.category}</span></span>
                    </div>
                </div>
                {onFocus && (
                    <button onClick={() => onFocus(node.offset, Math.max(node.offset, node.offset + node.total_len - 1))} style={{ background: 'transparent', border: '1px solid #333', color: '#888', padding: '4px 8px', fontSize: '0.65rem', cursor: 'pointer' }}>
                        LOCATE
                    </button>
                )}
            </div>

            {/* DESCRIPTION (No borders, just muted text) */}
            <div style={{ fontSize: '0.8rem', color: '#888', lineHeight: '1.4' }}>{info.description}</div>

            {/* UNIFIED TERMINAL READOUT */}
            <div style={{ flex: 1, background: '#080808', border: '1px solid #1a1a1a', display: 'flex', flexDirection: 'column' }}>
                <div style={{ padding: '8px 12px', background: '#111', borderBottom: '1px solid #1a1a1a', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.65rem', color: '#555', letterSpacing: '1px' }}>
                        DECODED VALUE
                        {!decoded.complete && (
                            <span style={{ color: '#ffaa00', marginLeft: 8, letterSpacing: 0 }}>
                                · malformed / truncated
                            </span>
                        )}
                    </span>
                    <button onClick={handleCopy} style={{ background: 'none', border: 'none', cursor: 'pointer', color: copied ? '#00ff9d' : '#555' }}>
                        {copied ? <Check size={12} /> : <Copy size={12} />}
                    </button>
                </div>

                <div style={{ padding: '15px', fontSize: '0.85rem', color: isText ? '#ddd' : 'var(--accent-cyan)', whiteSpace: 'pre-wrap', flex: 1, fontFamily: isText ? 'inherit' : 'monospace' }}>
                    {decodedValue}
                </div>

                {decoded.secondary && (
                    <div style={{ padding: '4px 15px 8px 15px', fontSize: '0.7rem', color: '#888', fontStyle: 'italic' }}>
                        {decoded.secondary}
                    </div>
                )}

                {decoded.notes && decoded.notes.length > 0 && (
                    <div style={{ padding: '4px 15px 8px 15px', fontSize: '0.65rem', color: '#ffaa00' }}>
                        {decoded.notes.map((n, i) => <div key={i}>⚠ {n}</div>)}
                    </div>
                )}

                <ColoredTlvBytes
                    tagBytes={tagBytes}
                    lengthBytes={lengthBytes}
                    valueBytes={valueBytes}
                    valueLen={node.value_len}
                    valueKind={decoded.kind}
                    incomplete={!segments.complete}
                    lengthEncoding={segments.lengthEncoding}
                />
                {!segments.complete && (
                    <div style={{ padding: '4px 15px 8px 15px', fontSize: '0.6rem', color: '#ffaa00', fontStyle: 'italic' }}>
                        Header re-parse disagreed with parser-reported lengths or value was truncated — segment boundaries are best-effort.
                    </div>
                )}
            </div>

            {resyncEvents.length > 0 && (
                <details
                    style={{
                        marginTop: '-6px',
                        border: '1px solid #222',
                        background: '#0a0a0a',
                        borderRadius: '8px',
                        padding: '10px 12px',
                        color: '#bbb',
                    }}
                >
                    <summary style={{ cursor: 'pointer', listStyle: 'none', color: '#ffb4b4', fontSize: '0.75rem', fontWeight: 700 }}>
                        ⚠️ Parser Recovery Logs ({resyncEvents.length} events)
                    </summary>
                    <div style={{ marginTop: '10px', fontSize: '0.7rem', color: '#777', lineHeight: 1.45, maxHeight: '180px', overflow: 'auto', paddingRight: '6px' }}>
                        {resyncEvents.slice(0, 200).map((e, i) => (
                            <div key={`${i}-${e}`} style={{ padding: '3px 0', borderBottom: '1px dotted #1f1f1f' }}>
                                {e}
                            </div>
                        ))}
                        {resyncEvents.length > 200 && (
                            <div style={{ paddingTop: '8px', color: '#555' }}>
                                … truncated (showing first 200)
                            </div>
                        )}
                    </div>
                </details>
            )}
        </div>
    );
};
// Color-coded badge that summarises the decoder's classification of a value.
// Stays inline beside the tag name so analysts see at a glance "this is an OID"
// versus "this is a date" versus "this is binary".
const KIND_COLORS: Record<TlvDecodedKind, { fg: string; bg: string }> = {
    boolean:     { fg: '#00ff9d', bg: 'rgba(0,255,157,0.10)' },
    integer:     { fg: '#00f0ff', bg: 'rgba(0,240,255,0.10)' },
    enumerated:  { fg: '#00f0ff', bg: 'rgba(0,240,255,0.10)' },
    bitstring:   { fg: '#aa66ff', bg: 'rgba(170,102,255,0.10)' },
    octetstring: { fg: '#aa66ff', bg: 'rgba(170,102,255,0.10)' },
    null:        { fg: '#888',    bg: 'rgba(255,255,255,0.05)' },
    oid:         { fg: '#ffaa00', bg: 'rgba(255,170,0,0.10)' },
    string:      { fg: '#ddd',    bg: 'rgba(255,255,255,0.06)' },
    datetime:    { fg: '#ffd966', bg: 'rgba(255,217,102,0.10)' },
    real:        { fg: '#00f0ff', bg: 'rgba(0,240,255,0.10)' },
    container:   { fg: '#00ff9d', bg: 'rgba(0,255,157,0.08)' },
    context:     { fg: '#ff7788', bg: 'rgba(255,119,136,0.10)' },
    binary:      { fg: '#666',    bg: 'rgba(255,255,255,0.04)' },
    unknown:     { fg: '#666',    bg: 'rgba(255,255,255,0.04)' },
};

const KindBadge: React.FC<{ kind: TlvDecodedKind }> = ({ kind }) => {
    const c = KIND_COLORS[kind] ?? KIND_COLORS.unknown;
    return (
        <span
            style={{
                fontSize: '0.6rem',
                fontWeight: 700,
                letterSpacing: '0.12em',
                padding: '2px 6px',
                borderRadius: '3px',
                color: c.fg,
                background: c.bg,
                border: `1px solid ${c.fg}33`,
                textTransform: 'uppercase',
            }}
            title={`Decoded value kind: ${kind}`}
        >
            {kind}
        </span>
    );
};

// ─────────────────────────────────────────────────────────────────────────────
// Color-coded raw bytes for a TLV node.
//
// Renders three labelled spans for Tag, Length, and Value, each in its own
// color so an analyst can immediately see WHICH bytes encode WHAT inside a
// node's header. Value bytes are tinted per decoded kind via KIND_COLORS.
//
// The value preview is capped to avoid blowing up the panel on huge values;
// the tag and length segments are always shown in full because they are tiny
// and structurally important.
// ─────────────────────────────────────────────────────────────────────────────
const VALUE_HEX_PREVIEW_BYTES = 64;

const renderHex = (bytes: Uint8Array): string =>
    Array.from(bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');

const SegmentChip: React.FC<{
    label: string;
    bytes: Uint8Array;
    fg: string;
    bg: string;
    border: string;
    extra?: string;
    truncated?: boolean;
}> = ({ label, bytes, fg, bg, border, extra, truncated }) => (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
            <span
                style={{
                    fontSize: '0.55rem',
                    fontWeight: 700,
                    letterSpacing: '0.18em',
                    color: fg,
                    textTransform: 'uppercase',
                }}
            >
                {label}
            </span>
            <span style={{ fontSize: '0.55rem', color: '#555' }}>
                {bytes.length}B{extra ? ` · ${extra}` : ''}
            </span>
        </div>
        <div
            style={{
                fontFamily: 'monospace',
                fontSize: '0.72rem',
                color: fg,
                background: bg,
                border: `1px solid ${border}`,
                borderRadius: '3px',
                padding: '5px 7px',
                wordBreak: 'break-all',
                lineHeight: 1.35,
                wordSpacing: '2px',
            }}
        >
            {bytes.length === 0 ? <span style={{ color: '#444' }}>—</span> : renderHex(bytes)}
            {truncated && <span style={{ color: '#666' }}> …</span>}
        </div>
    </div>
);

const ColoredTlvBytes: React.FC<{
    tagBytes: Uint8Array;
    lengthBytes: Uint8Array;
    valueBytes: Uint8Array;
    valueLen: number;
    valueKind: TlvDecodedKind;
    incomplete: boolean;
    lengthEncoding: string;
}> = ({ tagBytes, lengthBytes, valueBytes, valueLen, valueKind, lengthEncoding }) => {
    const valueColors = KIND_COLORS[valueKind] ?? KIND_COLORS.unknown;
    const previewBytes = valueBytes.slice(0, VALUE_HEX_PREVIEW_BYTES);
    const valueTruncated = valueBytes.length > VALUE_HEX_PREVIEW_BYTES;

    // Inline strip across the top: shows the three segments laid out in their
    // wire order ("read me left-to-right just like the raw file") so the
    // mental model maps 1:1 onto the hex view.
    const inlineStrip = (
        <div
            style={{
                display: 'flex',
                flexWrap: 'wrap',
                alignItems: 'center',
                gap: '4px',
                fontFamily: 'monospace',
                fontSize: '0.7rem',
                padding: '8px 15px 4px 15px',
                borderTop: '1px dotted #222',
                lineHeight: 1.6,
            }}
        >
            <span style={{ color: SEGMENT_COLORS.tag.fg, background: SEGMENT_COLORS.tag.bg, padding: '2px 5px', borderRadius: 2 }}>
                {tagBytes.length ? renderHex(tagBytes) : '—'}
            </span>
            <span style={{ color: SEGMENT_COLORS.length.fg, background: SEGMENT_COLORS.length.bg, padding: '2px 5px', borderRadius: 2 }}>
                {lengthBytes.length ? renderHex(lengthBytes) : '—'}
            </span>
            <span
                style={{
                    color: valueColors.fg,
                    background: valueColors.bg,
                    padding: '2px 5px',
                    borderRadius: 2,
                    maxWidth: '100%',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                }}
                title={valueTruncated ? `Showing first ${VALUE_HEX_PREVIEW_BYTES} of ${valueBytes.length} bytes` : undefined}
            >
                {previewBytes.length ? renderHex(previewBytes) : '—'}{valueTruncated ? ' …' : ''}
            </span>
        </div>
    );

    return (
        <div style={{ borderTop: '1px dotted #222' }}>
            {inlineStrip}
            <div
                style={{
                    display: 'grid',
                    gridTemplateColumns: 'auto auto 1fr',
                    gap: '10px',
                    padding: '6px 15px 12px 15px',
                    alignItems: 'start',
                }}
            >
                <SegmentChip
                    label="TAG"
                    bytes={tagBytes}
                    fg={SEGMENT_COLORS.tag.fg}
                    bg={SEGMENT_COLORS.tag.bg}
                    border={SEGMENT_COLORS.tag.border}
                />
                <SegmentChip
                    label="LENGTH"
                    bytes={lengthBytes}
                    fg={SEGMENT_COLORS.length.fg}
                    bg={SEGMENT_COLORS.length.bg}
                    border={SEGMENT_COLORS.length.border}
                    extra={`${lengthEncoding} → ${valueLen}B`}
                />
                <SegmentChip
                    label={`VALUE · ${valueKind}`}
                    bytes={previewBytes}
                    fg={valueColors.fg}
                    bg={valueColors.bg}
                    border={`${valueColors.fg}55`}
                    extra={valueTruncated ? `showing ${VALUE_HEX_PREVIEW_BYTES} / ${valueBytes.length}B` : undefined}
                    truncated={valueTruncated}
                />
            </div>
        </div>
    );
};

export default StructureInspector;
