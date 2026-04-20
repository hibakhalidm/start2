import React, { useMemo, useState } from 'react';
import { Terminal, Copy, Check } from 'lucide-react';
import { TlvNode, CryptoMode } from '../types/analysis';
import { getTagInfo } from '../utils/tag_dictionary';
import { FileMetadata } from '../utils/export';

interface Props {
    node: TlvNode | null;
    fileData: Uint8Array | null;
    fileMeta?: FileMetadata | null;
    inspectorContext?: 'file' | 'node' | 'trailing';
    trailingArtifacts?: string[];
    cryptoMode?: CryptoMode | null;
    protocolGuess?: string | null;
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

const StructureInspector: React.FC<Props> = ({
    node,
    fileData,
    fileMeta,
    inspectorContext = 'node',
    trailingArtifacts,
    cryptoMode = null,
    protocolGuess = null,
    onFocus,
}) => {
    const [copied, setCopied] = useState<string | null>(null);

    const showTrailingAlerts = useMemo(() => {
        const has = !!(trailingArtifacts && trailingArtifacts.length > 0);
        if (!has) return false;
        return inspectorContext === 'file' || inspectorContext === 'trailing';
    }, [inspectorContext, trailingArtifacts]);

    if (!node || !fileData) {
        return (
            <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {cryptoMode && <CryptoOverviewBadge mode={cryptoMode} />}
                {showTrailingAlerts && (
                    <div style={{ border: '1px solid rgba(255, 42, 42, 0.35)', background: 'rgba(255, 42, 42, 0.08)', padding: '12px', borderRadius: '6px' }}>
                        <div style={{ fontSize: '0.65rem', color: '#ff2a2a', letterSpacing: '1px', marginBottom: '8px' }}>SECURITY ALERT</div>
                        <div style={{ fontSize: '0.75rem', color: '#eee', marginBottom: '10px' }}>
                            Trailing artifacts detected on <span style={{ color: '#fff' }}>{fileMeta?.name ?? 'evidence'}</span>
                        </div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                            {trailingArtifacts!.map((a) => (
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

                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', opacity: 0.2 }}>
                    <Terminal size={32} strokeWidth={1} />
                    <div style={{ marginTop: 10, fontSize: '0.7rem', letterSpacing: '1px' }}>AWAITING SELECTION</div>
                </div>
            </div>
        );
    }

    const info = getTagInfo(node.tag);
    const valueStart = node.value_offset;
    const valueEnd = node.value_offset + node.value_len;
    const valueBytes = fileData.slice(valueStart, valueEnd);

    const rawHex = Array.from(valueBytes.slice(0, 64)).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');

    let decodedValue = "BINARY PAYLOAD";
    let isText = false;

    if (node.tag === 0x02 && valueBytes.length <= 8) {
        decodedValue = parseInt(Array.from(valueBytes).map(b => b.toString(16).padStart(2, '0')).join(''), 16).toLocaleString();
    } else if ([0x04, 0x13, 0x0C, 0x17].includes(node.tag)) {
        const text = new TextDecoder().decode(valueBytes);
        if (/^[\x20-\x7E]*$/.test(text)) { decodedValue = text; isText = true; }
    } else if (node.is_container) {
        decodedValue = `[CONTAINER] ${node.children.length} SUB-ITEMS`;
    }

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
            {protocolGuess && <ProtocolGuessBadge label={protocolGuess} />}
            {cryptoMode && <CryptoOverviewBadge mode={cryptoMode} />}
            {showTrailingAlerts && (
                <div style={{ border: '1px solid rgba(255, 42, 42, 0.35)', background: 'rgba(255, 42, 42, 0.08)', padding: '12px', borderRadius: '6px' }}>
                    <div style={{ fontSize: '0.65rem', color: '#ff2a2a', letterSpacing: '1px', marginBottom: '8px' }}>SECURITY ALERT</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                        {trailingArtifacts!.map((a) => (
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
                    <div style={{ fontSize: '1.1rem', color: '#fff', letterSpacing: '-0.5px' }}>{info.name}</div>
                    <div style={{ display: 'flex', gap: '10px', marginTop: '6px', fontSize: '0.7rem', color: '#666' }}>
                        <span>TAG: <span style={{ color: 'var(--accent-cyan)' }}>0x{node.tag.toString(16).toUpperCase()}</span></span>
                        <span>OFFSET: <span style={{ color: '#aaa' }}>0x{node.offset.toString(16).toUpperCase()}</span></span>
                        <span>LEN: <span style={{ color: '#aaa' }}>{node.value_len}B</span></span>
                    </div>
                </div>
                {onFocus && (
                    <button onClick={() => onFocus(node.offset, node.offset + node.total_len)} style={{ background: 'transparent', border: '1px solid #333', color: '#888', padding: '4px 8px', fontSize: '0.65rem', cursor: 'pointer' }}>
                        LOCATE
                    </button>
                )}
            </div>

            {/* DESCRIPTION (No borders, just muted text) */}
            <div style={{ fontSize: '0.8rem', color: '#888', lineHeight: '1.4' }}>{info.description}</div>

            {/* UNIFIED TERMINAL READOUT */}
            <div style={{ flex: 1, background: '#080808', border: '1px solid #1a1a1a', display: 'flex', flexDirection: 'column' }}>
                <div style={{ padding: '8px 12px', background: '#111', borderBottom: '1px solid #1a1a1a', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.65rem', color: '#555', letterSpacing: '1px' }}>DECODED OUTPUT</span>
                    <button onClick={handleCopy} style={{ background: 'none', border: 'none', cursor: 'pointer', color: copied ? '#00ff9d' : '#555' }}>
                        {copied ? <Check size={12} /> : <Copy size={12} />}
                    </button>
                </div>

                <div style={{ padding: '15px', fontSize: '0.85rem', color: isText ? '#ddd' : 'var(--accent-cyan)', whiteSpace: 'pre-wrap', flex: 1 }}>
                    {decodedValue}
                </div>

                <div style={{ padding: '10px 15px', borderTop: '1px dotted #222', fontSize: '0.7rem', color: '#444', wordSpacing: '2px' }}>
                    {rawHex} {valueBytes.length > 64 && '...'}
                </div>
            </div>
        </div>
    );
};
export default StructureInspector;
