import React, { useState, useEffect, useRef } from 'react';
import { Folder, ChevronDown, ChevronRight, Box, Shield, Minimize2, Maximize2 } from 'lucide-react';
import { TlvNode } from '../types/analysis';
import { DetectedStandard } from '../utils/standards';
import { FileMetadata } from '../utils/export';

interface Props {
    file: FileMetadata | null;
    fileSize?: number;
    structures?: TlvNode[];
    standard?: DetectedStandard | null;
    trailingArtifacts?: string[];
    selectionOffset?: number | null;
    inspectorContext?: 'file' | 'node' | 'trailing';
    onSelectRange: (start: number, end: number) => void;
    onHoverRange: (range: { start: number, end: number } | null) => void;
    onNodeSelect?: (node: TlvNode) => void;
    onSelectFileRoot?: () => void;
    onSelectTrailingArtifacts?: () => void;
}

const TreeNode: React.FC<{
    node: TlvNode,
    selectionOffset?: number | null,
    onSelect: (s: number, e: number) => void,
    onHover: (r: { start: number, end: number } | null) => void,
    onNodeClick?: (n: TlvNode) => void
}> = ({ node, selectionOffset, onSelect, onHover, onNodeClick }) => {
    const [expanded, setExpanded] = useState(false);
    const nodeRef = useRef<HTMLDivElement>(null);
    const hasChildren = node.children && node.children.length > 0;
    const endOffsetExclusive = node.offset + node.total_len;
    const endOffsetInclusive = Math.max(node.offset, endOffsetExclusive - 1);
    const containsSelection = selectionOffset !== undefined && selectionOffset !== null && selectionOffset >= node.offset && selectionOffset < endOffsetExclusive;

    useEffect(() => { if (containsSelection && hasChildren) setExpanded(true); }, [containsSelection, hasChildren]);
    useEffect(() => { if (containsSelection && !hasChildren && nodeRef.current) nodeRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }, [containsSelection, hasChildren]);

    return (
        <div style={{ marginLeft: '12px', marginTop: '4px', fontSize: '0.75rem' }}>
            <div
                ref={nodeRef}
                style={{
                    display: 'flex', alignItems: 'center', cursor: 'pointer', padding: '2px 4px',
                    background: containsSelection && !hasChildren ? 'rgba(0, 240, 255, 0.15)' : 'transparent',
                    color: containsSelection && !hasChildren ? '#fff' : '#aaa',
                }}
                onClick={(e) => {
                    e.stopPropagation(); onSelect(node.offset, endOffsetInclusive);
                    if (onNodeClick) onNodeClick(node);
                    if (hasChildren) setExpanded(!expanded);
                }}
                onMouseEnter={(e) => { e.stopPropagation(); onHover({ start: node.offset, end: endOffsetInclusive }); }}
                onMouseLeave={() => onHover(null)}
            >
                {hasChildren ? (expanded ? <ChevronDown size={12} color="#555" /> : <ChevronRight size={12} color="#555" />) : <span style={{ width: '12px' }} />}
                {node.is_container ? <Folder size={12} color={containsSelection ? "#fff" : "var(--accent-blue)"} style={{ marginLeft: '4px' }} /> : <Box size={12} color={containsSelection ? "#fff" : "#555"} style={{ marginLeft: '4px' }} />}
                <span style={{ marginLeft: '6px' }}>{node.name}</span>
            </div>
            {expanded && hasChildren && (
                <div style={{ borderLeft: '1px solid #222' }}>
                    {node.children.map((child: TlvNode, i: number) => <TreeNode key={i} node={child} selectionOffset={selectionOffset} onSelect={onSelect} onHover={onHover} onNodeClick={onNodeClick} />)}
                </div>
            )}
        </div>
    );
};

const FileTree: React.FC<Props> = ({
    file,
    fileSize = 0,
    structures,
    standard,
    trailingArtifacts,
    selectionOffset,
    inspectorContext,
    onSelectRange,
    onHoverRange,
    onNodeSelect,
    onSelectFileRoot,
    onSelectTrailingArtifacts
}) => {
    // Default to TREE so TLV decode is immediately usable.
    const [viewMode, setViewMode] = useState<'simple' | 'detailed'>('detailed');
    const [isMinimized, setIsMinimized] = useState(false);

    if (!file) return <div style={{ padding: '30px', color: '#444', fontSize: '0.75rem', textAlign: 'center' }}>NO SIGNAL SOURCE</div>;

    const simpleSections = [
        { name: "FILE HEADER", start: 0, end: Math.min(1024, fileSize), color: '#00ff9d' },
        { name: "DATA PAYLOAD", start: Math.min(1024, fileSize), end: Math.max(fileSize - 1024, 0), color: 'var(--accent-cyan)' },
        { name: "METADATA FOOTER", start: Math.max(fileSize - 1024, 0), end: fileSize, color: '#bd00ff' }
    ];

    return (
        <div className="file-tree" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
            <div className="panel-header">
                <div style={{ display: 'flex', gap: '15px' }}>
                    <span
                        onClick={() => onSelectFileRoot?.()}
                        style={{ cursor: onSelectFileRoot ? 'pointer' : 'default', color: inspectorContext === 'file' ? 'var(--accent-cyan)' : '#555', marginRight: '10px' }}
                        title="Select file root for intelligence summary"
                    >
                        FILE
                    </span>
                    <span onClick={() => setViewMode('simple')} style={{ cursor: 'pointer', color: viewMode === 'simple' ? 'var(--accent-cyan)' : '#555' }}>SECTIONS</span>
                    <span onClick={() => setViewMode('detailed')} style={{ cursor: 'pointer', color: viewMode === 'detailed' ? 'var(--accent-cyan)' : '#555' }}>TREE</span>
                </div>
                <button onClick={() => setIsMinimized(!isMinimized)} style={{ background: 'none', border: 'none', color: '#555', cursor: 'pointer' }}>
                    {isMinimized ? <Maximize2 size={12} /> : <Minimize2 size={12} />}
                </button>
            </div>

            {!isMinimized && (
                <div style={{ flex: 1, overflow: 'auto', padding: '15px' }}>
                    {standard && (
                        <div style={{ marginBottom: '20px', padding: '8px 10px', background: 'rgba(0, 255, 157, 0.05)', borderLeft: '2px solid #00ff9d' }}>
                            <div style={{ display: 'flex', alignItems: 'center', color: '#00ff9d', fontSize: '0.7rem', letterSpacing: '1px' }}>
                                <Shield size={10} style={{ marginRight: '6px' }} /> VERIFIED STANDARD
                            </div>
                            <div style={{ color: '#eee', fontSize: '0.85rem', marginTop: '4px' }}>{standard.name}</div>
                        </div>
                    )}

                    {viewMode === 'detailed' ? (
                        structures && structures.length > 0 ? (
                            <div style={{ paddingLeft: '0px' }}>
                                {structures.map((node, i) => <TreeNode key={i} node={node} selectionOffset={selectionOffset} onSelect={onSelectRange} onHover={onHoverRange} onNodeClick={onNodeSelect} />)}
                            </div>
                        ) : <div style={{ color: '#555', fontSize: '0.75rem' }}>Parsing stream...</div>
                    ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '1px' }}>
                            {/* NO BOXES: Just sleek rows separated by 1px gaps */}
                            {simpleSections.map((sec, i) => (
                                <div
                                    key={i} onClick={() => onSelectRange(sec.start, Math.max(sec.start, sec.end - 1))}
                                    style={{ padding: '12px', background: '#0a0a0a', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderLeft: `2px solid ${sec.color}` }}
                                >
                                    <div style={{ color: '#ccc', fontSize: '0.75rem' }}>{sec.name}</div>
                                    <div style={{ color: '#555', fontSize: '0.7rem' }}>{((sec.end - sec.start) / 1024).toFixed(1)} KB</div>
                                </div>
                            ))}
                        </div>
                    )}

                    {trailingArtifacts && trailingArtifacts.length > 0 && (
                        <div style={{ marginTop: '18px', borderTop: '1px solid #222', paddingTop: '12px' }}>
                            <div style={{ fontSize: '0.65rem', color: '#ff2a2a', letterSpacing: '1px', marginBottom: '8px' }}>TRAILING ARTIFACTS</div>
                            <div
                                onClick={() => {
                                    const footerStart = Math.max(0, fileSize - 64 * 1024);
                                    onSelectRange(footerStart, Math.max(footerStart, fileSize - 1));
                                    onSelectTrailingArtifacts?.();
                                }}
                                style={{
                                    padding: '10px 12px',
                                    background: inspectorContext === 'trailing' ? 'rgba(255, 42, 42, 0.12)' : '#0a0a0a',
                                    borderLeft: '2px solid #ff2a2a',
                                    cursor: 'pointer'
                                }}
                            >
                                <div style={{ color: '#eee', fontSize: '0.75rem', marginBottom: '6px' }}>Detected {trailingArtifacts.length} trailing signal(s)</div>
                                <div
                                    title="Hover to see full log"
                                    style={{
                                        color: '#777',
                                        fontSize: '0.65rem',
                                        lineHeight: '1.4',
                                        display: '-webkit-box',
                                        WebkitLineClamp: 4 as any,
                                        WebkitBoxOrient: 'vertical' as any,
                                        overflow: 'hidden',
                                        textOverflow: 'ellipsis',
                                    }}
                                >
                                    {trailingArtifacts.slice(0, 4).join(' • ')}
                                    {trailingArtifacts.length > 4 ? ' • …' : ''}
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};
export default FileTree;
