import React, { useState, useRef, useMemo, useEffect } from 'react';
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels';
import { useAnalysisEngine } from './hooks/useAnalysisEngine';
import { HilbertCurve } from './utils/hilbert';
import { detectStandard, DetectedStandard } from './utils/standards';
import { FileMetadata, generateReport } from './utils/export';
import { Download, HardDrive, Activity, MousePointer2, FileType } from 'lucide-react';

import Radar from './components/Radar';
import HexView, { HexViewRef } from './components/HexView';
import SemanticScrollbar from './components/SemanticScrollbar';
import AutocorrelationGraph from './components/AutocorrelationGraph';
import FileTree from './components/FileTree';
import StructureInspector from './components/StructureInspector';
import TransformationPipeline from './components/TransformationPipeline';
import { TlvNode } from './types/analysis';
import './App.css';

const calculateLocalAutocorrelation = (data: Uint8Array): number[] => { return []; };

function App() {
    const { isReady, analyzeFile, result } = useAnalysisEngine();
    const [fileData, setFileData] = useState<Uint8Array | null>(null);
    const [fileMeta, setFileMeta] = useState<FileMetadata | null>(null);
    const [fileObj, setFileObj] = useState<File | null>(null);
    const [inspectorContext, setInspectorContext] = useState<'file' | 'node' | 'trailing'>('file');
    const [isDragging, setIsDragging] = useState(false);

    // --- VIEW OPTIONS STATE ---
    const [showHilbert, setShowHilbert] = useState(true);
    const [showHeatmap, setShowHeatmap] = useState(true);
    const [showInspector, setShowInspector] = useState(true);
    const [showPipeline, setShowPipeline] = useState(true);

    const [hoveredOffset, setHoveredOffset] = useState<number | null>(null);
    const [selectionRange, setSelectionRange] = useState<{ start: number, end: number } | null>(null);
    const [hoverRange, setHoverRange] = useState<{ start: number, end: number } | null>(null);
    const [standard, setStandard] = useState<DetectedStandard | null>(null);
    const [selectedNode, setSelectedNode] = useState<TlvNode | null>(null);
    const [currentScrollOffset, setCurrentScrollOffset] = useState(0);

    const [hexStride, setHexStride] = useState(16);
    const [hilbert] = useState(() => new HilbertCurve(9));
    const hexViewRef = useRef<HexViewRef>(null);

    const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files[0]) {
            const file = e.target.files[0];
            await processFile(file);
        }
    };

    const processFile = async (file: File) => {
        setFileObj(file);
        setFileMeta({ name: file.name, size: file.size, type: file.type, lastModified: file.lastModified });
        setStandard(null);
        setSelectionRange(null);
        setSelectedNode(null);
        setInspectorContext('file');
        // 4GB+ bypass: only load a small preview window for UI (header), never the whole file.
        const headerBuf = await file.slice(0, 1024 * 1024).arrayBuffer(); // 1MB preview
        const headerBytes = new Uint8Array(headerBuf);
        setFileData(headerBytes);
        analyzeFile(file);
    };

    const handleDragOver = (e: React.DragEvent) => { e.preventDefault(); setIsDragging(true); };
    const handleDragLeave = () => setIsDragging(false);
    const handleDrop = async (e: React.DragEvent) => {
        e.preventDefault();
        setIsDragging(false);
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            const file = e.dataTransfer.files[0];
            await processFile(file);
        }
    };

    const handleJumpTo = (offset: number, length: number = 16) => {
        setSelectionRange({ start: offset, end: offset + length });
        hexViewRef.current?.scrollToOffset(offset);
    };

    const handleScrollUpdate = (offset: number) => {
        setCurrentScrollOffset(offset);
    };

    useEffect(() => {
        // Pass BOTH parsed structures AND raw bytes to detect signatures (PCAP, CR)
        setStandard(detectStandard(result?.parsed_structures, fileData));
    }, [result, fileData]);

    const [selectedBytes, setSelectedBytes] = useState<Uint8Array | null>(null);
    useEffect(() => {
        let cancelled = false;
        const load = async () => {
            if (!fileObj || !selectionRange) {
                setSelectedBytes(null);
                return;
            }
            const start = Math.max(0, selectionRange.start);
            const end = Math.min(fileObj.size, Math.max(selectionRange.end, start), start + 65536);
            const buf = await fileObj.slice(start, end).arrayBuffer();
            if (cancelled) return;
            setSelectedBytes(new Uint8Array(buf));
        };
        void load();
        return () => { cancelled = true; };
    }, [fileObj, selectionRange]);

    const liveGraphData = useMemo(() => {
        if (selectedBytes && selectedBytes.length > 0) return calculateLocalAutocorrelation(selectedBytes);
        return result?.autocorrelation_graph || [];
    }, [selectedBytes, result]);

    const currentViewPercent = fileMeta ? currentScrollOffset / fileMeta.size : 0;
    const isAnalyzing = !result && fileMeta; // Simple heuristic for now

    const showStructureInspector =
        showInspector &&
        (
            !!selectedNode ||
            (!!result?.trailing_artifacts &&
                result.trailing_artifacts.length > 0 &&
                (inspectorContext === 'file' || inspectorContext === 'trailing'))
        );

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
                    {/* VIEW TOGGLES */}
                    <div className={!fileData ? "disabled-toolbar" : ""} style={{ display: 'flex', gap: '2px', background: '#111', padding: '2px', borderRadius: '4px', border: '1px solid #333' }}>
                        <ToggleButton label="RADAR" active={showHilbert} onClick={() => setShowHilbert(!showHilbert)} />
                        <ToggleButton label="HEATMAP" active={showHeatmap} onClick={() => setShowHeatmap(!showHeatmap)} />
                        <span style={{ width: '1px', background: '#333', margin: '0 4px' }} />
                        <ToggleButton label="DETAILS" active={showInspector} onClick={() => setShowInspector(!showInspector)} />
                        <ToggleButton label="PIPELINE" active={showPipeline} onClick={() => setShowPipeline(!showPipeline)} />
                    </div>

                    <button
                        onClick={() => fileMeta && fileData && result && generateReport(fileMeta, fileData, result, standard)}
                        disabled={!result}
                        style={{
                            background: result ? 'rgba(0, 240, 255, 0.1)' : '#222',
                            color: result ? 'var(--accent-cyan)' : '#555',
                            border: result ? '1px solid var(--accent-cyan)' : '1px solid #333',
                            padding: '4px 12px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold', cursor: result ? 'pointer' : 'not-allowed',
                            display: 'flex', alignItems: 'center', gap: '6px'
                        }}
                    >
                        <Download size={14} /> EXPORT
                    </button>
                </div>
            </div>

            <div style={{ flex: 1, minHeight: 0, position: 'relative' }}>
                {!fileObj ? (
                    // 1. PREMIUM EMPTY STATE
                    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: '#444' }}>
                        <div style={{ width: '100px', height: '100px', border: '2px dashed #333', borderRadius: '20px', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '20px', animation: 'pulse-border 2s infinite' }}>
                            <Download size={40} color="#666" />
                        </div>
                        <h2 style={{ color: '#eee', marginBottom: '8px', letterSpacing: '1px' }}>DROP EVIDENCE FILE TO BEGIN</h2>
                        <p style={{ fontSize: '0.9rem', color: '#666' }}>Supports .pcap, .cr, and Raw Binaries</p>
                    </div>
                ) : (
                    <PanelGroup direction="horizontal">
                        {/* LEFT: TREE */}
                        <Panel defaultSize={20} minSize={10} className="bg-panel cyber-border-right">
                            <FileTree
                                file={fileMeta}
                                fileSize={fileMeta?.size}
                                structures={result?.parsed_structures}
                                standard={standard}
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

                        {/* CENTER */}
                        <Panel minSize={30}>
                            <PanelGroup direction="vertical">
                                {showHilbert && (
                                    <>
                                        <Panel defaultSize={40} minSize={20}>
                                            <div style={{ height: '100%', position: 'relative' }}>
                                                <div className="panel-header" style={{ position: 'absolute', top: 0, left: 0, zIndex: 10 }}>GLOBAL SIGNAL</div>
                                                {isReady && result ? (
                                                    <Radar
                                                        matrix={result.hilbert_matrix}
                                                        entropyMap={result.entropy_map}
                                                        highlightOffset={hoveredOffset}
                                                        selectionRange={selectionRange}
                                                        hilbert={hilbert}
                                                        onJump={(off) => handleJumpTo(off)}
                                                    />
                                                ) : <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#555' }}>AWAITING ANALYSIS...</div>}
                                            </div>
                                        </Panel>
                                        <PanelResizeHandle className="resize-handle-horizontal" />
                                    </>
                                )}

                                <Panel defaultSize={15} minSize={10} collapsible={true}>
                                    <AutocorrelationGraph fileData={fileData} onLagSelect={(off) => handleJumpTo(off)} />
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
                                            <div style={{ width: '24px', borderLeft: '1px solid #333' }}>
                                                {result && (
                                                    <SemanticScrollbar
                                                        entropyMap={result.entropy_map}
                                                        currentPercent={currentViewPercent}
                                                        onScroll={(p) => fileMeta && handleJumpTo(Math.floor(fileMeta.size * p))}
                                                    />
                                                )}
                                            </div>
                                        )}
                                    </div>
                                </Panel>
                            </PanelGroup>
                        </Panel>

                        {/* RIGHT: DETAILS (Only show if at least one view enabled) */}
                        {(showInspector || showPipeline) && (
                            <>
                                <PanelResizeHandle className="resize-handle" />
                                <Panel defaultSize={25} minSize={20} className="bg-panel cyber-border-left">
                                    <div className="panel-header">DETAILS</div>
                                    <div style={{ padding: '15px', display: 'flex', flexDirection: 'column', height: 'calc(100% - 30px)', gap: '15px', overflowY: 'auto' }}>

                                        {/* INSPECTOR VIEW */}
                                        {showStructureInspector && (
                                            <div style={{ flexShrink: 0 }}>
                                                <StructureInspector
                                                    node={selectedNode}
                                                    fileData={fileData}
                                                    fileMeta={fileMeta}
                                                    inspectorContext={inspectorContext}
                                                    trailingArtifacts={result?.trailing_artifacts}
                                                    onFocus={(s, e) => handleJumpTo(s, e - s)}
                                                />
                                            </div>
                                        )}

                                        {/* PIPELINE VIEW */}
                                        {showPipeline && (
                                            <div style={{ flex: 1, borderTop: showInspector ? '1px solid #333' : 'none', paddingTop: showInspector ? '15px' : '0' }}>
                                                <div style={{ fontSize: '10px', color: '#666', marginBottom: '10px' }}>TRANSFORMATION PIPELINE</div>
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

            {/* 2. THE STATUS BAR (New Footer) */}
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
                    <span>SEL: {selectionRange ? `0x${selectionRange.start.toString(16).toUpperCase()} (+${selectionRange.end - selectionRange.start})` : 'NONE'}</span>
                </div>
                <div style={{ width: '1px', height: '12px', background: '#333' }} />

                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <FileType size={12} color={standard ? '#00ff9d' : '#555'} />
                    <span style={{ color: standard ? '#00ff9d' : 'inherit' }}>
                        TYPE: {standard ? standard.name : 'RAW BINARY'}
                    </span>
                </div>

                <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Activity size={12} color={isAnalyzing ? '#ffff00' : '#00ff9d'} />
                    <span>{isAnalyzing ? 'PROCESSING...' : 'READY'}</span>
                </div>
            </div>
        </div>
    );
}

// Helper for the Toggle Buttons
const ToggleButton = ({ label, active, onClick }: { label: string, active: boolean, onClick: () => void }) => (
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