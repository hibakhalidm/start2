import React, { useMemo, useState, useRef, useEffect } from 'react';
import DeckGL from '@deck.gl/react';
import { BitmapLayer, ScatterplotLayer, PolygonLayer } from '@deck.gl/layers';
import { HilbertCurve } from '../utils/hilbert';
import { jumpOffsetFromIndex, radarCurveIndexFromFileOffset } from '../utils/spatialCorrelation';
import type { CryptoMode } from '../types/analysis';
import { Box, Activity, ZoomIn, ZoomOut, Maximize } from 'lucide-react';

const HILBERT_DIM = 512;
const HILBERT_TOTAL_POINTS = HILBERT_DIM * HILBERT_DIM;

interface RadarProps {
    matrix: Uint8Array;
    entropyMap?: number[];
    highlightOffset: number | null;
    selectionRange: { start: number, end: number } | null;
    hilbert: HilbertCurve;
    fileSize: number;
    cryptoMode?: CryptoMode | null;
    highEntropyRadarIndices?: number[];
    onJumpToOffset: (absoluteOffset: number) => void;
}

const Radar: React.FC<RadarProps> = ({
    matrix,
    entropyMap = [],
    highlightOffset,
    selectionRange,
    hilbert,
    fileSize,
    cryptoMode = null,
    highEntropyRadarIndices = [],
    onJumpToOffset,
}) => {
    const [viewMode, setViewMode] = useState<'HILBERT' | 'LINEAR'>('HILBERT');
    const [zoom, setZoom] = useState(0);

    // Deck.gl BitmapLayer expects RGBA (4 channels). Expand the single-channel WASM buffer into RGBA.
    const rgbaMatrix = useMemo(() => {
        const pixelCount = HILBERT_DIM * HILBERT_DIM;
        const out = new Uint8Array(pixelCount * 4);
        const len = Math.min(matrix.length, pixelCount);

        for (let i = 0; i < len; i++) {
            const v = matrix[i];
            const o = i * 4;
            out[o] = v;       // R
            out[o + 1] = v;   // G
            out[o + 2] = v;   // B
            out[o + 3] = 255; // A
        }

        // If matrix is shorter than expected, remaining pixels stay black/transparent-safe (A=0 by default).
        for (let i = len; i < pixelCount; i++) {
            out[i * 4 + 3] = 255;
        }

        return out;
    }, [matrix]);

    const getHilbertLayers = () => {
        const layers: any[] = [
            new BitmapLayer({
                id: 'hilbert-bitmap', image: { width: HILBERT_DIM, height: HILBERT_DIM, data: rgbaMatrix },
                bounds: [0, 0, HILBERT_DIM, HILBERT_DIM], pickable: true,
                onClick: (info: any) => {
                    if (!info?.bitmapPixel) return;
                    const curveIndex = hilbert.xyToOffset(info.bitmapPixel[0], info.bitmapPixel[1]);
                    const absoluteOffset = jumpOffsetFromIndex(curveIndex, HILBERT_TOTAL_POINTS, fileSize);
                    onJumpToOffset(absoluteOffset);
                }
            })
        ];

        if (highEntropyRadarIndices.length > 0) {
            layers.push(
                new PolygonLayer({
                    id: 'high-entropy-outline',
                    data: highEntropyRadarIndices,
                    getPolygon: (row: number) => [
                        [0, row],
                        [HILBERT_DIM, row],
                        [HILBERT_DIM, row + 1],
                        [0, row + 1],
                    ],
                    getFillColor: [255, 42, 42, 45],
                    stroked: true,
                    getLineColor: [255, 42, 42, 255],
                    getLineWidth: 1,
                    lineWidthUnits: 'pixels',
                    pickable: false,
                })
            );
        }

        if (selectionRange) {
            const startXY = hilbert.offsetToXY(radarCurveIndexFromFileOffset(selectionRange.start, fileSize, HILBERT_TOTAL_POINTS));
            const endXY = hilbert.offsetToXY(radarCurveIndexFromFileOffset(selectionRange.end, fileSize, HILBERT_TOTAL_POINTS));
            layers.push(new ScatterplotLayer({
                id: 'markers',
                data: [{ pos: [startXY[0] + 0.5, startXY[1] + 0.5], color: [0, 240, 255] }, { pos: [endXY[0] + 0.5, endXY[1] + 0.5], color: [255, 40, 40] }],
                getPosition: d => d.pos, getFillColor: d => d.color, getRadius: 6, updateTriggers: { data: selectionRange }
            }));
        }

        if (highlightOffset !== null) {
            const [x, y] = hilbert.offsetToXY(radarCurveIndexFromFileOffset(highlightOffset, fileSize, HILBERT_TOTAL_POINTS));
            layers.push(new ScatterplotLayer({
                id: 'reticle', data: [{ pos: [x + 0.5, y + 0.5] }],
                getPosition: d => d.pos, getFillColor: [0, 0, 0, 0], getLineColor: [0, 240, 255],
                stroked: true, radiusMinPixels: 10, getRadius: 20, updateTriggers: { getPosition: highlightOffset }
            }));
        }
        return layers;
    };

    const LinearView = () => {
        const canvasRef = useRef<HTMLCanvasElement>(null);
        useEffect(() => {
            const canvas = canvasRef.current;
            const ctx = canvas?.getContext('2d');
            if (!canvas || !ctx || !entropyMap.length) return;
            const { width, height } = canvas.getBoundingClientRect();
            canvas.width = width; canvas.height = height;
            ctx.clearRect(0, 0, width, height);

            const step = width / entropyMap.length;
            entropyMap.forEach((val, i) => {
                if (val > 7.0) ctx.fillStyle = '#ff2a2a';
                else if (val < 4.8) ctx.fillStyle = '#3b82f6';
                else ctx.fillStyle = '#1a1a20';
                ctx.fillRect(i * step, 0, Math.max(1, step), height);
            });
        }, [entropyMap]);

        return (
            <canvas ref={canvasRef} style={{ width: '100%', height: '100%', cursor: 'crosshair' }}
                onClick={(e) => {
                    const rect = e.currentTarget.getBoundingClientRect();
                    const percent = (e.clientX - rect.left) / rect.width;
                    const total = entropyMap.length;
                    const index = Math.min(total - 1, Math.max(0, Math.floor(percent * total)));
                    onJumpToOffset(jumpOffsetFromIndex(index, total, fileSize));
                }}
            />
        );
    };

    return (
        <div style={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column' }}>
            <div style={{ height: '32px', borderBottom: '1px solid #333', display: 'flex', alignItems: 'center', padding: '0 10px', justifyContent: 'space-between', background: '#0a0a0f' }}>
                <span style={{ fontSize: '10px', color: '#555', letterSpacing: '1px' }}>GLOBAL RADAR</span>

                <div style={{ display: 'flex', gap: '5px', alignItems: 'center' }}>
                    {/* Zoom Controls */}
                    {viewMode === 'HILBERT' && (
                        <div style={{ display: 'flex', gap: '2px', marginRight: '10px', borderRight: '1px solid #333', paddingRight: '10px' }}>
                            <button onClick={() => setZoom(z => Math.max(z - 1, -2))} title="Zoom Out" style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: '#888' }}><ZoomOut size={12} /></button>
                            <span style={{ fontSize: '9px', color: '#555', minWidth: '20px', textAlign: 'center' }}>{Math.round(zoom * 10) / 10}x</span>
                            <button onClick={() => setZoom(z => Math.min(z + 1, 10))} title="Zoom In" style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: '#888' }}><ZoomIn size={12} /></button>
                            <button onClick={() => setZoom(0)} title="Reset Zoom" style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: '#888' }}><Maximize size={12} /></button>
                        </div>
                    )}

                    {/* View toggles */}
                    <button onClick={() => setViewMode('HILBERT')} style={{ background: viewMode === 'HILBERT' ? 'var(--accent-cyan)' : 'transparent', border: '1px solid #333', padding: '2px', cursor: 'pointer' }}><Box size={14} color={viewMode === 'HILBERT' ? '#000' : '#888'} /></button>
                    <button onClick={() => setViewMode('LINEAR')} style={{ background: viewMode === 'LINEAR' ? 'var(--accent-cyan)' : 'transparent', border: '1px solid #333', padding: '2px', cursor: 'pointer' }}><Activity size={14} color={viewMode === 'LINEAR' ? '#000' : '#888'} /></button>
                </div>
            </div>
            <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
                {cryptoMode && (
                    <div
                        style={{
                            position: 'absolute',
                            top: 6,
                            right: 8,
                            zIndex: 20,
                            padding: '6px 10px',
                            borderRadius: '6px',
                            border: '2px solid #ff2a2a',
                            background: 'rgba(20, 0, 0, 0.92)',
                            color: '#ff2a2a',
                            fontSize: '10px',
                            fontWeight: 800,
                            letterSpacing: '0.08em',
                            pointerEvents: 'none',
                            boxShadow: '0 0 16px rgba(255,42,42,0.35)',
                        }}
                    >
                        CRYPTO: {cryptoMode}
                    </div>
                )}
                {viewMode === 'HILBERT' ? (
                    <DeckGL
                        viewState={{ target: [256, 256, 0], zoom, minZoom: -2, maxZoom: 10 } as any}
                        onViewStateChange={({ viewState }: any) => setZoom(viewState.zoom)}
                        controller={true}
                        layers={getHilbertLayers()}
                        getCursor={() => 'crosshair'}
                        style={{ background: '#000' }}
                    />
                ) : <LinearView />}
            </div>
        </div>
    );
};

export default Radar;