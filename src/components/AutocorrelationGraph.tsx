import React, { useMemo, useState } from 'react';
import { Activity, Minimize2, Maximize2 } from 'lucide-react';
import { jumpOffsetFromIndex } from '../utils/spatialCorrelation';

interface Props {
    fileData: Uint8Array | null;
    /** Full evidence size (must match Radar / Hex). */
    fileSize: number;
    /** WASM/worker autocorrelation (lag series); when empty, falls back to density profile from header bytes. */
    autocorrelationGraph: number[];
    onJumpToOffset: (absoluteOffset: number) => void;
}

const AutocorrelationGraph: React.FC<Props> = ({
    fileData,
    fileSize,
    autocorrelationGraph,
    onJumpToOffset,
}) => {
    const [isMinimized, setIsMinimized] = useState(false);

    const graphData = useMemo(() => {
        if (autocorrelationGraph.length > 0) return autocorrelationGraph;
        if (!fileData || fileData.length === 0) return [];
        const width = 200;
        const chunkSize = Math.max(1, Math.floor(fileData.length / width));
        const data: number[] = [];
        for (let i = 0; i < width; i++) {
            const start = i * chunkSize;
            if (start >= fileData.length) break;
            const end = Math.min(start + chunkSize, fileData.length);
            let sum = 0;
            for (let j = start; j < end; j++) sum += fileData[j];
            const denom = Math.max(1, end - start);
            data.push(sum / denom);
        }
        return data;
    }, [fileData, autocorrelationGraph]);

    const graphMax = useMemo(() => Math.max(1e-9, ...graphData.map((v) => Math.abs(Number(v)))), [graphData]);

    if (isMinimized) {
        return (
            <div style={{ padding: '10px', background: '#111', borderBottom: '1px solid #333', display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)' }}>GLOBAL SIGNAL</span>
                <Minimize2 size={14} color="#555" style={{ cursor: 'pointer' }} onClick={() => setIsMinimized(false)} />
            </div>
        );
    }

    return (
        <div style={{ background: '#050505', borderBottom: '1px solid #333', height: '100px', display: 'flex', flexDirection: 'column' }}>
            <div style={{ padding: '4px 10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.7rem', color: '#555', letterSpacing: '1px' }}>
                    {autocorrelationGraph.length > 0 ? 'AUTOCORRELATION (LAG)' : 'GLOBAL DENSITY (HEADER)'}
                </span>
                <Maximize2 size={12} color="#555" style={{ cursor: 'pointer' }} onClick={() => setIsMinimized(true)} />
            </div>

            <div style={{ flex: 1, display: 'flex', alignItems: 'flex-end', padding: '0 10px 10px 10px', gap: '1px' }}>
                {graphData.map((val, i) => {
                    const h = autocorrelationGraph.length > 0
                        ? Math.max(6, (Number(val) / graphMax) * 100)
                        : (val / 255) * 100;
                    const abs = jumpOffsetFromIndex(i, graphData.length, fileSize);
                    return (
                    <div
                        key={i}
                        onClick={() => onJumpToOffset(abs)}
                        style={{
                            flex: 1,
                            height: `${h}%`,
                            background: autocorrelationGraph.length > 0 && (i === 8 || i === 16) ? '#5a2a2a' : '#333',
                            cursor: 'pointer',
                            transition: 'height 0.2s'
                        }}
                        title={
                            autocorrelationGraph.length > 0
                                ? `Lag ${i} → offset 0x${abs.toString(16)}`
                                : `Bin ${i} → offset 0x${abs.toString(16)}`
                        }
                    />
                );})}
            </div>
        </div>
    );
};

export default AutocorrelationGraph;