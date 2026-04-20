import React, { useMemo, useState } from 'react';
import { Activity, Minimize2, Maximize2 } from 'lucide-react';

interface Props {
    fileData: Uint8Array | null; // Takes WHOLE file now
    onLagSelect: (lag: number) => void;
}

const AutocorrelationGraph: React.FC<Props> = ({ fileData, onLagSelect }) => {
    const [isMinimized, setIsMinimized] = useState(false);

    // Calculate a "Global Signal Profile" instead of local autocorrelation
    // This represents the byte density/variance across the whole file
    const graphData = useMemo(() => {
        if (!fileData || fileData.length === 0) return [];
        const width = 200; // Number of bars
        const chunkSize = Math.max(1, Math.floor(fileData.length / width)); // floor-guard: prevents div-by-zero on small files
        const data = [];

        for (let i = 0; i < width; i++) {
            const start = i * chunkSize;
            if (start >= fileData.length) break;
            const end = Math.min(start + chunkSize, fileData.length);
            // Calculate simple variance/activity for this chunk
            let sum = 0;
            for (let j = start; j < end; j++) sum += fileData[j];
            const denom = Math.max(1, end - start);
            const avg = sum / denom;
            data.push(avg);
        }
        return data;
    }, [fileData]);

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
                <span style={{ fontSize: '0.7rem', color: '#555', letterSpacing: '1px' }}>GLOBAL DENSITY OVERVIEW</span>
                <Maximize2 size={12} color="#555" style={{ cursor: 'pointer' }} onClick={() => setIsMinimized(true)} />
            </div>

            <div style={{ flex: 1, display: 'flex', alignItems: 'flex-end', padding: '0 10px 10px 10px', gap: '1px' }}>
                {graphData.map((val, i) => (
                    <div
                        key={i}
                        onClick={() => {
                            // Rough jump to section
                            const offset = Math.floor((i / graphData.length) * (fileData?.length || 0));
                            onLagSelect(offset); // HACK: We reuse onLagSelect to signal a jump
                        }}
                        style={{
                            flex: 1,
                            height: `${(val / 255) * 100}%`,
                            background: '#333',
                            cursor: 'pointer',
                            transition: 'height 0.2s'
                        }}
                        title={`Click to jump to ~${(i / graphData.length * 100).toFixed(0)}%`}
                    />
                ))}
            </div>
        </div>
    );
};

export default AutocorrelationGraph;