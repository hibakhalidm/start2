import React, { forwardRef, useImperativeHandle, useRef, useState } from 'react';
import { FixedSizeList as List } from 'react-window';
import { useHexPaginator } from '../hooks/useHexPaginator';

interface HexViewProps {
    file: File;
    fileSize: number;
    stride?: number;
    onScroll: (offset: number) => void;
    onSelect: (start: number, end: number) => void;
    selectionRange: { start: number, end: number } | null;
    hoverRange?: { start: number, end: number } | null; // <--- NEW
}

export interface HexViewRef { scrollToOffset: (offset: number) => void; }

const HexView = forwardRef<HexViewRef, HexViewProps>(({
    file, fileSize, stride = 16, onScroll, onSelect, selectionRange, hoverRange
}, ref) => {
    const listRef = useRef<List>(null);
    const rowCount = Math.ceil(fileSize / stride);
    const [isDragging, setIsDragging] = useState(false);
    const [dragStart, setDragStart] = useState<number | null>(null);
    const [dragMoved, setDragMoved] = useState(false);
    const [cacheEpoch, setCacheEpoch] = useState(0);
    const paginator = useHexPaginator(file, fileSize);
    const epochBumpScheduledRef = useRef(false);

    const bumpEpochOnce = () => {
        if (epochBumpScheduledRef.current) return;
        epochBumpScheduledRef.current = true;
        queueMicrotask(() => {
            epochBumpScheduledRef.current = false;
            setCacheEpoch((e) => e + 1);
        });
    };

    useImperativeHandle(ref, () => ({
        scrollToOffset: (offset: number) => {
            const rowIndex = Math.floor(offset / stride);
            listRef.current?.scrollToItem(rowIndex, 'center');
        }
    }));

    const handleByteDown = (index: number) => {
        setIsDragging(true);
        setDragStart(index);
        setDragMoved(false);
        // Initial click-down selects exactly one byte.
        onSelect(index, index);
    };

    const handleByteEnter = (index: number) => {
        if (isDragging && dragStart !== null) {
            if (index !== dragStart) setDragMoved(true);
            onSelect(Math.min(dragStart, index), Math.max(dragStart, index));
        }
    };

    const handleMouseUp = () => {
        // If the user simply clicked (no drag), force single-byte selection.
        if (dragStart !== null && !dragMoved) {
            onSelect(dragStart, dragStart);
        }
        setIsDragging(false);
        setDragStart(null);
        setDragMoved(false);
    };

    const Row = ({ index, style, data }: any) => {
        const offset = index * stride;
        if (offset >= fileSize) return null;

        // `data` carries cacheEpoch so react-window re-renders rows when chunk bytes arrive.
        void data;

        const { bytes, base, miss } = paginator.getChunkBytes(offset);
        if (miss) {
            paginator.ensureLoaded(offset, bumpEpochOnce);
        }

        const rowData = [];
        for (let i = 0; i < stride; i++) {
            const byteIndex = offset + i;
            if (byteIndex >= fileSize) break;
            const rel = byteIndex - base;
            const val = rel >= 0 && rel < bytes.length ? bytes[rel] : null;
            rowData.push({ val, idx: byteIndex });
        }

        return (
            <div style={{ ...style, fontFamily: 'var(--font-mono)', fontSize: '13px', display: 'flex', alignItems: 'center', userSelect: 'none' }}>
                <span style={{ color: '#555', marginRight: '16px', minWidth: '80px' }}>{offset.toString(16).padStart(8, '0').toUpperCase()}</span>
                <div style={{ display: 'flex', marginRight: '16px', flexWrap: 'nowrap' }}>
                    {rowData.map(({ val, idx }) => {
                        // Inclusive selection bounds (fix selection bleed).
                        const isSelected = !!selectionRange && idx >= selectionRange.start && idx <= selectionRange.end;
                        const isHovered = !isSelected && !!hoverRange && idx >= hoverRange.start && idx <= hoverRange.end; // inclusive hover bounds

                        return (
                            <span
                                key={idx}
                                onMouseDown={() => handleByteDown(idx)}
                                onMouseEnter={() => handleByteEnter(idx)}
                                onMouseUp={handleMouseUp}
                                onClick={(e) => {
                                    // CRITICAL: stop bubbling to parent rows; always select exactly this byte.
                                    e.stopPropagation();
                                    e.preventDefault();
                                    onSelect(idx, idx);
                                }}
                                style={{
                                    marginRight: '6px',
                                    color: isSelected ? '#000' : (isHovered ? 'var(--accent-cyan)' : '#a5b3ce'),
                                    background: isSelected ? 'var(--accent-cyan)' : (isHovered ? 'rgba(0, 240, 255, 0.1)' : 'transparent'),
                                    border: isHovered ? '1px solid rgba(0, 240, 255, 0.3)' : '1px solid transparent', // <--- GHOST BORDER
                                    cursor: 'pointer', padding: '0 1px', borderRadius: '2px'
                                }}
                            >
                                {val === null ? '--' : val.toString(16).padStart(2, '0').toUpperCase()}
                            </span>
                        );
                    })}
                </div>
            </div>
        );
    };

    return (
        <div onMouseLeave={handleMouseUp} style={{ height: '100%', width: '100%' }}>
            <List
                ref={listRef}
                height={600}
                itemCount={rowCount}
                itemSize={24}
                width="100%"
                itemData={cacheEpoch}
                onItemsRendered={({ visibleStartIndex, visibleStopIndex }: { visibleStartIndex: number; visibleStopIndex: number }) => {
                    const absOffset = visibleStartIndex * stride;
                    onScroll(absOffset);
                    let anyMiss = false;
                    const head = paginator.getChunkBytes(absOffset);
                    if (head.miss) anyMiss = true;

                    // Warm all chunks intersecting the visible window (bounded by react-window virtualization).
                    for (let r = visibleStartIndex; r <= visibleStopIndex; r++) {
                        const off = r * stride;
                        if (off >= fileSize) break;
                        const row = paginator.getChunkBytes(off);
                        if (row.miss) anyMiss = true;
                    }
                    if (anyMiss) {
                        // Async loads; coalesce epoch bumps to avoid render storms.
                        paginator.ensureLoaded(absOffset, bumpEpochOnce);
                        for (let r = visibleStartIndex; r <= visibleStopIndex; r++) {
                            const off = r * stride;
                            if (off >= fileSize) break;
                            paginator.ensureLoaded(off, bumpEpochOnce);
                        }
                    }

                    // Light prefetch of the trailing edge to reduce flicker on fast scroll.
                    const trailingOffset = visibleStopIndex * stride;
                    paginator.prefetch(trailingOffset);
                    paginator.prefetch(trailingOffset + paginator.CHUNK_SIZE);
                }}
            >
                {Row}
            </List>
        </div>
    );
});

export default HexView;