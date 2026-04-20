import { useCallback, useRef } from 'react';

const CHUNK_SIZE = 64 * 1024; // 64KB
const MAX_CHUNKS = 10;

function clamp(n: number, lo: number, hi: number) {
    return Math.max(lo, Math.min(hi, n));
}

function chunkBaseForOffset(offset: number) {
    return Math.floor(offset / CHUNK_SIZE) * CHUNK_SIZE;
}

export function useHexPaginator(file: File, fileSize: number) {
    const cacheRef = useRef<Map<number, Uint8Array>>(new Map());
    const inflightRef = useRef<Map<number, Promise<Uint8Array>>>(new Map());

    const touch = useCallback((baseOffset: number, bytes: Uint8Array) => {
        const cache = cacheRef.current;
        if (cache.has(baseOffset)) cache.delete(baseOffset);
        cache.set(baseOffset, bytes);

        while (cache.size > MAX_CHUNKS) {
            const oldestKey = cache.keys().next().value as number | undefined;
            if (oldestKey === undefined) break;
            cache.delete(oldestKey);
        }
    }, []);

    const loadChunk = useCallback(
        async (baseOffset: number) => {
            const base = clamp(baseOffset, 0, Math.max(0, fileSize - 1));
            const end = clamp(base + CHUNK_SIZE, 0, fileSize);
            const buf = await file.slice(base, end).arrayBuffer();
            const bytes = new Uint8Array(buf);
            touch(base, bytes);
            return bytes;
        },
        [file, fileSize, touch]
    );

    const ensureLoaded = useCallback(
        (absOffset: number, onLoaded?: () => void) => {
            const base = chunkBaseForOffset(absOffset);
            const inflight = inflightRef.current;

            if (inflight.has(base)) {
                void inflight.get(base)!.finally(() => onLoaded?.());
                return;
            }

            const p = loadChunk(base).finally(() => {
                inflight.delete(base);
                onLoaded?.();
            });
            inflight.set(base, p);
        },
        [loadChunk]
    );

    const getChunkBytes = useCallback(
        (absOffset: number) => {
            const base = chunkBaseForOffset(absOffset);
            const cache = cacheRef.current;
            const existing = cache.get(base);
            if (existing) {
                // LRU bump: delete + re-insert marks MRU.
                cache.delete(base);
                cache.set(base, existing);
                return { base, bytes: existing, miss: false };
            }
            return { base, bytes: new Uint8Array(0), miss: true };
        },
        []
    );

    const prefetch = useCallback(
        (absOffset: number) => {
            // Warm cache without forcing React state churn.
            ensureLoaded(absOffset);
        },
        [ensureLoaded]
    );

    return {
        CHUNK_SIZE,
        getChunkBytes,
        prefetch,
        ensureLoaded
    };
}
