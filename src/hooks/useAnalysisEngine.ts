import { useState, useEffect, useCallback, useRef } from 'react';
import { AnalysisResult } from '../types/analysis';

// ─────────────────────────────────────────────────────────────────────────────
// Analysis engine hook with race-safe cancellation.
//
// Two layers of cancellation are supported:
//   1. COOPERATIVE — the worker checks a per-id cancelled set at every await
//      boundary and bails with `cancelled`. Cheap, fast, no respawn.
//   2. HARD KILL — if the worker is wedged inside a synchronous WASM call,
//      callers can use `hardCancel()` to `worker.terminate()` and respawn.
//      Hard kill is also what the App-level watchdog triggers on timeout.
//
// AbortSignal is the public surface: `analyzeFile(file, { signal })` aborts on
// signal abort. The hook never silently leaks a pending promise — every kicked
// off request resolves OR rejects with a `cancelled` error, exactly once.
// ─────────────────────────────────────────────────────────────────────────────

interface AnalyzeOptions {
    signal?: AbortSignal;
    /** When true, an abort terminates and respawns the worker instead of just
     *  marking the request cancelled. Use when the worker is unresponsive. */
    hard?: boolean;
}

export const useAnalysisEngine = () => {
    const [isReady, setIsReady] = useState(false);
    const [result, setResult] = useState<AnalysisResult | null>(null);
    const [isAnalyzing, setIsAnalyzing] = useState(false);

    // Worker + request bookkeeping live in refs so they can be replaced on hard
    // kill without re-rendering / re-attaching from consumer hooks.
    const workerRef = useRef<Worker | null>(null);
    const nextIdRef = useRef(1);
    const pendingRef = useRef<Map<number, { resolve: (v: any) => void; reject: (e: any) => void; aborted: boolean }>>(new Map());
    const isDisposedRef = useRef(false);
    // Track the most recent in-flight request id so cancelAnalysis() / hardCancel()
    // can target it without callers having to remember the id.
    const latestRequestIdRef = useRef<number | null>(null);

    const spawnWorker = useCallback(() => {
        const worker = new Worker(new URL('../workers/analysis.worker.ts', import.meta.url), { type: 'module' });
        worker.onmessage = (evt: MessageEvent<any>) => {
            const msg = evt.data;
            const id = msg?.id;

            if (msg?.type === 'ready') {
                if (!isDisposedRef.current) setIsReady(true);
                return;
            }
            if (typeof id !== 'number') return;
            const p = pendingRef.current.get(id);
            if (!p) return;

            if (msg.type === 'result') {
                pendingRef.current.delete(id);
                p.resolve(msg.result);
            } else if (msg.type === 'error') {
                pendingRef.current.delete(id);
                const err = new Error(msg?.error?.message ?? 'Worker error');
                (err as any).stack = msg?.error?.stack;
                (err as any).cancelled = msg?.error?.message === 'cancelled' || p.aborted;
                p.reject(err);
            }
        };
        worker.postMessage({ type: 'init', id: nextIdRef.current++ });
        return worker;
    }, []);

    useEffect(() => {
        isDisposedRef.current = false;
        workerRef.current = spawnWorker();
        return () => {
            isDisposedRef.current = true;
            // Reject everything pending so no consumer promise dangles forever.
            for (const [, p] of pendingRef.current) {
                const err = new Error('cancelled');
                (err as any).cancelled = true;
                p.reject(err);
            }
            pendingRef.current.clear();
            workerRef.current?.terminate();
            workerRef.current = null;
            setIsReady(false);
        };
    }, [spawnWorker]);

    // Cooperative cancel: mark a single in-flight request as cancelled. The
    // worker will post an `error: cancelled` shortly. Safe to call multiple times.
    const cancelAnalysis = useCallback((targetId: number | null = null) => {
        const id = targetId ?? latestRequestIdRef.current;
        const w = workerRef.current;
        if (id == null || !w) return;
        const p = pendingRef.current.get(id);
        if (!p) return;
        p.aborted = true;
        try { w.postMessage({ type: 'cancel', id: nextIdRef.current++, targetId: id }); } catch { /* worker may already be torn down */ }
    }, []);

    // Hard cancel: terminate-and-respawn. Use only when cooperative cancel is
    // not making progress (e.g. soft-timeout fired). All pending requests are
    // rejected with `cancelled` so callers don't hang.
    const hardCancel = useCallback(() => {
        const w = workerRef.current;
        if (w) {
            try { w.terminate(); } catch { /* ignore */ }
        }
        for (const [, p] of pendingRef.current) {
            const err = new Error('cancelled');
            (err as any).cancelled = true;
            p.reject(err);
        }
        pendingRef.current.clear();
        latestRequestIdRef.current = null;
        setIsReady(false);
        if (!isDisposedRef.current) {
            workerRef.current = spawnWorker();
        }
    }, [spawnWorker]);

    const analyzeFile = useCallback(async (file: File, opts: AnalyzeOptions = {}) => {
        if (!isReady) return;
        if (opts.signal?.aborted) return;

        const id = nextIdRef.current++;
        latestRequestIdRef.current = id;
        setIsAnalyzing(true);

        const promise = new Promise<any>((resolve, reject) => {
            pendingRef.current.set(id, { resolve, reject, aborted: false });
            workerRef.current?.postMessage({ type: 'analyze', id, file });
        });

        // Wire AbortSignal → cancel.
        const onAbort = () => {
            if (opts.hard) hardCancel();
            else cancelAnalysis(id);
        };
        opts.signal?.addEventListener('abort', onAbort, { once: true });

        try {
            const workerResult = await promise;
            // Only commit results from the LATEST request — defeats race where
            // a stale (un-aborted) request from a previous call resolves after
            // a newer one has been started. App.tsx also re-checks via its own
            // run-token, but defending here keeps the hook honest standalone.
            if (latestRequestIdRef.current === id) {
                setResult(workerResult as AnalysisResult);
            }
        } catch (err) {
            const cancelled = (err as any)?.cancelled === true;
            if (!cancelled) {
                console.error('Critical Analysis Failure:', err);
                if (latestRequestIdRef.current === id) setResult(null);
            }
        } finally {
            opts.signal?.removeEventListener('abort', onAbort);
            if (latestRequestIdRef.current === id) setIsAnalyzing(false);
        }
    }, [isReady, cancelAnalysis, hardCancel]);

    return { isReady, analyzeFile, cancelAnalysis, hardCancel, result, isAnalyzing };
};
