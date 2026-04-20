import { useState, useEffect, useCallback } from 'react';
import { AnalysisResult } from '../types/analysis';

export const useAnalysisEngine = () => {
    const [isReady, setIsReady] = useState(false);
    const [result, setResult] = useState<AnalysisResult | null>(null);
    const [isAnalyzing, setIsAnalyzing] = useState(false);

    useEffect(() => {
        let isDisposed = false;
        const worker = new Worker(new URL('../workers/analysis.worker.ts', import.meta.url), { type: 'module' });
        let nextId = 1;
        const pending = new Map<number, { resolve: (v: any) => void; reject: (e: any) => void }>();

        const send = (msg: any) => {
            worker.postMessage(msg);
        };

        worker.onmessage = (evt: MessageEvent<any>) => {
            const msg = evt.data;
            const id = msg?.id;

            if (msg?.type === 'ready') {
                if (!isDisposed) setIsReady(true);
                return;
            }

            if (typeof id !== 'number') return;
            const p = pending.get(id);
            if (!p) return;

            if (msg.type === 'result') {
                pending.delete(id);
                p.resolve(msg.result);
            } else if (msg.type === 'error') {
                pending.delete(id);
                const err = new Error(msg?.error?.message ?? 'Worker error');
                (err as any).stack = msg?.error?.stack;
                p.reject(err);
            }
        };

        send({ type: 'init', id: nextId++ });

        // Stash worker + request helper on the function object via closure.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (useAnalysisEngine as any).__worker = worker;
        (useAnalysisEngine as any).__request = (file: File) => {
            const id = nextId++;
            return new Promise<any>((resolve, reject) => {
                pending.set(id, { resolve, reject });
                send({ type: 'analyze', id, file });
            });
        };

        return () => {
            isDisposed = true;
            pending.clear();
            worker.terminate();
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (useAnalysisEngine as any).__worker = null;
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (useAnalysisEngine as any).__request = null;
        };
    }, []);

    const analyzeFile = useCallback(async (file: File) => {
        if (!isReady) return;

        setIsAnalyzing(true);
        try {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const request = (useAnalysisEngine as any).__request as ((f: File) => Promise<any>) | null;
            if (!request) throw new Error('Analysis worker not available');
            const workerResult = await request(file);
            setResult(workerResult as AnalysisResult);

        } catch (err) {
            console.error("Critical Analysis Failure:", err);
            setResult(null);
        } finally {
            setIsAnalyzing(false);
        }
    }, [isReady]);

    return { isReady, analyzeFile, result, isAnalyzing };
};
