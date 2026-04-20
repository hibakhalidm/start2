/**
 * Unified spatial mapping: map a discrete visualization index to an absolute byte offset
 * in the evidence file (Phase 12 — Radar + Autocorrelation correlation with Hex).
 */
export function jumpOffsetFromIndex(index: number, totalPoints: number, fileSize: number): number {
    if (fileSize <= 0) return 0;
    if (totalPoints <= 0) return 0;
    const i = Math.max(0, Math.min(totalPoints - 1, Math.floor(index)));
    return Math.min(fileSize - 1, Math.floor((i / totalPoints) * fileSize));
}

/** Inverse of jumpOffsetFromIndex for Hilbert radar reticles (same linear proportion of file). */
export function radarCurveIndexFromFileOffset(offset: number, fileSize: number, totalPoints: number): number {
    if (fileSize <= 0 || totalPoints <= 0) return 0;
    const o = Math.max(0, Math.min(fileSize - 1, Math.floor(offset)));
    return Math.min(totalPoints - 1, Math.floor((o / fileSize) * totalPoints));
}
