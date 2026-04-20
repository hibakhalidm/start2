export interface TlvNode {
    name: string;
    tag: number;
    offset: number;
    header_len: number;
    value_len: number;
    value_offset: number;
    total_len: number;
    is_container: boolean;
    children: TlvNode[];
}

export type CryptoMode = 'AES-128/256' | 'DES/3DES';

export interface AnalysisResult {
    entropy_map: number[];
    hilbert_matrix: Uint8Array;
    autocorrelation_graph: number[];
    parsed_structures?: TlvNode[];
    trailing_artifacts?: string[];
    /** Heuristic from autocorrelation lag spikes (worker). */
    crypto_mode?: CryptoMode | null;
    /** Row indices 0..511 in the Hilbert radar where entropy is high (worker). */
    high_entropy_radar_indices?: number[];
    /** Web transport heuristic from header + entropy (worker): H1 / H2 / H3. */
    protocol_guess?: string | null;
}
