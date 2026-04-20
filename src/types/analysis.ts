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

export interface AnalysisResult {
    entropy_map: number[];
    hilbert_matrix: Uint8Array;
    autocorrelation_graph: number[];
    parsed_structures?: TlvNode[];
    trailing_artifacts?: string[];
}
