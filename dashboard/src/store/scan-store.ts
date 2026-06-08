import { create } from "zustand";

interface Scan {
  id: string;
  url: string;
  domain: string;
  risk_score: number;
  threat_level: string;
  threat_type: string;
  created_at: string;
}

interface ScanState {
  currentScan: Scan | null;
  history: Scan[];
  setCurrentScan: (scan: Scan | null) => void;
  addToHistory: (scan: Scan) => void;
  clearHistory: () => void;
}

export const useScanStore = create<ScanState>((set) => ({
  currentScan: null,
  history: [],
  setCurrentScan: (scan) => set({ currentScan: scan }),
  addToHistory: (scan) =>
    set((state) => ({
      history: [scan, ...state.history].slice(0, 100),
    })),
  clearHistory: () => set({ history: [] }),
}));
