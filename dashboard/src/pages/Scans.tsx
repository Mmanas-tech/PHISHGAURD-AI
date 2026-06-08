import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import api from "../services/api";
import ThreatBadge from "../components/ui/ThreatBadge";
import LoadingSkeleton from "../components/ui/LoadingSkeleton";
import { useState } from "react";

interface ScanItem {
  id: string;
  url: string;
  domain: string;
  risk_score: number;
  threat_level: string;
  threat_type: string;
  created_at: string;
}

export default function Scans() {
  const [page, setPage] = useState(1);

  const { data, isLoading } = useQuery({
    queryKey: ["scans", page],
    queryFn: async () => {
      const res = await api.get(`/scan/history?page=${page}&page_size=20`);
      return res.data;
    },
  });

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1 className="text-2xl font-bold">Scan History</h1>
        <p className="text-sm text-text-muted mt-1">
          Complete history of all URL scans
        </p>
      </motion.div>

      {isLoading ? (
        <LoadingSkeleton variant="table" />
      ) : (
        <div className="glass-card overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left p-4 text-xs font-semibold text-text-muted uppercase tracking-wider">
                  Domain
                </th>
                <th className="text-left p-4 text-xs font-semibold text-text-muted uppercase tracking-wider">
                  Risk Score
                </th>
                <th className="text-left p-4 text-xs font-semibold text-text-muted uppercase tracking-wider">
                  Level
                </th>
                <th className="text-left p-4 text-xs font-semibold text-text-muted uppercase tracking-wider">
                  Type
                </th>
                <th className="text-left p-4 text-xs font-semibold text-text-muted uppercase tracking-wider">
                  Date
                </th>
              </tr>
            </thead>
            <tbody>
              {data?.items?.map((scan: ScanItem) => (
                <motion.tr
                  key={scan.id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="border-b border-border hover:bg-white/[0.02] transition-colors"
                >
                  <td className="p-4">
                    <span className="text-sm font-medium text-text-primary">
                      {scan.domain}
                    </span>
                    <p className="text-xs text-text-muted font-mono mt-0.5 truncate max-w-[300px]">
                      {scan.url}
                    </p>
                  </td>
                  <td className="p-4">
                    <span
                      className={`text-lg font-bold font-mono ${
                        scan.risk_score > 70
                          ? "text-accent-red"
                          : scan.risk_score > 30
                            ? "text-accent-amber"
                            : "text-accent-green"
                      }`}
                    >
                      {scan.risk_score}
                    </span>
                  </td>
                  <td className="p-4">
                    <ThreatBadge level={scan.threat_level} size="sm" />
                  </td>
                  <td className="p-4">
                    <span className="text-xs text-text-muted capitalize">
                      {scan.threat_type.replace(/_/g, " ")}
                    </span>
                  </td>
                  <td className="p-4">
                    <span className="text-xs text-text-muted">
                      {new Date(scan.created_at).toLocaleDateString()}
                    </span>
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>

          {data?.items?.length === 0 && (
            <div className="p-12 text-center">
              <p className="text-text-muted">No scans yet</p>
            </div>
          )}

          {data?.total > 20 && (
            <div className="p-4 flex items-center justify-between border-t border-border">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="btn-secondary text-xs disabled:opacity-40"
              >
                Previous
              </button>
              <span className="text-xs text-text-muted">
                Page {page} of {Math.ceil(data.total / 20)}
              </span>
              <button
                onClick={() => setPage((p) => p + 1)}
                disabled={page * 20 >= data.total}
                className="btn-secondary text-xs disabled:opacity-40"
              >
                Next
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
