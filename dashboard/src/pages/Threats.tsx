import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { useState } from "react";
import api from "../services/api";
import ThreatCard from "../components/ui/ThreatCard";
import LoadingSkeleton from "../components/ui/LoadingSkeleton";

export default function Threats() {
  const [page, setPage] = useState(1);
  const [levelFilter, setLevelFilter] = useState<string>("");
  const [typeFilter, setTypeFilter] = useState<string>("");

  const { data, isLoading } = useQuery({
    queryKey: ["threats", page, levelFilter, typeFilter],
    queryFn: async () => {
      const params = new URLSearchParams({ page: page.toString() });
      if (levelFilter) params.set("threat_level", levelFilter);
      if (typeFilter) params.set("threat_type", typeFilter);
      const res = await api.get(`/dashboard/threats?${params.toString()}`);
      return res.data;
    },
  });

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1 className="text-2xl font-bold">Threat Management</h1>
        <p className="text-sm text-text-muted mt-1">
          View and manage detected threats
        </p>
      </motion.div>

      <div className="flex gap-3 flex-wrap">
        <select
          value={levelFilter}
          onChange={(e) => {
            setLevelFilter(e.target.value);
            setPage(1);
          }}
          className="input-field w-auto"
        >
          <option value="">All Levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <select
          value={typeFilter}
          onChange={(e) => {
            setTypeFilter(e.target.value);
            setPage(1);
          }}
          className="input-field w-auto"
        >
          <option value="">All Types</option>
          <option value="phishing">Phishing</option>
          <option value="credential_theft">Credential Theft</option>
          <option value="brand_impersonation">Brand Impersonation</option>
          <option value="malware">Malware</option>
          <option value="social_engineering">Social Engineering</option>
        </select>
      </div>

      {isLoading ? (
        <div className="space-y-3">
          {[...Array(5)].map((_, i) => (
            <LoadingSkeleton key={i} variant="card" />
          ))}
        </div>
      ) : data?.items?.length > 0 ? (
        <div className="space-y-3">
          {data.items.map((threat: Record<string, unknown>) => (
            <ThreatCard
              key={threat.id as string}
              domain={threat.domain as string}
              url={threat.url as string}
              riskScore={threat.risk_score as number}
              threatLevel={threat.threat_level as string}
              threatType={threat.threat_type as string}
              detectedAt={threat.created_at as string}
              signals={[]}
            />
          ))}
        </div>
      ) : (
        <div className="glass-card p-12 text-center">
          <p className="text-text-muted">No threats found</p>
        </div>
      )}

      {data?.total > 20 && (
        <div className="flex items-center justify-center gap-4">
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
  );
}
