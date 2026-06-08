import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Shield, Scan, Zap, Clock } from "lucide-react";
import api from "../services/api";
import StatsCard from "../components/ui/StatsCard";
import RiskGauge from "../components/ui/RiskGauge";
import ThreatCard from "../components/ui/ThreatCard";
import LoadingSkeleton from "../components/ui/LoadingSkeleton";
import ScanForm from "../components/ui/ScanForm";
import ThreatChart from "../components/charts/ThreatChart";
import { useState } from "react";

interface DashboardStats {
  scans_today: number;
  threats_blocked_today: number;
  detection_accuracy: number;
  avg_response_time_ms: number;
}

interface ThreatItem {
  id: string;
  url: string;
  domain: string;
  risk_score: number;
  threat_level: string;
  threat_type: string;
  created_at: string;
  signals: string[];
}

export default function Dashboard() {
  const [isScanning, setIsScanning] = useState(false);

  const { data: stats, isLoading: statsLoading } = useQuery<DashboardStats>({
    queryKey: ["dashboard-stats"],
    queryFn: async () => {
      const res = await api.get("/dashboard/stats");
      return res.data;
    },
  });

  const { data: threatsData, isLoading: threatsLoading } = useQuery({
    queryKey: ["dashboard-threats"],
    queryFn: async () => {
      const res = await api.get("/dashboard/threats?page_size=5");
      return res.data;
    },
  });

  const handleScan = async (url: string) => {
    setIsScanning(true);
    try {
      await api.post("/scan", { url });
    } catch {
      // handle error
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-sm text-text-muted mt-1">
            Real-time threat monitoring and analysis
          </p>
        </div>
      </motion.div>

      <ScanForm onScan={handleScan} isLoading={isScanning} />

      {statsLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <LoadingSkeleton key={i} variant="card" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatsCard
            title="Threats Blocked Today"
            value={stats?.threats_blocked_today ?? 0}
            icon={<Shield className="w-5 h-5 text-accent-red" />}
            accentColor="red"
            trend="up"
            trendValue="+12% from yesterday"
            delay={0}
          />
          <StatsCard
            title="Sites Scanned Today"
            value={stats?.scans_today ?? 0}
            icon={<Scan className="w-5 h-5 text-accent-cyan" />}
            accentColor="cyan"
            trend="up"
            trendValue="+8% from yesterday"
            delay={0.1}
          />
          <StatsCard
            title="Detection Accuracy"
            value={stats?.detection_accuracy ?? 98.4}
            suffix="%"
            icon={<Zap className="w-5 h-5 text-accent-green" />}
            accentColor="green"
            delay={0.2}
          />
          <StatsCard
            title="Avg Response Time"
            value={Math.round(stats?.avg_response_time_ms ?? 0)}
            suffix="ms"
            icon={<Clock className="w-5 h-5 text-accent-amber" />}
            accentColor="amber"
            delay={0.3}
          />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          {threatsLoading ? (
            <LoadingSkeleton variant="chart" />
          ) : (
            <ThreatChart />
          )}
        </div>

        <div className="glass-card p-6">
          <h3 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-4">
            Threat Level Overview
          </h3>
          <div className="flex justify-center">
            <RiskGauge
              score={Math.round(
                threatsData?.items?.[0]?.risk_score ?? 0
              )}
              size={180}
            />
          </div>
          <div className="mt-4 space-y-2">
            {["safe", "low", "medium", "high", "critical"].map((level) => {
              const count =
                threatsData?.items?.filter(
                  (t: ThreatItem) => t.threat_level === level
                ).length ?? 0;
              return (
                <div key={level} className="flex items-center justify-between text-xs">
                  <span className="capitalize text-text-muted">{level}</span>
                  <span className="font-mono text-text-primary">{count}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div>
        <h3 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-4">
          Recent Threats
        </h3>
        {threatsLoading ? (
          <div className="space-y-3">
            {[...Array(3)].map((_, i) => (
              <LoadingSkeleton key={i} variant="card" />
            ))}
          </div>
        ) : threatsData?.items?.length > 0 ? (
          <div className="space-y-3">
            {threatsData.items.slice(0, 5).map((threat: ThreatItem) => (
              <ThreatCard
                key={threat.id}
                domain={threat.domain}
                url={threat.url}
                riskScore={threat.risk_score}
                threatLevel={threat.threat_level}
                threatType={threat.threat_type}
                detectedAt={threat.created_at}
                signals={threat.signals || []}
              />
            ))}
          </div>
        ) : (
          <div className="glass-card p-8 text-center">
            <Shield className="w-12 h-12 text-text-muted mx-auto mb-3" />
            <p className="text-text-muted">No threats detected yet</p>
          </div>
        )}
      </div>
    </div>
  );
}
