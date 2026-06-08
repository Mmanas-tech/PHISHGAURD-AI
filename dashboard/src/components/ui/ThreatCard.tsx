import { motion } from "framer-motion";
import ThreatBadge from "./ThreatBadge";
import { ExternalLink } from "lucide-react";

interface ThreatCardProps {
  domain: string;
  url: string;
  riskScore: number;
  threatLevel: string;
  threatType: string;
  detectedAt: string;
  signals: string[];
  onClick?: () => void;
}

export default function ThreatCard({
  domain,
  url,
  riskScore,
  threatLevel,
  threatType,
  detectedAt,
  signals,
  onClick,
}: ThreatCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      whileHover={{ scale: 1.01 }}
      className="glass-card-hover p-4 cursor-pointer"
      onClick={onClick}
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h4 className="text-sm font-semibold text-text-primary truncate">
              {domain}
            </h4>
            <ExternalLink className="w-3 h-3 text-text-muted flex-shrink-0" />
          </div>
          <p className="text-xs text-text-muted font-mono truncate">{url}</p>
        </div>
        <ThreatBadge level={threatLevel} size="sm" />
      </div>

      <div className="flex items-center gap-4 mb-3">
        <div>
          <p className="text-[10px] text-text-muted uppercase tracking-wider">Score</p>
          <p
            className={`text-lg font-bold font-mono ${
              riskScore > 70
                ? "text-accent-red"
                : riskScore > 30
                  ? "text-accent-amber"
                  : "text-accent-green"
            }`}
          >
            {riskScore}
          </p>
        </div>
        <div className="h-8 w-px bg-border" />
        <div>
          <p className="text-[10px] text-text-muted uppercase tracking-wider">Type</p>
          <p className="text-xs font-medium text-text-primary capitalize">
            {threatType.replace(/_/g, " ")}
          </p>
        </div>
        <div className="h-8 w-px bg-border" />
        <div>
          <p className="text-[10px] text-text-muted uppercase tracking-wider">Detected</p>
          <p className="text-xs text-text-muted">
            {new Date(detectedAt).toLocaleDateString()}
          </p>
        </div>
      </div>

      {signals.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {signals.slice(0, 3).map((signal, i) => (
            <span
              key={i}
              className="text-[10px] px-2 py-0.5 rounded-full bg-white/5 text-text-muted"
            >
              {signal}
            </span>
          ))}
          {signals.length > 3 && (
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-white/5 text-text-muted">
              +{signals.length - 3} more
            </span>
          )}
        </div>
      )}
    </motion.div>
  );
}
