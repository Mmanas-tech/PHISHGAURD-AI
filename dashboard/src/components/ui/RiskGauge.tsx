import { motion } from "framer-motion";
import clsx from "clsx";

interface RiskGaugeProps {
  score: number;
  size?: number;
  showLabel?: boolean;
}

export default function RiskGauge({
  score,
  size = 160,
  showLabel = true,
}: RiskGaugeProps) {
  const circumference = 2 * Math.PI * 70;
  const offset = circumference - (score / 100) * circumference;

  const getColor = (s: number) => {
    if (s < 20) return "#10b981";
    if (s < 40) return "#10b981";
    if (s < 60) return "#f59e0b";
    if (s < 80) return "#ef4444";
    return "#ef4444";
  };

  const getLevel = (s: number) => {
    if (s < 20) return "SAFE";
    if (s < 40) return "LOW";
    if (s < 60) return "MEDIUM";
    if (s < 80) return "HIGH";
    return "CRITICAL";
  };

  const color = getColor(score);
  const level = getLevel(score);

  return (
    <div className="relative inline-flex flex-col items-center">
      <svg
        width={size}
        height={size}
        viewBox="0 0 160 160"
        className="transform -rotate-90"
      >
        <circle
          cx="80"
          cy="80"
          r="70"
          fill="none"
          stroke="rgba(255,255,255,0.05)"
          strokeWidth="10"
        />
        <motion.circle
          cx="80"
          cy="80"
          r="70"
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1, ease: "easeOut" }}
          style={{
            filter: `drop-shadow(0 0 8px ${color}50)`,
          }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <motion.span
          className="text-4xl font-bold font-mono"
          initial={{ opacity: 0, scale: 0.5 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5, delay: 0.3 }}
        >
          {score}
        </motion.span>
        {showLabel && (
          <motion.span
            className="text-xs font-semibold tracking-widest mt-1"
            style={{ color }}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
          >
            {level}
          </motion.span>
        )}
      </div>
    </div>
  );
}
