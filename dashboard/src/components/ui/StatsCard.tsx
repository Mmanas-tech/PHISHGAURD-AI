import { motion } from "framer-motion";
import clsx from "clsx";
import AnimatedCounter from "./AnimatedCounter";

interface StatsCardProps {
  title: string;
  value: number;
  suffix?: string;
  prefix?: string;
  icon: React.ReactNode;
  trend?: "up" | "down" | "neutral";
  trendValue?: string;
  accentColor: "cyan" | "red" | "green" | "amber";
  delay?: number;
}

const accentMap = {
  cyan: {
    border: "border-accent-cyan/20",
    bg: "bg-accent-cyan/10",
    text: "text-accent-cyan",
    glow: "hover:shadow-[0_0_30px_rgba(0,212,255,0.1)]",
  },
  red: {
    border: "border-accent-red/20",
    bg: "bg-accent-red/10",
    text: "text-accent-red",
    glow: "hover:shadow-[0_0_30px_rgba(239,68,68,0.1)]",
  },
  green: {
    border: "border-accent-green/20",
    bg: "bg-accent-green/10",
    text: "text-accent-green",
    glow: "hover:shadow-[0_0_30px_rgba(16,185,129,0.1)]",
  },
  amber: {
    border: "border-accent-amber/20",
    bg: "bg-accent-amber/10",
    text: "text-accent-amber",
    glow: "hover:shadow-[0_0_30px_rgba(245,158,11,0.1)]",
  },
};

export default function StatsCard({
  title,
  value,
  suffix,
  prefix,
  icon,
  trend,
  trendValue,
  accentColor,
  delay = 0,
}: StatsCardProps) {
  const accent = accentMap[accentColor];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay }}
      className={clsx(
        "glass-card p-6 transition-all duration-300",
        accent.glow
      )}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-text-muted mb-2">{title}</p>
          <p className={clsx("text-3xl font-bold", accent.text)}>
            <AnimatedCounter value={value} suffix={suffix} prefix={prefix} />
          </p>
          {trend && trendValue && (
            <p
              className={clsx(
                "text-xs mt-2 font-medium",
                trend === "up" ? "text-accent-green" : trend === "down" ? "text-accent-red" : "text-text-muted"
              )}
            >
              {trend === "up" ? "↑" : trend === "down" ? "↓" : "→"} {trendValue}
            </p>
          )}
        </div>
        <div className={clsx("p-3 rounded-xl", accent.bg)}>{icon}</div>
      </div>
    </motion.div>
  );
}
