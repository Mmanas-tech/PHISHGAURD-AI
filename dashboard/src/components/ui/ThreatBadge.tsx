import clsx from "clsx";

interface ThreatBadgeProps {
  level: string;
  size?: "sm" | "md" | "lg";
  showDot?: boolean;
}

const levelStyles: Record<string, string> = {
  safe: "bg-accent-green/10 text-accent-green border-accent-green/20",
  low: "bg-accent-green/10 text-accent-green border-accent-green/20",
  medium: "bg-accent-amber/10 text-accent-amber border-accent-amber/20",
  high: "bg-accent-red/10 text-accent-red border-accent-red/20",
  critical: "bg-accent-red/20 text-accent-red border-accent-red/30",
};

const dotStyles: Record<string, string> = {
  safe: "bg-accent-green",
  low: "bg-accent-green",
  medium: "bg-accent-amber",
  high: "bg-accent-red",
  critical: "bg-accent-red animate-pulse",
};

const sizeStyles = {
  sm: "text-[10px] px-2 py-0.5",
  md: "text-xs px-2.5 py-1",
  lg: "text-sm px-3 py-1.5",
};

export default function ThreatBadge({
  level,
  size = "md",
  showDot = true,
}: ThreatBadgeProps) {
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1.5 rounded-full border font-semibold uppercase tracking-wider",
        levelStyles[level] || levelStyles.unknown,
        sizeStyles[size]
      )}
    >
      {showDot && (
        <span
          className={clsx(
            "w-1.5 h-1.5 rounded-full",
            dotStyles[level] || dotStyles.unknown
          )}
        />
      )}
      {level}
    </span>
  );
}
