import clsx from "clsx";

interface LoadingSkeletonProps {
  className?: string;
  lines?: number;
  variant?: "text" | "card" | "chart" | "table";
}

export default function LoadingSkeleton({
  className,
  lines = 3,
  variant = "text",
}: LoadingSkeletonProps) {
  if (variant === "card") {
    return (
      <div className={clsx("glass-card p-6 space-y-4", className)}>
        <div className="skeleton h-4 w-1/3 rounded" />
        <div className="skeleton h-8 w-1/2 rounded" />
        <div className="skeleton h-3 w-2/3 rounded" />
      </div>
    );
  }

  if (variant === "chart") {
    return (
      <div className={clsx("glass-card p-6", className)}>
        <div className="skeleton h-4 w-1/4 rounded mb-4" />
        <div className="skeleton h-48 w-full rounded" />
      </div>
    );
  }

  if (variant === "table") {
    return (
      <div className={clsx("glass-card overflow-hidden", className)}>
        <div className="p-4 border-b border-border">
          <div className="skeleton h-4 w-1/4 rounded" />
        </div>
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="p-4 border-b border-border flex items-center gap-4">
            <div className="skeleton h-4 w-1/4 rounded" />
            <div className="skeleton h-4 w-1/6 rounded" />
            <div className="skeleton h-4 w-1/8 rounded" />
            <div className="skeleton h-4 w-1/6 rounded" />
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className={clsx("space-y-3", className)}>
      {Array.from({ length: lines }).map((_, i) => (
        <div
          key={i}
          className={clsx(
            "skeleton h-4 rounded",
            i === lines - 1 ? "w-2/3" : "w-full"
          )}
        />
      ))}
    </div>
  );
}
