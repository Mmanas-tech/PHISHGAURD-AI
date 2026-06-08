import { useState } from "react";
import { motion } from "framer-motion";
import { Search, Loader2 } from "lucide-react";

interface ScanFormProps {
  onScan: (url: string) => void;
  isLoading?: boolean;
}

export default function ScanForm({ onScan, isLoading }: ScanFormProps) {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    const trimmed = url.trim();
    if (!trimmed) {
      setError("Please enter a URL");
      return;
    }

    try {
      const parsed = new URL(
        trimmed.startsWith("http") ? trimmed : `https://${trimmed}`
      );
      onScan(parsed.href);
      setUrl("");
    } catch {
      setError("Please enter a valid URL");
    }
  };

  return (
    <motion.form
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      onSubmit={handleSubmit}
      className="flex gap-3"
    >
      <div className="flex-1 relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="Enter URL to scan (e.g., example.com)"
          className="input-field pl-10"
          disabled={isLoading}
        />
        {error && (
          <motion.p
            initial={{ opacity: 0, y: -5 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-xs text-accent-red mt-1"
          >
            {error}
          </motion.p>
        )}
      </div>
      <button
        type="submit"
        disabled={isLoading || !url.trim()}
        className="btn-primary flex items-center gap-2"
      >
        {isLoading ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : (
          <Search className="w-4 h-4" />
        )}
        Scan
      </button>
    </motion.form>
  );
}
