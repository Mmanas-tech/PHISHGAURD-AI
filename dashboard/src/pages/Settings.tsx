import { useState } from "react";
import { motion } from "framer-motion";
import { Shield, Bell, Eye, Download, Key } from "lucide-react";

export default function Settings() {
  const [protectionLevel, setProtectionLevel] = useState("balanced");
  const [notifications, setNotifications] = useState(true);
  const [dataSharing, setDataSharing] = useState("anonymized");

  return (
    <div className="space-y-6 max-w-2xl">
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-sm text-text-muted mt-1">
          Configure your PhishGuard protection
        </p>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="glass-card p-6"
      >
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-5 h-5 text-accent-cyan" />
          <h3 className="text-sm font-semibold">Protection Level</h3>
        </div>
        <div className="space-y-3">
          {[
            {
              value: "paranoid",
              label: "Paranoid",
              desc: "Maximum security. May flag some legitimate sites.",
            },
            {
              value: "balanced",
              label: "Balanced",
              desc: "Recommended. Good protection with minimal false positives.",
            },
            {
              value: "relaxed",
              label: "Relaxed",
              desc: "Basic protection. Fewer warnings, higher risk.",
            },
          ].map((option) => (
            <label
              key={option.value}
              className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
                protectionLevel === option.value
                  ? "border-accent-cyan/30 bg-accent-cyan/5"
                  : "border-border hover:border-white/10"
              }`}
            >
              <input
                type="radio"
                name="protection"
                value={option.value}
                checked={protectionLevel === option.value}
                onChange={(e) => setProtectionLevel(e.target.value)}
                className="mt-1 accent-accent-cyan"
              />
              <div>
                <p className="text-sm font-medium">{option.label}</p>
                <p className="text-xs text-text-muted">{option.desc}</p>
              </div>
            </label>
          ))}
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="glass-card p-6"
      >
        <div className="flex items-center gap-3 mb-4">
          <Bell className="w-5 h-5 text-accent-amber" />
          <h3 className="text-sm font-semibold">Notifications</h3>
        </div>
        <label className="flex items-center justify-between">
          <div>
            <p className="text-sm">Enable threat notifications</p>
            <p className="text-xs text-text-muted">
              Get alerted when phishing is detected
            </p>
          </div>
          <div
            className={`w-12 h-6 rounded-full transition-colors cursor-pointer ${
              notifications ? "bg-accent-cyan" : "bg-white/10"
            }`}
            onClick={() => setNotifications(!notifications)}
          >
            <div
              className={`w-5 h-5 rounded-full bg-white shadow transition-transform mt-0.5 ${
                notifications ? "translate-x-6" : "translate-x-0.5"
              }`}
            />
          </div>
        </label>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="glass-card p-6"
      >
        <div className="flex items-center gap-3 mb-4">
          <Eye className="w-5 h-5 text-accent-green" />
          <h3 className="text-sm font-semibold">Privacy</h3>
        </div>
        <div>
          <p className="text-sm mb-2">Data sharing preference</p>
          <select
            value={dataSharing}
            onChange={(e) => setDataSharing(e.target.value)}
            className="input-field"
          >
            <option value="none">No data sharing</option>
            <option value="anonymized">Anonymized data only</option>
            <option value="full">Full data sharing</option>
          </select>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="glass-card p-6"
      >
        <div className="flex items-center gap-3 mb-4">
          <Key className="w-5 h-5 text-text-muted" />
          <h3 className="text-sm font-semibold">API Keys</h3>
        </div>
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <input
              type="password"
              value="sk-xxxxxxxxxxxxxxxxxxxx"
              readOnly
              className="input-field flex-1 font-mono text-xs"
            />
            <button className="btn-secondary text-xs">Copy</button>
          </div>
          <button className="btn-secondary text-xs">Generate New Key</button>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="glass-card p-6"
      >
        <div className="flex items-center gap-3 mb-4">
          <Download className="w-5 h-5 text-text-muted" />
          <h3 className="text-sm font-semibold">Data Export</h3>
        </div>
        <p className="text-xs text-text-muted mb-3">
          Export all your scan data (GDPR compliance)
        </p>
        <button className="btn-secondary text-xs">Export All Data</button>
      </motion.div>
    </div>
  );
}
