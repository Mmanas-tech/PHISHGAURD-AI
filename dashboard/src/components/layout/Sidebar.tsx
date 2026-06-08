import { NavLink } from "react-router-dom";
import { useAuthStore } from "../../store/auth-store";
import { LayoutDashboard, Scan, Shield, Settings, LogOut } from "lucide-react";

const navItems = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/scans", label: "Scans", icon: Scan },
  { to: "/threats", label: "Threats", icon: Shield },
  { to: "/settings", label: "Settings", icon: Settings },
];

export default function Sidebar() {
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);

  return (
    <aside className="w-60 h-screen bg-base-elevated border-r border-border flex flex-col">
      <div className="p-6 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="relative">
            <Shield className="w-8 h-8 text-accent-cyan" />
            <div className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-accent-green rounded-full animate-pulse" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-gradient">PhishGuard</h1>
            <p className="text-xs text-text-muted">AI Protection</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-4 space-y-1">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 ${
                isActive
                  ? "bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20"
                  : "text-text-muted hover:text-text-primary hover:bg-white/5"
              }`
            }
          >
            <item.icon className="w-5 h-5" />
            <span className="text-sm font-medium">{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-border">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-full bg-accent-cyan/20 flex items-center justify-center">
              <span className="text-xs font-bold text-accent-cyan">
                {user?.email?.charAt(0).toUpperCase() || "U"}
              </span>
            </div>
            <div>
              <p className="text-xs font-medium text-text-primary truncate max-w-[120px]">
                {user?.email || "User"}
              </p>
              <p className="text-[10px] text-text-muted capitalize">
                {user?.tier || "free"} plan
              </p>
            </div>
          </div>
          <button
            onClick={logout}
            className="p-2 text-text-muted hover:text-accent-red transition-colors rounded-lg hover:bg-white/5"
            title="Logout"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </aside>
  );
}
