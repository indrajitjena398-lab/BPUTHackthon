"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ShieldAlert,
  LayoutDashboard,
  ScanSearch,
  AlertTriangle,
  Database,
  Network,
  Activity,
  FileText,
  Bot,
  Settings,
  UserCheck,
  ChevronDown
} from "lucide-react";
import { getCurrentUser, switchDemoRole, UserProfile } from "@/lib/api";

const NAV_ITEMS = [
  { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
  { name: "Threat Detection", href: "/threat-detection", icon: ScanSearch },
  { name: "Incidents", href: "/incidents", icon: AlertTriangle },
  { name: "Threat Intelligence", href: "/threat-intelligence", icon: Database },
  { name: "Attack Graph", href: "/attack-graph", icon: Network },
  { name: "Behaviour Analytics", href: "/behaviour-analytics", icon: Activity },
  { name: "Reports", href: "/reports", icon: FileText },
  { name: "AI Security Assistant", href: "/assistant", icon: Bot },
  { name: "Settings & Models", href: "/settings", icon: Settings },
];

const ROLES = ["Admin", "Security Analyst", "SOC Operator", "Organisation Manager", "Viewer"];

export default function Sidebar() {
  const pathname = usePathname();
  const [user, setUser] = useState<UserProfile | null>(null);
  const [roleDropdownOpen, setRoleDropdownOpen] = useState(false);

  useEffect(() => {
    setUser(getCurrentUser());
  }, []);

  const handleRoleChange = async (newRole: string) => {
    try {
      const updated = await switchDemoRole(newRole);
      setUser(updated);
      setRoleDropdownOpen(false);
      window.location.reload();
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <aside className="w-64 bg-white border-r border-slate-200 flex flex-col h-screen fixed left-0 top-0 z-30 select-none">
      {/* Brand Header */}
      <div className="h-16 border-b border-slate-100 flex items-center px-6 gap-3">
        <div className="w-9 h-9 rounded-lg bg-blue-600 flex items-center justify-center text-white shadow-sm">
          <ShieldAlert className="w-5 h-5" />
        </div>
        <div>
          <span className="font-bold text-slate-900 tracking-tight text-base block leading-none">
            CYBERGUARD
          </span>
          <span className="text-[11px] text-slate-500 font-medium tracking-wide">
            ENTERPRISE DEFENSE
          </span>
        </div>
      </div>

      {/* Nav Links */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <div className="px-3 pb-2 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
          Security Operations
        </div>
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href || (item.href !== "/dashboard" && pathname?.startsWith(item.href));
          return (
            <Link
              key={item.name}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? "bg-blue-50 text-blue-700 font-semibold"
                  : "text-slate-600 hover:text-slate-900 hover:bg-slate-50"
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? "text-blue-600" : "text-slate-400"}`} />
              {item.name}
            </Link>
          );
        })}
      </nav>

      {/* Role Switcher & User Profile */}
      <div className="p-4 border-t border-slate-100 bg-slate-50/50">
        <div className="relative">
          <button
            onClick={() => setRoleDropdownOpen(!roleDropdownOpen)}
            className="w-full text-left bg-white border border-slate-200 rounded-lg p-2.5 shadow-xs hover:border-slate-300 transition-colors flex items-center justify-between"
          >
            <div className="flex items-center gap-2 overflow-hidden">
              <div className="w-7 h-7 rounded-full bg-blue-100 text-blue-700 flex items-center justify-center text-xs font-semibold shrink-0">
                <UserCheck className="w-3.5 h-3.5" />
              </div>
              <div className="overflow-hidden">
                <div className="text-xs font-semibold text-slate-900 truncate">
                  {user?.full_name || "Ankit Kumar"}
                </div>
                <div className="text-[10px] text-blue-600 font-medium truncate">
                  Role: {user?.role || "Security Analyst"}
                </div>
              </div>
            </div>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400 shrink-0" />
          </button>

          {roleDropdownOpen && (
            <div className="absolute bottom-full left-0 w-full mb-1 bg-white border border-slate-200 rounded-lg shadow-lg py-1 z-50">
              <div className="px-3 py-1.5 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Switch Demo Role (RBAC)
              </div>
              {ROLES.map((r) => (
                <button
                  key={r}
                  onClick={() => handleRoleChange(r)}
                  className={`w-full text-left px-3 py-1.5 text-xs hover:bg-slate-50 flex items-center justify-between ${
                    user?.role === r ? "font-semibold text-blue-600 bg-blue-50/50" : "text-slate-700"
                  }`}
                >
                  <span>{r}</span>
                  {user?.role === r && <span className="w-1.5 h-1.5 rounded-full bg-blue-600" />}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </aside>
  );
}
