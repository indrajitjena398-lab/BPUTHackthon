"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldCheck, Lock, ArrowRight, UserCheck } from "lucide-react";
import { switchDemoRole } from "@/lib/api";

const PRESET_ROLES = [
  { role: "Security Analyst", email: "analyst@cyberguard.local", name: "Ankit Kumar", desc: "Threat hunting, investigations & playbook execution" },
  { role: "Admin", email: "admin@cyberguard.local", name: "Eleanor Vance", desc: "Full tenant administration, API keys & policy rules" },
  { role: "SOC Operator", email: "operator@cyberguard.local", name: "Marcus Chen", desc: "Tier-1/2 alert triage, event containment & escalation" },
  { role: "Organisation Manager", email: "manager@cyberguard.local", name: "Dr. Sarah Al-Mansoor", desc: "CISO governance, audit metrics & risk summaries" },
  { role: "Viewer", email: "viewer@cyberguard.local", name: "David Ross", desc: "Read-only compliance telemetry & security reports" }
];

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("analyst@cyberguard.local");
  const [password, setPassword] = useState("••••••••••••");
  const [loading, setLoading] = useState(false);

  const handleLogin = async (selectedRole?: string) => {
    setLoading(true);
    try {
      const targetRole = selectedRole || "Security Analyst";
      await switchDemoRole(targetRole);
      router.push("/dashboard");
    } catch (e) {
      console.error(e);
      router.push("/dashboard");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-6 bg-slate-50">
      <div className="w-full max-w-md bg-white border border-slate-200 rounded-2xl shadow-sm p-8">
        {/* Header */}
        <div className="flex flex-col items-center text-center mb-8">
          <div className="w-12 h-12 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-sm mb-3">
            <ShieldCheck className="w-7 h-7" />
          </div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">CYBERGUARD</h1>
          <p className="text-xs text-slate-500 mt-1 max-w-xs">
            Enterprise Threat, Phishing & Digital Impersonation Defense Platform
          </p>
        </div>

        {/* Standard Form */}
        <div className="space-y-4 mb-6">
          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">Corporate Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3.5 py-2 border border-slate-200 rounded-lg text-sm text-slate-900 bg-slate-50 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-colors"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">Password / SSO Token</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3.5 py-2 border border-slate-200 rounded-lg text-sm text-slate-900 bg-slate-50 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-colors"
            />
          </div>
          <button
            onClick={() => handleLogin()}
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm py-2.5 rounded-lg shadow-xs flex items-center justify-center gap-2 transition-colors"
          >
            <span>{loading ? "Authenticating..." : "Sign In with SSO"}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>

        {/* 1-Click Demo RBAC Switcher */}
        <div className="pt-6 border-t border-slate-100">
          <div className="flex items-center gap-2 mb-3">
            <UserCheck className="w-4 h-4 text-blue-600" />
            <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">
              Quick Demo Persona Switcher
            </span>
          </div>
          <div className="space-y-2">
            {PRESET_ROLES.map((p) => (
              <button
                key={p.role}
                onClick={() => handleLogin(p.role)}
                className="w-full text-left p-2.5 rounded-lg border border-slate-200 hover:border-blue-300 hover:bg-blue-50/50 transition-colors group flex items-start justify-between"
              >
                <div>
                  <div className="text-xs font-semibold text-slate-900 group-hover:text-blue-700">
                    {p.name}
                  </div>
                  <div className="text-[11px] text-slate-500 leading-tight">
                    <span className="font-medium text-blue-600">{p.role}</span> &bull; {p.desc}
                  </div>
                </div>
                <ArrowRight className="w-3.5 h-3.5 text-slate-300 group-hover:text-blue-600 mt-1" />
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
