"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Activity,
  ArrowUpRight,
  TrendingUp,
  CheckCircle2,
  Clock,
  Sparkles,
  Users,
  Server,
  Zap,
  Layers,
  ChevronRight
} from "lucide-react";
import { fetchDashboardMetrics } from "@/lib/api";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from "recharts";

const RISK_COLORS: Record<string, string> = {
  "Safe (0-20)": "#10b981",
  "Low (21-40)": "#3b82f6",
  "Medium (41-60)": "#f59e0b",
  "High (61-80)": "#f97316",
  "Critical (81-100)": "#ef4444"
};

export default function DashboardPage() {
  const [metrics, setMetrics] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardMetrics()
      .then((data) => setMetrics(data))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, []);

  if (loading || !metrics) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="h-8 bg-slate-200 rounded w-1/4"></div>
        <div className="grid grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-28 bg-slate-200 rounded-xl"></div>
          ))}
        </div>
      </div>
    );
  }

  // Format data for Recharts
  const threatCategoriesData = Object.entries(metrics.threats_by_category).map(([key, val]) => ({
    name: key,
    count: val as number
  }));

  const riskDistributionData = Object.entries(metrics.risk_distribution).map(([key, val]) => ({
    name: key,
    value: Math.max(val as number, 1)
  }));

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      {/* Welcome Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">Security Command & Telemetry Center</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Near real-time multi-source threat fusion, identity masquerade alerts, and autonomous defense monitoring.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link
            href="/threat-detection"
            className="bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold px-4 py-2 rounded-lg shadow-xs flex items-center gap-1.5 transition-colors"
          >
            <span>Run Multi-Source Analysis</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>

      {/* KPI Cards: Security Overview */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Events Analysed */}
        <div className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider mb-2">
            <span>Events Analysed</span>
            <Activity className="w-4 h-4 text-blue-600" />
          </div>
          <div className="text-2xl font-bold text-slate-900">
            {metrics.events_analyzed.toLocaleString()}
          </div>
          <div className="mt-2 flex items-center text-[11px] text-slate-500 gap-1">
            <span className="text-emerald-600 font-semibold flex items-center">
              <TrendingUp className="w-3 h-3 mr-0.5" /> +14.2%
            </span>
            <span>vs previous 24h</span>
          </div>
        </div>

        {/* Threats Detected */}
        <div className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider mb-2">
            <span>Threats Detected</span>
            <ShieldAlert className="w-4 h-4 text-amber-500" />
          </div>
          <div className="text-2xl font-bold text-slate-900">
            {metrics.threats_detected.toLocaleString()}
          </div>
          <div className="mt-2 text-[11px] text-slate-500">
            Across tech & human layers
          </div>
        </div>

        {/* Critical Threats */}
        <div className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider mb-2">
            <span>Critical Threats</span>
            <AlertTriangle className="w-4 h-4 text-rose-600" />
          </div>
          <div className="text-2xl font-bold text-rose-600">
            {metrics.critical_threats}
          </div>
          <div className="mt-2 text-[11px] text-rose-600 font-medium">
            Priority containment active
          </div>
        </div>

        {/* Open Incidents */}
        <div className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider mb-2">
            <span>Open Incidents</span>
            <Clock className="w-4 h-4 text-blue-600" />
          </div>
          <div className="text-2xl font-bold text-slate-900">
            {metrics.open_incidents}
          </div>
          <div className="mt-2 text-[11px] text-slate-500">
            Active SOC lifecycle queue
          </div>
        </div>
      </div>

      {/* Specific Threat Category Tally Badges (Explicitly listed on Page 5 of Problem Statement) */}
      <div className="bg-white border border-slate-200/90 rounded-xl p-4 shadow-xs">
        <div className="text-xs font-bold text-slate-700 uppercase tracking-wider mb-3 flex items-center justify-between">
          <span>Targeted Threat Vectors Breakdown</span>
          <span className="text-[11px] font-normal text-slate-400">Near Real-Time Telemetry</span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          <div className="p-3 bg-slate-50/70 border border-slate-200 rounded-lg">
            <span className="text-[10px] text-slate-400 font-bold uppercase block">Phishing Attempts</span>
            <div className="text-xl font-extrabold text-blue-600 mt-0.5">{metrics.phishing_attempts}</div>
            <span className="text-[10px] text-slate-500">Email, SMS, QR Quishing</span>
          </div>
          <div className="p-3 bg-slate-50/70 border border-slate-200 rounded-lg">
            <span className="text-[10px] text-slate-400 font-bold uppercase block">Impersonation</span>
            <div className="text-xl font-extrabold text-purple-600 mt-0.5">{metrics.impersonation_attempts}</div>
            <span className="text-[10px] text-slate-500">VC, Govt, C-Suite BEC</span>
          </div>
          <div className="p-3 bg-slate-50/70 border border-slate-200 rounded-lg">
            <span className="text-[10px] text-slate-400 font-bold uppercase block">Suspected Deepfakes</span>
            <div className="text-xl font-extrabold text-indigo-600 mt-0.5">{metrics.suspected_deepfakes}</div>
            <span className="text-[10px] text-slate-500">Synthetic Voice & Video</span>
          </div>
          <div className="p-3 bg-slate-50/70 border border-slate-200 rounded-lg">
            <span className="text-[10px] text-slate-400 font-bold uppercase block">Account Takeovers</span>
            <div className="text-xl font-extrabold text-rose-600 mt-0.5">{metrics.account_takeover_attempts}</div>
            <span className="text-[10px] text-slate-500">Impossible Travel & Spraying</span>
          </div>
          <div className="p-3 bg-slate-50/70 border border-slate-200 rounded-lg">
            <span className="text-[10px] text-slate-400 font-bold uppercase block">Network Threats</span>
            <div className="text-xl font-extrabold text-amber-600 mt-0.5">{metrics.network_threats}</div>
            <span className="text-[10px] text-slate-500">DNS Tunneling & Scans</span>
          </div>
        </div>
      </div>

      {/* Main Grid: Threat Overview & Risk Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Overview Bar Chart */}
        <div className="lg:col-span-2 bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-slate-900">Multi-Model Threat Distribution</h3>
              <p className="text-xs text-slate-500">Normalized detections across specialized AI engines</p>
            </div>
            <span className="text-xs font-semibold text-blue-600 bg-blue-50 px-2.5 py-1 rounded-md">
              7 Active Detection Engines
            </span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={threatCategoriesData} layout="vertical" margin={{ left: 30, right: 20 }}>
                <XAxis type="number" stroke="#94a3b8" fontSize={12} tickLine={false} />
                <YAxis dataKey="name" type="category" stroke="#64748b" fontSize={12} tickLine={false} width={110} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#ffffff", borderColor: "#e2e8f0", borderRadius: "8px", fontSize: "12px" }}
                />
                <Bar dataKey="count" fill="#2563eb" radius={[0, 6, 6, 0]} barSize={18} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Distribution Donut Chart */}
        <div className="bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs flex flex-col">
          <div className="mb-2">
            <h3 className="text-sm font-bold text-slate-900">Risk Severity Distribution</h3>
            <p className="text-xs text-slate-500">Unified 0–100 threat score breakdown</p>
          </div>

          <div className="h-52 w-full my-auto">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskDistributionData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {riskDistributionData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={RISK_COLORS[entry.name] || "#94a3b8"} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: "#ffffff", borderColor: "#e2e8f0", borderRadius: "8px", fontSize: "12px" }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Legend */}
          <div className="grid grid-cols-2 gap-1.5 pt-3 border-t border-slate-100 text-[11px]">
            {Object.entries(RISK_COLORS).map(([name, color]) => (
              <div key={name} className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: color }} />
                <span className="text-slate-600 truncate">{name}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Cyber Attack Kill Chain Timeline (Requested on Page 5) */}
      <div className="bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Layers className="w-4 h-4 text-blue-600" />
              <span>Cyber Attack Kill Chain Timeline</span>
            </h3>
            <p className="text-xs text-slate-500">Live multi-stage adversary campaign progression</p>
          </div>
          <span className="text-xs text-emerald-600 font-semibold bg-emerald-50 px-2 py-0.5 rounded">
            Near Real-Time Defense
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {metrics.attack_timeline?.map((step: any, idx: number) => (
            <div key={idx} className="p-3.5 bg-slate-50/70 border border-slate-200 rounded-xl flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between text-[11px] mb-1">
                  <span className="font-mono font-bold text-blue-600">{step.time}</span>
                  <span className="text-[10px] font-mono bg-blue-100 text-blue-700 px-1.5 py-0.2 rounded">
                    {step.technique}
                  </span>
                </div>
                <div className="text-xs font-bold text-slate-900">{step.stage}</div>
                <div className="text-[11px] text-slate-600 mt-1 line-clamp-2">{step.event}</div>
              </div>
              <div className="mt-3 pt-2 border-t border-slate-200/60 flex items-center justify-between text-[10px]">
                <span className="text-slate-400">Mitigation:</span>
                <span className="font-semibold text-emerald-700">{step.status}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Frequently Targeted Users & Services (Requested on Page 5) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Frequently Targeted Users */}
        <div className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Users className="w-4 h-4 text-blue-600" />
              <span>Frequently Targeted Identities (High-Risk Profiles)</span>
            </h3>
            <span className="text-[10px] text-slate-400 uppercase font-semibold">Priority Protection</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-100 text-slate-400 font-semibold uppercase">
                  <th className="pb-2">Identity / Account</th>
                  <th className="pb-2">Department / Authority</th>
                  <th className="pb-2">Incidents</th>
                  <th className="pb-2 text-right">Risk Tier</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-slate-700">
                {metrics.frequently_targeted_users?.map((u: any, i: number) => (
                  <tr key={i} className="hover:bg-slate-50/50">
                    <td className="py-2.5 font-semibold text-slate-900">{u.user}</td>
                    <td className="py-2.5 text-slate-600">{u.department}</td>
                    <td className="py-2.5 font-bold text-slate-800">{u.attacks} attempts</td>
                    <td className="py-2.5 text-right">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        u.risk_level === "CRITICAL" ? "bg-rose-100 text-rose-700" : "bg-orange-100 text-orange-700"
                      }`}>
                        {u.risk_level}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Frequently Targeted Services */}
        <div className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Server className="w-4 h-4 text-blue-600" />
              <span>Frequently Targeted Services & Infrastructure</span>
            </h3>
            <span className="text-[10px] text-slate-400 uppercase font-semibold">Perimeter Monitoring</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-100 text-slate-400 font-semibold uppercase">
                  <th className="pb-2">Service / Asset</th>
                  <th className="pb-2">Type / IP</th>
                  <th className="pb-2">Telemetry Events</th>
                  <th className="pb-2 text-right">Shield Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-slate-700">
                {metrics.frequently_targeted_services?.map((s: any, i: number) => (
                  <tr key={i} className="hover:bg-slate-50/50">
                    <td className="py-2.5 font-semibold text-slate-900">{s.service}</td>
                    <td className="py-2.5 text-slate-500 font-mono text-[11px]">{s.ip}</td>
                    <td className="py-2.5 font-bold text-slate-800">{s.events} flows</td>
                    <td className="py-2.5 text-right">
                      <span className="text-emerald-700 font-bold bg-emerald-50 px-2 py-0.5 rounded text-[10px]">
                        {s.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Lower Grid: Recent Incidents & Recommended Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Incidents Table */}
        <div className="lg:col-span-2 bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-slate-900">Recent Incidents</h3>
              <p className="text-xs text-slate-500">Prioritized cases under active investigation</p>
            </div>
            <Link
              href="/incidents"
              className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1"
            >
              View All Incidents &rarr;
            </Link>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-100 text-slate-400 font-semibold uppercase tracking-wider">
                  <th className="pb-2.5">Incident ID</th>
                  <th className="pb-2.5">Title</th>
                  <th className="pb-2.5">Severity</th>
                  <th className="pb-2.5">Status</th>
                  <th className="pb-2.5 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-slate-700">
                {metrics.recent_incidents.map((inc: any) => (
                  <tr key={inc.incident_id} className="hover:bg-slate-50/60 transition-colors">
                    <td className="py-3 font-mono font-medium text-slate-900">{inc.incident_id}</td>
                    <td className="py-3 font-medium text-slate-800 max-w-xs truncate">{inc.title}</td>
                    <td className="py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          inc.severity === "CRITICAL"
                            ? "bg-rose-50 text-rose-700 border border-rose-200"
                            : inc.severity === "HIGH"
                            ? "bg-orange-50 text-orange-700 border border-orange-200"
                            : "bg-amber-50 text-amber-700 border border-amber-200"
                        }`}
                      >
                        {inc.severity}
                      </span>
                    </td>
                    <td className="py-3">
                      <span className="text-slate-600 font-medium">{inc.status}</span>
                    </td>
                    <td className="py-3 text-right">
                      <Link
                        href={`/incidents`}
                        className="text-blue-600 hover:underline font-semibold"
                      >
                        Inspect
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recommended Actions List */}
        <div className="bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-slate-900">Recommended Actions</h3>
              <p className="text-xs text-slate-500">Autonomous & assisted defensive steps</p>
            </div>
            <Sparkles className="w-4 h-4 text-blue-600" />
          </div>

          <div className="space-y-3 flex-1">
            {metrics.recommended_actions.map((act: any, i: number) => (
              <div
                key={i}
                className="p-3 rounded-lg border border-slate-200 bg-slate-50/40 hover:bg-slate-50 transition-colors flex items-start gap-2.5"
              >
                <CheckCircle2 className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                <div className="flex-1">
                  <div className="text-xs font-semibold text-slate-800">{act.action}</div>
                  <div className="flex items-center gap-2 mt-1">
                    <span
                      className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                        act.priority === "CRITICAL"
                          ? "bg-rose-100 text-rose-700"
                          : "bg-blue-100 text-blue-700"
                      }`}
                    >
                      {act.priority}
                    </span>
                    <span className="text-[10px] text-slate-400">{act.category}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="pt-4 border-t border-slate-100 mt-4">
            <Link
              href="/threat-detection"
              className="w-full text-center block text-xs font-semibold text-blue-600 hover:text-blue-700 py-1.5 bg-blue-50/50 rounded-lg"
            >
              Configure Policy Thresholds &rarr;
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
