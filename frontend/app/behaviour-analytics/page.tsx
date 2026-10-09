"use client";

import React, { useState } from "react";
import {
  Activity,
  UserCheck,
  AlertTriangle,
  Smartphone,
  Globe,
  Clock,
  ShieldCheck,
  ShieldAlert,
  ArrowRight
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer
} from "recharts";

const SAMPLE_SESSIONS = [
  {
    user: "ankit.kumar@bput.ac.in",
    location: "Bhubaneswar, India",
    device: "Dell Precision 5570",
    ip: "10.14.80.25",
    time: "10:14 AM (Normal)",
    score: 12,
    status: "Baseline Normal",
    outlier: false
  },
  {
    user: "cfo@enterprise.com",
    location: "Mumbai, India",
    device: "MacBook Air (Finance Secure)",
    ip: "10.14.10.88",
    time: "11:30 AM (Normal)",
    score: 15,
    status: "Baseline Normal",
    outlier: false
  },
  {
    user: "cfo@enterprise.com",
    location: "Frankfurt, Germany",
    device: "Rogue Linux VM (x86_64)",
    ip: "185.220.101.5",
    time: "11:44 AM (14 min jump)",
    score: 94,
    status: "Impossible Travel / Anomaly",
    outlier: true
  },
  {
    user: "hr-director@enterprise.com",
    location: "Bengaluru, India",
    device: "ThinkPad T14",
    ip: "10.14.90.12",
    time: "02:15 PM (Normal)",
    score: 18,
    status: "Baseline Normal",
    outlier: false
  },
  {
    user: "dev-ops@enterprise.com",
    location: "St. Petersburg, Russia",
    device: "Automated Curl Script",
    ip: "194.26.29.112",
    time: "03:10 AM (Odd Hours)",
    score: 88,
    status: "Credential Spray Outlier",
    outlier: true
  }
];

const ANOMALY_CHART_DATA = [
  { hour: "00:00", normal: 2, anomaly: 0 },
  { hour: "04:00", normal: 1, anomaly: 2 },
  { hour: "08:00", normal: 18, anomaly: 0 },
  { hour: "10:00", normal: 42, anomaly: 1 },
  { hour: "12:00", normal: 38, anomaly: 3 },
  { hour: "14:00", normal: 45, anomaly: 0 },
  { hour: "16:00", normal: 35, anomaly: 0 },
  { hour: "20:00", normal: 14, anomaly: 1 },
  { hour: "22:00", normal: 5, anomaly: 0 }
];

export default function BehaviourAnalyticsPage() {
  const [selectedUser, setSelectedUser] = useState("cfo@enterprise.com");
  const [mounted, setMounted] = React.useState(false);

  React.useEffect(() => {
    setMounted(true);
  }, []);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-900 tracking-tight">User & Entity Behaviour Analytics (UEBA)</h2>
        <p className="text-xs text-slate-500 mt-0.5">
          Continuous adaptive authentication monitoring: Impossible travel, hardware fingerprinting, and Isolation Forest outliers.
        </p>
      </div>

      {/* Comparison Cards: Normal Baseline vs New Anomaly */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Normal Baseline Profile */}
        <div className="bg-white border border-emerald-200 rounded-xl p-5 shadow-xs bg-gradient-to-b from-emerald-50/20 to-white">
          <div className="flex items-center justify-between pb-3 border-b border-emerald-100 mb-4">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-emerald-600" />
              <span className="text-xs font-bold text-emerald-800 uppercase tracking-wider">
                Normal Historical Baseline (90 Days)
              </span>
            </div>
            <span className="text-[10px] font-bold text-emerald-700 bg-emerald-100 px-2 py-0.5 rounded">
              SAFE POSTURE
            </span>
          </div>

          <div className="space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-500 flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-slate-400" /> Primary Location:
              </span>
              <span className="font-semibold text-slate-900">India (Bhubaneswar / Mumbai)</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-500 flex items-center gap-1.5">
                <Smartphone className="w-3.5 h-3.5 text-slate-400" /> Trusted Hardware:
              </span>
              <span className="font-semibold text-slate-900">Corporate Enrolled Dell & MacBook</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-500 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-slate-400" /> Typical Hours:
              </span>
              <span className="font-semibold text-slate-900">08:00 – 20:00 IST</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-500 flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-slate-400" /> Failed Attempts:
              </span>
              <span className="font-semibold text-slate-900">Avg &lt; 0.2 / session</span>
            </div>
          </div>
        </div>

        {/* High Anomaly Event */}
        <div className="bg-white border border-rose-200 rounded-xl p-5 shadow-xs bg-gradient-to-b from-rose-50/20 to-white">
          <div className="flex items-center justify-between pb-3 border-b border-rose-100 mb-4">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-rose-600" />
              <span className="text-xs font-bold text-rose-800 uppercase tracking-wider">
                Detected Behavioral Anomaly
              </span>
            </div>
            <span className="text-[10px] font-bold text-rose-700 bg-rose-100 px-2 py-0.5 rounded">
              CRITICAL ATO (94/100)
            </span>
          </div>

          <div className="space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-500 flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-rose-500" /> New Geolocation:
              </span>
              <span className="font-bold text-rose-700">Frankfurt, Germany (Unknown IP 185.220.101.5)</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-500 flex items-center gap-1.5">
                <Smartphone className="w-3.5 h-3.5 text-rose-500" /> Unrecognized Hardware:
              </span>
              <span className="font-bold text-rose-700">Rogue Linux VM (Headless Browser)</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-500 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-rose-500" /> Impossible Travel Delta:
              </span>
              <span className="font-bold text-rose-700">6,700 km in 14 minutes</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-500 flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-rose-500" /> Preceding Burst:
              </span>
              <span className="font-bold text-rose-700">7 Consecutive Failed Passwords</span>
            </div>
          </div>
        </div>
      </div>

      {/* Hourly Authentication & Outlier Chart */}
      <div className="bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-900">Authentication Velocity & Outlier Distribution</h3>
            <p className="text-xs text-slate-500">24-hour observation envelope across corporate directory</p>
          </div>
          <span className="text-xs font-semibold text-blue-600 bg-blue-50 px-2.5 py-1 rounded-md">
            Isolation Forest Model v2.0.1
          </span>
        </div>

        <div className="h-60 w-full">
          {mounted ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={ANOMALY_CHART_DATA} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <XAxis dataKey="hour" stroke="#94a3b8" fontSize={11} tickLine={false} />
                <YAxis stroke="#94a3b8" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#ffffff", borderColor: "#e2e8f0", borderRadius: "8px", fontSize: "12px" }}
                />
                <Bar dataKey="normal" fill="#3b82f6" name="Normal Logins" radius={[4, 4, 0, 0]} />
                <Bar dataKey="anomaly" fill="#ef4444" name="Anomalies Flagged" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-full w-full flex items-center justify-center text-slate-400 text-xs">
              Loading anomaly velocity chart...
            </div>
          )}
        </div>
      </div>

      {/* Recent Monitored Authentication Sessions Table */}
      <div className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-bold text-slate-900">Live Monitored Authentication Telemetry</h3>
          <span className="text-xs text-slate-500">Auto-correlated with threat risk scoring</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200 text-slate-400 font-semibold uppercase tracking-wider">
                <th className="pb-3">User Profile</th>
                <th className="pb-3">Origin Location</th>
                <th className="pb-3">Device Hardware</th>
                <th className="pb-3">Source IP</th>
                <th className="pb-3">Risk Rating</th>
                <th className="pb-3">Behavior Status</th>
                <th className="pb-3 text-right">Adaptive Response</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-700">
              {SAMPLE_SESSIONS.map((s, idx) => (
                <tr key={idx} className={s.outlier ? "bg-rose-50/40" : "hover:bg-slate-50/60"}>
                  <td className="py-3 font-semibold text-slate-900">{s.user}</td>
                  <td className="py-3">{s.location}</td>
                  <td className="py-3 text-slate-600">{s.device}</td>
                  <td className="py-3 font-mono">{s.ip}</td>
                  <td className="py-3">
                    <span className={`font-bold ${s.outlier ? "text-rose-600" : "text-emerald-600"}`}>
                      {s.score}/100
                    </span>
                  </td>
                  <td className="py-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        s.outlier
                          ? "bg-rose-100 text-rose-700 border border-rose-200"
                          : "bg-emerald-50 text-emerald-700 border border-emerald-200"
                      }`}
                    >
                      {s.status}
                    </span>
                  </td>
                  <td className="py-3 text-right">
                    {s.outlier ? (
                      <button
                        onClick={() => alert(`Enforced immediate FIDO2 MFA challenge on user: ${s.user}`)}
                        className="bg-rose-600 hover:bg-rose-700 text-white font-semibold text-[11px] px-2.5 py-1 rounded shadow-xs"
                      >
                        Enforce MFA
                      </button>
                    ) : (
                      <span className="text-[11px] text-slate-400">Authorized</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
