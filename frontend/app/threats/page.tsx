"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  Search,
  Filter,
  ArrowRight,
  RefreshCw,
  AlertTriangle,
  Download,
  SlidersHorizontal,
  ChevronRight
} from "lucide-react";
import { fetchThreats } from "@/lib/api";

export default function ThreatsListPage() {
  const [threats, setThreats] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("ALL");
  const [riskFilter, setRiskFilter] = useState("ALL");

  const loadData = () => {
    setLoading(true);
    const cat = categoryFilter === "ALL" ? undefined : categoryFilter;
    const rsk = riskFilter === "ALL" ? undefined : riskFilter;
    fetchThreats(cat, rsk)
      .then((data) => setThreats(data || []))
      .catch((err) => console.error("Failed to fetch threats:", err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData();
  }, [categoryFilter, riskFilter]);

  const filteredThreats = threats.filter((t) => {
    if (!search) return true;
    const q = search.toLowerCase();
    const idMatch = (t.threat_id || "").toLowerCase().includes(q);
    const catMatch = (t.category || "").toLowerCase().includes(q);
    const classMatch = (t.classification || "").toLowerCase().includes(q);
    const indMatch = (t.indicators || []).some((i: string) => i.toLowerCase().includes(q));
    return idMatch || catMatch || classMatch || indMatch;
  });

  const getRiskBadge = (level: string, score: number) => {
    switch (level?.toUpperCase()) {
      case "CRITICAL":
        return <span className="px-2.5 py-1 text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200 rounded-md">CRITICAL ({score})</span>;
      case "HIGH":
        return <span className="px-2.5 py-1 text-xs font-semibold bg-orange-50 text-orange-700 border border-orange-200 rounded-md">HIGH ({score})</span>;
      case "MEDIUM":
        return <span className="px-2.5 py-1 text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200 rounded-md">MEDIUM ({score})</span>;
      case "LOW":
        return <span className="px-2.5 py-1 text-xs font-semibold bg-blue-50 text-blue-700 border border-blue-200 rounded-md">LOW ({score})</span>;
      default:
        return <span className="px-2.5 py-1 text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-md">SAFE ({score})</span>;
    }
  };

  const criticalCount = threats.filter(t => t.risk_level === "CRITICAL").length;
  const highCount = threats.filter(t => t.risk_level === "HIGH").length;
  const avgScore = threats.length > 0
    ? Math.round(threats.reduce((acc, t) => acc + (t.risk_score || 0), 0) / threats.length)
    : 0;

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(filteredThreats, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cyberguard_threats_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold text-slate-900 tracking-tight">Threat Investigation & Audit Log</h1>
            <span className="px-2 py-0.5 text-xs font-medium bg-blue-50 text-blue-700 border border-blue-200 rounded-full">
              Live SOC Feed
            </span>
          </div>
          <p className="text-sm text-slate-500 mt-1">
            Comprehensive audit registry of all AI-detected cyber threats, fusion risk calculations, and forensic telemetry.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={loadData}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-600 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors shadow-sm"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
          <button
            onClick={exportJSON}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            Export Telemetry
          </button>
        </div>
      </div>

      {/* Summary KPI Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white border border-slate-200/80 rounded-xl p-4 shadow-sm">
          <div className="text-xs font-medium text-slate-500 uppercase tracking-wider">Total Threats Logged</div>
          <div className="text-2xl font-bold text-slate-900 mt-1">{threats.length}</div>
          <div className="text-xs text-slate-400 mt-0.5">Continuous ingestion</div>
        </div>
        <div className="bg-white border border-rose-100 rounded-xl p-4 shadow-sm">
          <div className="text-xs font-medium text-rose-600 uppercase tracking-wider">Critical Threats</div>
          <div className="text-2xl font-bold text-rose-700 mt-1">{criticalCount}</div>
          <div className="text-xs text-rose-500 mt-0.5">Immediate playbook action</div>
        </div>
        <div className="bg-white border border-orange-100 rounded-xl p-4 shadow-sm">
          <div className="text-xs font-medium text-orange-600 uppercase tracking-wider">High Risk Threats</div>
          <div className="text-2xl font-bold text-orange-700 mt-1">{highCount}</div>
          <div className="text-xs text-orange-500 mt-0.5">Active triage needed</div>
        </div>
        <div className="bg-white border border-slate-200/80 rounded-xl p-4 shadow-sm">
          <div className="text-xs font-medium text-slate-500 uppercase tracking-wider">Avg Threat Score</div>
          <div className="text-2xl font-bold text-slate-900 mt-1">{avgScore} <span className="text-xs font-normal text-slate-400">/ 100</span></div>
          <div className="text-xs text-slate-400 mt-0.5">Weighted risk index</div>
        </div>
      </div>

      {/* Filter and Search Controls */}
      <div className="bg-white border border-slate-200/80 rounded-xl p-4 shadow-sm space-y-3">
        <div className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by Threat ID, indicators, classification, or affected targets..."
              className="w-full pl-9 pr-4 py-2 text-sm bg-slate-50/50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white transition-all text-slate-800 placeholder-slate-400"
            />
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5 text-xs text-slate-500">
              <Filter className="w-3.5 h-3.5 text-slate-400" />
              <span>Category:</span>
            </div>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="text-xs bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-2 text-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="ALL">All Categories</option>
              <option value="Phishing">Phishing</option>
              <option value="Impersonation">Impersonation</option>
              <option value="Deepfake">Deepfake</option>
              <option value="Account Takeover">Account Takeover</option>
              <option value="Network Threat">Network Threat</option>
            </select>

            <div className="flex items-center gap-1.5 text-xs text-slate-500 ml-2">
              <SlidersHorizontal className="w-3.5 h-3.5 text-slate-400" />
              <span>Severity:</span>
            </div>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="text-xs bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-2 text-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical (81-100)</option>
              <option value="HIGH">High (61-80)</option>
              <option value="MEDIUM">Medium (41-60)</option>
              <option value="LOW">Low (21-40)</option>
              <option value="SAFE">Safe (0-20)</option>
            </select>
          </div>
        </div>
      </div>

      {/* Threats Table */}
      <div className="bg-white border border-slate-200/80 rounded-xl shadow-sm overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-slate-400 text-sm">Loading security telemetry feed...</div>
        ) : filteredThreats.length === 0 ? (
          <div className="p-12 text-center">
            <ShieldAlert className="w-10 h-10 text-slate-300 mx-auto mb-2" />
            <div className="text-sm font-semibold text-slate-700">No threats match current query</div>
            <p className="text-xs text-slate-400 mt-1">Try resetting the filter criteria or search keyword.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-50/80 border-b border-slate-200 text-slate-500 uppercase tracking-wider font-semibold">
                  <th className="py-3 px-4">Threat ID</th>
                  <th className="py-3 px-4">Classification</th>
                  <th className="py-3 px-4">Category</th>
                  <th className="py-3 px-4">Risk Severity</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">Indicators / MITRE</th>
                  <th className="py-3 px-4">Detected At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-slate-700">
                {filteredThreats.map((t) => (
                  <tr key={t.threat_id} className="hover:bg-slate-50/70 transition-colors group">
                    <td className="py-3 px-4 font-mono font-medium text-blue-600">
                      <Link href={`/threats/${t.threat_id}`} className="hover:underline flex items-center gap-1">
                        {t.threat_id}
                      </Link>
                    </td>
                    <td className="py-3 px-4 font-medium text-slate-900 max-w-xs truncate">
                      {t.classification || "Unknown Threat Classification"}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 bg-slate-100 text-slate-700 rounded text-[11px] font-medium border border-slate-200/60">
                        {t.category}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      {getRiskBadge(t.risk_level, t.risk_score)}
                    </td>
                    <td className="py-3 px-4 font-medium">
                      {Math.round((t.confidence || 0) * 100)}%
                    </td>
                    <td className="py-3 px-4 max-w-xs">
                      <div className="flex flex-wrap gap-1">
                        {(t.mitre_tactics || []).slice(0, 2).map((m: string, idx: number) => (
                          <span key={idx} className="px-1.5 py-0.5 bg-blue-50 text-blue-700 text-[10px] rounded font-mono">
                            {m}
                          </span>
                        ))}
                        {(!t.mitre_tactics || t.mitre_tactics.length === 0) && (t.indicators || []).slice(0, 1).map((ind: string, idx: number) => (
                          <span key={idx} className="truncate max-w-[140px] text-slate-500 text-[11px]">
                            {ind}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                      {t.created_at ? new Date(t.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : "Just now"}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <Link
                        href={`/threats/${t.threat_id}`}
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-blue-600 hover:text-blue-700 hover:bg-blue-50 rounded transition-colors"
                      >
                        Investigate
                        <ChevronRight className="w-3.5 h-3.5" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
