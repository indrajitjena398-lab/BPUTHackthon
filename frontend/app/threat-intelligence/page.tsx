"use client";

import React, { useState, useEffect } from "react";
import {
  Database,
  Download,
  Plus,
  Shield,
  Search,
  ExternalLink,
  Tag,
  CheckCircle2,
  FileCode
} from "lucide-react";
import { fetchIOCs, fetchMitreMatrix } from "@/lib/api";

export default function ThreatIntelligencePage() {
  const [iocs, setIocs] = useState<any[]>([]);
  const [mitre, setMitre] = useState<any[]>([]);
  const [activeTab, setActiveTab] = useState<"iocs" | "mitre">("iocs");
  const [searchQuery, setSearchQuery] = useState("");
  const [stixJson, setStixJson] = useState<string | null>(null);

  useEffect(() => {
    fetchIOCs().then((data) => setIocs(data));
    fetchMitreMatrix().then((data) => setMitre(data));
  }, []);

  const handleExportStix = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/intelligence/stix");
      const bundle = await res.json();
      setStixJson(JSON.stringify(bundle, null, 2));
    } catch (e) {
      console.error(e);
    }
  };

  const filteredIocs = iocs.filter((ioc) => {
    const q = searchQuery.toLowerCase();
    return (
      ioc.value.toLowerCase().includes(q) ||
      ioc.threat_type.toLowerCase().includes(q) ||
      ioc.ioc_type.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">Threat Intelligence & MITRE ATT&CK</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Curated Indicators of Compromise (IOCs), STIX 2.1 feed exports, and MITRE behavioral matrix mappings.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportStix}
            className="flex items-center gap-2 border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 text-xs font-semibold px-3 py-2 rounded-lg shadow-xs transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export STIX 2.1 Bundle</span>
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-200 gap-6">
        <button
          onClick={() => setActiveTab("iocs")}
          className={`pb-3 text-xs font-bold border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === "iocs"
              ? "border-blue-600 text-blue-600"
              : "border-transparent text-slate-500 hover:text-slate-800"
          }`}
        >
          <Database className="w-4 h-4" />
          <span>Active IOC Repository ({iocs.length})</span>
        </button>
        <button
          onClick={() => setActiveTab("mitre")}
          className={`pb-3 text-xs font-bold border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === "mitre"
              ? "border-blue-600 text-blue-600"
              : "border-transparent text-slate-500 hover:text-slate-800"
          }`}
        >
          <Shield className="w-4 h-4" />
          <span>MITRE ATT&CK Enterprise Matrix ({mitre.length} Techniques)</span>
        </button>
      </div>

      {/* STIX Export Modal */}
      {stixJson && (
        <div className="bg-slate-900 text-slate-100 rounded-xl p-4 shadow-lg text-xs font-mono relative">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800 mb-3">
            <span className="font-bold text-blue-400">STIX 2.1 Compliant Threat Intelligence Bundle</span>
            <button
              onClick={() => setStixJson(null)}
              className="text-slate-400 hover:text-white px-2 py-1 rounded"
            >
              ✕ Close
            </button>
          </div>
          <pre className="overflow-x-auto max-h-60 text-[11px]">{stixJson}</pre>
        </div>
      )}

      {/* Tab 1: IOC Repository */}
      {activeTab === "iocs" && (
        <div className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <div className="relative w-80">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search IOCs (IP, domain, hash, email)..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>
            <span className="text-xs text-slate-500 font-medium">Auto-synced with boundary proxies</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 text-slate-400 font-semibold uppercase tracking-wider">
                  <th className="pb-3">Type</th>
                  <th className="pb-3">Indicator Value</th>
                  <th className="pb-3">Threat Category</th>
                  <th className="pb-3">Confidence</th>
                  <th className="pb-3">Intelligence Source</th>
                  <th className="pb-3">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-slate-700">
                {filteredIocs.map((ioc, idx) => (
                  <tr key={idx} className="hover:bg-slate-50/60 transition-colors">
                    <td className="py-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-100 text-slate-700 border border-slate-200">
                        {ioc.ioc_type}
                      </span>
                    </td>
                    <td className="py-3 font-mono font-medium text-slate-900">{ioc.value}</td>
                    <td className="py-3 font-semibold text-slate-800">{ioc.threat_type}</td>
                    <td className="py-3">
                      <span className="text-emerald-700 font-bold bg-emerald-50 px-2 py-0.5 rounded text-[10px]">
                        {ioc.confidence}%
                      </span>
                    </td>
                    <td className="py-3 text-slate-500">{ioc.source}</td>
                    <td className="py-3 text-slate-600 max-w-sm truncate">{ioc.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 2: MITRE ATT&CK Matrix */}
      {activeTab === "mitre" && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {mitre.map((m) => (
            <div
              key={m.id}
              className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs space-y-3 hover:border-blue-300 transition-colors"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-blue-600 bg-blue-50 px-2 py-0.5 rounded border border-blue-100">
                  {m.id}
                </span>
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">
                  {m.tactic}
                </span>
              </div>
              <h4 className="text-sm font-bold text-slate-900 leading-snug">{m.name}</h4>
              <p className="text-xs text-slate-600 leading-relaxed">{m.description}</p>
              <div className="pt-2 border-t border-slate-100">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-0.5">
                  Mitigation Rule
                </span>
                <div className="text-xs font-medium text-slate-800">{m.mitigation}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
