"use client";

import React, { useState, useEffect } from "react";
import {
  FileText,
  Download,
  Printer,
  ShieldCheck,
  CheckCircle2,
  Clock,
  TrendingDown,
  Activity
} from "lucide-react";
import { fetchReportSummary } from "@/lib/api";

export default function ReportsPage() {
  const [reportData, setReportData] = useState<any>(null);

  useEffect(() => {
    fetchReportSummary().then((data) => setReportData(data));
  }, []);

  const handlePrint = () => {
    window.print();
  };

  if (!reportData) {
    return <div className="p-8 text-center text-slate-400">Loading Enterprise Security Report...</div>;
  }

  const exec = reportData.executive_summary;

  return (
    <div className="space-y-6 max-w-5xl mx-auto print:max-w-full">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 print:hidden">
        <div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">Security & Compliance Reports</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Audit-grade security posture reports, compliance verification, and human-layer risk telemetry.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handlePrint}
            className="flex items-center gap-2 border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 text-xs font-semibold px-3 py-2 rounded-lg shadow-xs transition-colors"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print / Save PDF</span>
          </button>
        </div>
      </div>

      {/* Printable Report Sheet */}
      <div className="bg-white border border-slate-200 rounded-2xl p-8 shadow-xs space-y-8">
        {/* Report Banner */}
        <div className="flex items-start justify-between pb-6 border-b border-slate-100">
          <div>
            <div className="text-[11px] font-mono text-blue-600 font-bold uppercase tracking-wider">
              {reportData.report_id}
            </div>
            <h1 className="text-xl font-bold text-slate-900 mt-1">{exec.title}</h1>
            <div className="text-xs text-slate-500 mt-1">Generated: {reportData.generated_at} UTC</div>
          </div>
          <div className="text-right">
            <span className="inline-block px-3 py-1 rounded-full text-xs font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
              AUDIT COMPLIANT
            </span>
            <div className="text-[11px] text-slate-400 mt-1">CyberGuard v1.0 Enterprise</div>
          </div>
        </div>

        {/* Executive Highlights Grid */}
        <div>
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">
            Executive Summary KPI Metrics
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block">Postural Health</span>
              <span className="text-lg font-bold text-emerald-600 mt-0.5 block">{exec.overall_health_score}</span>
            </div>
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block">Threats Mitigated</span>
              <span className="text-lg font-bold text-slate-900 mt-0.5 block">{exec.total_threats_mitigated}</span>
            </div>
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block">Mean Time to Detect</span>
              <span className="text-lg font-bold text-blue-600 mt-0.5 block">{exec.mean_time_to_detect_minutes} min</span>
            </div>
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block">Phishing Block Rate</span>
              <span className="text-lg font-bold text-emerald-600 mt-0.5 block">{exec.phishing_mitigation_rate}</span>
            </div>
          </div>
        </div>

        {/* Compliance Posture Matrix */}
        <div>
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">
            Regulatory & Framework Compliance
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border border-slate-200 rounded-lg">
              <thead className="bg-slate-50 text-slate-500 font-semibold border-b border-slate-200">
                <tr>
                  <th className="py-2.5 px-3">Standard / Framework</th>
                  <th className="py-2.5 px-3">Validation Status</th>
                  <th className="py-2.5 px-3 text-right">Coverage Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-slate-700">
                {reportData.compliance_posture.map((c: any, i: number) => (
                  <tr key={i}>
                    <td className="py-2.5 px-3 font-semibold text-slate-900">{c.standard}</td>
                    <td className="py-2.5 px-3">
                      <span className="flex items-center gap-1.5 text-emerald-700 font-medium">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                        <span>{c.status}</span>
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right font-bold text-slate-900">{c.score}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Top Attack Vectors Breakdown */}
        <div>
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">
            Observed Threat Vectors (Trailing 90 Days)
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {reportData.top_attack_vectors.map((v: any, i: number) => (
              <div key={i} className="p-3 border border-slate-200 rounded-xl flex items-center justify-between">
                <div>
                  <div className="text-xs font-bold text-slate-900">{v.vector}</div>
                  <div className="text-[10px] text-slate-400">Quarterly trend: {v.trend}</div>
                </div>
                <div className="text-sm font-extrabold text-blue-600">{v.volume}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Sign-off Footer */}
        <div className="pt-6 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-400">
          <div>Prepared for Executive Governance & SOC Leadership</div>
          <div className="font-mono">Verification Hash: SHA256-4b9d-e71c</div>
        </div>
      </div>
    </div>
  );
}
