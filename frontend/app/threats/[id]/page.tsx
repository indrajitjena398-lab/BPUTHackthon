"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import {
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  ArrowLeft,
  Clock,
  Sparkles,
  Zap,
  Activity,
  Layers
} from "lucide-react";
import { fetchThreatDetail, executeDefensiveAction } from "@/lib/api";

export default function ThreatDetailPage() {
  const params = useParams();
  const threatId = params.id as string;
  const [threat, setThreat] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  useEffect(() => {
    if (threatId) {
      fetchThreatDetail(threatId)
        .then((data) => setThreat(data))
        .catch((err) => console.error(err))
        .finally(() => setLoading(false));
    }
  }, [threatId]);

  const handleAction = async (actionType: string) => {
    if (!threat) return;
    try {
      await executeDefensiveAction({
        action_type: actionType,
        target: threat.threat_id,
        reason: `Manual execution from threat inspection console for ${threat.classification}`,
        threat_id: threat.threat_id
      });
      setActionSuccess(`Defensive action '${actionType}' triggered.`);
      // Refresh
      fetchThreatDetail(threatId).then((data) => setThreat(data));
    } catch (e) {
      console.error(e);
      alert("Error: " + e);
    }
  };

  if (loading) {
    return <div className="p-8 text-center text-slate-400">Loading Threat Investigation Telemetry...</div>;
  }

  if (!threat) {
    return (
      <div className="p-8 text-center">
        <div className="text-slate-800 font-bold">Threat Not Found</div>
        <Link href="/threat-detection" className="text-xs text-blue-600 hover:underline mt-2 inline-block">
          &larr; Back to Threat Detection
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Breadcrumb Header */}
      <div className="flex items-center justify-between">
        <Link
          href="/threat-detection"
          className="text-xs font-semibold text-slate-500 hover:text-slate-900 flex items-center gap-1"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Detection Workbench</span>
        </Link>

        <span className="font-mono text-xs text-slate-400">Threat ID: {threat.threat_id}</span>
      </div>

      {/* Main Threat Header Card */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span
              className={`px-2.5 py-0.5 rounded text-[11px] font-bold ${
                threat.risk_level === "CRITICAL"
                  ? "bg-rose-100 text-rose-700 border border-rose-200"
                  : threat.risk_level === "HIGH"
                  ? "bg-orange-100 text-orange-700 border border-orange-200"
                  : "bg-amber-100 text-amber-700 border border-amber-200"
              }`}
            >
              {threat.risk_level} RISK
            </span>
            <span className="text-xs text-slate-400 font-medium">Category: {threat.category}</span>
          </div>

          <h1 className="text-xl font-bold text-slate-900">{threat.classification}</h1>
          <p className="text-xs text-slate-500 mt-1 max-w-xl">{threat.explanation}</p>
        </div>

        {/* Risk Score Circle / Stat */}
        <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 text-center shrink-0 min-w-[140px]">
          <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
            Threat Fusion Score
          </span>
          <div className="text-3xl font-extrabold text-slate-900 mt-0.5">
            {threat.risk_score}
            <span className="text-xs text-slate-400 font-normal"> / 100</span>
          </div>
          <span className="text-[11px] text-emerald-600 font-semibold block mt-1">
            Confidence: {Math.round(threat.confidence * 100)}%
          </span>
        </div>
      </div>

      {/* Two Column Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Left Column: Explainable AI Evidence & SHAP Attributions */}
        <div className="space-y-6">
          {/* Grounded Evidence Checklist */}
          <div className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs">
            <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-blue-600" />
              <span>Grounded Evidence Checklist</span>
            </h3>
            <div className="space-y-2">
              {threat.indicators?.map((ind: string, i: number) => (
                <div key={i} className="p-2.5 bg-slate-50 border border-slate-100 rounded-lg text-xs text-slate-700 flex items-start gap-2">
                  <span className="text-blue-600 font-bold mt-0.5">✓</span>
                  <span>{ind}</span>
                </div>
              ))}
            </div>
          </div>

          {/* SHAP Feature Contribution */}
          {threat.xai_report?.feature_attributions && (
            <div className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs">
              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <Activity className="w-4 h-4 text-blue-600" />
                <span>Feature Importance Attributions (SHAP)</span>
              </h3>
              <div className="space-y-2.5">
                {threat.xai_report.feature_attributions.map((feat: any, idx: number) => (
                  <div key={idx} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="font-medium text-slate-700 capitalize">
                        {feat.feature.replace("_", " ")}
                      </span>
                      <span className="font-mono text-slate-500 font-semibold">{feat.percentage}% impact</span>
                    </div>
                    <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                      <div
                        className="bg-blue-600 h-2 rounded-full"
                        style={{ width: `${Math.min(100, feat.percentage * 2)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right Column: MITRE ATT&CK & Defensive Actions */}
        <div className="space-y-6">
          {/* MITRE Techniques */}
          <div className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs">
            <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-blue-600" />
              <span>MITRE ATT&CK Mapping</span>
            </h3>
            <div className="space-y-2.5">
              {threat.mitre_tactics?.map((m: any, i: number) => (
                <div key={i} className="p-3 border border-slate-200 rounded-lg bg-slate-50/50 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-blue-600 bg-blue-50 px-2 py-0.5 rounded border border-blue-100">
                      {m.technique_id}
                    </span>
                    <span className="text-[10px] font-semibold text-slate-500 uppercase">{m.tactic}</span>
                  </div>
                  <div className="text-xs font-bold text-slate-900">{m.technique_name}</div>
                  <div className="text-[11px] text-slate-600">{m.mitigation}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Response Actions Trigger Card */}
          <div className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs space-y-3">
            <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
              <Zap className="w-4 h-4 text-blue-600" />
              <span>Execute Defensive Playbook</span>
            </h3>

            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={() => handleAction("Quarantine Email")}
                className="p-2.5 border border-slate-200 bg-white hover:bg-blue-50 hover:border-blue-300 rounded-lg text-xs font-semibold text-slate-800 transition-colors text-left"
              >
                Quarantine Payload
              </button>
              <button
                onClick={() => handleAction("Block URL")}
                className="p-2.5 border border-slate-200 bg-white hover:bg-blue-50 hover:border-blue-300 rounded-lg text-xs font-semibold text-slate-800 transition-colors text-left"
              >
                Block Perimeter URL
              </button>
              <button
                onClick={() => handleAction("Require MFA")}
                className="p-2.5 border border-slate-200 bg-white hover:bg-blue-50 hover:border-blue-300 rounded-lg text-xs font-semibold text-slate-800 transition-colors text-left"
              >
                Enforce Step-Up MFA
              </button>
              <button
                onClick={() => handleAction("Block IP")}
                className="p-2.5 border border-rose-200 bg-white hover:bg-rose-50 hover:border-rose-300 rounded-lg text-xs font-semibold text-rose-700 transition-colors text-left"
              >
                Block Origin IP
              </button>
            </div>

            {actionSuccess && (
              <div className="p-2.5 bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs rounded-lg font-medium">
                {actionSuccess}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
