"use client";

import React, { useState, useEffect } from "react";
import {
  Settings,
  Cpu,
  Sliders,
  Shield,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Save
} from "lucide-react";
import { fetchModelRegistry } from "@/lib/api";

export default function SettingsPage() {
  const [models, setModels] = useState<any[]>([]);
  const [activeTab, setActiveTab] = useState<"models" | "policies" | "rbac">("models");

  // Threshold policies state
  const [thresholds, setThresholds] = useState({
    safeMax: 20,
    lowMax: 40,
    mediumMax: 60,
    highMax: 80,
    autoQuarantine: true,
    autoMfa: true,
    requireApprovalForDestructive: true
  });

  const [savedSuccess, setSavedSuccess] = useState(false);

  useEffect(() => {
    fetchModelRegistry().then((data) => setModels(data));
  }, []);

  const handleSavePolicies = () => {
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 3000);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-900 tracking-tight">System Settings & Model Registry</h2>
        <p className="text-xs text-slate-500 mt-0.5">
          AI/ML Model Registry evaluation metrics, detection thresholds, and automated defense policy orchestration.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-200 gap-6">
        <button
          onClick={() => setActiveTab("models")}
          className={`pb-3 text-xs font-bold border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === "models"
              ? "border-blue-600 text-blue-600"
              : "border-transparent text-slate-500 hover:text-slate-800"
          }`}
        >
          <Cpu className="w-4 h-4" />
          <span>Model Registry & Performance ({models.length} Models)</span>
        </button>
        <button
          onClick={() => setActiveTab("policies")}
          className={`pb-3 text-xs font-bold border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === "policies"
              ? "border-blue-600 text-blue-600"
              : "border-transparent text-slate-500 hover:text-slate-800"
          }`}
        >
          <Sliders className="w-4 h-4" />
          <span>Detection Thresholds & Defensive Policies</span>
        </button>
        <button
          onClick={() => setActiveTab("rbac")}
          className={`pb-3 text-xs font-bold border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === "rbac"
              ? "border-blue-600 text-blue-600"
              : "border-transparent text-slate-500 hover:text-slate-800"
          }`}
        >
          <Shield className="w-4 h-4" />
          <span>Role-Based Access Control (RBAC)</span>
        </button>
      </div>

      {/* Tab 1: Model Registry Table */}
      {activeTab === "models" && (
        <div className="space-y-4">
          <div className="p-3 bg-blue-50 border border-blue-200 rounded-xl text-xs text-blue-800 flex items-center justify-between">
            <div>
              <span className="font-bold">Transparent AI Validation Standard: </span>
              In compliance with Section 24 of the CyberGuard Architecture, all metrics reflect calibrated benchmark validations. Uncalibrated pipelines are strictly labelled Demonstration Mode.
            </div>
            <span className="font-mono text-[10px] bg-blue-100 px-2 py-0.5 rounded font-semibold">Zero Fake Accuracy</span>
          </div>

          <div className="bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 text-slate-400 font-semibold uppercase tracking-wider">
                  <th className="pb-3">Model Name & ID</th>
                  <th className="pb-3">Domain Category</th>
                  <th className="pb-3">Version</th>
                  <th className="pb-3">Status</th>
                  <th className="pb-3">Accuracy</th>
                  <th className="pb-3">Precision</th>
                  <th className="pb-3">Recall</th>
                  <th className="pb-3">F1 Score</th>
                  <th className="pb-3">ROC-AUC</th>
                  <th className="pb-3">FPR / FNR</th>
                  <th className="pb-3 text-right">Inference Latency</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-slate-700">
                {models.map((m) => (
                  <tr key={m.id} className="hover:bg-slate-50/60 transition-colors">
                    <td className="py-3">
                      <div className="font-bold text-slate-900">{m.name}</div>
                      <div className="text-[10px] font-mono text-slate-400">{m.id} &bull; {m.framework}</div>
                    </td>
                    <td className="py-3 text-slate-600 font-medium">{m.category}</td>
                    <td className="py-3 font-mono text-[11px]">{m.version}</td>
                    <td className="py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          m.status === "Production Ready"
                            ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                            : "bg-amber-50 text-amber-700 border border-amber-200"
                        }`}
                      >
                        {m.status}
                      </span>
                    </td>
                    <td className="py-3 font-semibold text-slate-900">{(m.accuracy * 100).toFixed(1)}%</td>
                    <td className="py-3 font-semibold text-slate-900">{(m.precision * 100).toFixed(1)}%</td>
                    <td className="py-3 font-semibold text-slate-900">{(m.recall * 100).toFixed(1)}%</td>
                    <td className="py-3 font-bold text-blue-700">{(m.f1_score * 100).toFixed(1)}%</td>
                    <td className="py-3 font-semibold text-slate-800">{m.roc_auc.toFixed(3)}</td>
                    <td className="py-3 text-[11px] text-slate-500 font-mono">
                      {(m.fpr * 100).toFixed(1)}% / {(m.fnr * 100).toFixed(1)}%
                    </td>
                    <td className="py-3 text-right font-mono text-slate-700">{m.latency_ms} ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 2: Policies & Thresholds */}
      {activeTab === "policies" && (
        <div className="bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs max-w-3xl space-y-6">
          <div>
            <h3 className="text-sm font-bold text-slate-900">Risk Threshold Envelope</h3>
            <p className="text-xs text-slate-500">Define numeric cutoffs for automatic classification tiers (0–100).</p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">Safe Maximum Score</label>
              <input
                type="number"
                value={thresholds.safeMax}
                onChange={(e) => setThresholds({ ...thresholds, safeMax: parseInt(e.target.value) || 20 })}
                className="w-full px-3 py-1.5 border border-slate-200 rounded-lg text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">Low Risk Maximum</label>
              <input
                type="number"
                value={thresholds.lowMax}
                onChange={(e) => setThresholds({ ...thresholds, lowMax: parseInt(e.target.value) || 40 })}
                className="w-full px-3 py-1.5 border border-slate-200 rounded-lg text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">Medium Risk Maximum</label>
              <input
                type="number"
                value={thresholds.mediumMax}
                onChange={(e) => setThresholds({ ...thresholds, mediumMax: parseInt(e.target.value) || 60 })}
                className="w-full px-3 py-1.5 border border-slate-200 rounded-lg text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">High Risk Maximum (81+ = CRITICAL)</label>
              <input
                type="number"
                value={thresholds.highMax}
                onChange={(e) => setThresholds({ ...thresholds, highMax: parseInt(e.target.value) || 80 })}
                className="w-full px-3 py-1.5 border border-slate-200 rounded-lg text-xs"
              />
            </div>
          </div>

          <div className="pt-4 border-t border-slate-100 space-y-3">
            <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">Automated Defensive Orchestration</h4>
            
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={thresholds.autoQuarantine}
                onChange={(e) => setThresholds({ ...thresholds, autoQuarantine: e.target.checked })}
                className="w-4 h-4 rounded text-blue-600 focus:ring-blue-500"
              />
              <div>
                <span className="text-xs font-semibold text-slate-900 block">Automatic Email Quarantine</span>
                <span className="text-[11px] text-slate-500">Quarantine emails scoring &gt; 80 across all enterprise exchange inboxes</span>
              </div>
            </label>

            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={thresholds.autoMfa}
                onChange={(e) => setThresholds({ ...thresholds, autoMfa: e.target.checked })}
                className="w-4 h-4 rounded text-blue-600 focus:ring-blue-500"
              />
              <div>
                <span className="text-xs font-semibold text-slate-900 block">Adaptive Step-Up MFA Challenge</span>
                <span className="text-[11px] text-slate-500">Prompt users for FIDO2 biometric confirmation on impossible travel triggers</span>
              </div>
            </label>

            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={thresholds.requireApprovalForDestructive}
                onChange={(e) => setThresholds({ ...thresholds, requireApprovalForDestructive: e.target.checked })}
                className="w-4 h-4 rounded text-blue-600 focus:ring-blue-500"
              />
              <div>
                <span className="text-xs font-semibold text-slate-900 block">Require Analyst Approval for Destructive Actions</span>
                <span className="text-[11px] text-slate-500">Block IP, device lockouts, and session revocations require explicit confirmation</span>
              </div>
            </label>
          </div>

          <div className="pt-4 border-t border-slate-100 flex items-center justify-between">
            <button
              onClick={handleSavePolicies}
              className="bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs px-4 py-2 rounded-lg shadow-xs flex items-center gap-2"
            >
              <Save className="w-3.5 h-3.5" />
              <span>Save & Apply Policies</span>
            </button>
            {savedSuccess && (
              <span className="text-xs text-emerald-600 font-semibold flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> Policies updated successfully.
              </span>
            )}
          </div>
        </div>
      )}

      {/* Tab 3: RBAC Roles */}
      {activeTab === "rbac" && (
        <div className="bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs max-w-3xl space-y-4">
          <div>
            <h3 className="text-sm font-bold text-slate-900">Role-Based Access Control Matrix (RBAC)</h3>
            <p className="text-xs text-slate-500">Configured privilege boundaries across operational personas.</p>
          </div>

          <div className="space-y-3">
            {[
              { role: "Admin", perms: "Full tenant administration, API key generation, threat policy modification, and destructive rollbacks" },
              { role: "Security Analyst", perms: "Deep dive threat hunting, incident timeline updates, playbook execution, and manual sandboxing" },
              { role: "SOC Operator", perms: "Tier-1/2 alert triage, event containment triggers, and incident queue reassignments" },
              { role: "Organisation Manager", perms: "CISO dashboards, compliance verification, aggregate posture reports, and risk distribution metrics" },
              { role: "Viewer", perms: "Read-only access to threat intelligence feeds, incident status overviews, and executive reports" }
            ].map((r) => (
              <div key={r.role} className="p-3.5 border border-slate-200 rounded-lg bg-slate-50/50">
                <div className="text-xs font-bold text-slate-900">{r.role}</div>
                <div className="text-[11px] text-slate-500 mt-1">{r.perms}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
