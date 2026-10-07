"use client";

import React, { useState, useEffect } from "react";
import {
  AlertTriangle,
  Clock,
  CheckCircle2,
  Filter,
  Search,
  UserCheck,
  ChevronRight,
  Shield,
  RotateCcw,
  Plus
} from "lucide-react";
import {
  fetchIncidents,
  fetchIncidentDetail,
  updateIncident,
  executeDefensiveAction
} from "@/lib/api";

const STATUSES = ["All", "New", "Investigating", "Contained", "Resolved", "False Positive", "Closed"];
const SEVERITIES = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedStatus, setSelectedStatus] = useState("All");
  const [selectedSeverity, setSelectedSeverity] = useState("All");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedIncident, setSelectedIncident] = useState<any | null>(null);
  const [resolutionNote, setResolutionNote] = useState("");
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const loadIncidents = async () => {
    try {
      setLoading(true);
      const data = await fetchIncidents(
        selectedStatus === "All" ? undefined : selectedStatus,
        selectedSeverity === "All" ? undefined : selectedSeverity
      );
      setIncidents(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, [selectedStatus, selectedSeverity]);

  const handleOpenDetail = async (incId: string) => {
    try {
      const detail = await fetchIncidentDetail(incId);
      setSelectedIncident(detail);
      setResolutionNote(detail.resolution_notes || "");
      setActionSuccess(null);
    } catch (e) {
      console.error(e);
    }
  };

  const handleStatusChange = async (newStatus: string) => {
    if (!selectedIncident) return;
    try {
      await updateIncident(selectedIncident.incident_id, {
        status: newStatus,
        resolution_notes: resolutionNote
      });
      handleOpenDetail(selectedIncident.incident_id);
      loadIncidents();
    } catch (e) {
      console.error(e);
    }
  };

  const handleExecuteAction = async (actionType: string) => {
    if (!selectedIncident) return;
    try {
      await executeDefensiveAction({
        action_type: actionType,
        target: selectedIncident.affected_user || selectedIncident.affected_asset || "Target Asset",
        reason: `Defensive playbook triggered from incident ${selectedIncident.incident_id}`,
        incident_id: selectedIncident.incident_id
      });
      setActionSuccess(`Defensive Action '${actionType}' executed and logged.`);
      handleOpenDetail(selectedIncident.incident_id);
    } catch (e) {
      console.error(e);
      alert("Error: " + e);
    }
  };

  const filteredIncidents = incidents.filter((inc) => {
    const matchesSearch =
      inc.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      inc.incident_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (inc.affected_user && inc.affected_user.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesSearch;
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">Incident Management</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            SOC incident investigation, containment workflows, and audit-logged response orchestration.
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-white border border-slate-200/90 rounded-xl p-4 shadow-xs flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3 flex-1 min-w-[280px]">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by ID, title, or affected entity..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 bg-slate-50 p-1 border border-slate-200 rounded-lg text-xs">
            <span className="text-[11px] font-semibold text-slate-500 px-2">Status:</span>
            {STATUSES.map((st) => (
              <button
                key={st}
                onClick={() => setSelectedStatus(st)}
                className={`px-2.5 py-1 rounded text-xs font-semibold transition-colors ${
                  selectedStatus === st
                    ? "bg-white text-blue-700 shadow-xs border border-slate-200"
                    : "text-slate-600 hover:text-slate-900"
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Incidents Table & Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Table View (7 cols or 12 cols if no drawer) */}
        <div className={`${selectedIncident ? "lg:col-span-7" : "lg:col-span-12"} bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs transition-all`}>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 text-slate-400 font-semibold uppercase tracking-wider">
                  <th className="pb-3">Incident ID</th>
                  <th className="pb-3">Title & Category</th>
                  <th className="pb-3">Severity</th>
                  <th className="pb-3">Status</th>
                  <th className="pb-3">Affected Target</th>
                  <th className="pb-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-slate-700">
                {filteredIncidents.map((inc) => (
                  <tr
                    key={inc.incident_id}
                    onClick={() => handleOpenDetail(inc.incident_id)}
                    className={`cursor-pointer transition-colors ${
                      selectedIncident?.incident_id === inc.incident_id
                        ? "bg-blue-50/60"
                        : "hover:bg-slate-50/70"
                    }`}
                  >
                    <td className="py-3 font-mono font-medium text-slate-900">{inc.incident_id}</td>
                    <td className="py-3 max-w-xs">
                      <div className="font-semibold text-slate-900 truncate">{inc.title}</div>
                      <div className="text-[10px] text-slate-400">{inc.category}</div>
                    </td>
                    <td className="py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
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
                      <span className="font-semibold text-slate-800">{inc.status}</span>
                    </td>
                    <td className="py-3 max-w-[140px] truncate text-slate-600">
                      {inc.affected_user || inc.affected_asset}
                    </td>
                    <td className="py-3 text-right">
                      <button className="text-blue-600 font-semibold text-xs hover:underline flex items-center gap-0.5 ml-auto">
                        <span>Details</span>
                        <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected Incident Detail Drawer (5 cols) */}
        {selectedIncident && (
          <div className="lg:col-span-5 bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs flex flex-col space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div>
                <span className="font-mono text-xs font-bold text-slate-400">
                  {selectedIncident.incident_id}
                </span>
                <h3 className="text-sm font-bold text-slate-900 mt-0.5">{selectedIncident.title}</h3>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="text-slate-400 hover:text-slate-600 text-xs font-semibold px-2 py-1 rounded"
              >
                ✕ Close
              </button>
            </div>

            {/* Severity & Status Controls */}
            <div className="grid grid-cols-2 gap-3 p-3 bg-slate-50/70 border border-slate-200 rounded-lg text-xs">
              <div>
                <span className="text-[10px] text-slate-400 uppercase font-semibold block">Severity</span>
                <span className="font-bold text-rose-700">{selectedIncident.severity}</span>
              </div>
              <div>
                <span className="text-[10px] text-slate-400 uppercase font-semibold block">Assigned Analyst</span>
                <span className="font-semibold text-slate-800">{selectedIncident.assigned_analyst}</span>
              </div>
            </div>

            {/* Status Workflow Action Bar */}
            <div>
              <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider block mb-1.5">
                Update Incident Lifecycle Status
              </span>
              <div className="flex flex-wrap gap-1.5">
                {["New", "Investigating", "Contained", "Resolved", "False Positive", "Closed"].map((st) => (
                  <button
                    key={st}
                    onClick={() => handleStatusChange(st)}
                    className={`px-2.5 py-1 rounded text-xs font-semibold transition-colors ${
                      selectedIncident.status === st
                        ? "bg-blue-600 text-white"
                        : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                    }`}
                  >
                    {st}
                  </button>
                ))}
              </div>
            </div>

            {/* Defensive Playbook Execution */}
            <div>
              <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider block mb-1.5">
                Trigger Controlled Defensive Action
              </span>
              <div className="grid grid-cols-2 gap-2">
                <button
                  onClick={() => handleExecuteAction("Quarantine Email")}
                  className="px-2.5 py-2 text-left bg-white border border-slate-200 hover:border-blue-400 hover:bg-blue-50/30 rounded-lg text-xs font-semibold text-slate-800 transition-colors"
                >
                  Quarantine Email
                </button>
                <button
                  onClick={() => handleExecuteAction("Require MFA")}
                  className="px-2.5 py-2 text-left bg-white border border-slate-200 hover:border-blue-400 hover:bg-blue-50/30 rounded-lg text-xs font-semibold text-slate-800 transition-colors"
                >
                  Require MFA Challenge
                </button>
                <button
                  onClick={() => handleExecuteAction("Revoke Session")}
                  className="px-2.5 py-2 text-left bg-white border border-slate-200 hover:border-blue-400 hover:bg-blue-50/30 rounded-lg text-xs font-semibold text-slate-800 transition-colors"
                >
                  Revoke Active Session
                </button>
                <button
                  onClick={() => handleExecuteAction("Block IP")}
                  className="px-2.5 py-2 text-left bg-white border border-slate-200 hover:border-rose-400 hover:bg-rose-50/30 rounded-lg text-xs font-semibold text-rose-700 transition-colors"
                >
                  Block IP / Domain
                </button>
              </div>
              {actionSuccess && (
                <div className="mt-2 p-2 bg-emerald-50 border border-emerald-200 rounded text-xs text-emerald-800 font-medium">
                  {actionSuccess}
                </div>
              )}
            </div>

            {/* Timeline */}
            <div>
              <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider block mb-1.5">
                Incident Timeline & Audit Trail
              </span>
              <div className="space-y-2 border-l-2 border-slate-200 pl-3 text-xs">
                {selectedIncident.timeline?.map((ev: any, i: number) => (
                  <div key={i} className="text-slate-600">
                    <span className="font-semibold text-slate-900">{ev.event}</span>
                    <div className="text-[10px] text-slate-400">Actor: {ev.actor}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
