"use client";

import React, { useState, useEffect } from "react";
import {
  Network,
  Download,
  ShieldAlert,
  Search,
  Info,
  Maximize2,
  Users,
  Server,
  Globe,
  Smartphone,
  Mail,
  Building
} from "lucide-react";
import { fetchAttackGraph } from "@/lib/api";

const NODE_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  person: { bg: "bg-blue-50", border: "border-blue-300", text: "text-blue-700" },
  email: { bg: "bg-indigo-50", border: "border-indigo-300", text: "text-indigo-700" },
  domain: { bg: "bg-cyan-50", border: "border-cyan-300", text: "text-cyan-700" },
  ip: { bg: "bg-slate-50", border: "border-slate-300", text: "text-slate-700" },
  device: { bg: "bg-emerald-50", border: "border-emerald-300", text: "text-emerald-700" },
  organization: { bg: "bg-purple-50", border: "border-purple-300", text: "text-purple-700" },
  threat: { bg: "bg-rose-50", border: "border-rose-400", text: "text-rose-700" }
};

export default function AttackGraphPage() {
  const [graphData, setGraphData] = useState<any>(null);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [cypherModal, setCypherModal] = useState<string | null>(null);

  useEffect(() => {
    fetchAttackGraph().then((data) => {
      setGraphData(data);
      if (data.nodes.length > 0) {
        setSelectedNode(data.nodes[0]);
      }
    });
  }, []);

  const handleExportCypher = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/graph/cypher");
      const data = await res.json();
      setCypherModal(data.cypher);
    } catch (e) {
      console.error(e);
    }
  };

  if (!graphData) {
    return <div className="p-8 text-center text-slate-400">Loading Attack Graph Telemetry...</div>;
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">Attack & Identity Relationship Graph</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Neo4j-compatible topology: Person &rarr; Email &rarr; Domain &rarr; IP &rarr; Device &rarr; Organization.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportCypher}
            className="flex items-center gap-2 border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 text-xs font-semibold px-3 py-2 rounded-lg shadow-xs transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Neo4j Cypher Script</span>
          </button>
        </div>
      </div>

      {/* Cypher Script Modal */}
      {cypherModal && (
        <div className="bg-slate-900 text-slate-100 rounded-xl p-4 shadow-lg text-xs font-mono">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800 mb-3">
            <span className="font-bold text-blue-400">Neo4j Cypher Statements</span>
            <button onClick={() => setCypherModal(null)} className="text-slate-400 hover:text-white">
              ✕ Close
            </button>
          </div>
          <pre className="overflow-x-auto max-h-60 text-[11px]">{cypherModal}</pre>
        </div>
      )}

      {/* Main Graph Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Interactive Visual Graph Canvas (8 cols) */}
        <div className="lg:col-span-8 bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs flex flex-col min-h-[500px]">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-4">
            <div className="flex items-center gap-2">
              <Network className="w-4 h-4 text-blue-600" />
              <span className="text-xs font-bold text-slate-800">Entity Topology Map</span>
            </div>
            <div className="flex items-center gap-2 text-[11px] text-slate-500">
              <span>{graphData.metrics.total_entities} Entities</span>
              <span>&bull;</span>
              <span>{graphData.metrics.total_relationships} Linkages</span>
              <span>&bull;</span>
              <span className="text-rose-600 font-semibold">{graphData.metrics.critical_entities} Anomalies</span>
            </div>
          </div>

          {/* SVG Diagram Visualizer */}
          <div className="flex-1 bg-slate-50/70 border border-slate-200 rounded-xl p-4 relative overflow-auto">
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {graphData.nodes.map((node: any) => {
                const styling = NODE_COLORS[node.type] || { bg: "bg-slate-100", border: "border-slate-300", text: "text-slate-700" };
                const isSelected = selectedNode?.id === node.id;
                const isCritical = node.risk_level === "CRITICAL";

                return (
                  <div
                    key={node.id}
                    onClick={() => setSelectedNode(node)}
                    className={`cursor-pointer p-3 rounded-xl border transition-all ${
                      isSelected
                        ? "ring-2 ring-blue-500 shadow-md bg-white border-blue-400"
                        : `${styling.bg} ${styling.border} hover:shadow-xs`
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className={`text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${styling.text}`}>
                        {node.type}
                      </span>
                      {isCritical && (
                        <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
                      )}
                    </div>
                    <div className="text-xs font-bold text-slate-900 truncate">{node.label}</div>
                    <div className="text-[10px] text-slate-500 mt-1 flex items-center justify-between">
                      <span className="font-mono">{node.id}</span>
                      <span className={isCritical ? "text-rose-600 font-bold" : "text-emerald-600 font-semibold"}>
                        {node.risk_level}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="pt-3 flex items-center justify-between text-[11px] text-slate-400">
            <span>Click any node to inspect relationship linkages and associated threat indicators.</span>
            <span>Graph engine: NetworkX 3.7 &bull; Neo4j Bolt Driver ready</span>
          </div>
        </div>

        {/* Node Inspector Panel (4 cols) */}
        <div className="lg:col-span-4 bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs flex flex-col space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-blue-600" />
              <span>Entity Inspector</span>
            </h3>
            {selectedNode && (
              <span
                className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                  selectedNode.risk_level === "CRITICAL"
                    ? "bg-rose-100 text-rose-700"
                    : "bg-emerald-100 text-emerald-700"
                }`}
              >
                {selectedNode.risk_level}
              </span>
            )}
          </div>

          {selectedNode ? (
            <div className="space-y-4 text-xs">
              <div>
                <span className="text-[10px] text-slate-400 font-semibold uppercase block">Node Label</span>
                <div className="text-sm font-bold text-slate-900 mt-0.5">{selectedNode.label}</div>
              </div>

              <div className="grid grid-cols-2 gap-2 p-3 bg-slate-50 border border-slate-200 rounded-lg">
                <div>
                  <span className="text-[10px] text-slate-400 uppercase block">Node ID</span>
                  <span className="font-mono font-medium text-slate-800">{selectedNode.id}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 uppercase block">Entity Class</span>
                  <span className="font-bold text-blue-700 capitalize">{selectedNode.type}</span>
                </div>
              </div>

              {/* Connected Relationships */}
              <div>
                <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block mb-2">
                  Direct Graph Relationships
                </span>
                <div className="space-y-2">
                  {graphData.edges
                    .filter((e: any) => e.source === selectedNode.id || e.target === selectedNode.id)
                    .map((edge: any, i: number) => (
                      <div
                        key={i}
                        className="p-2.5 rounded-lg border border-slate-200 bg-slate-50/60 flex items-center justify-between"
                      >
                        <span className="font-mono text-slate-700">
                          {edge.source === selectedNode.id ? edge.target : edge.source}
                        </span>
                        <span className="text-[10px] font-bold text-blue-600 bg-blue-50 px-2 py-0.5 rounded border border-blue-100">
                          {edge.relation}
                        </span>
                      </div>
                    ))}
                </div>
              </div>

              <div className="pt-3 border-t border-slate-100">
                <button
                  onClick={() => alert(`Initiating perimeter quarantine for node: ${selectedNode.label}`)}
                  className="w-full text-center bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 rounded-lg text-xs shadow-xs"
                >
                  Isolate Entity in Access Gateway
                </button>
              </div>
            </div>
          ) : (
            <div className="text-center py-12 text-slate-400 text-xs">Select a node to inspect relationships.</div>
          )}
        </div>
      </div>
    </div>
  );
}
