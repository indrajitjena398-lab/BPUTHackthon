"use client";

import React, { useState } from "react";
import {
  Bot,
  Send,
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  Terminal,
  HelpCircle,
  FileQuestion
} from "lucide-react";
import { queryAIAssistant } from "@/lib/api";

const SUGGESTED_PROMPTS = [
  "Why was Threat THT-20261006-001A classified as phishing?",
  "Which MITRE ATT&CK techniques apply to credential harvesting?",
  "What defensive actions should the administrator execute?",
  "Which enterprise assets or accounts are currently impacted?",
  "Explain the evidence behind the impossible travel detection."
];

interface ChatMessage {
  sender: "user" | "assistant";
  text: string;
  evidence?: string[];
  mitre?: any[];
  actions?: string[];
}

export default function AssistantPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      sender: "assistant",
      text: "Hello! I am CyberGuard AI Security Analyst. I provide grounded, evidence-backed security investigations across all platform events, MITRE matrices, and defensive playbooks. How can I assist your investigation today?"
    }
  ]);
  const [inputQuery, setInputQuery] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSend = async (queryText?: string) => {
    const q = queryText || inputQuery;
    if (!q.trim()) return;

    const userMsg: ChatMessage = { sender: "user", text: q };
    setMessages((prev) => [...prev, userMsg]);
    setInputQuery("");
    setLoading(true);

    try {
      const res = await queryAIAssistant(q);
      const assistantMsg: ChatMessage = {
        sender: "assistant",
        text: res.answer,
        evidence: res.evidence_cited,
        mitre: res.mitre_techniques,
        actions: res.recommended_actions
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (e) {
      console.error(e);
      setMessages((prev) => [
        ...prev,
        {
          sender: "assistant",
          text: "I encountered an error querying platform telemetry. Please verify backend connectivity."
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto flex flex-col h-[calc(100vh-8rem)]">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <Bot className="w-5 h-5 text-blue-600" />
          <span>AI Security Analyst Copilot</span>
        </h2>
        <p className="text-xs text-slate-500 mt-0.5">
          Grounded conversational investigation copilot. Strict zero-hallucination policy using verified detection evidence.
        </p>
      </div>

      {/* Suggested Query Pills */}
      <div className="flex flex-wrap gap-2">
        {SUGGESTED_PROMPTS.map((prompt, i) => (
          <button
            key={i}
            onClick={() => handleSend(prompt)}
            className="text-left text-xs bg-white hover:bg-blue-50 border border-slate-200 hover:border-blue-300 text-slate-700 px-3 py-1.5 rounded-full transition-colors flex items-center gap-1.5 shadow-xs"
          >
            <Sparkles className="w-3 h-3 text-blue-600 shrink-0" />
            <span className="truncate">{prompt}</span>
          </button>
        ))}
      </div>

      {/* Chat Messages Container */}
      <div className="flex-1 bg-white border border-slate-200/90 rounded-xl p-5 shadow-xs overflow-y-auto space-y-4">
        {messages.map((m, idx) => (
          <div
            key={idx}
            className={`flex gap-3 text-xs leading-relaxed ${
              m.sender === "user" ? "justify-end" : "justify-start"
            }`}
          >
            {m.sender === "assistant" && (
              <div className="w-7 h-7 rounded-lg bg-blue-600 text-white flex items-center justify-center shrink-0 mt-0.5 shadow-xs">
                <Bot className="w-4 h-4" />
              </div>
            )}

            <div
              className={`max-w-2xl rounded-2xl p-4 ${
                m.sender === "user"
                  ? "bg-blue-600 text-white"
                  : "bg-slate-50 border border-slate-200 text-slate-800"
              }`}
            >
              <div className="whitespace-pre-wrap">{m.text}</div>

              {/* Cited Evidence Cards */}
              {m.evidence && m.evidence.length > 0 && (
                <div className="mt-3 pt-3 border-t border-slate-200 space-y-1">
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                    Verified Grounded Indicators
                  </span>
                  {m.evidence.map((ev, i) => (
                    <div key={i} className="flex items-center gap-1.5 text-[11px] text-slate-600">
                      <CheckCircle2 className="w-3 h-3 text-blue-600 shrink-0" />
                      <span>{ev}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex gap-3 text-xs">
            <div className="w-7 h-7 rounded-lg bg-blue-600 text-white flex items-center justify-center shrink-0 shadow-xs">
              <Bot className="w-4 h-4 animate-pulse" />
            </div>
            <div className="bg-slate-50 border border-slate-200 rounded-2xl p-3 text-slate-500 animate-pulse">
              Synthesizing platform evidence...
            </div>
          </div>
        )}
      </div>

      {/* Input Bar */}
      <div className="flex gap-2">
        <input
          type="text"
          placeholder="Ask about detected threats, MITRE mappings, root cause, or defensive actions..."
          value={inputQuery}
          onChange={(e) => setInputQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSend()}
          className="flex-1 px-4 py-2.5 border border-slate-200 rounded-xl text-xs text-slate-900 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 shadow-xs"
        />
        <button
          onClick={() => handleSend()}
          disabled={loading}
          className="bg-blue-600 hover:bg-blue-700 text-white font-semibold px-4 py-2.5 rounded-xl text-xs flex items-center gap-1.5 shadow-xs transition-colors"
        >
          <span>Send</span>
          <Send className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}
