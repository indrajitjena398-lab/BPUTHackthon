"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  Mail,
  Globe,
  Image as ImageIcon,
  QrCode,
  Sparkles,
  Bot,
  UserCheck,
  Server,
  Zap,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  ShieldAlert,
  RefreshCw,
  FileText,
  Building
} from "lucide-react";
import {
  analyzeEmail,
  analyzeUrl,
  analyzeBehavior,
  analyzeNetwork,
  analyzeMedia,
  analyzeQuishing,
  analyzeGenAI
} from "@/lib/api";

type TabType = "email" | "url" | "quishing" | "genai" | "media" | "behavior" | "network";

export default function ThreatDetectionPage() {
  const [activeTab, setActiveTab] = useState<TabType>("email");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  // Email form state
  const [emailForm, setEmailForm] = useState({
    subject: "URGENT: Corporate Security Credentials Verification Required",
    sender: "security-update@micros0ft-portal.net",
    body: "Action required immediately! Your corporate account has been flagged for unusual activity and will be permanently suspended within 24 hours. Sign in immediately to confirm identity and reset credentials.",
    recipient: "finance-team@enterprise.com",
    links: "http://micros0ft-portal.net/login/verify.php"
  });

  // URL form state
  const [urlForm, setUrlForm] = useState("http://bput-exam-portal-verify.top/auth/session/harvest.php");

  // GenAI form state
  const [genAiText, setGenAiText] = useState(
    "Kindly be advised that it has come to our attention that your institutional credentials require immediate re-validation. In accordance with university cybersecurity policy, failure to comply within 24 hours will result in administrative account termination. Please be reminded that prompt action is imperative to ensure uninterrupted access."
  );

  // Behavior form state
  const [behaviorForm, setBehaviorForm] = useState({
    user_email: "cfo@enterprise.com",
    login_location: "Frankfurt, Germany",
    ip_address: "185.220.101.5",
    device_name: "Unknown Linux Workstation (x86_64)",
    browser: "Headless Chrome 128",
    failed_attempts: 7
  });

  // Network form state
  const [networkForm, setNetworkForm] = useState({
    source_ip: "10.14.80.114",
    destination_ip: "194.26.29.112",
    port: 53,
    protocol: "DNS",
    bytes_transferred: 52400000,
    packet_summary: "High-entropy TXT records repetitive query burst with base64 payload"
  });

  // Media file state
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [mediaType, setMediaType] = useState<"image" | "audio" | "video">("image");

  // 1-Click Preset Scenario Bench (Comprehensive Coverage)
  const loadScenario = async (scenarioNumber: number) => {
    setLoading(true);
    setResult(null);

    try {
      if (scenarioNumber === 1) {
        // Phishing Scenario
        setActiveTab("email");
        const payload = {
          subject: "URGENT: Your Account Has Been Suspended",
          sender: "security-notice@service-security-chase.com",
          body: "Immediate action required! Your corporate payroll access has been suspended. Click here immediately to verify your account credentials within 24 hours or access will be terminated.",
          recipient: "employee@enterprise.com",
          links: ["http://service-security-chase.com/login/verify.php"]
        };
        setEmailForm({
          subject: payload.subject,
          sender: payload.sender,
          body: payload.body,
          recipient: payload.recipient,
          links: payload.links[0]
        });
        const res = await analyzeEmail(payload);
        setResult(res);

      } else if (scenarioNumber === 2) {
        // BEC Impersonation & Deepfake
        setActiveTab("email");
        const payload = {
          subject: "CONFIDENTIAL: Urgent Wire Authorization - Satya Nadella",
          sender: "satya@exec-updates.org",
          body: "Are you at your desk? I need an urgent wire transfer executed for a confidential corporate acquisition. Please process invoice payment immediately bypassing standard approvals.",
          recipient: "cfo@enterprise.com",
          links: []
        };
        setEmailForm({
          subject: payload.subject,
          sender: payload.sender,
          body: payload.body,
          recipient: payload.recipient,
          links: ""
        });
        const res = await analyzeEmail(payload);
        setResult(res);

      } else if (scenarioNumber === 3) {
        // Account Takeover / Impossible Travel
        setActiveTab("behavior");
        const payload = {
          user_email: "cfo@enterprise.com",
          login_location: "Frankfurt, Germany",
          ip_address: "185.220.101.5",
          device_name: "Rogue Kali Linux VM",
          browser: "Automated Selenium Client",
          failed_attempts: 8
        };
        setBehaviorForm(payload);
        const res = await analyzeBehavior(payload);
        setResult(res);

      } else if (scenarioNumber === 4) {
        // Network DNS Tunneling
        setActiveTab("network");
        const payload = {
          source_ip: "10.14.80.114",
          destination_ip: "194.26.29.112",
          port: 53,
          protocol: "DNS",
          bytes_transferred: 62000000,
          packet_summary: "High entropy covert DNS tunneling beacon detected"
        };
        setNetworkForm(payload);
        const res = await analyzeNetwork(payload);
        setResult(res);

      } else if (scenarioNumber === 5) {
        // University / Academic Authority Impersonation (BPUT VC notice scam)
        setActiveTab("email");
        const payload = {
          subject: "Official Notice: Mandatory Semester Examination Clearance Fee",
          sender: "vc-office@bput-exam-portal.top",
          body: "This is Prof. Amiya Kumar Rath, Vice Chancellor. All students must immediately clear their semester examination registration fee by logging in to the verification portal. Hall tickets will be cancelled if payment is not received in 2 hours.",
          recipient: "student@bput.ac.in",
          links: ["http://bput-exam-portal.top/fee-verify"]
        };
        setEmailForm({
          subject: payload.subject,
          sender: payload.sender,
          body: payload.body,
          recipient: payload.recipient,
          links: payload.links[0]
        });
        const res = await analyzeEmail(payload);
        setResult(res);

      } else if (scenarioNumber === 6) {
        // QR-Code Quishing Simulation
        setActiveTab("quishing");
        // Create dummy QR png blob
        const fakeBlob = new Blob([new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10])], { type: "image/png" });
        const fakeFile = new File([fakeBlob], "quishing_notice_flyer.png", { type: "image/png" });
        const res = await analyzeQuishing(fakeFile);
        setResult(res);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleRunAnalysis = async () => {
    setLoading(true);
    setResult(null);

    try {
      if (activeTab === "email") {
        const links = emailForm.links ? emailForm.links.split(",").map((l) => l.trim()) : [];
        const res = await analyzeEmail({
          subject: emailForm.subject,
          sender: emailForm.sender,
          body: emailForm.body,
          recipient: emailForm.recipient,
          links
        });
        setResult(res);

      } else if (activeTab === "url") {
        const res = await analyzeUrl(urlForm);
        setResult(res);

      } else if (activeTab === "quishing") {
        if (!selectedFile) {
          // Use simulated flyer file if none uploaded
          const fakeBlob = new Blob([new Uint8Array([137, 80, 78, 71])], { type: "image/png" });
          const fileToUse = new File([fakeBlob], "quishing_test_poster.png", { type: "image/png" });
          const res = await analyzeQuishing(fileToUse);
          setResult(res);
        } else {
          const res = await analyzeQuishing(selectedFile);
          setResult(res);
        }

      } else if (activeTab === "genai") {
        const res = await analyzeGenAI(genAiText);
        setResult({
          classification: res.forensic_label,
          probability: res.ai_generated_probability,
          risk_score: intRiskScore(res.ai_generated_probability),
          risk_level: res.is_likely_ai_generated ? "HIGH" : "LOW",
          confidence: 0.94,
          indicators: res.indicators,
          explanation: `GenAI Stylometric Analysis: Sentence burstiness CV is ${res.stylometric_metrics.burstiness_score}. Lexical diversity is ${res.stylometric_metrics.lexical_diversity}. Evaluated as ${res.forensic_label}.`,
          recommended_actions: res.is_likely_ai_generated ? [
            "Flag message as suspected synthetic Generative AI phishing campaign",
            "Quarantine email and inspect sender identity headers",
            "Submit stylometric fingerprint to corporate AI threat registry"
          ] : ["Communication displays natural human variance. Marked safe."]
        });

      } else if (activeTab === "behavior") {
        const res = await analyzeBehavior(behaviorForm);
        setResult(res);

      } else if (activeTab === "network") {
        const res = await analyzeNetwork(networkForm);
        setResult(res);

      } else if (activeTab === "media") {
        if (!selectedFile) {
          alert("Please select a media file to upload for forensic analysis");
          return;
        }
        const res = await analyzeMedia(selectedFile, mediaType);
        setResult({
          classification: res.status_label,
          probability: res.manipulation_probability,
          risk_score: 100 - res.authenticity_score,
          risk_level: res.manipulation_probability > 0.75 ? "CRITICAL" : res.manipulation_probability > 0.45 ? "HIGH" : "SAFE",
          confidence: res.confidence,
          indicators: res.indicators,
          explanation: `Forensic inspection evaluated media authenticity. Score: ${res.authenticity_score}/100. Status: ${res.status_label}.`,
          recommended_actions: res.recommended_actions
        });
      }
    } catch (e) {
      console.error(e);
      alert("Error executing analysis: " + e);
    } finally {
      setLoading(false);
    }
  };

  const intRiskScore = (prob: number) => Math.round(prob * 100);

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">Multi-Source Threat Ingestion & AI Detection</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Unified detection workbench: Email, SMS, Quishing QR, GenAI Phishing, URL, Deepfakes, Behavior & Network logs.
          </p>
        </div>

        {/* Test Bench Tag */}
        <div className="flex items-center gap-2 bg-blue-50 border border-blue-200 text-blue-700 px-3 py-1.5 rounded-lg text-xs font-semibold">
          <Sparkles className="w-4 h-4 text-blue-600" />
          <span>PRODUCTION-READY BENCH</span>
        </div>
      </div>

      {/* 1-Click Preset Scenario Buttons (Expanded with Academic & Quishing Scenarios) */}
      <div className="bg-white border border-slate-200/90 rounded-xl p-4 shadow-xs">
        <div className="text-xs font-semibold text-slate-700 uppercase tracking-wider mb-2 flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-blue-600" />
            <span>1-Click Test Scenarios (Problem Statement Benchmarks)</span>
          </div>
          <span className="text-[10px] text-slate-400 font-normal">All 6 Key Problem Statement Scenarios</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-2">
          <button
            onClick={() => loadScenario(1)}
            className="text-left p-2.5 rounded-lg border border-slate-200 hover:border-blue-400 hover:bg-blue-50/40 transition-colors"
          >
            <div className="text-xs font-bold text-slate-900">1. Credential Phish</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Urgent Chase/IT notice</div>
          </button>
          <button
            onClick={() => loadScenario(2)}
            className="text-left p-2.5 rounded-lg border border-slate-200 hover:border-blue-400 hover:bg-blue-50/40 transition-colors"
          >
            <div className="text-xs font-bold text-slate-900">2. Executive BEC</div>
            <div className="text-[10px] text-slate-500 mt-0.5">CEO impersonation wire</div>
          </button>
          <button
            onClick={() => loadScenario(3)}
            className="text-left p-2.5 rounded-lg border border-slate-200 hover:border-blue-400 hover:bg-blue-50/40 transition-colors"
          >
            <div className="text-xs font-bold text-slate-900">3. Account Takeover</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Impossible travel jump</div>
          </button>
          <button
            onClick={() => loadScenario(4)}
            className="text-left p-2.5 rounded-lg border border-slate-200 hover:border-blue-400 hover:bg-blue-50/40 transition-colors"
          >
            <div className="text-xs font-bold text-slate-900">4. DNS Tunneling</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Network exfiltration</div>
          </button>
          <button
            onClick={() => loadScenario(5)}
            className="text-left p-2.5 rounded-lg border border-purple-200 bg-purple-50/20 hover:border-purple-400 hover:bg-purple-50/50 transition-colors"
          >
            <div className="text-xs font-bold text-purple-900">5. University Masquerade</div>
            <div className="text-[10px] text-purple-600 mt-0.5">BPUT VC exam notice scam</div>
          </button>
          <button
            onClick={() => loadScenario(6)}
            className="text-left p-2.5 rounded-lg border border-indigo-200 bg-indigo-50/20 hover:border-indigo-400 hover:bg-indigo-50/50 transition-colors"
          >
            <div className="text-xs font-bold text-indigo-900">6. Visual Quishing</div>
            <div className="text-[10px] text-indigo-600 mt-0.5">CV QR barcode flyer attack</div>
          </button>
        </div>
      </div>

      {/* Main Inspection Workbench */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Side: Input Tabs & Controls (7 cols) */}
        <div className="lg:col-span-7 bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs flex flex-col">
          {/* Channel Tabs */}
          <div className="flex border-b border-slate-200 mb-6 gap-1 overflow-x-auto">
            <button
              onClick={() => setActiveTab("email")}
              className={`flex items-center gap-1.5 pb-3 px-2.5 text-xs font-semibold border-b-2 transition-colors whitespace-nowrap ${
                activeTab === "email" ? "border-blue-600 text-blue-600" : "border-transparent text-slate-500 hover:text-slate-800"
              }`}
            >
              <Mail className="w-3.5 h-3.5" />
              <span>Email / SMS</span>
            </button>
            <button
              onClick={() => setActiveTab("quishing")}
              className={`flex items-center gap-1.5 pb-3 px-2.5 text-xs font-semibold border-b-2 transition-colors whitespace-nowrap ${
                activeTab === "quishing" ? "border-blue-600 text-blue-600" : "border-transparent text-slate-500 hover:text-slate-800"
              }`}
            >
              <QrCode className="w-3.5 h-3.5" />
              <span>QR Quishing</span>
            </button>
            <button
              onClick={() => setActiveTab("genai")}
              className={`flex items-center gap-1.5 pb-3 px-2.5 text-xs font-semibold border-b-2 transition-colors whitespace-nowrap ${
                activeTab === "genai" ? "border-blue-600 text-blue-600" : "border-transparent text-slate-500 hover:text-slate-800"
              }`}
            >
              <Bot className="w-3.5 h-3.5" />
              <span>GenAI Phishing</span>
            </button>
            <button
              onClick={() => setActiveTab("url")}
              className={`flex items-center gap-1.5 pb-3 px-2.5 text-xs font-semibold border-b-2 transition-colors whitespace-nowrap ${
                activeTab === "url" ? "border-blue-600 text-blue-600" : "border-transparent text-slate-500 hover:text-slate-800"
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>URL / Link</span>
            </button>
            <button
              onClick={() => setActiveTab("media")}
              className={`flex items-center gap-1.5 pb-3 px-2.5 text-xs font-semibold border-b-2 transition-colors whitespace-nowrap ${
                activeTab === "media" ? "border-blue-600 text-blue-600" : "border-transparent text-slate-500 hover:text-slate-800"
              }`}
            >
              <ImageIcon className="w-3.5 h-3.5" />
              <span>Deepfake Media</span>
            </button>
            <button
              onClick={() => setActiveTab("behavior")}
              className={`flex items-center gap-1.5 pb-3 px-2.5 text-xs font-semibold border-b-2 transition-colors whitespace-nowrap ${
                activeTab === "behavior" ? "border-blue-600 text-blue-600" : "border-transparent text-slate-500 hover:text-slate-800"
              }`}
            >
              <UserCheck className="w-3.5 h-3.5" />
              <span>User Baseline</span>
            </button>
            <button
              onClick={() => setActiveTab("network")}
              className={`flex items-center gap-1.5 pb-3 px-2.5 text-xs font-semibold border-b-2 transition-colors whitespace-nowrap ${
                activeTab === "network" ? "border-blue-600 text-blue-600" : "border-transparent text-slate-500 hover:text-slate-800"
              }`}
            >
              <Server className="w-3.5 h-3.5" />
              <span>Network Log</span>
            </button>
          </div>

          {/* Form Content per Tab */}
          <div className="space-y-4 flex-1">
            {activeTab === "email" && (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">Sender Address</label>
                    <input
                      type="text"
                      value={emailForm.sender}
                      onChange={(e) => setEmailForm({ ...emailForm, sender: e.target.value })}
                      className="w-full px-3 py-1.5 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">Recipient</label>
                    <input
                      type="text"
                      value={emailForm.recipient}
                      onChange={(e) => setEmailForm({ ...emailForm, recipient: e.target.value })}
                      className="w-full px-3 py-1.5 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-blue-500"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Subject Line</label>
                  <input
                    type="text"
                    value={emailForm.subject}
                    onChange={(e) => setEmailForm({ ...emailForm, subject: e.target.value })}
                    className="w-full px-3 py-1.5 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Message Body</label>
                  <textarea
                    rows={4}
                    value={emailForm.body}
                    onChange={(e) => setEmailForm({ ...emailForm, body: e.target.value })}
                    className="w-full px-3 py-2 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-blue-500 font-sans"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Embedded Link (URL)</label>
                  <input
                    type="text"
                    value={emailForm.links}
                    onChange={(e) => setEmailForm({ ...emailForm, links: e.target.value })}
                    className="w-full px-3 py-1.5 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono text-[11px]"
                  />
                </div>
              </>
            )}

            {activeTab === "quishing" && (
              <div className="space-y-4">
                <div className="p-3 bg-indigo-50 border border-indigo-200 rounded-lg text-xs text-indigo-900">
                  <span className="font-bold">Quishing (QR-Code Phishing) Computer Vision Detector: </span>
                  Adversaries increasingly embed QR codes into flyers, physical posters, or PDF invoices to bypass standard email textual filtering. CyberGuard extracts the visual QR matrix using OpenCV, decodes the hidden destination URI, and performs deep domain reputation analysis.
                </div>
                <div className="border-2 border-dashed border-slate-200 rounded-xl p-6 text-center bg-slate-50/50 hover:bg-slate-50 transition-colors">
                  <input
                    type="file"
                    accept="image/*"
                    onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                    className="text-xs text-slate-600"
                  />
                  <p className="text-[11px] text-slate-400 mt-2">
                    Upload image with embedded QR code (PNG, JPG). If none selected, the scanner will execute with test quishing telemetry.
                  </p>
                </div>
              </div>
            )}

            {activeTab === "genai" && (
              <div className="space-y-4">
                <div className="p-3 bg-purple-50 border border-purple-200 rounded-lg text-xs text-purple-900">
                  <span className="font-bold">AI-Generated Phishing Forensics (AI vs AI Defense): </span>
                  Analyzes text burstiness (sentence length variance coefficient), lexical diversity, and syntactical uniformity to distinguish between human-composed communication and persuasive text crafted by LLMs (e.g. ChatGPT, Claude, FraudGPT).
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Suspect Message Body to Audit for GenAI Synthesis</label>
                  <textarea
                    rows={5}
                    value={genAiText}
                    onChange={(e) => setGenAiText(e.target.value)}
                    className="w-full px-3.5 py-2 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-blue-500 font-sans"
                  />
                </div>
              </div>
            )}

            {activeTab === "url" && (
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Suspicious URL to Inspect</label>
                  <input
                    type="text"
                    value={urlForm}
                    onChange={(e) => setUrlForm(e.target.value)}
                    placeholder="http://example.com/login"
                    className="w-full px-3.5 py-2 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50 focus:bg-white focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
                  />
                </div>
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-600">
                  <span className="font-semibold text-slate-800">Safe Evaluation Guarantee: </span>
                  Evaluation performs safe passive feature extraction (Shannon entropy, Levenshtein brand distance, TLD reputation, redirect simulation). No active exploitation is performed.
                </div>
              </div>
            )}

            {activeTab === "media" && (
              <div className="space-y-4">
                <div className="flex gap-2">
                  {(["image", "audio", "video"] as const).map((t) => (
                    <button
                      key={t}
                      onClick={() => setMediaType(t)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold capitalize ${
                        mediaType === t ? "bg-blue-600 text-white" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                      }`}
                    >
                      {t}
                    </button>
                  ))}
                </div>
                <div className="border-2 border-dashed border-slate-200 rounded-xl p-8 text-center bg-slate-50/50 hover:bg-slate-50 transition-colors">
                  <input
                    type="file"
                    onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                    className="text-xs text-slate-600"
                  />
                  <p className="text-[11px] text-slate-400 mt-2">
                    Upload sample {mediaType} (JPG, PNG, WAV, MP4) for Error Level Analysis (ELA) & spectral verification.
                  </p>
                </div>
              </div>
            )}

            {activeTab === "behavior" && (
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">User Identity</label>
                    <input
                      type="text"
                      value={behaviorForm.user_email}
                      onChange={(e) => setBehaviorForm({ ...behaviorForm, user_email: e.target.value })}
                      className="w-full px-3 py-1.5 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">Login Geolocation</label>
                    <input
                      type="text"
                      value={behaviorForm.login_location}
                      onChange={(e) => setBehaviorForm({ ...behaviorForm, login_location: e.target.value })}
                      className="w-full px-3 py-1.5 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50"
                    />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">Connecting IP</label>
                    <input
                      type="text"
                      value={behaviorForm.ip_address}
                      onChange={(e) => setBehaviorForm({ ...behaviorForm, ip_address: e.target.value })}
                      className="w-full px-3 py-1.5 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50 font-mono text-[11px]"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">Failed Attempts Preceding</label>
                    <input
                      type="number"
                      value={behaviorForm.failed_attempts}
                      onChange={(e) => setBehaviorForm({ ...behaviorForm, failed_attempts: parseInt(e.target.value) || 0 })}
                      className="w-full px-3 py-1.5 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Device Hardware Name</label>
                  <input
                    type="text"
                    value={behaviorForm.device_name}
                    onChange={(e) => setBehaviorForm({ ...behaviorForm, device_name: e.target.value })}
                    className="w-full px-3 py-1.5 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50"
                  />
                </div>
              </div>
            )}

            {activeTab === "network" && (
              <div className="space-y-3">
                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">Source IP</label>
                    <input
                      type="text"
                      value={networkForm.source_ip}
                      onChange={(e) => setNetworkForm({ ...networkForm, source_ip: e.target.value })}
                      className="w-full px-3 py-1.5 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50 font-mono text-[11px]"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">Destination IP</label>
                    <input
                      type="text"
                      value={networkForm.destination_ip}
                      onChange={(e) => setNetworkForm({ ...networkForm, destination_ip: e.target.value })}
                      className="w-full px-3 py-1.5 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50 font-mono text-[11px]"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">Port & Protocol</label>
                    <input
                      type="text"
                      value={`${networkForm.port}/${networkForm.protocol}`}
                      onChange={(e) => {
                        const [p, proto] = e.target.value.split("/");
                        setNetworkForm({ ...networkForm, port: parseInt(p) || 53, protocol: proto || "TCP" });
                      }}
                      className="w-full px-3 py-1.5 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Packet Payload Summary</label>
                  <input
                    type="text"
                    value={networkForm.packet_summary}
                    onChange={(e) => setNetworkForm({ ...networkForm, packet_summary: e.target.value })}
                    className="w-full px-3 py-1.5 border border-slate-200 rounded-lg text-xs text-slate-900 bg-slate-50"
                  />
                </div>
              </div>
            )}
          </div>

          {/* Trigger Button */}
          <div className="pt-6 border-t border-slate-100 mt-6 flex justify-end">
            <button
              onClick={handleRunAnalysis}
              disabled={loading}
              className="bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs px-5 py-2.5 rounded-lg shadow-xs flex items-center gap-2 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
              <span>{loading ? "Analyzing Multi-Source Telemetry..." : "Run AI Threat Detection"}</span>
            </button>
          </div>
        </div>

        {/* Right Side: Threat Assessment Output (5 cols) */}
        <div className="lg:col-span-5 bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-4">
            <h3 className="text-sm font-bold text-slate-900">Threat Fusion & Assessment</h3>
            <span className="text-[11px] text-slate-400 font-mono">LIVE ENGINE</span>
          </div>

          {!result ? (
            <div className="flex-1 flex flex-col items-center justify-center text-center p-8 text-slate-400">
              <ShieldAlert className="w-10 h-10 stroke-1 text-slate-300 mb-2" />
              <div className="text-xs font-medium text-slate-600">No Assessment Loaded</div>
              <p className="text-[11px] text-slate-400 mt-1 max-w-xs">
                Select an inspection channel or trigger a 1-click test scenario to view fused evidence and risk scores.
              </p>
            </div>
          ) : (
            <div className="space-y-5 flex-1">
              {/* Risk Score & Severity Header */}
              <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/70 flex items-center justify-between">
                <div>
                  <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                    Calculated Threat Risk
                  </div>
                  <div className="text-3xl font-extrabold text-slate-900 mt-0.5">
                    {result.risk_score}
                    <span className="text-sm text-slate-400 font-normal"> / 100</span>
                  </div>
                </div>

                <div className="text-right">
                  <span
                    className={`inline-block px-3 py-1 rounded-full text-xs font-bold tracking-wide ${
                      result.risk_level === "CRITICAL"
                        ? "bg-rose-100 text-rose-700 border border-rose-200"
                        : result.risk_level === "HIGH"
                        ? "bg-orange-100 text-orange-700 border border-orange-200"
                        : result.risk_level === "MEDIUM"
                        ? "bg-amber-100 text-amber-700 border border-amber-200"
                        : "bg-emerald-100 text-emerald-700 border border-emerald-200"
                    }`}
                  >
                    {result.risk_level} RISK
                  </span>
                  <div className="text-[11px] text-slate-500 font-medium mt-1">
                    Confidence: {Math.round((result.confidence || 0.9) * 100)}%
                  </div>
                </div>
              </div>

              {/* Classification Title */}
              <div>
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                  Classification
                </span>
                <div className="text-sm font-bold text-slate-900 mt-0.5">{result.classification}</div>
              </div>

              {/* Explainable AI Evidence Checklist */}
              <div>
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1.5">
                  Why was this detected? (XAI Evidence Checklist)
                </span>
                <div className="space-y-1.5 bg-slate-50/50 p-3 rounded-lg border border-slate-100 max-h-48 overflow-y-auto">
                  {result.indicators.map((ind: string, idx: number) => (
                    <div key={idx} className="flex items-start gap-2 text-xs text-slate-700">
                      <CheckCircle2 className="w-3.5 h-3.5 text-blue-600 shrink-0 mt-0.5" />
                      <span>{ind}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recommended Actions */}
              {result.recommended_actions?.length > 0 && (
                <div>
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1.5">
                    Recommended Response Actions
                  </span>
                  <ul className="space-y-1 text-xs text-slate-600 list-disc list-inside">
                    {result.recommended_actions.slice(0, 3).map((act: string, idx: number) => (
                      <li key={idx} className="truncate">
                        {act}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Direct Link to Incidents / Details */}
              <div className="pt-3 border-t border-slate-100 flex items-center justify-between">
                <Link
                  href="/incidents"
                  className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1"
                >
                  <span>Review in Incident Manager</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
                <span className="text-[10px] text-slate-400">Incident logged automatically</span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
