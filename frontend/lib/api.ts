const API_BASE = "http://localhost:8000/api";

export interface UserProfile {
  email: string;
  full_name: string;
  role: string;
  department: string;
}

export function getCurrentUser(): UserProfile {
  if (typeof window === "undefined") {
    return {
      email: "analyst@cyberguard.local",
      full_name: "Ankit Kumar (Senior Security Analyst)",
      role: "Security Analyst",
      department: "SOC Threat Intelligence"
    };
  }
  const saved = localStorage.getItem("cyberguard_user");
  if (saved) {
    try {
      return JSON.parse(saved);
    } catch (e) {
      // fallback
    }
  }
  return {
    email: "analyst@cyberguard.local",
    full_name: "Ankit Kumar (Senior Security Analyst)",
    role: "Security Analyst",
    department: "SOC Threat Intelligence"
  };
}

export function setCurrentUser(user: UserProfile) {
  if (typeof window !== "undefined") {
    localStorage.setItem("cyberguard_user", JSON.stringify(user));
  }
}

export async function switchDemoRole(role: string): Promise<UserProfile> {
  const res = await fetch(`${API_BASE}/auth/switch-demo-role?role=${encodeURIComponent(role)}`, {
    method: "POST"
  });
  if (!res.ok) throw new Error("Failed to switch role");
  const data = await res.json();
  const user = data.user_info;
  setCurrentUser(user);
  return user;
}

export async function fetchDashboardMetrics() {
  const res = await fetch(`${API_BASE}/dashboard/metrics`);
  if (!res.ok) throw new Error("Failed to fetch dashboard metrics");
  return res.json();
}

export async function fetchThreats(category?: string, riskLevel?: string) {
  const params = new URLSearchParams();
  if (category) params.append("category", category);
  if (riskLevel) params.append("risk_level", riskLevel);
  const res = await fetch(`${API_BASE}/threats?${params.toString()}`);
  if (!res.ok) throw new Error("Failed to fetch threats");
  return res.json();
}

export async function fetchThreatDetail(threatId: string) {
  const res = await fetch(`${API_BASE}/threats/${threatId}`);
  if (!res.ok) throw new Error("Failed to fetch threat details");
  return res.json();
}

export async function fetchIncidents(status?: string, severity?: string) {
  const params = new URLSearchParams();
  if (status) params.append("status", status);
  if (severity) params.append("severity", severity);
  const res = await fetch(`${API_BASE}/incidents?${params.toString()}`);
  if (!res.ok) throw new Error("Failed to fetch incidents");
  return res.json();
}

export async function fetchIncidentDetail(incidentId: string) {
  const res = await fetch(`${API_BASE}/incidents/${incidentId}`);
  if (!res.ok) throw new Error("Failed to fetch incident details");
  return res.json();
}

export async function updateIncident(incidentId: string, payload: any) {
  const res = await fetch(`${API_BASE}/incidents/${incidentId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error("Failed to update incident");
  return res.json();
}

export async function analyzeEmail(payload: { subject: string; sender: string; body: string; recipient?: string; links?: string[] }) {
  const res = await fetch(`${API_BASE}/analyze/email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error("Failed to analyze email");
  return res.json();
}

export async function analyzeUrl(url: string, context?: string) {
  const res = await fetch(`${API_BASE}/analyze/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, context: context || "Interactive analysis" })
  });
  if (!res.ok) throw new Error("Failed to analyze URL");
  return res.json();
}

export async function analyzeBehavior(payload: {
  user_email: string;
  login_location: string;
  ip_address: string;
  device_name: string;
  browser: string;
  failed_attempts: number;
}) {
  const res = await fetch(`${API_BASE}/analyze/behavior`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error("Failed to analyze behavior");
  return res.json();
}

export async function analyzeNetwork(payload: {
  source_ip: string;
  destination_ip: string;
  port: number;
  protocol: string;
  bytes_transferred: number;
  packet_summary: string;
  raw_logs?: string;
}) {
  const res = await fetch(`${API_BASE}/analyze/network`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error("Failed to analyze network event");
  return res.json();
}

export async function analyzeMedia(file: File, mediaType: "image" | "audio" | "video") {
  const formData = new FormData();
  formData.append("file", file);
  const res = await fetch(`${API_BASE}/analyze/${mediaType}`, {
    method: "POST",
    body: formData
  });
  if (!res.ok) throw new Error(`Failed to analyze ${mediaType}`);
  return res.json();
}

export async function analyzeQuishing(file: File) {
  const formData = new FormData();
  formData.append("file", file);
  const res = await fetch(`${API_BASE}/analyze/quishing`, {
    method: "POST",
    body: formData
  });
  if (!res.ok) throw new Error("Failed to scan QR Code");
  return res.json();
}

export async function analyzeGenAI(text: string) {
  const formData = new FormData();
  formData.append("text", text);
  const res = await fetch(`${API_BASE}/analyze/genai-phishing`, {
    method: "POST",
    body: formData
  });
  if (!res.ok) throw new Error("Failed to analyze GenAI stylometry");
  return res.json();
}


export async function fetchIOCs() {
  const res = await fetch(`${API_BASE}/intelligence/iocs`);
  if (!res.ok) throw new Error("Failed to fetch IOCs");
  return res.json();
}

export async function fetchMitreMatrix() {
  const res = await fetch(`${API_BASE}/intelligence/mitre`);
  if (!res.ok) throw new Error("Failed to fetch MITRE matrix");
  return res.json();
}

export async function fetchAttackGraph() {
  const res = await fetch(`${API_BASE}/graph`);
  if (!res.ok) throw new Error("Failed to fetch attack graph");
  return res.json();
}

export async function fetchReportSummary() {
  const res = await fetch(`${API_BASE}/reports/summary`);
  if (!res.ok) throw new Error("Failed to fetch reports");
  return res.json();
}

export async function fetchModelRegistry() {
  const res = await fetch(`${API_BASE}/settings/models`);
  if (!res.ok) throw new Error("Failed to fetch model registry");
  return res.json();
}

export async function executeDefensiveAction(payload: {
  action_type: string;
  target: string;
  reason: string;
  evidence_summary?: string;
  threat_id?: string;
  incident_id?: string;
}) {
  const res = await fetch(`${API_BASE}/response/execute`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error("Failed to execute response action");
  return res.json();
}

export async function rollbackDefensiveAction(actionId: string) {
  const res = await fetch(`${API_BASE}/response/rollback/${actionId}`, {
    method: "POST"
  });
  if (!res.ok) throw new Error("Failed to rollback action");
  return res.json();
}

export async function queryAIAssistant(query: string, incidentId?: string, threatId?: string) {
  const res = await fetch(`${API_BASE}/assistant/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query, incident_id: incidentId, threat_id: threatId })
  });
  if (!res.ok) throw new Error("Failed to query AI assistant");
  return res.json();
}
