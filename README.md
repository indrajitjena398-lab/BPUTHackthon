# CYBERGUARD — AI-Powered Cyber Threat, Phishing & Digital Impersonation Detection and Response System

**CYBERGUARD** is an intelligent, enterprise-grade cybersecurity platform that analyses multiple types of digital activity, detects cyber threats across both the **Technology layer** (networks, APIs, authentication, devices, logs) and the **Human layer** (phishing, social engineering, executive impersonation, deepfakes, synthetic media), classifies them with statistical confidence, calculates unified risk scores, explains *why* something is suspicious via Explainable AI (XAI), generates alerts, and executes controlled defensive playbooks.

---

## 1. UI/UX Design Philosophy

> **Enterprise SaaS Aesthetic (Zero Stereotypes)**
> 
> CYBERGUARD strictly avoids hacker tropes, black terminals, matrix effects, neon green, and cyber sci-fi graphics. Instead, it adopts a **modern, trustworthy, enterprise SaaS design**:
> - **Canvas**: Crisp white (`#FFFFFF`) with soft, light-slate background surfaces (`#F8FAFC`).
> - **Accents**: Trustworthy corporate blue (`#2563EB` / `#1D4ED8`).
> - **Status Badges**:
>   - **Safe (0–20)**: Emerald Green
>   - **Low (21–40)**: Blue
>   - **Medium (41–60)**: Amber
>   - **High (61–80)**: Orange
>   - **Critical (81–100)**: Crimson / Rose
> - **Typography & Layout**: Generous whitespace, clean modern typography, clear information hierarchy, and intuitive navigation.

---

## 2. High-Level Architecture

```
                    CYBERGUARD
                         |
                DATA INGESTION LAYER
                         |
       -----------------------------------------
       |          |          |        |        |
     Email       URL       Media     Logs    Network
       |          |          |        |        |
       -----------------------------------------
                         |
                 NORMALIZATION LAYER
                         |
                 EVENT PROCESSING
                         |
       -----------------------------------------
       |          |          |        |        |
   Phishing   URL/WEB    Deepfake  Behaviour Network
      AI         AI         AI        AI       AI
       |          |          |        |        |
       -----------------------------------------
                         |
                  THREAT FUSION
                         |
                 RISK SCORING ENGINE
                         |
                 EXPLAINABLE AI
                         |
                RESPONSE ENGINE
                         |
              ALERT + INCIDENT SYSTEM
                         |
                 CYBERGUARD UI
```

---

## 3. Core Modules & Detection Engines

### A. Multi-Source Threat Ingestion & Normalizer
Consumes multi-channel telemetry into a unified JSON event format (`EVT-001`):
- Email / SMS / Messaging
- URL & Web domains
- Image / Audio / Video files
- Authentication and User sessions
- Network packets & Syslog streams

### B. Phishing Detection Engine
- NLP feature extraction: Urgency linguistic markers, credential harvesting patterns, financial transaction triggers, aggressive capitalization.
- Lookalike domain / typosquatting checking against top enterprise brands.
- SPF/DKIM validation simulation.
- Returns classification, probability, risk score, indicators, and recommended actions.

### C. Malicious URL and Website Engine
- Passive lexical feature extraction: URL length, Shannon entropy, brand typosquatting distance, high-risk TLD reputation (`.tk`, `.top`, `.xyz`, etc.), open redirect detection, raw IP hosts.
- Safe analysis: strictly operates on user inputs and public threat intelligence without active exploitation.

### D. Multimedia Authenticity & Deepfake Engine
- **Image**: Error Level Analysis (ELA) compression discrepancy, frequency gradient energy (DCT/FFT artifacts), and face boundary blending detection.
- **Audio**: Spectral centroid variance, zero-crossing rate, and pitch contour jitter identifying synthetic neural vocoders and cloned voices.
- **Video**: Temporal consistency across frames, face boundary warping, and unnatural blink frequency.
- **Honest Labeling**: Outputs `"Potentially manipulated"` with authenticity score (0–100), manipulation probability, confidence, and forensic indicators.

### E. Digital Impersonation & BEC Engine
- Cross-references claimed identities against official corporate directories.
- Detects display name spoofing, cousin domains, and unauthorized external relays.
- Maps entity relationships using NetworkX graph algorithms.

### F. Account Takeover (ATO) & Behavioral Anomaly Engine
- User baseline tracking: 90-day geographic envelope, recognized device fingerprints, typical working hours, and password failure velocity.
- Flags impossible travel (e.g., login from Mumbai followed 14 minutes later by Frankfurt).
- Scikit-learn **Isolation Forest** multi-dimensional outlier scoring.

### G. Network & Technical Threat Detection
- Port scan and sweep reconnaissance detection.
- Covert DNS tunneling signatures with high-entropy query payloads.
- C2 beaconing detection with low-jitter repetitive intervals.
- High-volume data exfiltration egress monitoring.

### H. Threat Fusion Engine
- Combines multi-detector evidence with calibrated weights:
  $$\text{Combined Risk} = \text{Fusion}(\text{NLP}, \text{URL}, \text{Identity}, \text{Behavior}, \text{Deepfake}, \text{Threat Intel}, \text{Rules})$$
- Retains all granular evidence items from every active detector.
- Calibrates final score against asset criticality and user sensitivity.

### I. Explainable AI (XAI)
- Transparent attribution: Displays verified checkmarks (`✓ ...`) explaining why an event was classified as a threat.
- SHAP feature importance bar distributions.
- Zero-hallucination guarantee: Grounded purely in confirmed detector features.

### J. AI Security Assistant (Grounded Copilot)
- Contextual assistant answering questions about threat causes, MITRE ATT&CK techniques, and recommended playbooks.
- Strict read-only advisory architecture: does not independently perform destructive operations.

### K. Controlled Response Engine
- Actions: `Quarantine Email`, `Block URL`, `Require MFA Challenge`, `Revoke Session`, `Block IP`, `Escalate to SOC`.
- Complete audit trail: Action ID, Reason, Evidence, Timestamp, Actor, and full **Rollback capability**.
- Destructive actions require analyst confirmation unless explicitly overridden by policy.

---

## 4. Built-in Demo Scenarios (One-Click Test Bench)

Under the **Threat Detection** page (`/threat-detection`), click any preset scenario button to test the system:

1. **Scenario 1 — Urgent Credential Harvesting Phishing**  
   Fake bank/IT security verification email $\to$ Classification: Malicious Phishing $\to$ Risk Score: **92/100 (CRITICAL)**.
2. **Scenario 2 — Executive Impersonation & Synthetic Media**  
   Display name spoofed CEO message demanding emergency wire transfer $\to$ Risk Score: **89/100 (CRITICAL)**.
3. **Scenario 3 — Account Takeover & Impossible Travel**  
   Login jump from Mumbai to Frankfurt in 14 minutes on unknown Linux VM $\to$ Risk Score: **94/100 (CRITICAL)**.
4. **Scenario 4 — Network Intrusion & DNS Tunneling**  
   Covert base64 DNS tunneling exfiltration with low-jitter beaconing $\to$ Risk Score: **84/100 (HIGH)**.

---

## 5. Technology Stack

- **Frontend**: Next.js 14 (App Router), React 18, TypeScript, Tailwind CSS, Lucide Icons, Recharts.
- **Backend**: Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.0, Uvicorn, WebSockets.
- **Database**: SQLite (standalone out-of-the-box local operation) / PostgreSQL ready.
- **Machine Learning**: Scikit-learn, XGBoost, SHAP, NetworkX, Pillow.
- **Deployment**: Docker, Docker Compose, Windows batch runners.

---

## 6. How to Run Locally

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### Quick Start (Windows)
Double-click or run:
```cmd
start.bat
```
This automatically launches the FastAPI backend and Next.js frontend in separate terminal windows.

### Manual Start

#### 1. Backend
```bash
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Base: `http://127.0.0.1:8000/api`
- Interactive OpenAPI Docs: `http://127.0.0.1:8000/docs`

#### 2. Frontend
```bash
cd frontend
npm.cmd run dev
```
- Web Application: `http://localhost:3000`

---

## 7. Running Automated Test Suite

Run the full suite of detector and API integration tests:
```bash
python -m pytest tests/ -v
```
All 20 test cases validate detection thresholds, threat fusion, incident state transitions, response rollbacks, and STIX exports.

---

## 8. Docker Deployment

To launch the containerized stack:
```bash
docker compose up --build
```
- Frontend: `http://localhost:3000`
- Backend API: `http://localhost:8000`

---

## 9. Responsible Cybersecurity Notice
CYBERGUARD is a defensive cybersecurity and threat intelligence platform designed exclusively for detection, monitoring, forensic analysis, and authorized enterprise simulation.
