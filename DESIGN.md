# AVIGHNA (DOME) - System Design Document

**Project Name**: AVIGHNA - AI-Driven Cybersecurity System for Real-Time Device Threat Detection and Automated Isolation  
**Alternative Name**: DOME (Distributed Observation & Monitoring Engine)  
**Version**: 2.0 (Enterprise Edition)  
**Last Updated**: 2024

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Architecture](#system-architecture)
3. [Core Components](#core-components)
4. [Data Flow](#data-flow)
5. [Machine Learning Pipeline](#machine-learning-pipeline)
6. [Security Features](#security-features)
7. [API Specification](#api-specification)
8. [Database Schema](#database-schema)
9. [Deployment Architecture](#deployment-architecture)
10. [Testing Strategy](#testing-strategy)

---

## 1. Executive Summary

### 1.1 Project Overview

AVIGHNA is a lightweight, real-time network defense system that monitors connected devices for suspicious activity, detects attack patterns using machine learning, and automatically isolates compromised devices. It serves as a mini-SIEM (Security Information and Event Management) system designed for small to medium networks.

### 1.2 Key Capabilities

- **Real-time Device Monitoring**: Continuous telemetry collection and analysis
- **ML-based Anomaly Detection**: Multi-model ensemble (Isolation Forest + Autoencoder + LSTM)
- **Proactive Reconnaissance Detection**: Identifies attack preparation before exploitation
- **Automated Response System**: Auto-isolation, forensics collection, and reporting
- **Live Dashboard**: Web-based monitoring interface with 5-second auto-refresh
- **Mobile Demo Platform**: Android phone integration via Termux for live demonstrations
- **Enterprise Forensics**: YARA rules, VirusTotal integration, PE analysis
- **Natural Language Reports**: PDF generation with plain English explanations

### 1.3 Technology Stack

**Backend**:
- Python 3.8+
- FastAPI (REST API framework)
- Uvicorn (ASGI server)
- Pydantic (data validation)

**Machine Learning**:
- scikit-learn (Isolation Forest)
- TensorFlow/Keras (Autoencoder, LSTM)
- pandas (data processing)
- joblib (model serialization)

**Frontend**:
- HTML5, CSS3, JavaScript (Vanilla)
- Tailwind CSS (utility-first styling)
- Real-time polling (5-second intervals)

**Security Tools**:
- YARA (malware signature detection)
- VirusTotal API (hash reputation)
- python-magic (file type detection)
- pefile (PE file analysis)
- ssdeep (fuzzy hashing)

**Reporting**:
- ReportLab (PDF generation)
- Jinja2 (template rendering)

---

## 2. System Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    AVIGHNA ECOSYSTEM                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐ │
│  │   AGENT LAYER   │    │  BACKEND LAYER  │    │  UI LAYER   │ │
│  │  (Termux/Phone) │◄──►│ (FastAPI Server)│◄──►│ (Dashboard) │ │
│  │                 │    │                 │    │             │ │
│  │ • Telemetry Gen │    │ • Risk Analysis │    │ • Live View │ │
│  │ • Attack Sim    │    │ • ML Detection  │    │ • Alerts    │ │
│  │ • Recon Modes   │    │ • Auto Response │    │ • Reports   │ │
│  └─────────────────┘    └─────────────────┘    └─────────────┘ │
│           │                       │                     │      │
│           │              ┌────────▼────────┐           │      │
│           │              │  CORE MODULES   │           │      │
│           │              ├─────────────────┤           │      │
│           │              │ • State Mgmt    │           │      │
│           │              │ • Risk Scoring  │           │      │
│           │              │ • Reconnaissance│           │      │
│           │              │ • Forensics     │           │      │
│           │              │ • Response      │           │      │
│           │              │ • Background    │           │      │
│           │              └─────────────────┘           │      │
│           │                       │                     │      │
│           └───────────────────────┼─────────────────────┘      │
│                                   │                            │
│  ┌─────────────────────────────────▼─────────────────────────┐ │
│  │              MACHINE LEARNING LAYER                      │ │
│  ├──────────────────────────────────────────────────────────┤ │
│  │ • Isolation Forest (30% weight)                         │ │
│  │ • Autoencoder (40% weight)                              │ │
│  │ • LSTM (30% weight)                                     │ │
│  │ • Ensemble Prediction with Confidence Scoring           │ │
│  └──────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Layer Breakdown

#### Agent Layer
- **Termux Agent** (`termux_agent.py`): Runs on Android phones
- **Modes**: normal, suspicious, attack, recon, real
- **Connection**: HTTP POST to `/telemetry/ingest`
- **Frequency**: Configurable (5-30 second intervals)

#### Backend Layer
- **FastAPI Application** (`backend/main.py`): Core server
- **Routers**: Modular endpoint organization
- **State Management**: In-memory data structures
- **Background Workers**: ARP discovery, health monitoring

#### UI Layer
- **Dashboard** (`templates/dashboard.html`): Real-time monitoring
- **Auto-refresh**: 5-second polling intervals
- **Interactive**: Demo buttons, manual IP connection

---

## 3. Core Components

### 3.1 Backend Components

#### 3.1.1 Main Application (`backend/main.py`)
- FastAPI application initialization
- Router registration (telemetry, alerts, actions, reports, devices, UI)
- Startup/shutdown event handlers
- Signal handling for graceful termination
- Background task initialization

#### 3.1.2 State Management (`backend/state.py`)
```python
# In-memory data structures
alerts: List[Dict[str, Any]] = []           # Alert history
devices: Dict[str, Dict[str, Any]] = {}     # Device metadata
device_history: Dict[str, list] = {}        # Per-device event history
device_profile: Dict[str, Dict[str, Any]] = {}  # Behavioral profiles
reconnaissance_data: Dict[str, Dict[str, Any]] = {}  # Recon patterns
reconnaissance_findings: List[Dict[str, Any]] = []   # Recon alerts
```

**Telemetry Health Tracking**:
- `TELEMETRY_TIMEOUT = 60s`: Mark as stale
- `TELEMETRY_LOST_TIMEOUT = 180s`: Mark as lost
- Health score: 0-100 (100 = healthy, 0 = lost)
- Status: ACTIVE, STALE, LOST

#### 3.1.3 Telemetry Router (`backend/routers/telemetry.py`)
**Endpoint**: `POST /telemetry/ingest`

**Processing Pipeline**:
1. Pydantic validation
2. Device registration/update
3. Rule-based detection
4. Reconnaissance analysis
5. Forensics analysis (if suspicious file)
6. Enhanced ML prediction (ensemble)
7. Risk score calculation
8. Response action determination
9. Alert generation (if threshold exceeded)
10. PDF report generation

**Response Actions**:
- **GREEN (0-39)**: Continue monitoring
- **YELLOW (40-69)**: Under observation (bandwidth limiting)
- **RED (70-100)**: Automatic isolation + forensics

#### 3.1.4 Risk Scoring (`backend/risk_score.py`)
**Formula**: 60% ML + 40% Forensics + Rules Boost

**Weights**:
```python
WEIGHTS = {
    "failed_logins": 2.5,
    "connections": 1.0,
    "bytes_out": 1.0,
    "suspicious_file": 15.0,
    "risky_outbound": 20.0,
    "anomaly_score": 30.0,
    "recon_score": 10.0,
    "telemetry_health_score": 15.0,
}
```

**Risk Levels**:
- **GREEN**: 0-39 (Normal)
- **YELLOW**: 40-69 (Suspicious)
- **RED**: 70-100 (Critical)

#### 3.1.5 Response Engine (`backend/response.py`)
**Functions**:
- `auto_fix()`: Attempt simple remediation
- `set_under_observation()`: Bandwidth limiting, restricted access
- `isolate_device()`: Full quarantine + forensics collection
- `handle_risk_action()`: Orchestrates response based on risk level

**Isolation Process**:
1. Set device status to ISOLATED
2. Record isolation timestamp and details
3. Generate network blocking commands (simulated)
4. Collect forensics evidence
5. Create isolation alert
6. Generate PDF isolation report

#### 3.1.6 Forensics Engine (`backend/forensics_engine.py`)
**Enterprise-Grade Analysis**:
- YARA rule matching (framework ready, rules not loaded in demo)
- VirusTotal hash reputation (API ready, demo key)
- PE file analysis (Windows executables)
- Fuzzy hashing with ssdeep
- Heuristic behavior checks

**Heuristic Checks**:
- File extension vs MIME type mismatches
- Suspicious filename patterns (invoice.exe, document.scr)
- Double extensions (document.pdf.exe)
- Unusual file sizes for type

**Output**: `ForensicsResult` dataclass with threat score (0-100), threat level, detections, confidence

#### 3.1.7 Enhanced ML Engine (`backend/enhanced_ml.py`)
**Multi-Model Ensemble**:

1. **Isolation Forest** (30% weight)
   - Unsupervised anomaly detection
   - 200 estimators, 5% contamination
   - Features: [failed_logins, connections, bytes_out, forensics_score]

2. **Autoencoder** (40% weight)
   - Neural network: 4→8→4→2→4→8→4
   - Reconstruction error for anomaly detection
   - Trained only on normal data

3. **LSTM** (30% weight)
   - Temporal pattern analysis
   - Architecture: LSTM(32)→Dropout→LSTM(16)→Dense(8)→Dense(1)
   - 5-step sequence sliding window

**Ensemble Prediction**:
```python
ensemble_score = (if_score * 0.3) + (ae_score * 0.4) + (lstm_score * 0.3)
final_score = min(1.0, ensemble_score + forensics_boost)
```

**Confidence Metrics**:
- `ensemble_confidence`: Based on number of models available
- `model_agreement`: Variance between model predictions

#### 3.1.8 Reconnaissance Detector (`backend/reconnaissance.py`)
**Detection Patterns**:
- Port scanning (sequential port probes)
- Brute force preparation (failed login spikes)
- Network mapping (ARP request floods)
- DNS enumeration

**Cyber Kill Chain Mapping**:
1. RECONNAISSANCE ← **DOME DETECTS HERE**
2. WEAPONIZATION ← **DOME PREDICTS THIS**
3. DELIVERY
4. EXPLOITATION
5. INSTALLATION

#### 3.1.9 PDF Report Generator (`backend/pdf_reports.py`)
**Natural Language Reports**:
- Executive summary in plain English
- Timeline of events
- Risk assessment explanation
- Technical evidence details
- Recommended remediation actions
- Digital evidence chain of custody

**Report Types**:
1. **Incident Reports**: Alert-based analysis
2. **Isolation Reports**: Device quarantine documentation

**Library**: ReportLab with custom paragraph styles

#### 3.1.10 Background Tasks (`backend/background_tasks.py`)
**Workers**:
1. **ARP Worker**: Device discovery via ARP table scanning (8s interval)
2. **Nmap Scanner**: Port scanning for discovered devices
3. **Telemetry Health Monitor**: Updates device health scores (30s interval)
4. **Active Network Scanner**: Reconnaissance detection (5min interval)

---

### 3.2 Frontend Components

#### 3.2.1 Dashboard (`templates/dashboard.html`)
**Sections**:
1. **Header**: System status, mode indicators
2. **Summary Cards**: Total devices, under observation, isolated, reconnaissance
3. **Device Discovery**: Network scanning, manual IP connection
4. **Device Health Monitor**: Real-time device table with risk scores
5. **Recent Alerts**: Alert history with forensics details
6. **Reconnaissance Activity**: Pre-attack pattern detection
7. **Isolated Nodes**: Quarantined devices with isolation details

**Features**:
- Auto-refresh every 5 seconds
- Interactive demo buttons (normal, suspicious, attack, sequence)
- Manual IP connection with force option
- PDF report download buttons
- Real-time status badges (GREEN/YELLOW/RED)
- Telemetry health warnings

**JavaScript Functions**:
- `fetchJSON()`: API calls with error handling
- `loadDevices()`: Device list refresh
- `loadAlerts()`: Alert list refresh
- `loadReconnaissanceFindings()`: Recon activity refresh
- `loadIsolated()`: Isolated devices refresh
- `scanForDevices()`: Network discovery trigger
- `connectDevice()`: Manual device registration
- `runPhoneDemo()`: Interactive demo execution

### 3.3 Agent Components

#### 3.3.1 Termux Agent (`termux_agent.py`)
**Modes**:
- **normal**: Baseline behavior (0-1 failed logins, 1-3 connections)
- **suspicious**: Elevated activity (3-6 failed logins, 8-15 connections)
- **attack**: Malicious behavior (10+ failed logins, 25+ connections)
- **recon**: Reconnaissance patterns (port scanning, network mapping)
- **real**: Live system statistics collection

**Network Statistics Collection**:
- Connection count via netstat/ss
- Bytes transmitted via /proc/net/dev or netstat -e
- Failed login attempts (simulated or from logs)

**Configuration**:
- `--mode`: Operation mode
- `--device-id`: Unique device identifier
- `--server-url`: DOME backend URL
- `--duration`: Run duration in seconds
- `--interval`: Telemetry send interval

---

## 4. Data Flow

### 4.1 Telemetry Ingestion Flow

```
┌──────────────┐
│ Termux Agent │
│  (Phone)     │
└──────┬───────┘
       │ HTTP POST /telemetry/ingest
       │ {device_id, failed_logins, connections, bytes_out, ...}
       ▼
┌──────────────────────────────────────────────────────────┐
│ Backend: telemetry.py                                    │
├──────────────────────────────────────────────────────────┤
│ 1. Pydantic Validation (TelemetryIn model)              │
│ 2. Device Registration/Update (state.devices)           │
│ 3. Rule-Based Detection (_detect_rules)                 │
│ 4. Reconnaissance Analysis (ReconnaissanceDetector)     │
│ 5. Forensics Analysis (forensics_engine.analyze_file)   │
│ 6. Enhanced ML Prediction (enhanced_ml_engine.predict)  │
│ 7. Risk Score Calculation (compute_risk)                │
│ 8. Response Action (handle_risk_action)                 │
│ 9. Alert Generation (if threshold exceeded)             │
│ 10. PDF Report Generation (make_report)                 │
└──────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│ Response                                                 │
├──────────────────────────────────────────────────────────┤
│ {                                                        │
│   "status": "alert",                                     │
│   "alert_id": "uuid",                                    │
│   "risk": {"risk_score": 85.5, "risk_level": "RED"},   │
│   "forensics": [...],                                    │
│   "enhanced_ml": {...},                                  │
│   "response_actions": {"actions": ["isolate"]}          │
│ }                                                        │
└──────────────────────────────────────────────────────────┘
```

### 4.2 Dashboard Update Flow

```
┌──────────────┐
│  Dashboard   │
│  (Browser)   │
└──────┬───────┘
       │ Auto-refresh every 5 seconds
       │
       ├─► GET /devices/
       │   └─► Returns: {devices: [...], count: N}
       │
       ├─► GET /alerts/?limit=20
       │   └─► Returns: {alerts: [...]}
       │
       ├─► GET /reconnaissance/findings?limit=5
       │   └─► Returns: {findings: [...]}
       │
       └─► GET /reports/isolation/details
           └─► Returns: {isolated_devices: [...]}
```

### 4.3 Isolation Flow

```
┌──────────────────────────────────────────────────────────┐
│ Trigger: Risk Score >= 70 OR Recon Risk >= 70           │
└──────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│ isolate_device() in response.py                          │
├──────────────────────────────────────────────────────────┤
│ 1. Set device status to ISOLATED                        │
│ 2. Record isolation timestamp and details               │
│ 3. Generate network blocking commands (simulated)       │
│    - block_ip(ip) → netsh/iptables commands            │
│    - disconnect_wifi(mac) → WiFi disconnection          │
│ 4. Collect forensics evidence (collect_forensics)       │
│ 5. Create isolation alert                               │
│ 6. Generate PDF isolation report                        │
│ 7. Update dashboard status                              │
└──────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│ Outputs                                                  │
├──────────────────────────────────────────────────────────┤
│ • Device quarantined in state.devices                   │
│ • Isolation alert in state.alerts                       │
│ • PDF report in reports/pdf/                            │
│ • Forensics JSON in reports/                            │
│ • Dashboard shows RED status with ISOLATED badge        │
└──────────────────────────────────────────────────────────┘
```

---

## 5. Machine Learning Pipeline

### 5.1 Training Pipeline

```
┌──────────────────────────────────────────────────────────┐
│ Data Generation (Synthetic)                             │
├──────────────────────────────────────────────────────────┤
│ • 5000 samples (80% normal, 20% anomalous)              │
│ • Features: [failed_logins, connections, bytes_out,     │
│              forensics_score]                            │
│ • Normal: Low values, log-normal distribution           │
│ • Anomalous: High values, elevated patterns             │
└──────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│ Model Training                                           │
├──────────────────────────────────────────────────────────┤
│ 1. Isolation Forest                                     │
│    - StandardScaler normalization                       │
│    - 200 estimators, contamination=0.1                  │
│    - Save: backend/enhanced_if_model.joblib             │
│                                                          │
│ 2. Autoencoder                                          │
│    - MinMaxScaler normalization (0-1)                   │
│    - Train only on normal data                          │
│    - 50 epochs, batch_size=32                           │
│    - Save: backend/autoencoder_model.h5                 │
│                                                          │
│ 3. LSTM                                                 │
│    - Create 5-step sequences                            │
│    - Binary classification (anomaly/normal)             │
│    - 30 epochs, batch_size=16                           │
│    - Save: backend/lstm_model.h5                        │
└──────────────────────────────────────────────────────────┘
```

### 5.2 Inference Pipeline

```
┌──────────────────────────────────────────────────────────┐
│ Input: Telemetry Data                                    │
│ {failed_logins, connections, bytes_out, forensics_score}│
└──────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│ Model Predictions                                        │
├──────────────────────────────────────────────────────────┤
│ 1. Isolation Forest                                     │
│    X_scaled = scaler.transform(X)                       │
│    if_score = model.decision_function(X_scaled)         │
│    if_anomaly = normalize(if_score) → [0, 1]           │
│                                                          │
│ 2. Autoencoder                                          │
│    X_ae_scaled = ae_scaler.transform(X)                 │
│    reconstruction = model.predict(X_ae_scaled)          │
│    mse = mean((X - reconstruction)²)                    │
│    ae_anomaly = min(1.0, mse * 10)                      │
│                                                          │
│ 3. LSTM                                                 │
│    lstm_input = create_sequence(X, length=5)            │
│    lstm_anomaly = model.predict(lstm_input)             │
└──────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│ Ensemble Prediction                                      │
├──────────────────────────────────────────────────────────┤
│ ensemble_score = (if_anomaly * 0.3) +                   │
│                  (ae_anomaly * 0.4) +                    │
│                  (lstm_anomaly * 0.3)                    │
│                                                          │
│ forensics_boost = min(0.3, forensics_score / 100)       │
│ final_score = min(1.0, ensemble_score + forensics_boost)│
│                                                          │
│ confidence = num_models / 3.0                            │
│ agreement = 1.0 - variance(predictions) * 4              │
└──────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│ Output                                                   │
│ {                                                        │
│   "anomaly_score": 0.85,                                │
│   "model_predictions": {                                │
│     "isolation_forest": 0.82,                           │
│     "autoencoder": 0.88,                                │
│     "lstm": 0.84                                        │
│   },                                                     │
│   "ensemble_confidence": 1.0,                           │
│   "model_agreement": 0.95                               │
│ }                                                        │
└──────────────────────────────────────────────────────────┘
```

---

## 6. Security Features

### 6.1 Threat Detection

#### Rule-Based Detection
- Failed login threshold (≥2 triggers alert)
- Connection count threshold (>8 suspicious)
- Data exfiltration detection (>5MB)
- Risky IP detection (known malicious prefixes)
- Suspicious file patterns

#### ML-Based Detection
- Behavioral anomaly detection (Isolation Forest)
- Zero-day pattern recognition (Autoencoder)
- Temporal attack patterns (LSTM)
- Ensemble confidence scoring

#### Reconnaissance Detection
- Port scanning patterns
- Brute force preparation
- Network mapping activity
- DNS enumeration
- ARP request floods

### 6.2 Automated Response

#### Response Levels
1. **Auto-Fix** (All levels)
   - Mark suspicious files for analysis
   - Recommend password resets
   - Log security events

2. **Under Observation** (YELLOW: 40-69)
   - Bandwidth limiting (100 kbps)
   - Restricted outbound access
   - Enhanced monitoring
   - Observation alert generation

3. **Isolation** (RED: 70+)
   - Complete network quarantine
   - Forensics evidence collection
   - PDF report generation
   - Backup of critical files (simulated)


### 6.3 Forensics & Evidence Collection

#### Evidence Chain
- SHA256 cryptographic hashing
- Timestamp recording
- Chain of custody tracking
- Evidence integrity verification
- Backup location documentation

#### Forensics Data
- Suspicious file analysis
- Network connection logs
- Failed authentication attempts
- Malicious IP communications
- Reconnaissance indicators

---

## 7. API Specification

### 7.1 Core Endpoints

#### Telemetry Ingestion
```
POST /telemetry/ingest
Content-Type: application/json

Request Body:
{
  "device_id": "string",
  "failed_logins": 0,
  "connections": 0,
  "bytes_out": 0,
  "outbound_ips": ["string"],
  "suspicious_file": "string (optional)",
  "extra": {}
}

Response:
{
  "status": "ok|alert",
  "alert_id": "uuid (if alert)",
  "risk": {
    "risk_score": 85.5,
    "risk_level": "RED",
    "ml_score": 82.0,
    "forensics_score": 75.0
  },
  "device_status": {},
  "response_actions": {}
}
```

#### Device List
```
GET /devices/?include_network=false

Response:
{
  "count": 5,
  "devices": [
    {
      "device_id": "string",
      "quarantined": false,
      "last_seen": 1234567890.0,
      "last_risk": 45.5,
      "risk_level": "YELLOW",
      "status": "WARNING",
      "telemetry_health_score": 100.0,
      "telemetry_status": "ACTIVE"
    }
  ]
}
```

#### Alerts
```
GET /alerts/?limit=20

Response:
{
  "alerts": [
    {
      "id": "uuid",
      "device_id": "string",
      "reason": "string",
      "severity": 3,
      "risk": {},
      "forensics": [],
      "enhanced_ml": {},
      "ts": 1234567890.0
    }
  ]
}
```

#### Reconnaissance Findings
```
GET /reconnaissance/findings?limit=5

Response:
{
  "findings": [
    {
      "scan_time": 1234567890.0,
      "device_id": "string",
      "threat_indicators": ["Port scanning", "Brute force"],
      "recon_risk": 75.0,
      "recon_level": "CRITICAL"
    }
  ]
}
```

#### PDF Reports
```
GET /reports/pdf/{alert_id}
Response: application/pdf (binary)

GET /reports/pdf/isolation/{device_id}
Response: application/pdf (binary)
```

### 7.2 Discovery Endpoints

```
POST /discovery/scan
Response: {devices_found: N, subnet: "string", devices: [...]}

POST /discovery/connect/{ip}?force=true
Response: {success: true, device_id: "string", verified: false}
```

---

## 8. Database Schema

### 8.1 In-Memory State Structure

#### Devices
```python
devices: Dict[str, Dict[str, Any]] = {
  "device-id": {
    "quarantined": bool,
    "last_seen": float,
    "last_risk": float,
    "risk_level": str,  # GREEN|YELLOW|RED
    "status": str,  # OK|WARNING|UNDER_ATTACK|ISOLATED
    "last_alert_id": str,
    "ip": str,
    "mac": str,
    "telemetry_health_score": float,  # 0-100
    "telemetry_status": str,  # ACTIVE|STALE|LOST
    "isolation_details": {},
    "observation": {}
  }
}
```

#### Alerts
```python
alerts: List[Dict[str, Any]] = [
  {
    "id": str,
    "device_id": str,
    "reason": str,
    "severity": int,  # 1-4
    "payload": {},
    "risk": {},
    "forensics": [],
    "enhanced_ml": {},
    "recon": {},
    "response_actions": {},
    "ts": float
  }
]
```

#### Device History
```python
device_history: Dict[str, List[Tuple]] = {
  "device-id": [
    (timestamp, event_type, extra_data),
    ...
  ]
}
```

---

## 9. Deployment Architecture

### 9.1 System Requirements

**Server (Laptop/Desktop)**:
- OS: Windows/Linux/macOS
- Python: 3.8+
- RAM: 2GB minimum, 4GB recommended
- Storage: 500MB for application + models
- Network: WiFi or LAN with DHCP

**Client (Android Phone)**:
- Termux app (from F-Droid)
- Python 3.8+ in Termux
- Network: WiFi connection to same network as server

### 9.2 Deployment Steps

#### Server Setup
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Train ML models (if not present)
python train_if_model.py

# 3. Start server
python start_server.py
# OR
uvicorn backend.main:app --host 0.0.0.0 --port 8000

# 4. Access dashboard
http://localhost:8000/dashboard
```

#### Phone Setup
```bash
# 1. Install Termux from F-Droid
# 2. Install Python and dependencies
pkg update && pkg install python
pip install requests

# 3. Copy agent script to phone
# 4. Run agent
python termux_agent.py --mode normal --device-id my-phone --server-url http://192.168.x.x:8000
```

### 9.3 Network Configuration

**Connection Methods**:
1. **WiFi (Recommended)**: Both devices on same WiFi network
2. **USB Tethering**: Phone tethered to laptop via USB
3. **Hotspot**: Laptop creates hotspot, phone connects
4. **LAN**: Both devices on same wired network

**Firewall Configuration**:
- Allow inbound TCP port 8000
- Allow HTTP traffic from local network

---

## 10. Testing Strategy

### 10.1 Test Scenarios

#### Automated Tests
1. **Normal Activity** (`comprehensive_test.py`)
   - 0-1 failed logins, 1-3 connections
   - Expected: GREEN status

2. **Suspicious Activity** (`comprehensive_test.py`)
   - 3-6 failed logins, 8-15 connections
   - Expected: YELLOW status, under observation

3. **Attack Simulation** (`comprehensive_test.py`)
   - 10+ failed logins, 25+ connections, malicious IPs
   - Expected: RED status, automatic isolation

4. **Reconnaissance Detection** (`comprehensive_test.py`)
   - Port scanning (30 ports)
   - Expected: Recon alerts generated

5. **Real Mode** (`test_real_mode.py`)
   - Live system statistics
   - Expected: Accurate telemetry collection

#### Interactive Demos
1. **Step-by-Step Demo** (`phone_demo.py`)
   - Manual progression with screenshots
   - 4 stages: Normal → Suspicious → Attack → Recovery

2. **Hacker Simulation** (`termux_hacker_simulation.py`)
   - 5-stage attack: Normal → Recon → Brute Force → Malware → Exfiltration
   - Expected: Progressive risk escalation to isolation

3. **Complete Demo** (`complete_demo_script.py`)
   - Automated 2-minute demo
   - All stages with real-time dashboard updates

### 10.2 Test Files

**Core Test Scripts**:
- `comprehensive_test.py`: Multi-scenario test suite
- `test_real_mode.py`: Live monitoring tests
- `test_enterprise_forensics.py`: Forensics engine tests
- `test_heartbeat_telemetry.py`: Telemetry health tests
- `test_pdf_generation.py`: Report generation tests

**Simulation Scripts**:
- `termux_hacker_simulation.py`: 5-stage attack
- `realistic_hacker_simulation.py`: APT-style attack
- `phone_demo.py`: Interactive step-by-step
- `complete_demo_script.py`: Automated demo

**Utility Scripts**:
- `clear_state_now.py`: Reset all state
- `verify_empty.py`: Verify clean state
- `debug_state.py`: Inspect current state
- `quick_test.py`: System health check

### 10.3 Expected Outputs

#### Dashboard Updates
- Device count changes (0 → N)
- Risk level transitions (GREEN → YELLOW → RED)
- Status updates (OK → WARNING → ISOLATED)
- Real-time alert generation
- Telemetry health indicators

#### Generated Reports
- PDF incident reports (natural language)
- PDF isolation reports (forensics details)
- JSON forensics data
- Alert metadata

#### Console Logs
- Telemetry processing logs
- Risk score calculations
- ML model predictions
- Response action execution

---

## 11. File Structure

```
avighna/
├── backend/
│   ├── main.py                 # FastAPI application
│   ├── state.py                # In-memory data structures
│   ├── risk_score.py           # Risk calculation
│   ├── response.py             # Automated response
│   ├── enhanced_ml.py          # ML ensemble
│   ├── forensics_engine.py     # Enterprise forensics
│   ├── reconnaissance.py       # Recon detection
│   ├── pdf_reports.py          # Report generation
│   ├── background_tasks.py     # Background workers
│   ├── active_scanner.py       # Network scanning
│   ├── profile.py              # Behavioral profiling
│   ├── routers/
│   │   ├── telemetry.py        # Telemetry ingestion
│   │   ├── alerts.py           # Alert management
│   │   ├── devices.py          # Device listing
│   │   ├── reports.py          # Report endpoints
│   │   ├── discovery.py        # Device discovery
│   │   ├── reconnaissance_monitoring.py
│   │   └── ui.py               # Dashboard serving
│   ├── utils/
│   │   ├── quarantine.py       # Network isolation
│   │   └── observation.py      # Observation mode
│   ├── reports/
│   │   └── generator.py        # Report generation
│   ├── enhanced_if_model.joblib    # Isolation Forest
│   ├── autoencoder_model.h5        # Autoencoder
│   └── lstm_model.h5               # LSTM model
├── templates/
│   └── dashboard.html          # Web dashboard
├── reports/                    # Generated reports
│   └── pdf/                    # PDF reports
├── scans/                      # Nmap scan results
├── backups/                    # Device backups
├── logs/                       # System logs
├── tests/
│   ├── comprehensive_test.py
│   ├── test_real_mode.py
│   ├── test_enterprise_forensics.py
│   └── ...
├── termux_agent.py             # Phone agent
├── termux_hacker_simulation.py # Attack simulation
├── phone_demo.py               # Interactive demo
├── complete_demo_script.py     # Automated demo
├── start_server.py             # Server startup
├── requirements.txt            # Dependencies
├── DESIGN.md                   # This document
├── DOME_COMPREHENSIVE_TECHNICAL_ANALYSIS.md
├── MCA_VIVA_SUMMARY.md
└── README.md
```

---

## 12. Key Design Decisions

### 12.1 Architecture Choices

**In-Memory State vs Database**:
- **Decision**: In-memory Python dictionaries
- **Rationale**: Simplicity, fast access, demo-friendly
- **Trade-off**: Data lost on restart (acceptable for demo)
- **Production**: Would use PostgreSQL/Redis

**Synchronous vs Asynchronous**:
- **Decision**: FastAPI with async support
- **Rationale**: Non-blocking I/O for concurrent requests
- **Implementation**: Background workers in separate threads

**Monolithic vs Microservices**:
- **Decision**: Monolithic application
- **Rationale**: Easier deployment, lower complexity for demo
- **Production**: Could split into services (API, ML, Forensics)

### 12.2 ML Model Selection

**Ensemble Approach**:
- **Decision**: 3-model ensemble (IF + AE + LSTM)
- **Rationale**: Different models catch different attack patterns
- **Weights**: 30% IF, 40% AE, 30% LSTM (tuned empirically)

**Unsupervised Learning**:
- **Decision**: No labeled training data required
- **Rationale**: Adapts to new attack patterns, no manual labeling
- **Trade-off**: May have higher false positive rate

**Synthetic Training Data**:
- **Decision**: Generate synthetic data for demo
- **Rationale**: No real attack data available, reproducible results
- **Production**: Would use real network traffic logs

### 12.3 Security Considerations

**Simulated vs Real Isolation**:
- **Decision**: Generate commands but don't execute
- **Rationale**: Safety - avoid breaking real networks
- **Implementation**: Commands logged for demonstration

**Authentication**:
- **Decision**: No authentication in demo
- **Rationale**: Simplicity for local network demo
- **Production**: Would require JWT/OAuth2

**Data Privacy**:
- **Decision**: All data stays local
- **Rationale**: No external data transmission
- **Implementation**: Self-contained system

---

## 13. Future Enhancements

### 13.1 Planned Features

**Database Integration**:
- PostgreSQL for persistent storage
- Redis for caching and real-time data
- Time-series database for metrics

**Advanced ML**:
- Transfer learning from pre-trained models
- Real-time model retraining
- Federated learning across multiple deployments

**Enhanced Forensics**:
- Full YARA rule library
- Real VirusTotal API integration
- Memory forensics analysis
- Network packet capture

**Scalability**:
- Kubernetes deployment
- Horizontal scaling
- Load balancing
- Multi-tenant support

### 13.2 Known Limitations

**Current Limitations**:
- In-memory state (data lost on restart)
- Simulated network isolation
- Limited YARA rules
- Demo VirusTotal key
- Single-server deployment
- No authentication/authorization
- Basic error handling

**Mitigation Strategies**:
- Document limitations clearly
- Provide production-ready alternatives
- Focus on core functionality demonstration
- Emphasize educational/demo purpose

---

## 14. Conclusion

AVIGHNA (DOME) demonstrates a comprehensive approach to real-time network security monitoring with:

- **Multi-layered Detection**: Rules + ML + Forensics
- **Automated Response**: Observation → Isolation
- **Real-time Monitoring**: 5-second dashboard refresh
- **Enterprise Features**: YARA, VirusTotal, PDF reports
- **Educational Value**: Clear demonstrations of security concepts

The system successfully bridges academic concepts with practical implementation, providing a working demonstration of modern cybersecurity techniques including machine learning, behavioral analysis, and automated incident response.

**Target Audience**: MCA students, cybersecurity researchers, network administrators, educational demonstrations

**Use Cases**: Network security education, threat detection research, security awareness training, proof-of-concept demonstrations

---

**Document Version**: 1.0  
**Last Updated**: 2024  
**Maintained By**: AVIGHNA Development Team  
**License**: Educational/Research Use
