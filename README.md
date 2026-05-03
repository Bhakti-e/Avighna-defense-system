# 🛡️ AVIGHNA Defense System

**AI-Driven Cybersecurity Defense Platform for Network Threat Detection & Response**

AVIGHNA is an intelligent network security monitoring system that provides real-time threat detection, device discovery, reconnaissance monitoring, and automated incident response capabilities.

![AVIGHNA Dashboard](docs/screenshots/dashboard.png)

---

## 🎯 Problem Statement

Modern networks face constant threats from:
- **Unauthorized device connections** - Unknown devices joining your network
- **Port scanning & reconnaissance** - Attackers mapping your network infrastructure  
- **Insider threats** - Compromised devices within your network
- **Zero-day attacks** - Novel threats that traditional systems miss
- **Lack of visibility** - Not knowing what's happening on your network in real-time

AVIGHNA addresses these challenges with intelligent monitoring, ML-based threat detection, and automated response capabilities.

---

## ✨ Core Features

### 🔍 **Device Discovery & Monitoring**
- Automatic network device discovery using nmap
- Real-time device status tracking
- Manual device registration for known assets
- Vendor identification and device profiling

### 🚨 **Threat Detection**
- **Reconnaissance Detection** - Identifies port scans and network mapping attempts
- **Anomaly Detection** - ML-based behavioral analysis
- **Real-time Packet Analysis** - Scapy-based traffic monitoring
- **Risk Scoring** - Automated threat severity assessment

### 🦊 **FOX Threat Intelligence**
- Integration-ready for external threat feeds (CISA, MITRE, NVD, etc.)
- CVE tracking and vulnerability alerts
- Malware campaign monitoring
- Threat actor intelligence

### 🔬 **Investigation Console**
- Controlled command execution for security investigation
- Whitelisted tools: `ping`, `nmap`, `nslookup`, `tracert`, `arp`, `netstat`
- Safe command restrictions to prevent misuse
- Real-time output display

### 🔒 **Automated Response**
- **Observation Mode** - Monitor suspicious devices without blocking
- **Isolation Mode** - Quarantine threats automatically
- **Forensic Reporting** - Generate detailed PDF reports
- **Alert System** - Real-time notifications

### 📊 **Dashboard & Reporting**
- Real-time security dashboard
- Device status visualization
- Threat intelligence feed preview
- Forensic PDF report generation
- Investigation console integration

---

## 🏗️ Architecture

```
AVIGHNA/
├── frontend/          # Next.js React dashboard
│   ├── app/          # Pages (dashboard, devices, reports, etc.)
│   └── components/   # Reusable UI components
│
├── backend/          # FastAPI Python backend
│   ├── routers/     # API endpoints
│   ├── core/        # Core detection logic
│   ├── scanning/    # Network scanning modules
│   └── utils/       # Utilities (quarantine, observation)
│
├── data/            # Training datasets (not included in repo)
└── docs/            # Documentation
```

### Technology Stack

**Frontend:**
- Next.js 15 (React)
- TypeScript
- TailwindCSS
- Framer Motion

**Backend:**
- FastAPI (Python)
- SQLAlchemy (Database ORM)
- Scapy (Packet analysis)
- Nmap (Network scanning)
- Scikit-learn & TensorFlow (ML models)
- YARA (Malware detection)

**Database:**
- SQLite (development)
- PostgreSQL (production-ready)

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- npm or yarn
- nmap installed on system
- Administrator/root privileges (for packet capture)

### Backend Setup

```bash
# Clone repository
git clone https://github.com/Bhakti-e/Avighna-defense-system.git
cd Avighna-defense-system

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Run backend
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Backend will be available at: `http://localhost:8000`

### Frontend Setup

```bash
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Configure environment
cp .env.local.example .env.local
# Edit .env.local if needed

# Run development server
npm run dev
```

Frontend will be available at: `http://localhost:3000`

### Docker Setup (Alternative)

```bash
# Build and run with Docker Compose
docker-compose up --build
```

---

## 📖 Usage

### 1. **Initial Setup**
- Access dashboard at `http://localhost:3000`
- Create admin account via signup
- Login to access the system

### 2. **Device Discovery**
- Navigate to Dashboard
- System automatically discovers devices on your network
- View live devices in the "Live Devices" card

### 3. **Manual Device Registration**
- Click "Register Device" in sidebar
- Enter device MAC address and IP
- System verifies connectivity before registration

### 4. **Threat Monitoring**
- Monitor "Reconnaissance" card for port scans
- Check "Active Alerts" for security events
- View "Under Observation" for suspicious devices

### 5. **Investigation**
- Use Investigation Console on dashboard
- Run commands like: `nmap 192.168.1.100`
- View results in real-time

### 6. **Response Actions**
- Isolated devices appear in "Isolated Devices" card
- Generate forensic reports from Reports page
- Review threat intelligence in FOX page

---

## 🔧 Configuration

### Network Settings

Edit `backend/config.py` or `.env`:

```python
NETWORK_CIDR = "192.168.0.0/24"  # Your network range
NETWORK_SCAN_INTERVAL = 300       # Scan every 5 minutes
NETWORK_MONITORING_ENABLED = True
```

### Threat Detection Thresholds

Adjust in Settings page or `backend/config.py`:
- Port scan threshold: 20 ports in 5 minutes
- Risk score thresholds: Low (0-30), Medium (30-70), High (70-100)

---

## ⚠️ Current Limitations

**AVIGHNA is an early-stage prototype. Current limitations:**

### Network Visibility
- ✅ Detects traffic to/from the host machine
- ⚠️ Cannot see all network traffic without router integration
- ⚠️ Misses sleeping/idle devices (WiFi power-saving)
- ⚠️ Limited to ARP-based discovery

### Enforcement
- ✅ Can detect and alert on threats
- ⚠️ Cannot block traffic without router access
- ⚠️ Isolation is logical (database flag), not network-level
- ⚠️ Requires manual router configuration for true blocking

### Threat Intelligence
- ✅ UI and architecture ready
- ⚠️ External feed integration pending
- ⚠️ Currently shows placeholder data

### ML Models
- ✅ Models trained and included
- ⚠️ Require retraining on your network data for accuracy
- ⚠️ May produce false positives initially

### Router Integration
- ⚠️ Automatic router control blocked by authentication
- ⚠️ Requires manual router API configuration
- ⚠️ Currently limited to device discovery only

**These limitations are being actively addressed in future releases.**

---

## 🛣️ Roadmap

- [ ] Router API integration for true network enforcement
- [ ] Real-time threat intelligence feed integration
- [ ] Enhanced ML model training pipeline
- [ ] Mobile app for alerts
- [ ] Multi-network support
- [ ] Cloud deployment options
- [ ] Advanced forensics capabilities
- [ ] Integration with SIEM systems

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Datasets**: BCCC-CIC-IDS-2017, UNSW-NB15, CSE-CIC-IDS2018
- **Libraries**: FastAPI, Next.js, Scapy, Scikit-learn, TensorFlow
- **Threat Intelligence**: CISA, MITRE, NVD, AlienVault OTX

---

## 📧 Contact

**Bhakti** - [GitHub](https://github.com/Bhakti-e)

Project Link: [https://github.com/Bhakti-e/Avighna-defense-system](https://github.com/Bhakti-e/Avighna-defense-system)

---

## ⚡ Quick Commands Reference

```bash
# Backend
uvicorn backend.main:app --reload

# Frontend
cd frontend && npm run dev

# Docker
docker-compose up

# Run tests (when available)
pytest backend/tests/

# Check API docs
# Visit: http://localhost:8000/docs
```

---

**Built with ❤️ for a safer internet**
