# AVIGHNA Defense Edition v3.0

**Network Defense & Threat Detection Platform**

AVIGHNA Defense is an advanced network security platform designed for critical infrastructure protection, specifically targeting WiFi drone threats, rogue device detection, and comprehensive network monitoring for defense establishments (DRDO/ISRO campuses).

---

## 🎯 Overview

AVIGHNA Defense provides:
- **Passive Network Monitoring** - Scapy-based ARP/WiFi scanning
- **Threat Detection** - ML-powered anomaly detection + YARA malware scanning
- **Reconnaissance Detection** - Pre-attack scanning and probing detection
- **Automated Response** - Network isolation, iptables enforcement
- **Cyber Threat Intelligence** - Real-time IOC feeds (URLhaus, ThreatFox, Feodo)
- **Forensic Reports** - Professional PDF evidence generation

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AVIGHNA DEFENSE v3.0                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Network Scanning          Core Detection                   │
│  ├─ Passive (Scapy)       ├─ Risk Scoring                  │
│  ├─ Active (Nmap)         ├─ ML Anomaly Detection          │
│  └─ WiFi Monitoring       ├─ Reconnaissance Engine         │
│                            ├─ YARA Forensics                │
│                            └─ CTI Integration               │
│                                                              │
│  Response & Enforcement    Database & Storage               │
│  ├─ Network Isolation     ├─ PostgreSQL/SQLite             │
│  ├─ iptables Rules        ├─ Device Registry               │
│  ├─ Router MAC Ban        ├─ Alert History                 │
│  └─ Forensic Backup       └─ Telemetry Archive             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- PostgreSQL 12+ (or SQLite for development)
- Root/Administrator privileges (for network scanning)

### Installation

```bash
# Clone repository
git clone https://github.com/your-org/avighna-defense.git
cd avighna-defense

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\Activate.ps1  # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.template .env
# Edit .env with your settings

# Initialize database
python -c "from backend.database import init_db; init_db()"

# Start server
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### Docker Deployment

```bash
# Build and run with docker-compose
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

---

## 📊 Features

### Network Scanning
- **Passive ARP Scanning** - Discover all devices without active probing
- **WiFi Monitoring** - Detect rogue access points and deauth attacks
- **Device Fingerprinting** - Vendor identification via MAC OUI
- **Rogue Device Detection** - Whitelist-based unauthorized device alerts

### Threat Detection
- **Rule-Based Detection** - Failed logins, suspicious connections, risky IPs
- **ML Anomaly Detection** - 3-model ensemble (Isolation Forest, Autoencoder, LSTM)
- **Reconnaissance Detection** - Port scanning, brute force setup, network mapping
- **YARA Malware Scanning** - Signature-based malware detection
- **CTI Integration** - Real-time threat intelligence feeds

### Automated Response
- **Risk-Based Actions**:
  - GREEN (0-39): Normal - No action
  - YELLOW (40-69): Observation - Enhanced monitoring
  - RED (70-100): Isolation - Network blocking
- **Network Enforcement**:
  - Linux: iptables (FORWARD + INPUT chains)
  - Windows: Windows Firewall
  - Router: MAC filtering (if configured)

### Forensic Reports
- Professional PDF evidence reports
- Device information (IP, MAC, vendor)
- Isolation details (date, time, reason)
- Malware identification (type, version, hash)
- QR code for mobile download
- Chain of custody timestamps

---

## 🔧 Configuration

### Database Setup

**SQLite (Development):**
```env
DATABASE_URL=sqlite:///./avighna_defense.db
```

**PostgreSQL (Production):**
```env
DATABASE_URL=postgresql://user:password@localhost:5432/avighna
```

### Network Monitoring

```env
NETWORK_MONITORING_ENABLED=true
NETWORK_CIDR=192.168.1.0/24
NETWORK_INTERFACE=eth0
NETWORK_SCAN_INTERVAL=60
AUTO_BLOCK_ROGUE_DEVICES=true
```

### Security

```env
SAFE_MODE=false  # Enable real enforcement
GATEWAY_MODE=true  # Act as network gateway
API_KEY_ENABLED=true
API_KEY=your-secure-api-key
JWT_SECRET_KEY=your-jwt-secret
```

---

## 📡 API Endpoints

### Health & Status
- `GET /` - API information
- `GET /health` - Health check

### Network Monitoring
- `GET /network/devices` - List all discovered devices
- `GET /network/devices/rogue` - List unauthorized devices
- `POST /network/scan/now` - Trigger immediate scan
- `POST /network/devices/authorize` - Authorize device
- `POST /network/devices/block` - Block device

### Alerts & Devices
- `GET /alerts` - List all alerts
- `GET /devices` - List all devices
- `GET /devices/{device_id}` - Get device details

### Reconnaissance
- `GET /reconnaissance/findings` - List reconnaissance detections
- `GET /reconnaissance/stats` - Reconnaissance statistics

### Reports
- `GET /reports` - List generated reports
- `GET /reports/{report_id}/download` - Download PDF report

---

## 🛡️ Security Considerations

### Network Scanning Permissions
- Requires root/administrator privileges
- Use with caution on production networks
- Ensure compliance with network policies

### Safe Mode
- **Enabled (default)**: Simulates enforcement, logs only
- **Disabled**: Real network blocking, requires gateway mode

### Gateway Mode
- Backend must be network gateway
- Requires proper routing configuration
- Test thoroughly before production deployment

---

## 📈 Deployment Options

### Option 1: Railway (Cloud)
See `deployment/railway.md` for detailed guide

### Option 2: AWS Lightsail (VPS)
See `deployment/lightsail.md` for detailed guide

### Option 3: On-Premise (Gateway)
- Deploy on dedicated gateway machine
- Configure as network router
- Enable gateway mode for enforcement

---

## 🔬 Testing

### Network Scanner Test
```bash
python -c "from backend.scanning.passive_scanner import network_scanner; \
network_scanner._perform_scan(); \
print(f'Found {len(network_scanner.get_all_devices())} devices')"
```

### API Test
```bash
# Health check
curl http://localhost:8000/health

# List devices
curl http://localhost:8000/network/devices

# Trigger scan
curl -X POST http://localhost:8000/network/scan/now
```

---

## 📚 Documentation

- **Architecture**: See `DESIGN.md` (if available)
- **API Docs**: http://localhost:8000/docs (Swagger UI)
- **Deployment**: See `deployment/` folder

---

## 🤝 Contributing

AVIGHNA Defense is part of the AVIGHNA platform family:
- **AVIGHNA Defense** - Critical infrastructure (this edition)
- **AVIGHNA Startup** - SMB/café security (coming soon)
- **AVIGHNA OT** - Industrial/manufacturing (coming soon)

---

## 📄 License

[Your License Here]

---

## 🆘 Support

For issues, questions, or feature requests:
- GitHub Issues: [your-repo-url]
- Email: [your-email]
- Documentation: [your-docs-url]

---

## 🎯 Roadmap

### v3.1 (Next Release)
- [ ] MISP CTI integration
- [ ] Nuclei vulnerability scanning
- [ ] Router API integration (TP-Link, Netgear)
- [ ] Enhanced WiFi monitoring

### v3.2 (Future)
- [ ] Next.js dashboard
- [ ] WebSocket real-time updates
- [ ] Email/Slack alerting
- [ ] Multi-tenancy support

---

**AVIGHNA Defense v3.0** - Protecting Critical Infrastructure
