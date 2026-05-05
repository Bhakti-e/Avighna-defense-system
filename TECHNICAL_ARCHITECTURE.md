# AVIGHNA Architecture

## System Overview

AVIGHNA is built as a modern web application with a clear separation between frontend and backend components.

## Components

### Frontend (Next.js)
- **Dashboard**: Real-time security monitoring
- **Device Management**: View and register devices
- **FOX Intelligence**: Threat intelligence center
- **Investigation Console**: Safe command execution
- **Reports**: Forensic PDF generation
- **Settings**: System configuration

### Backend (FastAPI)
- **API Layer**: RESTful endpoints
- **Detection Engine**: ML-based threat detection
- **Network Scanner**: Nmap + Scapy integration
- **Database**: SQLAlchemy ORM
- **Background Tasks**: Continuous monitoring

### Detection Pipeline

```
Network Traffic
    ↓
Scapy Packet Capture
    ↓
Feature Extraction
    ↓
ML Model Analysis
    ↓
Risk Scoring
    ↓
Alert Generation
    ↓
Response Action (Observe/Isolate)
```

## Database Schema

### Tables
- **users**: Authentication and user management
- **devices**: Network device inventory
- **alerts**: Security alerts and events
- **telemetry_history**: Historical device data
- **reports**: Generated forensic reports

## API Endpoints

See `/docs` endpoint on running backend for full API documentation.

Key endpoints:
- `/auth/*` - Authentication
- `/devices/*` - Device management
- `/reconnaissance/*` - Threat detection
- `/reports/*` - Report generation
- `/investigation/*` - Command execution
- `/stats/*` - Dashboard statistics
