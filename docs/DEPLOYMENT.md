# Deployment Guide

## Local Development

See main README.md for quick start instructions.

## Production Deployment

### Option 1: Docker Compose

```bash
# Build and run
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### Option 2: Manual Deployment

#### Backend

```bash
# Install dependencies
pip install -r requirements.txt

# Set production environment
export DATABASE_URL="postgresql://user:pass@localhost/avighna"
export SECRET_KEY="your-production-secret-key"

# Run with gunicorn
gunicorn backend.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

#### Frontend

```bash
cd frontend

# Build for production
npm run build

# Start production server
npm start
```

### Option 3: Cloud Deployment

#### AWS/Azure/GCP

1. Deploy backend as containerized service
2. Deploy frontend as static site or containerized service
3. Configure PostgreSQL database
4. Set environment variables
5. Configure security groups/firewall rules

#### Heroku

```bash
# Backend
heroku create avighna-backend
git push heroku main

# Frontend
cd frontend
heroku create avighna-frontend
git push heroku main
```

## Security Considerations

### Production Checklist

- [ ] Change SECRET_KEY in .env
- [ ] Use PostgreSQL instead of SQLite
- [ ] Enable HTTPS/TLS
- [ ] Configure CORS properly
- [ ] Set up firewall rules
- [ ] Enable rate limiting
- [ ] Configure backup strategy
- [ ] Set up monitoring/logging
- [ ] Restrict API access
- [ ] Use strong passwords

### Network Requirements

- Backend needs raw socket access for packet capture
- Requires elevated privileges (root/admin)
- Consider running in isolated network segment
- Configure firewall to allow necessary ports

### Recommended Ports

- Frontend: 3000 (or 80/443 with reverse proxy)
- Backend: 8000 (or behind reverse proxy)
- Database: 5432 (PostgreSQL) - internal only

## Monitoring

### Health Checks

- Backend: `GET /health`
- Frontend: Check if page loads

### Logs

- Backend: `backend.log` or stdout
- Frontend: Browser console + server logs

### Metrics to Monitor

- API response times
- Database connection pool
- Memory usage
- Packet capture performance
- Alert generation rate
