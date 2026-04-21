# Evidence Protector - Complete Deployment Guide

**Full-Stack Application Setup (Frontend + Backend)**

## 📋 Overview

Evidence Protector provides both:
- **Backend API** (`evidence_protector_api.py`): REST API for scanning, signing, and verifying evidence
- **Frontend Web UI** (`Evidence Protector Web UI/`): React + TypeScript web application

This guide covers production-grade deployment with comprehensive security hardening.

---

## 🔐 Security First

**Before deployment, review:**
- [SECURITY.md](SECURITY.md) - Security policies & best practices
- [DEPLOYMENT_SECURITY_CHECKLIST.md](DEPLOYMENT_SECURITY_CHECKLIST.md) - Pre-deployment verification
- [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md) - Key lifecycle & rotation

**Critical**: Never commit `.env`, API keys, tokens, or private keys. Use environment variables.

---

## 🚀 Quick Start (Development)

### Prerequisites
- **Backend**: Python 3.13+, pip
- **Frontend**: Node.js 18+, pnpm
- **Docker** (optional): For containerized deployment

### Backend Setup

1. **Create virtual environment**:
```bash
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or: .venv\Scripts\activate  # Windows
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Configure environment**:
```bash
# Copy template and edit with your values
cp .env.backend.example .env
nano .env  # Add your API keys, paths, etc.
```

4. **Generate cryptographic keys** (first run):
```bash
export EVIDENCE_PROTECTOR_PRIVATE_KEY_PATH=~/.evidence-protector/private.key
evidence_protector key rotate
```

5. **Start backend API**:
```bash
python evidence_protector_api.py
# API runs on http://127.0.0.1:8000/api
```

### Frontend Setup

1. **Navigate to frontend directory**:
```bash
cd "Evidence Protector Web UI"
```

2. **Install dependencies** (using pnpm recommended):
```bash
pnpm install
# or: npm install
```

3. **Configure environment**:
```bash
# Copy template
cp .env.frontend.example .env.local

# Edit with backend API endpoint
nano .env.local
# Set: VITE_API_BASE_URL=http://localhost:8000/api
```

4. **Start development server**:
```bash
pnpm dev
# Frontend runs on http://127.0.0.1:5173
```

5. **Access the application**:
- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000/api
- **API Docs**: http://localhost:8000/api/docs

---

## 🐳 Docker Deployment (Recommended)

### Using Docker Compose

1. **Configure environment**:
```bash
# Copy backend configuration
cp .env.backend.example .env

# Edit with production values
nano .env
```

2. **Build and start**:
```bash
docker-compose up -d
```

3. **Verify services**:
```bash
# Check backend API
curl http://localhost:8000/api/health

# Check frontend
curl http://localhost:3000

# Check reverse proxy
curl http://localhost:8080

# View logs
docker-compose logs -f backend
docker-compose logs -f frontend
```

### Environment Variables in Docker

**Never hardcode secrets in `docker-compose.yml`**.

```yaml
# ✓ CORRECT - Use .env file (git-ignored)
services:
  backend:
    environment:
      - EVIDENCE_PROTECTOR_API_KEYS_JSON=${EVIDENCE_PROTECTOR_API_KEYS_JSON}
      - EVIDENCE_PROTECTOR_PRIVATE_KEY_PATH=/app/keys/private.key

  # Or use env_file
  env_file:
    - .env
```

### Production Docker Build

```bash
# Build production image
docker build -f Dockerfile -t evidence-protector:latest .

# Push to registry
docker push your-registry/evidence-protector:latest

# Run with secrets
docker run \
  -e EVIDENCE_PROTECTOR_API_KEYS_JSON='{"key":"admin"}' \
  -e EVIDENCE_PROTECTOR_PRIVATE_KEY_PATH=/keys/private.key \
  -v /secure/path/keys:/keys:ro \
  -p 8000:8000 \
  evidence-protector:latest
```

---

## 📊 API Endpoints

### Health & Status

```bash
# Health check
curl http://localhost:8000/api/health

# Readiness check
curl http://localhost:8000/api/health/ready

# Liveness check
curl http://localhost:8000/api/health/live

# Audit log
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:8000/api/audit
```

### Scanning & Evidence

```bash
# Scan log file
curl -X POST http://localhost:8000/api/scan \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"file_path":"./sample.log","gap_threshold":300}'

# Sign evidence
curl -X POST http://localhost:8000/api/sign \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"file_path":"./evidence.log"}'

# Verify evidence
curl -X POST http://localhost:8000/api/verify \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"file_path":"./evidence.log","manifest_path":"./manifest.json"}'
```

### Interactive API Documentation

Visit: http://localhost:8000/api/docs (Swagger UI)

---

## 🔑 Authentication & Authorization

### API Key Configuration

1. **Generate API keys**:
```bash
# Single key (legacy)
export EVIDENCE_PROTECTOR_API_KEY="your-secret-key-here"

# Role-based keys (recommended)
export EVIDENCE_PROTECTOR_API_KEYS_JSON='
{
  "cli-key-prod": "admin",
  "web-viewer-key": "viewer",
  "analyst-key": "analyst"
}
'
```

2. **Use API keys in requests**:
```bash
# Header-based authentication
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:8000/api/audit

# Query parameter (not recommended for sensitive data)
curl "http://localhost:8000/api/scan?key=YOUR_API_KEY"
```

### Roles & Permissions

| Role | Permissions |
|------|-------------|
| `admin` | Full access: scan, sign, verify, key management, audit |
| `analyst` | Read/write: scan, sign, verify; read-only audit |
| `viewer` | Read-only: scan, verify; no signing or key access |

---

## ⚙️ Configuration Reference

### Backend (.env.backend.example)

```bash
# === API Server ===
EVIDENCE_PROTECTOR_API_PORT=8000
EVIDENCE_PROTECTOR_API_HOST=127.0.0.1

# === Authentication ===
EVIDENCE_PROTECTOR_API_KEYS_JSON='{"key":"role"}'
EVIDENCE_PROTECTOR_PRIVATE_KEY_PATH=~/.evidence-protector/private.key

# === CORS (development only) ===
EVIDENCE_PROTECTOR_CORS_ORIGINS=http://localhost:5173

# === Logging ===
LOG_LEVEL=INFO
AUDIT_LOG_PATH=./logs/audit.log

# === Performance ===
MAX_WORKERS=4
MAX_UPLOAD_SIZE=104857600
```

### Frontend (.env.frontend.example)

```bash
# === API Endpoint ===
VITE_API_BASE_URL=http://localhost:8000/api
VITE_API_TIMEOUT=30000

# === Development ===
VITE_PORT=5173
VITE_HOST=127.0.0.1
VITE_DEBUG=true

# === Theme ===
VITE_DEFAULT_THEME=system
```

---

## 📝 Key Management

### Initial Setup

```bash
# Generate Ed25519 key pair (automatic on first run)
# Stored at: $EVIDENCE_PROTECTOR_PRIVATE_KEY_PATH

# Or manually rotate:
evidence_protector key rotate

# List key IDs:
evidence_protector key list-revoked
```

### Rotating Keys

```bash
# Create new key pair
evidence_protector key rotate

# Revoke old key
evidence_protector key revoke OLD_KEY_ID

# Re-sign critical evidence with new key
evidence_protector sign --file evidence.log --recursive
```

### Backup Keys

```bash
# Secure backup
tar --encrypt -czf evidence-protector-keys.tar.gz.gpg \
  ~/.evidence-protector/

# Verify backup
tar -tzf evidence-protector-keys.tar.gz.gpg
```

---

## 🧪 Testing

### Unit Tests

```bash
# Run all tests
pytest -v

# Run specific test suite
pytest test_evidence_protector.py -v

# Run with coverage
pytest --cov=src --cov-report=html
```

### Security Tests

```bash
# API authentication tests
pytest test_api_contract.py::TestAPIAuth -v

# Signature verification tests
pytest test_evidence_protector.py::TestSignatureVerification -v
```

### E2E Testing

```bash
# Backend health checks
curl -s http://localhost:8000/api/health | jq .

# UI smoke tests
cd "Evidence Protector Web UI"
pnpm run test:e2e
```

---

## 📊 Monitoring & Logging

### Log Locations

```bash
# Application logs
tail -f ./logs/evidence-protector.log

# API audit trail
tail -f ./logs/audit.log

# Docker container logs
docker-compose logs -f backend
docker-compose logs -f frontend
```

### Health Check Endpoints

```bash
# Overall health
curl -s http://localhost:8000/api/health | jq .

# Detailed metrics
curl -s http://localhost:9090/metrics  # if Prometheus enabled
```

### Alerts to Configure

- [ ] Failed authentication attempts
- [ ] Key rotation events
- [ ] Unusual API access patterns
- [ ] File upload size violations
- [ ] Service downtime

---

## 🔒 Production Hardening Checklist

### Before Going Live

- [ ] All .env files configured with production values
- [ ] Private keys secured with 600 permissions
- [ ] API keys rotated within last 30 days
- [ ] HTTPS/TLS configured with valid certificates
- [ ] CORS restricted to production domain only
- [ ] Rate limiting configured
- [ ] Audit logging enabled and monitored
- [ ] Database backed up and tested
- [ ] Monitoring & alerting configured
- [ ] Incident response plan documented
- [ ] Run `DEPLOYMENT_SECURITY_CHECKLIST.md`

### Production Configuration

```bash
# Backend
export EVIDENCE_PROTECTOR_API_HOST=0.0.0.0  # Behind reverse proxy
export LOG_LEVEL=WARNING
export DEBUG=false
export ENABLE_AUDIT_LOG=true

# Frontend
export VITE_DEBUG=false
export VITE_API_BASE_URL=https://api.yourdomain.com
export VITE_ENABLE_ANALYTICS=true  # If applicable
```

---

## 🚨 Troubleshooting

### Backend Fails to Start

```bash
# Check if port is already in use
lsof -i :8000

# Check logs
tail -f ./logs/evidence-protector.log

# Verify configuration
echo $EVIDENCE_PROTECTOR_API_KEYS_JSON
echo $EVIDENCE_PROTECTOR_PRIVATE_KEY_PATH
```

### API Key Authentication Fails

```bash
# Verify API key format
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:8000/api/health

# Check key configuration
grep EVIDENCE_PROTECTOR_API_KEYS_JSON .env
```

### Frontend Can't Connect to Backend

```bash
# Check backend is running
curl http://localhost:8000/api/health

# Verify CORS configuration
grep CORS .env

# Check frontend config
cat "Evidence Protector Web UI/.env.local" | grep VITE_API_BASE_URL
```

### High Memory/CPU Usage

```bash
# Check MAX_WORKERS setting
grep MAX_WORKERS .env

# Monitor processes
docker stats  # if using Docker

# Optimize log file sizes
# Implement log rotation and retention policies
```

---

## 📚 Additional Resources

- [SECURITY.md](SECURITY.md) - Security policies & incident response
- [DEPLOYMENT_SECURITY_CHECKLIST.md](DEPLOYMENT_SECURITY_CHECKLIST.md) - Production checklist
- [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md) - Key lifecycle
- [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) - Operational security
- [GHOST_PROTOCOL_THREAT_MODEL.md](GHOST_PROTOCOL_THREAT_MODEL.md) - Threat analysis

---

## 📞 Support & Issues

1. **Check existing issues**: https://github.com/sayaksatpathi/Evidence_protector/issues
2. **Enable debug mode**: Set `DEBUG=true` and `VITE_DEBUG=true`
3. **Collect logs**: Include output from `tail logs/evidence-protector.log`
4. **Report security issues privately**: See SECURITY.md

---

## 📄 License

[Add your license here]

---

**Last Updated**: April 2024  
**Maintainers**: Security team  
**Version**: 0.1.0 + Web UI integration
