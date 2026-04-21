# 🚀 Quick Start - Getting Evidence Protector Running Locally

**Get the full-stack web application running in 5 minutes!**

## Prerequisites

```bash
# Check you have these installed:
python3 --version       # Python 3.13+
node --version          # Node.js 18+
npm --version           # npm 8+
docker --version        # Optional: for containerized deployment
```

---

## Option 1️⃣: Docker Compose (Easiest)

Complete stack in one command:

```bash
# Clone the repo
git clone https://github.com/sayaksatpathi/Evidence_protector.git
cd Evidence_protector

# Copy environment template
cp .env.backend.example .env

# Start everything (backend, frontend, reverse proxy)
docker-compose up -d

# Verify services are running
docker-compose ps
docker-compose logs -f
```

**Access the app:**
- 🌐 **Frontend**: http://localhost:3000
- 🔌 **API (Proxy)**: http://localhost:8080/api
- 📚 **Swagger Docs**: http://localhost:8080/api/docs

---

## Option 2️⃣: Local Development (Full Control)

### Backend Setup (Terminal 1)

```bash
# Clone repo
git clone https://github.com/sayaksatpathi/Evidence_protector.git
cd Evidence_protector

# Create Python environment
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or: .venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.backend.example .env
# Edit .env with your settings (optional for dev):
#   - API port: 8000
#   - API host: 127.0.0.1
#   - CORS allowed: http://localhost:5173

# Start backend API
python evidence_protector_api.py
```

**Backend running on**: http://127.0.0.1:8000/api

### Frontend Setup (Terminal 2)

```bash
# Navigate to frontend
cd "Evidence Protector Web UI"

# Install dependencies
npm install
# or: pnpm install  (faster)

# Configure environment
cp .env.frontend.example .env.local
# Edit .env.local to set API endpoint:
#   VITE_API_BASE_URL=http://localhost:8000/api

# Start dev server
npm run dev
# or: pnpm dev
```

**Frontend running on**: http://127.0.0.1:5173

---

## 🎯 Now What?

### 1. Access the web application
```
http://localhost:5173
```

### 2. Upload a log file to scan
- Click "Scan" in the navigation
- Upload any text log file (`.log`, `.txt`)
- Select gap threshold (e.g., 300 seconds)
- View results

### 3. Sign evidence (create manifest)
- Upload log file
- Generate Ed25519 signature
- Download `.manifest.json` file

### 4. Verify evidence
- Upload original log + manifest
- Verify signature is valid
- Check for tampering

### 5. Use CLI commands (Terminal)

```bash
# Must have backend running

# Scan a file
evidence_protector scan --file sample.log --gap 300 --format json

# Sign evidence
evidence_protector sign --file sample.log

# Verify signature
evidence_protector verify --file sample.log --manifest sample.manifest.json

# Generate canary token
evidence_protector ghost baseline

# Analyze with GHOST protocol
evidence_protector ghost analyze
```

---

## 📊 API Examples (with backend running)

### Scan via API

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"file_path":"./sample.log","gap_threshold":300}' | jq .
```

### View audit log

```bash
curl http://localhost:8000/api/audit | jq .
```

### Health check

```bash
curl http://localhost:8000/api/health | jq .
```

---

## 🔐 First-Time Setup

### Generate cryptographic keys

```bash
# Backend will auto-generate on first run
# Or manually:
evidence_protector key rotate

# Find keys at:
# Linux/macOS: ~/.evidence-protector/
# Windows: %USERPROFILE%\.evidence-protector\
```

### Configure API authentication (optional)

```bash
# Edit .env file:
export EVIDENCE_PROTECTOR_API_KEYS_JSON='
{
  "dev-key": "admin",
  "web-key": "viewer"
}
'
```

---

## 🐛 Troubleshooting

### Port already in use?

```bash
# Check what's using the port
lsof -i :8000   # Backend
lsof -i :5173   # Frontend

# Kill and restart, or use different ports:
# EVIDENCE_PROTECTOR_API_PORT=8001 python evidence_protector_api.py
```

### Frontend can't connect to backend?

```bash
# Verify backend is running
curl http://localhost:8000/api/health

# Check .env.local in frontend has correct API URL:
cat "Evidence Protector Web UI/.env.local"

# Should show: VITE_API_BASE_URL=http://localhost:8000/api
```

### Dependency errors?

```bash
# Backend
pip install -r requirements.txt --upgrade

# Frontend
npm install --legacy-peer-deps
# or: pnpm install
```

---

## 📝 Next Steps

1. **Read & understand security**:
   - [SECURITY.md](SECURITY.md) - Essential for production
   - [DEPLOYMENT_SECURITY_CHECKLIST.md](DEPLOYMENT_SECURITY_CHECKLIST.md) - Before going live

2. **Deploy to production**:
   - Follow [DEPLOYMENT_README.md](DEPLOYMENT_README.md)
   - Configure real API keys & database
   - Set up monitoring & alerting

3. **Explore features**:
   - Web UI at http://localhost:5173
   - API docs at http://localhost:8000/api/docs
   - CLI commands: `evidence_protector --help`

---

## 📚 Documentation

- **Full Deployment Guide**: [DEPLOYMENT_README.md](DEPLOYMENT_README.md)
- **Security Policies**: [SECURITY.md](SECURITY.md)
- **Pre-Deployment Checklist**: [DEPLOYMENT_SECURITY_CHECKLIST.md](DEPLOYMENT_SECURITY_CHECKLIST.md)
- **Key Management**: [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md)
- **Operational Security**: [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md)

---

## ⚡ Common Commands

```bash
# Stop everything (Docker)
docker-compose down

# View logs
docker-compose logs -f backend
docker-compose logs -f frontend

# Run tests
pytest -v
npm run test  # from frontend directory

# Build for production
npm run build  # frontend
docker build -f Dockerfile -t evidence-protector:prod .
```

---

**Questions?** Check the documentation files or create an issue on GitHub.

**Ready to deploy?** Read DEPLOYMENT_SECURITY_CHECKLIST.md before going to production! 🔐

---

**Version**: 0.1.0+Web | **Last Updated**: April 2024
