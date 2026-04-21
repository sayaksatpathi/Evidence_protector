# Deploy Evidence Protector: Backend on Render + Frontend on Vercel

**Complete step-by-step guide to deploy your application across cloud platforms**

---

## 🚀 Overview

- **Backend (Python API)**: Hosted on [Render](https://render.com) (free tier available)
- **Frontend (React)**: Hosted on [Vercel](https://vercel.com) (free tier available)
- **Database/Storage**: Render persistent disk for key management
- **CI/CD**: Automatic deployments on git push

---

## ⚙️ Prerequisites

1. **GitHub Account**: Already have your repo
2. **Render Account**: https://render.com (free with GitHub login)
3. **Vercel Account**: https://vercel.com (free with GitHub login)
4. **GitHub Repository**: https://github.com/sayaksatpathi/Evidence_protector

---

## 📋 Part 1: Deploy Backend on Render

### Step 1: Create Render Account

1. Go to https://render.com
2. Sign up with GitHub
3. Grant repository access
4. Connect your GitHub account

### Step 2: Create Backend Service on Render

1. **Go to Dashboard** → "New Web Service"
2. **Select Repository**: `Evidence_protector`
3. **Configure Service**:
   - **Name**: `evidence-protector-backend`
   - **Environment**: `Docker`
   - **Region**: `Oregon` (or closest to you)
   - **Plan**: Start with `Free` (0.50 USD credits/month)
   - **Dockerfile**: `Dockerfile.render`
   - **Auto-deploy**: Enable (recommended)

### Step 3: Set Environment Variables on Render

Navigate to **Service Settings** → **Environment** and add:

```
EVIDENCE_PROTECTOR_API_PORT=8000
EVIDENCE_PROTECTOR_API_HOST=0.0.0.0
LOG_LEVEL=INFO
ENABLE_AUDIT_LOG=true
DEBUG=false

# Add these as SECRET environment variables:
EVIDENCE_PROTECTOR_API_KEYS_JSON=<your-json-here>
EVIDENCE_PROTECTOR_PRIVATE_KEY_PATH=/opt/render/project/src/.keys/private.key
EVIDENCE_PROTECTOR_CORS_ORIGINS=https://<your-vercel-frontend-url>.vercel.app
```

### Step 4: Configuration Instructions

1. **Generate API Keys** (before deployment):

```bash
# Locally, generate your role-based API keys
export EVIDENCE_PROTECTOR_API_KEYS_JSON='
{
  "prod-viewer-key": "viewer",
  "prod-analyst-key": "analyst", 
  "prod-admin-key": "admin"
}'

# Copy this value and paste into Render environment variables
```

2. **Set API Keys JSON** (in Render Dashboard):
   - **Key**: `EVIDENCE_PROTECTOR_API_KEYS_JSON`
   - **Value**: Paste your JSON from above
   - **Mark as SECRET**: Check the lock icon

3. **Get your Backend URL**:
   - Once deployed, Render assigns a URL like:
   - `https://evidence-protector-backend.onrender.com`
   - Use this in frontend configuration

### Step 5: Deploy

1. **Commit and push** the render.yaml and Dockerfile.render:

```bash
git add render.yaml Dockerfile.render
git commit -m "Add Render deployment configuration for backend"
git push origin main
```

2. **Trigger Deploy**:
   - Render auto-deploys on git push
   - Visit Render dashboard to monitor deployment
   - Wait for "Live" status (takes 2-5 minutes)

3. **Verify Backend**:

```bash
# Replace with your Render URL
curl https://evidence-protector-backend.onrender.com/api/health

# Should return:
# {"status":"healthy","timestamp":"2024-04-21T..."}
```

---

## 📋 Part 2: Deploy Frontend on Vercel

### Step 1: Create Vercel Account

1. Go to https://vercel.com
2. Sign up with GitHub
3. Import your repository

### Step 2: Import Project on Vercel

1. **Dashboard** → **Add New** → **Project**
2. **Import Git Repository**:
   - Search and select: `Evidence_protector`
   - Click "Import"

### Step 3: Configure Project Settings

1. **Framework Preset**: `Vite`
2. **Root Directory**: `Evidence Protector Web UI`
3. **Build Command**: `npm run build`
4. **Output Directory**: `dist`
5. **Install Command**: `npm install`

### Step 4: Set Environment Variables on Vercel

In **Project Settings** → **Environment Variables**, add:

```
VITE_API_BASE_URL=https://evidence-protector-backend.onrender.com/api
VITE_API_TIMEOUT=30000
VITE_LOG_LEVEL=info
VITE_DEBUG=false
```

**Replace** `evidence-protector-backend.onrender.com` with your actual Render URL!

### Step 5: Deploy

1. **Click "Deploy"** button
2. **Wait for build** (takes 1-3 minutes)
3. **Get Frontend URL**:
   - Vercel assigns a URL like: `https://evidence-protector.vercel.app`
   - This is your public frontend!

### Step 6: Update Backend CORS

Go back to **Render Dashboard** and update:

```
EVIDENCE_PROTECTOR_CORS_ORIGINS=https://evidence-protector.vercel.app
```

Render will auto-restart with new settings.

---

## ✅ Verification Checklist

### Backend (Render)
- [ ] Service status shows "Live" (green)
- [ ] Health endpoint returns 200: `curl https://<your-render-url>/api/health`
- [ ] API docs accessible: `https://<your-render-url>/api/docs`
- [ ] Environment variables set (check dashboard)

### Frontend (Vercel)
- [ ] Deployment shows "Ready" (green)
- [ ] Website loads: `https://<your-vercel-url>`
- [ ] Can access all pages (Scan, Sign, Verify)
- [ ] API calls work (upload a test log)

### Integration
- [ ] Frontend connects to backend (check browser console)
- [ ] Scan operation works end-to-end
- [ ] No CORS errors in browser console
- [ ] Audit logs visible in backend

---

## 🔐 Security Configuration

### Backend Secrets on Render

**Never paste real secrets in Render dashboard directly!** Use secret files:

1. **Create local** `.env.render`:
```bash
EVIDENCE_PROTECTOR_API_KEYS_JSON='{"key":"role"}'
EVIDENCE_PROTECTOR_PRIVATE_KEY_PATH=/opt/render/project/src/.keys/private.key
```

2. **Add to .gitignore**:
```
.env.render
```

3. **In Render Dashboard**:
   - Add as SECRET variables (locked icon)
   - Verify they don't appear in logs

### Frontend Environment

- Frontend environment variables are **public** (visible in browser)
- **Never** put API keys in frontend `.env` files
- Backend handles all authentication

---

## 📊 Monitoring & Logs

### Render Backend Logs

```bash
# View real-time logs in Render Dashboard
# Settings → Logs → View all logs

# Common issues to check:
- Port binding errors
- API key configuration
- CORS policy rejections
```

### Vercel Frontend Logs

```bash
# View in Vercel Dashboard
# Deployments → Select deployment → Logs

# Check for:
- Build errors
- Environment variable issues
- API connectivity problems
```

---

## 🚨 Troubleshooting

### Frontend Can't Connect to Backend

**Error**: `Cannot POST /api/scan` or CORS errors

**Solutions**:
1. Check `VITE_API_BASE_URL` in Vercel environment variables
2. Verify Render backend is running: `curl https://<render-url>/api/health`
3. Check Render `EVIDENCE_PROTECTOR_CORS_ORIGINS` includes your Vercel URL
4. Clear browser cache and hard refresh (Ctrl+Shift+R)

### Backend Service Won't Start

**Error**: Exit code 143, build fails, or service keeps restarting

**Solutions**:
1. Check logs in Render dashboard for specific errors
2. Verify `EVIDENCE_PROTECTOR_API_KEYS_JSON` is valid JSON
3. Ensure Python dependencies installed: `pip install -r requirements.txt`
4. Check file paths are correct in environment variables

### Slow Page Loads

**Causes**: Free tier limits, cold starts

**Solutions**:
1. Upgrade Render plan (paid tier = no cold starts)
2. Keep services warm: Set up uptime monitoring
3. Optimize frontend bundle size
4. Enable caching in Vercel

---

## 💰 Cost Estimates (Free Tier)

| Service | Free Tier | Cost/Month |
|---------|-----------|-----------|
| **Render** (Backend) | 0.50 USD credits | $0 (limited) |
| **Vercel** (Frontend) | Generous free tier | $0 |
| **Total** | All included | **$0** 🎉 |

**Paid Tiers** (when you scale):
- Render Pro: $7/month (1 web service + database)
- Vercel Pro: $20/month (if needed)

---

## 🔄 Continuous Deployment

### Auto-Deploy on Git Push

1. **Both services auto-deploy** on git push to main
2. **Deployment flow**:
   ```
   git push origin main
   ↓
   GitHub triggers webhooks
   ↓
   Render rebuilds backend (2-5 min)
   ↓
   Vercel rebuilds frontend (1-3 min)
   ↓
   New version live!
   ```

3. **Monitor deployments**:
   - Render: Dashboard → Deployments
   - Vercel: Dashboard → Deployments

---

## 🛠️ Custom Domain (Optional)

### Add Custom Domain to Vercel

1. **Vercel Dashboard** → Project Settings → Domains
2. Add your domain: `app.yourdomain.com`
3. Update DNS records (Vercel provides instructions)

### Add Custom Domain to Render

1. **Render Dashboard** → Service → Custom Domain
2. Add domain: `api.yourdomain.com`
3. Update DNS records

---

## 📝 Environment Variable Reference

### Backend (Render)

```bash
# Core Settings
EVIDENCE_PROTECTOR_API_PORT=8000              # Port (Render uses 8000)
EVIDENCE_PROTECTOR_API_HOST=0.0.0.0           # Accept from anywhere
LOG_LEVEL=INFO                                 # Logging level
DEBUG=false                                    # Never in production!

# Authentication (SECRET)
EVIDENCE_PROTECTOR_API_KEYS_JSON='{...}'      # Role-based keys
EVIDENCE_PROTECTOR_PRIVATE_KEY_PATH=/opt/...  # Key storage path

# CORS (update with Vercel URL)
EVIDENCE_PROTECTOR_CORS_ORIGINS=https://your-app.vercel.app

# Audit & Monitoring
ENABLE_AUDIT_LOG=true                         # Log all API access
AUDIT_LOG_PATH=/opt/render/project/logs/audit.log

# Performance
MAX_WORKERS=2                                 # Free tier limit
MAX_UPLOAD_SIZE=104857600                     # 100MB
CACHE_SIZE=100                                # Lower for free tier
```

### Frontend (Vercel)

```bash
# API Configuration
VITE_API_BASE_URL=https://your-render-url/api    # Backend endpoint
VITE_API_TIMEOUT=30000                           # 30 seconds

# UI Settings
VITE_LOG_LEVEL=info                              # Browser console logs
VITE_DEBUG=false                                 # Disable in production
VITE_DEFAULT_THEME=system                        # Theme preference
VITE_ENABLE_ANALYTICS=false                      # Disable tracking
```

---

## 🎯 Next Steps

1. **Deploy Backend**:
   ```bash
   git push
   # Monitor: Render Dashboard
   # Get URL when Live
   ```

2. **Update Frontend Config**:
   ```bash
   # Set VITE_API_BASE_URL to Render URL in Vercel
   ```

3. **Deploy Frontend**:
   ```bash
   # Vercel auto-deploys when you push
   ```

4. **Test End-to-End**:
   - Open frontend URL
   - Upload a log file
   - Verify backend processes it
   - Check audit logs

5. **Set Up Monitoring**:
   - Enable alerts (Render: settings)
   - Monitor uptime (external service)
   - Check logs daily first week

---

## 🔐 Security Reminders

- ✅ Never commit `.env` files
- ✅ Use SECRET variables in Render for API keys
- ✅ CORS restricted to your Vercel domain
- ✅ Enable HTTPS (default for both services)
- ✅ Regular key rotation (quarterly)
- ✅ Monitor audit logs for suspicious activity
- ✅ Backup private keys securely

---

## 📚 Useful Links

- **Render Docs**: https://render.com/docs
- **Vercel Docs**: https://vercel.com/docs
- **Vite Build Guide**: https://vitejs.dev/guide/build.html
- **FastAPI Deployment**: https://fastapi.tiangolo.com/deployment/

---

## ❓ Common Questions

**Q: Can I use a database with Render free tier?**
A: Render offers a free PostgreSQL database. See docs for setup.

**Q: How do I update the backend without downtime?**
A: Render uses blue-green deployments automatically.

**Q: Can I use edge functions on Vercel?**
A: Yes! But frontend auth should be backend-managed for security.

**Q: What if Render backend goes to sleep?**
A: Free tier doesn't sleep. Paid tier available for better uptime.

---

**Deployment Complete! 🎉 Your app is now live and accessible globally!**

---

**Need help?** Check the logs in each dashboard or refer to respective documentation.  
**Last Updated**: April 2024
