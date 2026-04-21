# Quick Deploy: Render + Vercel - 10 Minutes

**Get Evidence Protector live on the internet in 10 minutes!**

---

## ⚡ Super Quick Summary

| Step | Service | Time | Cost |
|------|---------|------|------|
| 1 | Push code to GitHub | 1 min | $0 |
| 2 | Deploy backend on Render | 3 min | $0 (free tier) |
| 3 | Deploy frontend on Vercel | 3 min | $0 (free tier) |
| 4 | Connect & test | 3 min | $0 |
| **Total** | **Live!** | **~10 min** | **$0** 🎉 |

---

## 🚀 Step 1: Push Code (1 minute)

```bash
cd ~/Downloads/DEVOPIA1\ 3.0\ \(2\)/DEVOPIA1\ 3.0

# Commit deployment files
git add render.yaml Dockerfile.render "Evidence Protector Web UI/vercel.json"
git commit -m "Add Render and Vercel deployment configuration"
git push origin main

# ✅ Done! Code is now in GitHub
```

---

## 🔧 Step 2: Deploy Backend on Render (3 minutes)

### 2.1 Create Account
- Go to **https://render.com**
- Sign up with GitHub
- Authorize access

### 2.2 Create Web Service
1. **Dashboard** → **New Web Service**
2. Select your repo: `Evidence_protector`
3. Fill in:
   - **Name**: `evidence-protector-backend`
   - **Environment**: `Docker`
   - **Dockerfile**: `Dockerfile.render`
   - **Plan**: `Free`

### 2.3 Set Secrets
Click **Service Settings** → **Environment**

Add these variables:

```bash
# Regular variables (not secret):
EVIDENCE_PROTECTOR_API_PORT=8000
EVIDENCE_PROTECTOR_API_HOST=0.0.0.0
LOG_LEVEL=INFO
DEBUG=false
EVIDENCE_PROTECTOR_CORS_ORIGINS=https://evidence-protector.vercel.app

# SECRET variables (click lock icon):
EVIDENCE_PROTECTOR_API_KEYS_JSON={"prod":"admin"}
```

### 2.4 Deploy
1. Click **Deploy** 
2. Wait for "Live" status (2-5 minutes)
3. **Copy your Render URL**: `https://evidence-protector-backend.onrender.com`

**✅ Backend is now LIVE!**

---

## 🎨 Step 3: Deploy Frontend on Vercel (3 minutes)

### 3.1 Create Account
- Go to **https://vercel.com**
- Sign up with GitHub
- Authorize access

### 3.2 Import Project
1. **Dashboard** → **Add New** → **Project**
2. Select: `Evidence_protector`
3. Click **Import**

### 3.3 Configure Build
1. **Framework Preset**: Vite
2. **Root Directory**: `Evidence Protector Web UI`
3. **Build Command**: `npm run build`
4. **Output Directory**: `dist`

### 3.4 Set Environment Variables
In **Project Settings** → **Environment Variables**, add:

```bash
VITE_API_BASE_URL=https://evidence-protector-backend.onrender.com/api
VITE_API_TIMEOUT=30000
```

**Replace** `evidence-protector-backend.onrender.com` with YOUR Render URL!

### 3.5 Deploy
1. Click **Deploy**
2. Wait for "Ready" status (1-3 minutes)
3. **Copy your Vercel URL**: `https://evidence-protector.vercel.app`

**✅ Frontend is now LIVE!**

---

## 🧪 Step 4: Connect & Test (3 minutes)

### 4.1 Test Backend
```bash
# Replace with your Render URL
curl https://evidence-protector-backend.onrender.com/api/health

# Should return:
# {"status":"healthy",...}
```

### 4.2 Test Frontend
1. Open: https://evidence-protector.vercel.app
2. Click "Scan" tab
3. Upload any `.log` or `.txt` file
4. Click "Scan"
5. **You should see results!** ✅

### 4.3 Test Full Integration
1. **Sign** a file (creates manifest)
2. **Verify** the signed file
3. Check audit logs work

---

## 📊 What You Just Deployed

```
🌐 Your Application Flow:
┌─────────────────────────────────────────────────────┐
│ User opens: https://evidence-protector.vercel.app   │
├─────────────────────────────────────────────────────┤
│ Frontend (React) loads from Vercel CDN              │
│ User uploads log file                               │
│ ↓                                                    │
│ Frontend sends to Backend API                        │
│ ↓                                                    │
│ Backend (Python) on Render processes                │
│ ↓                                                    │
│ Returns results to Frontend                         │
│ ↓                                                    │
│ User sees forensic analysis 🔍                      │
└─────────────────────────────────────────────────────┘
```

---

## ✅ Verify Everything Works

### Checklist
- [ ] Backend URL responds to health check (`/api/health`)
- [ ] Frontend loads without errors
- [ ] Can upload file in browser
- [ ] Scan completes and shows results
- [ ] No CORS errors in browser console
- [ ] Sign/Verify operations work

### Check Logs If Issues
```bash
# Render Backend Logs:
Render Dashboard → Service → Logs

# Vercel Frontend Logs:
Vercel Dashboard → Deployments → Selected deployment → Logs
```

---

## 🔐 Security Notes

- ✅ API keys stored as **SECRET** on Render (not visible)
- ✅ CORS restricted to your Vercel domain
- ✅ HTTPS enabled by default on both
- ✅ No secrets in git repo
- ✅ All data encrypted in transit

---

## 💰 Cost

**Everything is FREE!**

- Render free tier: $0 (0.50 USD credits)
- Vercel free tier: $0 (generous limits)
- **Total monthly**: $0.00 🎉

*Upgrade anytime if you need better performance*

---

## 🔄 Making Updates

After initial setup, just push code:

```bash
# Make changes locally
nano src/...

# Commit and push
git add .
git commit -m "Update feature"
git push origin main

# Both services auto-deploy!
# Monitor in dashboards
```

---

## 🆘 Quick Troubleshooting

### Frontend shows "Cannot connect to API"
1. Check `VITE_API_BASE_URL` in Vercel environment
2. Make sure it points to correct Render URL
3. Hard refresh browser (Ctrl+Shift+R)

### Backend keeps restarting
1. Check Render logs for errors
2. Verify `EVIDENCE_PROTECTOR_API_KEYS_JSON` is valid JSON
3. Try redeploying

### Upload fails
1. Check browser console (F12) for error messages
2. Verify backend is responding: `curl https://your-render-url/api/health`
3. Check file size isn't over limit

### Slow performance
1. Free tier has rate limits
2. Backend might be cold-starting (upgrade to Pro to keep warm)
3. Clear browser cache

---

## 📚 Next Steps

1. **Monitor Dashboard**:
   - Check logs daily first week
   - Set up alerts for errors

2. **Custom Domain** (optional):
   - Add your domain to Vercel
   - Add your domain to Render
   - Update DNS records

3. **Backup Strategy**:
   - Backup private keys securely
   - Document API key rotation schedule
   - Keep DEPLOYMENT_URLS.txt safe

4. **Production Hardening**:
   - Rotate API keys monthly
   - Monitor audit logs
   - Review DEPLOYMENT_SECURITY_CHECKLIST.md

---

## 🎉 You're Live!

Your Evidence Protector application is now:
- ✅ **Accessible globally**
- ✅ **Highly available** (CDN for frontend, auto-scaling backend)
- ✅ **Secure** (HTTPS, environment-based secrets)
- ✅ **Continuously deployed** (auto-updates on git push)
- ✅ **FREE** (for now!)

**Share your URLs or access privately. You're ready to go!** 🚀

---

**Detailed guide**: See `DEPLOY_RENDER_VERCEL.md` for complete instructions, troubleshooting, and advanced setup.

**Questions?** Check service documentation:
- Render: https://render.com/docs
- Vercel: https://vercel.com/docs
