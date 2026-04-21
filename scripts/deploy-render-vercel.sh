#!/bin/bash
# Quick deployment script for Evidence Protector on Render + Vercel
# Run this after setting up both services

set -e

echo "========================================"
echo "Evidence Protector - Deployment Script"
echo "========================================"
echo ""

# Get user input
read -p "Enter your Render backend URL (e.g., https://evidence-protector-backend.onrender.com): " RENDER_URL
read -p "Enter your Vercel frontend URL (e.g., https://evidence-protector.vercel.app): " VERCEL_URL

# Validate URLs
if [[ ! $RENDER_URL =~ ^https://.*onrender.com$ ]]; then
    echo "❌ Invalid Render URL format"
    exit 1
fi

if [[ ! $VERCEL_URL =~ ^https://.*vercel.app$ ]]; then
    echo "❌ Invalid Vercel URL format"
    exit 1
fi

echo ""
echo "🔧 Generating deployment configuration..."
echo ""

# Create environment files
echo "📝 Creating environment variable documentation..."

cat > DEPLOYMENT_URLS.txt << EOF
=== DEPLOYMENT URLS ===

Backend (Render):
  API: $RENDER_URL/api
  Health: $RENDER_URL/api/health
  Docs: $RENDER_URL/api/docs

Frontend (Vercel):
  URL: $VERCEL_URL

=== RENDER - Environment Variables to Set ===
EVIDENCE_PROTECTOR_API_PORT=8000
EVIDENCE_PROTECTOR_API_HOST=0.0.0.0
LOG_LEVEL=INFO
DEBUG=false
ENABLE_AUDIT_LOG=true

# SECRET variables:
EVIDENCE_PROTECTOR_API_KEYS_JSON={your-json-here}
EVIDENCE_PROTECTOR_CORS_ORIGINS=$VERCEL_URL

=== VERCEL - Environment Variables to Set ===
VITE_API_BASE_URL=$RENDER_URL/api
VITE_API_TIMEOUT=30000
VITE_LOG_LEVEL=info
VITE_DEBUG=false

=== NEXT STEPS ===
1. Set EVIDENCE_PROTECTOR_API_KEYS_JSON in Render as a SECRET variable
2. Set VITE_API_BASE_URL in Vercel to: $RENDER_URL/api
3. Test backend health: curl $RENDER_URL/api/health
4. Visit frontend: $VERCEL_URL
5. Upload test log to verify end-to-end integration

EOF

echo "✅ Configuration saved to: DEPLOYMENT_URLS.txt"
echo ""
echo "📋 Next steps:"
echo "1. Open Render Dashboard and set environment variables"
echo "2. Open Vercel Dashboard and set environment variables"
echo "3. Run verification test below"
echo ""

# Verification function
verify_deployment() {
    echo "🧪 Testing deployment..."
    echo ""
    
    # Test backend health
    echo "Testing backend health endpoint..."
    if curl -s "$RENDER_URL/api/health" > /dev/null 2>&1; then
        echo "✅ Backend is responding"
    else
        echo "⚠️  Backend not ready yet (still starting up)"
    fi
    
    echo ""
    echo "🌐 Frontend URL: $VERCEL_URL"
    echo "   Open in browser and test upload"
}

read -p "Run verification test now? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    verify_deployment
fi

echo ""
echo "✅ Deployment script complete!"
echo ""
echo "📚 For detailed instructions, see: DEPLOY_RENDER_VERCEL.md"
