# Evidence Protector - Production Deployment Checklist

## 🔐 Pre-Deployment Security Verification

### Backend Security ✓
- [ ] **Secrets Management**
  - [ ] No hardcoded API keys in code
  - [ ] No hardcoded database credentials
  - [ ] No hardcoded JWT secrets
  - [ ] `.env` file is in `.gitignore`
  - [ ] `.env.backend.example` is committed

- [ ] **API Security**
  - [ ] Authentication enabled (`EVIDENCE_PROTECTOR_API_KEYS_JSON`)
  - [ ] CORS restricted to specific origins (production domain only)
  - [ ] Rate limiting configured
  - [ ] HTTPS/TLS enforced in production
  - [ ] API key rotation policy documented

- [ ] **Data Protection**
  - [ ] Private key permissions set to 600
  - [ ] Database connection requires password
  - [ ] Audit logging enabled
  - [ ] Sensitive data not logged to stdout
  - [ ] File upload size limits configured

- [ ] **Key Management**
  - [ ] Ed25519 private key securely stored
  - [ ] Key rotation script tested
  - [ ] Key revocation mechanism working
  - [ ] Backup of public key rings available
  - [ ] Key expiration policy documented

### Frontend Security ✓
- [ ] **Configuration**
  - [ ] No API keys in source code
  - [ ] `.env.local` is in `.gitignore`
  - [ ] `.env.frontend.example` is committed
  - [ ] API endpoint points to HTTPS in production
  - [ ] Debug mode disabled in production

- [ ] **XSS Prevention**
  - [ ] Content Security Policy configured
  - [ ] User inputs sanitized
  - [ ] Template variables escaped
  - [ ] No use of `innerHTML` with user data

- [ ] **CSRF Protection**
  - [ ] CSRF tokens implemented for state-changing requests
  - [ ] SameSite cookie attribute set
  - [ ] Origin header validation

- [ ] **Authentication**
  - [ ] API key stored securely (sessionStorage, not localStorage)
  - [ ] Session timeout implemented
  - [ ] Logout clears sensitive data
  - [ ] Token refresh mechanism implemented

### Docker & Deployment ✓
- [ ] **Secrets in Docker**
  - [ ] No secrets in `docker-compose.yml`
  - [ ] No secrets in `Dockerfile` (use build args)
  - [ ] Secrets injected via environment variables at runtime
  - [ ] Use Docker secrets or external secret management (e.g., HashiCorp Vault)

- [ ] **Network Security**
  - [ ] Backend runs on non-root user
  - [ ] Unnecessary ports not exposed
  - [ ] Reverse proxy (nginx) shields backend
  - [ ] SSL/TLS certificates valid and current
  - [ ] Firewall rules restrict database access

- [ ] **Image Security**
  - [ ] Base images from trusted registries (python:3.13-slim)
  - [ ] No root containers in production
  - [ ] Security scanning performed (e.g., Trivy, Snyk)
  - [ ] Minimal dependencies in container

### GitHub Repository ✓
- [ ] **Access Control**
  - [ ] Repository is private (unless open-source)
  - [ ] Branch protection enabled
  - [ ] Only maintainers can push to main
  - [ ] Code review required before merge

- [ ] **Secrets Protection**
  - [ ] No secrets in commit history
  - [ ] `.gitignore` comprehensive and tested
  - [ ] Secrets scan performed (`git-secrets`, `detect-secrets`)
  - [ ] Branch with secrets removed/re-created if exposed

- [ ] **CI/CD Pipeline**
  - [ ] No credentials in GitHub Actions workflows
  - [ ] Use GitHub Secrets for sensitive values
  - [ ] Security tests run on every commit
  - [ ] SAST tools configured (CodeQL, SonarQube)

### Monitoring & Logging ✓
- [ ] **Audit Trail**
  - [ ] Audit logging enabled
  - [ ] All API access logged
  - [ ] User actions tracked with timestamps
  - [ ] Failed authentication attempts logged

- [ ] **Error Handling**
  - [ ] No sensitive data in error messages
  - [ ] Stack traces not exposed to users
  - [ ] Exception logging captures context safely
  - [ ] Log rotation configured

- [ ] **Alerting**
  - [ ] Alerts for failed login attempts
  - [ ] Alerts for key rotation events
  - [ ] Alerts for unusual API access patterns
  - [ ] On-call schedule for security incidents

### Compliance ✓
- [ ] **Documentation**
  - [ ] SECURITY.md present and up-to-date
  - [ ] Key management policy documented
  - [ ] Incident response plan documented
  - [ ] Data retention policy documented

- [ ] **Privacy**
  - [ ] No unnecessary PII collection
  - [ ] Data retention limits set
  - [ ] GDPR/privacy policy present
  - [ ] User consent obtained if required

- [ ] **Dependency Management**
  - [ ] `pip audit` passes (Python)
  - [ ] `npm audit` passes (Node.js)
  - [ ] No deprecated dependencies
  - [ ] Security patches applied

## 📋 Pre-Deployment Verification Script

```bash
#!/bin/bash
# Run this before pushing to production

echo "🔐 Running Security Verification..."

# Check for secrets in code
echo "Checking for hardcoded secrets..."
grep -r "API_KEY\|PASSWORD\|SECRET\|TOKEN" --include="*.py" --include="*.ts" --include="*.tsx" --exclude-dir=node_modules src/ 2>/dev/null | grep -v "ENV\|env_\|EXAMPLE" && echo "⚠️  WARNING: Check these references" || echo "✓ No obvious secrets found"

# Verify .gitignore
echo "Checking .gitignore..."
[ -f .gitignore ] && grep -q "\.env" .gitignore && echo "✓ .env in .gitignore" || echo "❌ Add .env to .gitignore"

# Security audit Python
echo "Running Python security audit..."
pip audit 2>/dev/null && echo "✓ No known Python vulnerabilities" || echo "⚠️  Review Python dependencies"

# Security audit Node.js
echo "Running Node.js security audit..."
cd "Evidence Protector Web UI" 2>/dev/null && npm audit --audit-level=moderate 2>/dev/null && echo "✓ No critical Node.js vulnerabilities" || echo "⚠️  Review Node.js dependencies"

echo "✅ Security verification complete!"
```

## 🚀 Deployment Steps

1. **Pre-deployment**: Run security verification script
2. **Testing**: Run full test suite including security tests
3. **Configuration**: Set environment variables in production environment
4. **Secrets**: Inject secrets via secure mechanism (AWS Secrets Manager, Vault, etc.)
5. **Deployment**: Deploy with security-hardened configurations
6. **Verification**: Verify all security measures in production
7. **Monitoring**: Enable monitoring and alerting
8. **Documentation**: Update deployment documentation

## 📞 Post-Deployment

- [ ] Monitor security logs for anomalies
- [ ] Test incident response procedures
- [ ] Schedule regular security audits
- [ ] Plan dependency updates (monthly)
- [ ] Review and rotate credentials (quarterly)
- [ ] Conduct security training with team

---

**Created**: 2024  
**Next Review**: Before production deployment
