# Security Policy & Guidelines

## 🔐 Critical Security Practices

### 1. **NEVER Commit Secrets**
- **API Keys, Tokens, Passwords**: Always use environment variables
- **Private Keys**: Keep in secure locations, protected with file permissions (600)
- **Database Credentials**: Use `.env` files (git-ignored)
- **OAuth/JWT Tokens**: Generate dynamically, never hardcode

### 2. **Environment Configuration**
```bash
# WRONG ❌ - Never do this
export API_KEY="sk-1234567890abcdef"
hardcoded_password = "admin123"

# RIGHT ✅ - Use environment variables
export EVIDENCE_PROTECTOR_API_KEYS_JSON='{"key":"role"}'
# Load from .env file (git-ignored)
```

### 3. **File Permissions**
```bash
# Private keys: Read-only for owner
chmod 600 ~/.evidence-protector/private.key

# Configuration with secrets: Read-only for owner
chmod 600 .env

# Public keys: CAN be readable
chmod 644 ~/.evidence-protector/public.key
```

## 🛡️ Backend Security

### API Authentication
- **Role-based Key Mapping**: Use `EVIDENCE_PROTECTOR_API_KEYS_JSON` for multi-role support
  ```json
  {"viewer-api-key": "viewer", "analyst-key": "analyst", "admin-key": "admin"}
  ```
- **Legacy Single Key**: `EVIDENCE_PROTECTOR_API_KEY` (deprecated, use role-based)
- **Token Expiration**: Implement short-lived tokens (see `.env.backend.example`)

### CORS Configuration
- **Development**: Allow localhost only
  ```
  EVIDENCE_PROTECTOR_CORS_ORIGINS=http://localhost:3000,http://localhost:5173
  ```
- **Production**: Use specific domain, never `*`
  ```
  EVIDENCE_PROTECTOR_CORS_ORIGINS=https://yourdomain.com
  ```

### Cryptographic Keys
- **Ed25519** key pair auto-generated on first run
- **Location**: `EVIDENCE_PROTECTOR_PRIVATE_KEY_PATH` environment variable
- **Rotation**: Implement key rotation policy (see `KEY_MANAGEMENT.md`)
- **Backup**: Store securely with encryption at rest

### Input Validation
- Validate all file uploads
- Enforce file size limits: `MAX_UPLOAD_SIZE` (default: 100MB)
- Sanitize manifest JSON inputs
- Check malformed log formats

### Rate Limiting
- Implement rate limiting on API endpoints
- Set thresholds per IP/API key
- Return 429 status for exceeded limits

## 🎨 Frontend Security

### XSS Prevention
- Sanitize user inputs
- Use Content Security Policy (CSP)
- Escape template variables
- Avoid `innerHTML` for user-controlled data

### CSRF Protection
- Include CSRF tokens in POST/PUT/DELETE requests
- Validate origin headers
- Use SameSite cookies

### Data Protection
- Never store API keys in localStorage (use sessionStorage)
- Clear sensitive data on logout
- Implement session timeout
- No PII in console logs (development only)

### API Communication
```typescript
// Secure headers
headers: {
  'Authorization': `Bearer ${token}`,
  'X-Requested-With': 'XMLHttpRequest',
  'Content-Type': 'application/json',
  // Add CSRF token if required
}
```

## 🔒 Docker & Deployment Security

### Secrets Management
```dockerfile
# WRONG ❌
ENV API_KEY="secret123"

# RIGHT ✅
# Use Docker secrets / environment variables at runtime
```

### docker-compose.yml
```yaml
# WRONG ❌
environment:
  - API_KEY=sk-1234567890abcdef

# RIGHT ✅
env_file:
  - .env  # git-ignored
```

### Network Security
- Run backend on `127.0.0.1:8000` (local only) in development
- Use reverse proxy (nginx) in production with SSL/TLS
- Implement firewall rules for database access

## 📋 Audit & Logging

### Enable Audit Logging
```bash
export ENABLE_AUDIT_LOG=true
export AUDIT_LOG_PATH=./logs/audit.log
```

### Log Sensitive Information Carefully
- **DO Log**: User actions, timestamps, IPs, file hashes
- **DON'T Log**: API keys, passwords, private keys, PII

### Log Rotation
Implement log rotation to prevent disk space issues:
```bash
# Use logrotate on Linux
/var/log/evidence-protector/*.log {
    daily
    rotate 7
    compress
    delaycompress
}
```

## 🚨 Incident Response

### If Credentials Are Exposed:
1. **Immediately**: Rotate the exposed key/password
2. **Within 1 hour**: Invalidate old tokens
3. **Within 24 hours**: Audit logs for unauthorized access
4. **Communicate**: Notify affected users
5. **Document**: Record incident and remediation steps

### If Private Key Is Compromised:
1. Revoke immediately: `evidence-protector key revoke {key_id}`
2. Generate new key pair
3. Re-sign all critical evidence
4. Update key references in manifests

## 🔐 Cryptographic Operations

### Key Generation
```bash
# Ed25519 key pair (auto-generated)
evidence-protector key rotate

# Output: Private key stored at EVIDENCE_PROTECTOR_PRIVATE_KEY_PATH
#         Public key stored alongside
```

### Signing
- Only sign with verified private keys
- Include key_id in signature metadata
- Timestamp signatures for audit trail

### Verification
- Always verify before trusting evidence
- Check key revocation status
- Validate timestamps are reasonable

## 🧪 Testing Security

### Security Tests (Included)
- API authentication test
- CORS policy test
- Input validation test
- Manifest integrity test
- Key rotation test

Run security tests:
```bash
python -m pytest test_security.py -v
```

## 📚 Additional Resources

- [SECURITY_OPERATIONS.md](SECURITY_OPERATIONS.md) - Operational security guide
- [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md) - Key lifecycle management
- [GHOST_PROTOCOL_THREAT_MODEL.md](GHOST_PROTOCOL_THREAT_MODEL.md) - Threat analysis
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Web Application Security
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - Best practices

## 🛠️ Security Dependency Updates

### Regular Updates
- Check dependencies for CVEs: `pip audit` (Python), `npm audit` (Node.js)
- Update critical security patches immediately
- Test thoroughly before production deployment

```bash
# Python security audit
pip install pip-audit
pip-audit

# Node security audit
npm audit
npm audit fix
```

## 📞 Report Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

Instead:
1. Email `security@yourdomain.com` with detailed description
2. Include proof-of-concept if applicable
3. Allow 90 days for patch before public disclosure
4. Follow coordinated disclosure practices

## ✅ Security Checklist

- [ ] All secrets removed from repository
- [ ] `.gitignore` blocks sensitive files
- [ ] `.env.example` is committed (without secrets)
- [ ] API keys are environment-based
- [ ] Private keys have proper file permissions (600)
- [ ] CORS configured for specific domains
- [ ] Rate limiting implemented
- [ ] Input validation tested
- [ ] Audit logging enabled
- [ ] Dependencies audited for CVEs
- [ ] SSL/TLS configured in production
- [ ] Database connections encrypted
- [ ] Secrets rotation policy documented
- [ ] Incident response plan documented
- [ ] Security testing automated

---

**Last Updated**: 2024  
**Maintainer**: Security team
