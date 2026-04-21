# Docker & Cloud Security Hardening

**Complete guide to securing Evidence Protector in containerized and cloud environments**

## 🐳 Docker Security Best Practices

### 1. Base Image Security

**❌ AVOID**:
```dockerfile
FROM ubuntu:latest          # Bloated, unpatched
FROM python:3.13            # Large image
RUN apt-get install everything
```

**✓ USE**:
```dockerfile
FROM python:3.13-slim       # Minimal, maintained
FROM python:3.13-alpine     # Smallest footprint
```

### 2. Non-Root User in Container

**❌ WRONG** - Runs as root (security risk):
```dockerfile
RUN pip install /app
CMD ["python", "app.py"]
```

**✓ CORRECT** - Non-root user:
```dockerfile
RUN useradd -m -u 1000 appuser
USER appuser
RUN pip install --user -r requirements.txt
CMD ["python", "-u", "app.py"]
```

### 3. Secrets in Docker

**❌ NEVER HARDCODE**:
```dockerfile
ENV API_KEY="sk-1234567890"          # Exposed in image!
RUN echo "db_password=secret" > config
```

**✓ INJECT AT RUNTIME**:
```dockerfile
# Dockerfile (no secrets)
EXPOSE 8000
CMD ["python", "app.py"]

# Run with secrets:
docker run \
  -e EVIDENCE_PROTECTOR_API_KEYS_JSON='{"key":"admin"}' \
  -v /secure/secrets:/app/secrets:ro \
  evidence-protector:latest
```

### 4. Multi-Stage Builds (Smaller Images)

```dockerfile
# Stage 1: Builder
FROM python:3.13-slim as builder
RUN pip install --user -r requirements.txt

# Stage 2: Runtime (only what's needed)
FROM python:3.13-slim
COPY --from=builder /root/.local /root/.local
COPY src/ /app/src/
ENV PATH=/root/.local/bin:$PATH
USER 1000:1000
CMD ["python", "-m", "evidence_protector.cli"]
```

### 5. Security Scanning

```bash
# Scan image for vulnerabilities
docker scan evidence-protector:latest

# Or use Trivy
trivy image evidence-protector:latest

# Or use Snyk
snyk container test evidence-protector:latest
```

---

## 🔒 Docker Compose Security

### Secrets Configuration

**❌ WRONG** - Hardcoded in compose file:
```yaml
services:
  backend:
    environment:
      - API_KEY=secret123
      - DB_PASSWORD=password
```

**✓ CORRECT** - External secrets:
```yaml
services:
  backend:
    environment:
      - API_KEY=${API_KEY}  # From .env (git-ignored)
    env_file:
      - .env.prod           # Git-ignored file
    secrets:
      - db_password
      - api_keys

secrets:
  db_password:
    file: /run/secrets/db_password
  api_keys:
    file: /run/secrets/api_keys
```

### Network Isolation

```yaml
services:
  backend:
    networks:
      - backend_net    # Only communicate with frontend
    expose:
      - "8000"         # Don't publish, use internal network
    environment:
      - EVIDENCE_PROTECTOR_API_HOST=0.0.0.0  # Listen inside container only

  frontend:
    networks:
      - frontend_net
      - backend_net    # Can reach backend

  reverse_proxy:
    ports:
      - "80:80"        # Only reverse proxy exposed
      - "443:443"
    networks:
      - frontend_net

networks:
  backend_net:
    internal: true     # No external access
  frontend_net:
```

### Volume Permissions

```yaml
volumes:
  # Read-only key files
  keys:
    driver: local
    driver_opts:
      type: tmpfs
      device: tmpfs
      o: "size=10m,mode=1700"  # 700 = only owner can access

  # Private data - host controlled permissions
  data:
    driver: local
```

---

## 🚀 Kubernetes Security

### Secret Management (NOT ConfigMap for sensitive data!)

```yaml
# ❌ WRONG: Using ConfigMap for secrets
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  api_key: "sk-1234567890"  # EXPOSED in etcd!

---

# ✓ CORRECT: Using Kubernetes Secrets
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
type: Opaque
stringData:
  api_keys: |
    {
      "prod-key": "admin",
      "viewer-key": "viewer"
    }
  private_key: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----

---
apiVersion: v1
kind: Pod
metadata:
  name: evidence-protector
spec:
  containers:
  - name: backend
    image: evidence-protector:latest
    env:
    - name: EVIDENCE_PROTECTOR_API_KEYS_JSON
      valueFrom:
        secretKeyRef:
          name: app-secrets
          key: api_keys
    volumeMounts:
    - name: keys
      mountPath: /app/keys
      readOnly: true

  volumes:
  - name: keys
    secret:
      secretName: app-secrets
      defaultMode: 0600  # Read-only for owner
```

### Pod Security Policy

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: evidence-protector-policy
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  allowedCapabilities:
    - NET_BIND_SERVICE
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
    ranges:
      - min: 1000
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1000
        max: 65535
  readOnlyRootFilesystem: true
  seLinux:
    rule: 'MustRunAs'
    seLinuxOptions:
      level: 's0:c100,c200'
```

---

## ☁️ Cloud Provider Secrets Management

### AWS Secrets Manager

```python
import boto3
import json
import os

def get_secrets_from_aws():
    client = boto3.client('secretsmanager')
    
    try:
        response = client.get_secret_value(
            SecretId='evidence-protector/prod'
        )
        
        if 'SecretString' in response:
            secret = json.loads(response['SecretString'])
            # Set environment variables
            os.environ['EVIDENCE_PROTECTOR_API_KEYS_JSON'] = json.dumps(secret['api_keys'])
            
    except Exception as e:
        print(f"Failed to retrieve secrets: {e}")
        exit(1)

# Call at startup
get_secrets_from_aws()
```

### Azure Key Vault

```python
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import json
import os

def get_secrets_from_azure():
    credential = DefaultAzureCredential()
    client = SecretClient(
        vault_url="https://evidence-protector.vault.azure.net/",
        credential=credential
    )
    
    try:
        api_keys_secret = client.get_secret("api-keys")
        os.environ['EVIDENCE_PROTECTOR_API_KEYS_JSON'] = api_keys_secret.value
        
        private_key_secret = client.get_secret("private-key")
        with open('~/.evidence-protector/private.key', 'w') as f:
            f.write(private_key_secret.value)
        os.chmod('~/.evidence-protector/private.key', 0o600)
        
    except Exception as e:
        print(f"Failed to retrieve secrets: {e}")
        exit(1)

get_secrets_from_azure()
```

### HashiCorp Vault

```bash
# Configure Vault agent in Docker

# agent.hcl
vault {
  address = "https://vault.example.com:8200"
}

auto_auth {
  method {
    type = "kubernetes"
    config = {
      role = "evidence-protector"
    }
  }
}

cache {
  use_auto_auth_token = true
}

listener "unix" {
  address = "/tmp/agent.sock"
}

# Run with agent
docker run \
  -v /path/to/agent.hcl:/etc/vault/agent.hcl:ro \
  evidence-protector:latest \
  vault agent -config=/etc/vault/agent.hcl
```

---

## 📋 Container Security Checklist

- [ ] Use minimal base image (slim/alpine)
- [ ] Container runs as non-root user (UID > 1000)
- [ ] No hardcoded secrets in Dockerfile
- [ ] Secrets injected via environment/volumes at runtime
- [ ] Security scanning passed (Trivy/Snyk/Grype)
- [ ] Base image security patches applied
- [ ] Multi-stage builds for minimal image size
- [ ] Network isolation configured
- [ ] Read-only root filesystem (if possible)
- [ ] Resource limits set (memory, CPU)
- [ ] Health checks configured
- [ ] Logging configured (not stdout for production)
- [ ] Image signing/verification enabled
- [ ] Regular image rebuilds with latest patches

---

## 🚨 Common Vulnerabilities to Avoid

### 1. Exposed Secrets in Layers

```bash
# ❌ Secret will persist even if removed later
RUN echo "password=secret123" > config.txt
RUN rm config.txt  # Still in layer history!

# ✓ Use multi-stage or mount
RUN --mount=type=secret,id=mysecret \
    cat /run/secrets/mysecret > config.txt
```

### 2. Unnecessary Packages

```dockerfile
# ❌ Includes development tools (security risk, bloat)
RUN apt-get install -y python3-dev build-essential

# ✓ Minimal runtime only
RUN apt-get install -y --no-install-recommends python3
```

### 3. Latest Tag

```dockerfile
# ❌ Unpredictable, might include breaking changes
FROM python:latest

# ✓ Specific pinned version
FROM python:3.13.4-slim
```

---

## 🔐 Production Hardening Script

```bash
#!/bin/bash
set -e

# Build secure image
docker build \
  -f Dockerfile \
  -t evidence-protector:latest \
  -t evidence-protector:$(date +%Y%m%d) \
  .

# Scan for vulnerabilities
echo "Scanning image for vulnerabilities..."
trivy image --severity HIGH,CRITICAL evidence-protector:latest

# Scan for secrets
echo "Scanning for hardcoded secrets..."
trivy image --scan-type secret evidence-protector:latest

# Test in isolated environment
docker run --rm \
  -e CHECK_ONLY=true \
  evidence-protector:latest \
  python -c "import evidence_protector; print('OK')"

echo "✅ Image hardening passed!"
```

---

## 📚 Additional Resources

- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [CIS Docker Benchmark](https://www.cisecurity.org/cis-benchmarks/)
- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)
- [OWASP Container Security](https://owasp.org/www-community/attacks/Web_Service_API_Giveaways)

---

**Last Updated**: April 2024  
**Security Focus**: Container & Cloud Hardening
