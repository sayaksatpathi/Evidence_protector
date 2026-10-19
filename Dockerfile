# Evidence Protector API container. Shared engine comes from the pinned
# evidence-protector dependency declared in pyproject.toml.
FROM python:3.13-slim@sha256:d168b8d9eb761f4d3fe305ebd04aeb7e7f2de0297cec5fb2f8f6403244621664

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# pip needs git to resolve the pinned Log-Guardian dependency. Remove git
# after installation so it is not included in the runtime image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY evidence_protector_api.py evidence_protector_legacy_stdlib.py main.py asgi.py app.py ./
RUN pip install --no-cache-dir . \
    && apt-get purge -y --auto-remove git \
    && rm -rf /var/lib/apt/lists/*

# Preserve the legacy script entry point; it forwards to the installed core.
COPY evidence_protector.py ./evidence_protector.py

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "evidence_protector_api:app", "--host", "0.0.0.0", "--port", "8000"]
