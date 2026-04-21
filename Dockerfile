# Evidence Protector API container
# Runs the FastAPI backend used by the Web UI.

FROM python:3.13-slim@sha256:d168b8d9eb761f4d3fe305ebd04aeb7e7f2de0297cec5fb2f8f6403244621664

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY evidence_protector.py ./evidence_protector.py
COPY evidence_protector_api.py ./evidence_protector_api.py

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "evidence_protector_api:app", "--host", "0.0.0.0", "--port", "8000"]
