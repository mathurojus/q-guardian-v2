# Demo base image manifest — companion to requirements.txt for Trivy fs scans.
FROM python:3.9-slim

WORKDIR /srv/app

# Legacy TLS-era cryptography stack (pre-PQC)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8443
CMD ["python", "-m", "http.server", "8443", "--bind", "0.0.0.0"]
