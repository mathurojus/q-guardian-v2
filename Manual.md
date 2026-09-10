# Q-Guardian Software Documentation

## 1. Introduction

Q-Guardian is an enterprise-grade Quantum Transition Intelligence platform designed for the banking and regulated-finance sector. Its primary objective is to inventory, analyze, and map an organisation's cryptographic landscape to prepare for Post-Quantum Cryptography (PQC) migration.

The platform provides a holistic view of the cryptographic attack surface through passive infrastructure discovery, active API penetration testing, and theoretical risk modeling (Mosca and HNDL timelines).

---

## 2. System Architecture

Q-Guardian operates as a decoupled full-stack application.

### 2.1 Backend (Python / FastAPI)
- **Framework**: FastAPI providing RESTful APIs with automatic OpenAPI schema generation.
- **ASGI Server**: Uvicorn for asynchronous request handling.
- **Database**: SQLite interface via SQLModel (SQLAlchemy + Pydantic).
- **Authentication**: JWT-based stateless authentication (`auth.py`).
- **Core Orchestrator**: `main.py` which delegates long-running tasks to `BackgroundTasks`.

### 2.2 Frontend (React / Vite)
- **Framework**: React 18 using a Single Page Application (SPA) architecture.
- **Styling**: TailwindCSS configured with a specific enterprise color palette.
- **State Management**: React Hooks (`useState`, `useEffect`, `useContext`).
- **Visualization**: Recharts for statistical graphs and `react-force-graph-2d` for cryptographic topology mapping.

---

## 3. Core Core Analytical Engines

### 3.1 Passive Discovery Engine (`discovery.py`)
- **Mechanism**: Queries `crt.sh` (Certificate Transparency logs) to identify subdomains associated with a target base domain.
- **TLS Analysis**: For each discovered hostname, it establishes a socket connection, wraps it with `ssl.create_default_context(ssl.CERT_NONE)`, and parses the X.509 certificate using the `cryptography` library.
- **Output**: Extracts TLS version, Cipher Suite, Algorithm, Key Size, Forward Secrecy, Expiration, and determines basic PQC presence.

### 3.2 Active Discovery Engine (`active_discovery.py`)
- **Mechanism**: A proactive scanning module designed to uncover hidden API endpoints.
- **Techniques**:
  - **Spec Parsing**: Automatically looks for `/swagger.json`, `/openapi.json`, and `/v2/api-docs`.
  - **JavaScript Crawling**: Scrapes the homepage and linked `.js` bundles, applying regex to extract hardcoded API routes.
  - **Banking Directory Fuzzing**: Probes a curated list of high-value banking paths (e.g., `/finacle`, `/rtgs-api`, `/swift-gateway`).

### 3.3 Deep OWASP API Scanner (`api_scanner.py`)
- **Mechanism**: A targeted penetration testing engine.
- **Vectors Analyzed**:
  - **API1 (IDOR)**: Probes sequential IDs (`/users/1`, `/accounts/2`).
  - **API2 (Broken Auth / JWT)**: Injects `alg:none` signed JWT tokens to test signature validation.
  - **API3 (GraphQL Introspection)**: Queries `/graphql` with the `__schema` introspection payload.
  - **API4 (Rate Limiting)**: Performs a 15-request rapid burst to identify unthrottled endpoints.
  - **API5 (BFLA)**: Tests HTTP method switching (e.g., `DELETE` on unprotected routes).
  - **API6 (Mass Assignment)**: Injects privileged fields (`role`, `is_admin`) into POST payloads.

### 3.4 Dynamic Q-TRI Scoring Engine (`scoring.py`)
- **Mechanism**: The Quantum-Threat Resilience Index evaluates cryptographic health on a 0-100 scale.
- **Tier-Aware Weighting**: Replaces rigid scoring by adjusting the weights of TLS, Forward Secrecy, Certificate Hygiene, Cipher Strength, and PQC based on the asset's **RBI Sensitivity Tier**.
- **Example**: S1 (Payment gateways) heavily penalize a lack of PQC. S5 (Public blogs) treat PQC as a bonus and weight basic TLS more heavily.

### 3.5 Mosca Countdown Engine (`mosca.py`)
- **Mechanism**: Calculates migration timelines using the Mosca Theorem: **X + Y > Z**.
  - **X (Migration Complexity)**: Derived algorithmically from the current cipher footprint (0.5 to 4.0 years).
  - **Y (Data Shelf Life)**: Defined by the sensitivity tier (1 to 10 years).
  - **Z (CRQC Timeline)**: Estimated time until Cryptographically Relevant Quantum Computers (5 to 15 years).
- **Output**: Assesses if an asset forces the organization into the "Risk Window" (`CRITICAL`, `WARNING`, `SAFE`).

### 3.6 HNDL Exposure Simulator (`hndl.py`)
- **Mechanism**: Models Harvest-Now-Decrypt-Later risk for assets lacking Perfect Forward Secrecy.
- **Computation**: Uses RBI-tiered baseline traffic volumes (e.g., S1 = 800 GB/month) multiplied by months elapsed since a configured harvest start date.
- **Advisory Notice**: Includes UI and PDF disclosures indicating these figures are theoretical upper limits, not exact PCAP-verified telemetry.

---

## 4. Security & Compliance

### 4.1 Authentication & Authorization
- **Implementation**: The platform enforces a strict security boundary. All sensitive endpoints (Asset Listing, API Scanning, Board Brief Generation) require a valid `Authorization: Bearer <token>`.
- **Validation**: On server startup, `auth.py` validates the `SECRET_KEY`. If the key is missing, weak, or left as a default placeholder, the ASGI server aggressively halts execution to prevent insecure deployments.

### 4.2 Regulatory Alignment
The engines and resulting Board Brief PDF (`reporting.py`) are mapped against:
1. **RBI Cybersecurity Framework (CSF) 2.0**
2. **NIST IR 8547 PQC Migration Guidelines**
3. **NSA HNDL Advisory (2023)**

---

## 5. Development & Deployment

### 5.1 Environment Setup
The backend requires a `.env` file containing:
```env
# backend/.env
SECRET_KEY=your_highly_secure_random_string_here
ADMIN_USERNAME=qguardian_admin
ADMIN_PASSWORD_HASH=$2b$12$e... # bcrypt hash of the admin password
```

### 5.2 Server Execution
The project uses a unified PowerShell launch script:
```powershell
.\run.ps1
```
This automatically boots Uvicorn on `0.0.0.0:8000` and the Vite dev server on `0.0.0.0:5173`.

### 5.3 Database
The platform relies on SQLite (`qguardian.db`). By default, `create_db_and_tables()` is called on server startup to initialize schema structures automatically. For distributed production, change the SQLModel connection engine in `database.py` to point to a PostgreSQL/MySQL instance.
