# Q-Guardian v2 — USP + Judge Q&A Brief

## 1. Unique Selling Proposition (what makes this different)

Most "crypto discovery" tools stop at one surface. Q-Guardian is built around the idea that a single scanner gives you a false picture of cryptographic posture, because the same asset can look compliant from one view and vulnerable from another. The differentiators are:

1. **Four independent evidence vectors, reconciled into one inventory.**
   Live TLS endpoints, static source code, container images, and compiled binaries are each scanned by a real engine, then correlated by a reconciler that flags "declared vs actual" drift. That is the core architectural decision, not a feature layer on top of one scanner.

2. **Real scanners, not stubs.**
   - Network: Certificate Transparency enumeration (crt.sh) plus a real TLS handshake using Python `ssl`, extracting protocol version, cipher, forward secrecy, certificate chain, expiry, key type and key size.
   - Source: Semgrep with a hand-built crypto ruleset (`rules/crypto.yml`), with an AST/regex fallback when Semgrep is not installed.
   - Container: Trivy (`trivy fs` / `trivy image`), with Syft and a heuristic fallback; plus a quantum-readiness table that maps package/version to PQC capability, which is the thing vanilla SBOM scanners do not give you for free.
   - Binary: LIEF for ELF/PE/Mach-O inspection plus constant-signature matching for ML-KEM NTT tables, AES S-box, MD5 IVs, SHA-1 initial state, DES S-box, and liboqs interface strings.

3. **The risk engine is the point, not the scan.**
   Mosca's inequality `X + Y > Z` is implemented with real migration-complexity derivation from algorithm/key-size/primitive, not a made-up number. Q-TRI is a weighted per-tier score, not a single global badge. HNDL is modeled with a clear "weakly grounded" advisory instead of pretending the numbers are measured packet captures.

4. **Compliance is not an afterthought panel.**
   The platform maps findings to RBI CSF 2.0 controls, NIST IR 8547 PQC transition milestones T1–T4, and India DST/TEC National Quantum Mission guidance, with milestone deadlines and AT-RISK/OPEN/TRACK states. That combination is aimed at a specific judging context: Indian financial/regulated-sector readiness for post-quantum migration.

5. **Export is a real standard, not a pretty table.**
   The CBOM is generated as CycloneDX 1.6 with the cryptographic asset extension, and also as PDF board brief. The intent is auditable artifact output, not just a dashboard.

6. **Honest grounding wherever the data is weak.**
   HNDL volumes are flagged as modeled baselines. RAG answers are grounded with a local FAISS index and a vocabulary overlap gate, and degrade to rule-based answers when dependencies are missing. The system does not claim more certainty than it has.

The short version for a judge:
> "Q-Guardian is a multi-source post-quantum cryptography discovery and risk platform that reconciles live TLS, source code, container images, and compiled binaries into one cryptographic bill of materials, scores each asset with a real Mosca countdown and a tiered Q-TRI, maps findings to RBI/NIST IR 8547/India DST-TEC compliance, and exports a CycloneDX 1.6 CBOM — with declared-vs-actual divergence as the key insight."

---

## 2. One-line product definition

A post-quantum cryptography risk assessment platform that discovers cryptographic assets across four evidence sources, scores quantum risk using Mosca's inequality and a tiered Q-TRI, maps violations to regulatory frameworks, recommends PQC migration paths, and exports a standards-compliant CBOM.

---

## 3. Who it is for

- Banks and regulated financial institutions preparing for post-quantum migration.
- Security and compliance teams that need evidence for audits, not just a dashboard.
- Organizations subject to RBI cybersecurity guidance, NIST IR 8547-style transition planning, or India DST/TEC quantum-readiness expectations.
- Security analysts who want a single place where source, container, binary, and network crypto findings meet.

---

## 4. What the user actually sees

- A login-gated console with a header scan bar for domain-based network discovery.
- A posture dashboard with enterprise cyber rating, Mosca risk distribution, asset metrics, and a live threat-intel feed.
- An inventory/table view of all discovered cryptographic assets across sources.
- A multi-source scanner for static code, Semgrep rules, containers, and binaries.
- An API scanner for targeted OWASP API Top 10 checks.
- An HNDL exposure simulator with a clear "modeled baseline" advisory.
- A dependency graph showing assets, algorithms, and divergence edges.
- A compliance mapper for RBI, NIST IR 8547, and India DST/TEC.
- A CBOM viewer with CycloneDX-style export to JSON and PDF, plus before/after diff.
- A chatbot that answers from a local knowledge base and live inventory.

---

## 5. Architecture in plain language

The system has three layers:

1. **Ingestion layer**
   Each scanner is its own engine. They all produce the same internal asset shape, so the rest of the platform does not care whether a finding came from a TLS handshake, a source file, a container manifest, or a binary constant table.

2. **Risk and reasoning layer**
   Once assets are normalized, the platform computes:
   - Mosca clocks from real algorithm/key-size/primitive data
   - Q-TRI from a tier-weighted scoring matrix
   - HNDL exposure for non-forward-secret assets
   - Reconciliation divergences across sources
   - Migration playbooks
   - Compliance mappings

3. **Presentation and export layer**
   The frontend is a React/Vite app talking to a FastAPI backend. The backend persists everything in SQLite and exposes the scan, asset, risk, compliance, CBOM, and chat endpoints. Exports go to JSON and PDF.

---

## 6. Project structure and what each part stands for

### Backend core
- `backend/app/main.py` — FastAPI app, auth, scan orchestration, asset serialization, and all the route surface.
- `backend/app/database.py` — SQLModel models and DB setup: scan jobs, assets, audit log, CBOM history.
- `backend/app/auth.py` — JWT login, token verification, bcrypt password check.
- `backend/app/settings.py` — env loading, secret validation, CORS, DB URL.
- `backend/app/engines/` — scanner and risk engines.

### Scanner engines
- `backend/app/engines/discovery.py` — crt.sh subdomain enumeration plus live TLS handshake assessment.
- `backend/app/engines/active_discovery.py` — endpoint fuzzing, JS path extraction, spec probing.
- `backend/app/engines/port_scanner.py` — asyncio TCP port scan against common service ports.
- `backend/app/engines/source_scanner.py` — Semgrep shell-out with AST/regex fallback.
- `backend/app/engines/static_analysis.py` — AST visitor + regex rules for Python/JS source files and manifests.
- `backend/app/engines/container_scanner.py` — Trivy/Syft with a quantum-readiness package table and heuristic fallback.
- `backend/app/engines/binary_scanner.py` — LIEF + byte-constant signatures for ML-KEM, AES, MD5, SHA-1, DES, liboqs symbols.
- `backend/app/engines/sample_binary.py` — generates a synthetic ELF-style binary with embedded crypto constants for demo/testing.

### Risk engines
- `backend/app/engines/mosca.py` — migration complexity derivation, `X + Y > Z` clocks, business-impact tiering.
- `backend/app/engines/scoring.py` — tier-weighted Q-TRI and overall cyber rating.
- `backend/app/engines/hndl.py` — harvest-now-decrypt-later exposure model for assets without forward secrecy.
- `backend/app/engines/migration.py` — algorithm-to-PQC migration playbook table.
- `backend/app/engines/compliance.py` — RBI CSF 2.0, NIST IR 8547, India DST/TEC mappings.
- `backend/app/engines/reconciler.py` — cross-source divergence detection and crypto-agility maturity.

### CBOM and reporting
- `backend/app/engines/cbom.py` — CycloneDX 1.6 JSON generator with crypto properties and PDF export.
- `backend/app/engines/reporting.py` — board brief PDF.
- `backend/app/engines/threat_intel.py` — RSS feed collector for security/quantum news.
- `backend/app/engines/chatbot.py` — rule-based assistant with RAG fallback.
- `backend/app/engines/rag_advisor.py` — offline LangChain + FAISS advisor.

### Rules and validation
- `backend/rules/crypto.yml` — Semgrep crypto ruleset.
- `backend/validate_cbom_schema.py` — CBOM schema validation script.

### Demo
- `demo/seed_demo.py` — deterministic demo seed using real scanner engines on local fixtures.

### Frontend
- `frontend/` — Vite + React app with context providers, API helper, and component tabs.

---

## 7. How each scanner works — operational detail

### Network / TLS discovery
1. The domain is queried against crt.sh to enumerate subdomains.
2. Each endpoint is reached over TCP 443 and a real TLS handshake is performed.
3. From the handshake, the system reads TLS version, cipher suite, forward secrecy indicator, certificate validity, public-key algorithm, and key size.
4. Active discovery may also fuzz common API paths, extract paths from JavaScript, and probe OpenAPI/Swagger specs.
5. Port scanning adds an extra surface view of open services.

What is real: the handshake and certificate parsing.
What is modeled: traffic baselines for HNDL and the sensitivity tier classification rules.

### Source code scanning
1. If Semgrep is available, the engine runs `semgrep --config rules/crypto.yml --json <target>`.
2. If Semgrep is unavailable, it falls back to an internal rule evaluator that includes both AST-based Python analysis and regex matching.
3. The ruleset covers weak hashes, weak RSA key sizes, ECB mode, deprecated TLS protocol constants, insecure PRNGs, and Java analogues.
4. Each finding is stored with file path, line number, algorithm, primitive, and Q-TRI metadata.

What is real: the rule evaluation and the file/line evidence.
What is not: the rule set is curated for demo/assessment relevance rather than being an exhaustive industrial static-analysis suite.

### Container scanning
1. The engine prefers Trivy. It tries `trivy fs` for a local path and `trivy image` for an image reference.
2. It parses native JSON if a vulnerability DB is available; otherwise it falls back to CycloneDX SBOM output, which works without a DB.
3. If neither Trivy nor Syft is available, a heuristic engine assesses known base-image crypto profiles and Dockerfile package installations.
4. Crucially, every discovered package/version is run through a quantum-readiness lookup table, so the result is not just "here is a package list" but "here is what this package version means for PQC readiness."

What is real: Trivy/Syft SBOM parsing and the per-package version comparison.
What is modeled: the heuristic base-image profiles and the PQC capability thresholds are curated knowledge, not live vulnerability DB truth.

### Binary scanning
1. The file is read as raw bytes.
2. If LIEF is available, the parser extracts sections and symbols.
3. The engine searches for constant signatures: ML-KEM NTT zetas, AES S-box, MD5 initial constants, SHA-1 initial state, DES S-box, and crypto-related symbol/string patterns.
4. Matches are recorded with byte offset and section context so they behave like real reverse-engineering findings.

What is real: byte-level constant detection and LIEF symbol/section parsing.
What is not: this is signature-based detection, not a full disassembly or decompilation of cryptographic logic.

---

## 8. How the risk math works — plain version

### Mosca
- `X` = how long migration will take. It is derived from what cryptography the asset actually uses: weak hashes, legacy ciphers, ECB, small RSA keys, old TLS versions, missing forward secrecy, and high-sensitivity tier all increase migration complexity.
- `Y` = how long the data needs to stay protected. It comes from sensitivity tier by default, with an optional per-asset override.
- `Z` = years until a cryptographically relevant quantum computer. The system uses a worst-case and best-case horizon.
- If `X + Y > Z`, the asset is in the quantum risk window. Worst-case determines CRITICAL/WARNING; best-case determines MONITOR.

### Q-TRI
- Each asset gets a 0–100 score.
- The score is a weighted combination of TLS version, forward secrecy, certificate hygiene, cipher strength, and PQC adoption.
- Weights change by sensitivity tier: critical assets care more about PQC; low-tier assets treat PQC as a bonus.
- A quantum-vulnerable algorithm cap can pull the score down.
- The enterprise cyber rating is the average Q-TRI scaled to 0–1000.

### HNDL
- If an asset does not have forward secrecy, the model estimates exposure using tier-based traffic baselines and the time since harvest start.
- The output is explicitly labeled as a modeled risk ceiling, not a measured exfiltration.

---

## 9. The "declared vs actual" idea

This is the conceptual center of the project.

A bank may believe its applications are modern because the source code or container base looks fine. But the live endpoint may still negotiate an old TLS version, or a compiled binary may embed a legacy cipher constant that the container library does not reflect.

The reconciler looks for exactly those mismatches:
- Static code declares modern TLS/PQC but the live endpoint is legacy.
- Container environment is modern but a compiled binary contains legacy constants.
- Code is flagged for PQC migration but the live certificate is still classical.
- A critical-tier asset is non-compliant with no divergence flag yet.

That is what produces divergence flags and the amber "declared vs actual" visualization.

---

## 10. Compliance mapping — what each framework contributes

### RBI CSF 2.0
- Legacy TLS versions.
- Weak public-key sizes.
- Broken hashes.
- Legacy symmetric ciphers and unsafe modes.
- Missing forward secrecy on TLS-bearing assets.

### NIST IR 8547
- Each quantum-vulnerable asset is mapped to T1–T4 transition milestones with deadlines.
- Critical assets and S1/S2 assets are marked AT-RISK across the timeline; others are tracked with OPEN/TRACK states.

### India DST/TEC
- Assets are mapped to the National Quantum Mission horizon and supply-chain crypto dependency review flags.
- Financial/core-tier assets are emphasized because the NQM scale-up window is the relevant exposure closure point for them.

---

## 11. Most likely judge questions and how to answer them

### General product
**Q: What problem are you solving?**
A: Organizations need to find every cryptography asset they actually use, understand which ones are quantum-vulnerable, know when they must migrate, and prove it to regulators. Q-Guardian does discovery, risk scoring, compliance mapping, migration guidance, and CBOM export in one place.

**Q: Why do you need four scanners?**
A: One scanner gives a partial truth. Source may look modern while the live endpoint is old, or the container may be current while a compiled binary still embeds a legacy constant. Reconciling multiple sources is what exposes declared-vs-actual drift.

**Q: What is the key insight of the project?**
A: The most useful finding is not "you have a weak algorithm"; it is "your declared posture and your actual posture disagree." That divergence is what the reconciler is built to surface.

**Q: Is this a scanner or a risk platform?**
A: Both, but the risk platform is the point. Scanning is the input; Mosca, Q-TRI, HNDL, compliance, migration playbooks, and CBOM export are the value.

### Architecture
**Q: What is the backend stack?**
A: FastAPI with SQLModel/SQLite, with scanner engines implemented as Python modules. The frontend is React with Vite.

**Q: How do the scanners talk to the rest of the system?**
A: Every scanner produces the same internal asset shape, so the risk engines, reconciler, CBOM generator, and export paths all treat network, source, container, and binary findings uniformly.

**Q: What happens if a scanner tool is missing?**
A: The system degrades gracefully. For example, source scanning falls back to AST/regex if Semgrep is absent; container scanning falls back to Syft, then to heuristics.

**Q: How is state persisted?**
A: Scan jobs, assets, audit log, and CBOM history snapshots are stored in SQLite via SQLModel.

### Cryptography
**Q: What is post-quantum cryptography?**
A: Cryptographic algorithms designed to remain secure even against quantum computers. The project focuses on NIST-standardized families such as ML-KEM, ML-DSA, and SLH-DSA.

**Q: Why is RSA vulnerable?**
A: Shor's algorithm can solve the integer factorization problem that RSA depends on. RSA is not quantum-safe.

**Q: Why is ECC/ECDSA vulnerable?**
A: Shor's algorithm also breaks the discrete-log problems behind elliptic-curve cryptography.

**Q: What about symmetric algorithms like AES?**
A: Grover's algorithm roughly halves the effective security bit strength, so AES-256 is generally treated as the safe symmetric target. The bigger quantum concern is usually public-key crypto.

**Q: What is ML-KEM?**
A: A NIST-standardized post-quantum key encapsulation mechanism, used for key exchange.

**Q: What is ML-DSA?**
A: A NIST-standardized post-quantum digital signature algorithm.

**Q: What is the difference between classical security and quantum security?**
A: Classical security is about today's attackers. Quantum security is about attackers with a cryptographically relevant quantum computer. A scheme can be classically fine and still be quantum-vulnerable.

### Quantum risk concepts
**Q: What is Mosca's inequality?**
A: It says if `X + Y > Z`, where X is migration time, Y is data shelf life, and Z is time to a cryptographically relevant quantum computer, then the asset is in the risk window.

**Q: What is a CRQC?**
A: A cryptographically relevant quantum computer — one powerful and fault-tolerant enough to break meaningful cryptography.

**Q: What is HNDL?**
A: Harvest Now, Decrypt Later. An attacker records encrypted traffic today and decrypts it later once quantum capability exists. Forward secrecy is the main practical mitigation.

**Q: Why does forward secrecy matter for HNDL?**
A: If session keys are ephemeral and not derivable from long-term keys, recorded traffic is much harder to decrypt later even if the long-term key is eventually broken.

**Q: What is Q-TRI?**
A: The platform's Quantum Transition Resilience Index, a 0–100 score combining TLS posture, forward secrecy, certificate hygiene, cipher strength, and PQC adoption, weighted by sensitivity tier.

### Compliance
**Q: Which compliance frameworks are covered?**
A: RBI CSF 2.0, NIST IR 8547, and India DST/TEC National Quantum Mission guidance.

**Q: What does NIST IR 8547 provide?**
A: A phased post-quantum transition timeline. The project uses discovery/inventory, prioritization, priority migration, and full migration milestones.

**Q: What is the India DST/TEC angle?**
A: The National Quantum Mission sets a strategic horizon that matters for Indian financial and telecom sectors. The platform maps vulnerable assets to that horizon and to supply-chain review expectations.

**Q: Does the platform certify compliance?**
A: No. It maps findings to controls and timelines and produces evidence artifacts. Compliance certification is a broader process; this is an assessment and inventory tool.

### Project-specific
**Q: Is the data real or dummy?**
A: Both, and the difference matters. The engines are real. Semgrep, Trivy, LIEF, TLS handshakes, and CBOM generation are all real. The canonical demo seed uses local fixtures so the demo is deterministic and repeatable. A real end-to-end run on actual repo code and a real container image produced genuine findings, including a real self-scan hit in the project's own code.

**Q: What is the CBOM format?**
A: CycloneDX 1.6 with cryptographic asset properties, plus PDF board brief export.

**Q: What makes the container scan different from running Trivy alone?**
A: Trivy gives packages and versions. The platform adds a quantum-readiness mapping layer so package/version results are interpreted in PQC terms.

**Q: What does the binary scanner actually detect?**
A: Byte-level cryptographic constants and symbols, including ML-KEM NTT tables, AES S-box, MD5 and SHA-1 initial constants, DES S-box, and liboqs-style interface strings.

**Q: What is the limitation of the binary scanner?**
A: It is signature-based. It can detect known constants and symbols, but it is not a full decompiler or a formal cryptographic audit.

**Q: How should we interpret the HNDL numbers?**
A: As a modeled exposure ceiling based on tier baselines, not as measured captured traffic. The UI labels this explicitly.

### Making the answer stronger in a demo
If a judge asks "is this real?", the strongest answer is:
- Show the scanner engines and their outputs.
- Show the CBOM export.
- Show the divergence concept.
- Be explicit about what is measured and what is modeled.
- Avoid overclaiming. The honesty is part of the credibility.

---

## 12. Short judge-ready pitch

Q-Guardian is a post-quantum cryptography risk platform that discovers cryptographic assets across four independent sources — live TLS, source code, container images, and compiled binaries — reconciles them to expose declared-vs-actual divergence, scores each asset with a real Mosca countdown and a tiered Q-TRI, models HNDL exposure with clear grounding, maps findings to RBI CSF 2.0, NIST IR 8547, and India DST/TEC, recommends PQC migration paths, and exports a CycloneDX 1.6 CBOM plus a board-brief PDF.

---

## 13. Things to be ready to say honestly

- The demo seed is deterministic by design; the engines are real.
- HNDL is modeled, not measured.
- Binary scanning is signature-based, not a full reverse-engineering audit.
- Compliance mapping is assessment and evidence, not certification.
- If a scanner dependency is missing, the platform degrades rather than failing silently.
- If asked about scope, distinguish "discovered and scored" from "every possible enterprise artefact," especially for HSMs and cloud KMS, which are not the current scanning focus.
