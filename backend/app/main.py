from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from typing import List, Optional
import os
import re
import uuid
import json
from datetime import datetime, timedelta
from sqlmodel import Session, select

# Import DB
from app.database import engine, create_db_and_tables, get_session, DBScanJob, DBAsset, DBCBOMHistory
try:
    from app.database import DBAuditLog
except Exception:  # pragma: no cover - table may be absent on older schemas
    DBAuditLog = None
from app.settings import FRONTEND_ORIGINS, FRONTEND_ORIGIN_REGEX
from app.net_guard import resolve_scan_path, TargetNotAllowed
from app.auth import (
    LoginRequest, TokenResponse,
    authenticate_user, create_access_token, verify_token,
    validate_auth_configuration,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

# Import Engines
from app.engines.static_analysis import scan_file_static, scan_directory_static
from app.engines.container_scanner import scan_container
from app.engines.binary_scanner import scan_binary
from app.engines.sample_binary import generate_sample_crypto_binary
from app.engines.source_scanner import scan_semgrep
from app.engines.reconciler import reconcile_assets
from app.engines.discovery import run_discovery, scan_asset
from app.engines.mosca import calculate_mosca_clocks, derive_migration_complexity
from app.engines.scoring import calculate_qtri_score, calculate_cyber_rating
from app.engines.hndl import calculate_hndl_exposure
from app.engines.cbom import CBOMGenerator
from app.engines.migration import get_migration_playbook, generate_strategy_stub
from app.engines.reporting import generate_board_brief_pdf
from app.engines.compliance import map_to_rbi_controls, map_to_all_frameworks
from app.engines.port_scanner import run_port_scan
from app.engines.api_scanner import run_api_scan
from app.engines.managed_crypto import (
    ingest_kms_inventory,
    ingest_hsm_inventory,
    get_sample_kms_fixtures,
    get_sample_hsm_fixtures
)
import logging
logger = logging.getLogger("qguardian")

from fastapi.responses import StreamingResponse
import io

app = FastAPI(title="Q-Guardian API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_origin_regex=FRONTEND_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    validate_auth_configuration()
    create_db_and_tables()

class ScanRequest(BaseModel):
    domain: str
    harvest_start: Optional[str] = "2023-01-01"

class ApiScanRequest(BaseModel):
    url: str

@app.get("/")
async def root():
    return {"message": "Q-Guardian Quantum Transition Intelligence Platform API"}

# ─── Auth Endpoint (Public) ────────────────────────────────────────────────────
@app.post("/api/v1/auth/login", response_model=TokenResponse, tags=["Auth"])
async def login(req: LoginRequest):
    try:
        user = authenticate_user(req.username, req.password)
        logger.debug("authenticate_user returned: %s", user)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid username or password.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token = create_access_token(
            data={"sub": user["username"], "role": user["role"]},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        _audit(user["username"], "login", "auth")
        return TokenResponse(
            access_token=token,
            token_type="bearer",
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            username=user["username"]
        )
    except Exception as exc:
        logger.exception("login failed")
        raise HTTPException(status_code=500, detail=f"Login failed: {exc}")

def update_job_progress(job_uuid: str, progress: int, step: str, status: Optional[str] = None, session: Optional[Session] = None):
    # If no session provided, create one
    if session is None:
        with Session(engine) as new_session:
            _perform_update(new_session, job_uuid, progress, step, status)
    else:
        _perform_update(session, job_uuid, progress, step, status)

def _perform_update(session: Session, job_uuid: str, progress: int, step: str, status: Optional[str] = None):
    statement = select(DBScanJob).where(DBScanJob.job_uuid == job_uuid)
    job = session.exec(statement).first()
    if job:
        job.progress = progress
        job.current_step = step
        if status:
            job.status = status
        if status == "COMPLETED":
            job.completed_at = datetime.now().isoformat()
        session.add(job)
        session.commit()

_OID_MAP = {
    "RSA": "1.2.840.113549.1.1.1",
    "ECDSA": "1.2.840.10045.2.1",
    "EC": "1.2.840.10045.2.1",
    "X25519": "1.3.101.110",
    "ML-KEM-768": "2.16.840.1.101.3.4.4.2",
    "ML-DSA-65": "2.16.840.1.101.3.4.3.18",
}


def _derive_crypto_fields(algorithm: str, key_size, is_pqc: bool) -> dict:
    """Derive CBOM crypto metadata (primitive/classical level/oid) from a network
    asset's algorithm + key size, instead of leaving misleading schema defaults."""
    algo = (algorithm or "").upper()
    try:
        ks = int(key_size or 0)
    except (TypeError, ValueError):
        ks = 0
    primitive, classical, oid = "unknown", None, None
    if "RSA" in algo:
        primitive = "public-key-encryption"
        classical = 80 if ks and ks < 2048 else (112 if ks <= 2048 else (128 if ks <= 3072 else 152))
        oid = _OID_MAP["RSA"]
    elif "ECDSA" in algo or algo.startswith("EC-") or "ECDH" in algo:
        primitive = "signature" if "ECDSA" in algo else "key-agreement"
        classical = 128
        oid = _OID_MAP["ECDSA"]
    elif "X25519" in algo:
        primitive = "key-agreement"; classical = 128; oid = _OID_MAP["X25519"]
    elif "ML-KEM" in algo or "KYBER" in algo:
        primitive = "key-agreement"; classical = 192; oid = _OID_MAP.get("ML-KEM-768")
    elif "ML-DSA" in algo or "DILITHIUM" in algo:
        primitive = "signature"; classical = 192; oid = _OID_MAP.get("ML-DSA-65")
    nql = 3 if is_pqc else 0
    return {"primitive": primitive, "classical_security_level": classical,
            "nist_quantum_security_level": nql, "oid": oid}


def _audit(username: str, action: str, target: str = ""):
    """Best-effort audit-trail write (never breaks the request path)."""
    if DBAuditLog is None:
        return
    try:
        with Session(engine) as s:
            s.add(DBAuditLog(timestamp=datetime.now().isoformat(),
                             username=username or "unknown", action=action, target=target[:400]))
            s.commit()
    except Exception as e:
        print(f"[audit] write failed: {e}")


def process_scan_background(job_uuid: str, domain: str, harvest_start: str = "2023-01-01"):
    try:
        update_job_progress(job_uuid, 5, "Initializing engines...", "SCANNING")
        
        # Discovery Phase
        update_job_progress(job_uuid, 10, f"Running subdomain discovery for {domain}...")
        results = run_discovery(domain)
        
        total_assets = len(results)
        update_job_progress(job_uuid, 30, f"Discovered {total_assets} assets. Starting deep scan...")
        
        for idx, asset in enumerate(results):
            # We open a fresh session for each asset to avoid long-held locks
            with Session(engine) as session:
                # Port Scanning Phase
                progress_base = 30 + (idx / total_assets * 40)
                update_job_progress(job_uuid, int(progress_base), f"Scanning {asset['hostname']} ports...", session=session)
                
                port_result = run_port_scan(asset["hostname"])
                asset["open_ports"] = port_result.get("open_ports", [])
                
                # Analytics Phase
                update_job_progress(job_uuid, int(progress_base + 5), f"Calculating Q-TRI and Mosca metrics for {asset['hostname']}...", session=session)
                qtri = calculate_qtri_score(asset)
                mosca = calculate_mosca_clocks(
                    derive_migration_complexity(asset), asset["sensitivity_tier"],
                    is_pqc=asset.get("is_pqc", False))
                hndl = calculate_hndl_exposure(asset, harvest_start)
                crypto = _derive_crypto_fields(asset["algorithm"], asset["key_size"], asset.get("is_pqc", False))

                db_asset = DBAsset(
                    asset_uuid=str(uuid.uuid4()),
                    job_uuid=job_uuid,
                    hostname=asset["hostname"],
                    tls_version=asset["tls_version"],
                    algorithm=asset["algorithm"],
                    key_size=asset["key_size"],
                    cipher_suite=asset["cipher_suite"],
                    forward_secrecy=asset["forward_secrecy"],
                    cert_valid=asset["cert_valid"],
                    cert_expiry=asset["cert_expiry"],
                    sensitivity_tier=asset["sensitivity_tier"],
                    is_pqc=asset["is_pqc"],
                    policy_compliant=asset["policy_compliant"],
                    qtri_score=qtri,
                    source_type=asset.get("source_type", "network_live"),
                    primitive=crypto["primitive"],
                    classical_security_level=crypto["classical_security_level"] or 0,
                    nist_quantum_security_level=crypto["nist_quantum_security_level"],
                    oid=crypto["oid"],
                    mosca_data=json.dumps(mosca),
                    hndl_data=json.dumps(hndl) if hndl else None,
                    open_ports_data=json.dumps(asset.get("open_ports", [])),
                    discovered_endpoints_data=json.dumps(asset.get("discovered_endpoints", [])),
                    last_scanned=datetime.now().isoformat()
                )
                session.add(db_asset)
                session.commit() # Commit each asset to ensure visibility during polling
                
        update_job_progress(job_uuid, 90, "Finalizing report and compliance mapping...")
        update_job_progress(job_uuid, 100, "Scan Complete", "COMPLETED")
    except Exception as e:
        # Log the detail server-side; return only a generic message to clients.
        print(f"SCAN ERROR for {domain}: {str(e)}")
        import traceback
        traceback.print_exc()
        update_job_progress(job_uuid, 0, "Scan failed (see server logs).", "FAILED")

@app.post("/api/v1/scan/trigger", tags=["Scan"])
async def trigger_scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    job_uuid = str(uuid.uuid4())
    job = DBScanJob(job_uuid=job_uuid, domain=req.domain, status="SCANNING")
    session.add(job)
    session.commit()
    
    background_tasks.add_task(process_scan_background, job_uuid, req.domain, req.harvest_start)
    _audit(current_user.get("username", "unknown"), "scan_trigger", req.domain)

    return {"status": "success", "job_id": job_uuid}

# API Scanner is intentionally public — used by external security teams
# UPDATE Phase 6: Now protected.
@app.post("/api/v1/scan/api", tags=["Scan"])
async def scan_api(
    req: ApiScanRequest,
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    result = run_api_scan(req.url)
    return {"status": "success", "result": result}

@app.get("/api/v1/scan/{job_id}/status", tags=["Scan"])
async def get_scan_status(
    job_id: str,
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    job = session.exec(select(DBScanJob).where(DBScanJob.job_uuid == job_id)).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "job_id": job.job_uuid, 
        "status": job.status, 
        "domain": job.domain,
        "progress": job.progress,
        "current_step": job.current_step
    }

# ── Internal helper (no auth dependency — safe for server-side calls) ────────
def _serialize_assets(session: Session) -> list:
    """Serialize all DBAsset rows to the dict format expected by the frontend."""
    assets = session.exec(select(DBAsset)).all()
    result = []
    for a in assets:
        adict = a.dict()
        adict["id"] = a.asset_uuid
        adict["mosca"] = json.loads(a.mosca_data)
        adict["hndl"] = json.loads(a.hndl_data) if a.hndl_data else None
        adict["open_ports"] = json.loads(a.open_ports_data) if getattr(a, "open_ports_data", None) else []
        result.append(adict)
    return result

@app.get("/api/v1/assets", tags=["Assets"])
async def list_assets(
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    return _serialize_assets(session)

@app.delete("/api/v1/assets/by-job/{job_uuid}", tags=["Assets"])
async def delete_assets_by_job(
    job_uuid: str,
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    """Remove every asset produced by one scan run (one scanned target) from
    the inventory, along with its scan-job row and CBOM history snapshot."""
    assets = session.exec(select(DBAsset).where(DBAsset.job_uuid == job_uuid)).all()
    if not assets:
        raise HTTPException(status_code=404, detail="No assets found for that job.")

    deleted = len(assets)
    for a in assets:
        session.delete(a)

    job = session.exec(select(DBScanJob).where(DBScanJob.job_uuid == job_uuid)).first()
    if job:
        session.delete(job)

    history = session.exec(select(DBCBOMHistory).where(DBCBOMHistory.scan_uuid == job_uuid)).all()
    for h in history:
        session.delete(h)

    session.commit()
    _audit(current_user.get("username", "unknown"), "delete_target", job_uuid)
    return {"status": "completed", "job_uuid": job_uuid, "deleted_assets": deleted}

@app.delete("/api/v1/assets", tags=["Assets"])
async def delete_all_assets(
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    """Wipe the entire asset inventory, all scan jobs, and all CBOM history."""
    assets = session.exec(select(DBAsset)).all()
    jobs = session.exec(select(DBScanJob)).all()
    history = session.exec(select(DBCBOMHistory)).all()
    for row in (*assets, *jobs, *history):
        session.delete(row)
    session.commit()
    _audit(current_user.get("username", "unknown"), "delete_all_assets", f"{len(assets)} assets")
    return {"status": "completed", "deleted_assets": len(assets), "deleted_jobs": len(jobs)}

@app.get("/api/v1/enterprise/rating", tags=["Assets"])
async def get_rating(
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    assets = session.exec(select(DBAsset)).all()
    if not assets:
        return {"score": 0, "status": "N/A", "asset_count": 0}
        
    qtri_scores = [a.qtri_score for a in assets]

    def _state(a):
        try:
            return (json.loads(a.mosca_data) or {}).get("risk_state") if a.mosca_data else None
        except Exception:
            return None
    mosca_states = [s for s in (_state(a) for a in assets) if s]
    rating = calculate_cyber_rating(qtri_scores, mosca_states)

    status = "F — Insecure"
    if rating > 700: status = "A — Excellent"
    elif rating > 400: status = "B/C — Good"
    elif rating > 200: status = "D — Needs Work"
    
    return {
        "score": rating,
        "status": status,
        "asset_count": len(assets)
    }

@app.get("/api/v1/migration/{asset_id}/playbook", tags=["Migration"])
async def get_playbook(
    asset_id: str,
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    asset = session.exec(select(DBAsset).where(DBAsset.asset_uuid == asset_id)).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    asset_dict = {
        "hostname": asset.hostname,
        "algorithm": asset.algorithm,
        "tls_version": asset.tls_version,
        "key_size": asset.key_size,
        "source_type": asset.source_type,
        "sensitivity_tier": asset.sensitivity_tier,
        "is_pqc": asset.is_pqc
    }
    playbook = get_migration_playbook(asset_dict)
    # Also attach the pre-rendered strategy stub
    playbook["strategy_stub"] = generate_strategy_stub(asset_dict, playbook)
    return playbook

@app.get("/api/v1/migration/{asset_id}/codegen", tags=["Migration"])
async def get_playbook_codegen(
    asset_id: str,
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    """Downloadable Python Crypto-Agility Strategy-Pattern stub rendered via Jinja2."""
    asset = session.exec(select(DBAsset).where(DBAsset.asset_uuid == asset_id)).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    asset_dict = {
        "hostname": asset.hostname,
        "algorithm": asset.algorithm,
        "tls_version": asset.tls_version,
        "key_size": asset.key_size,
        "source_type": asset.source_type,
        "sensitivity_tier": asset.sensitivity_tier,
        "is_pqc": asset.is_pqc
    }
    playbook = get_migration_playbook(asset_dict)
    code = generate_strategy_stub(asset_dict, playbook)
    clean_host = re.sub(r"[^A-Za-z0-9_]", "_", asset.hostname)
    return {
        "asset_id": asset_id,
        "hostname": asset.hostname,
        "filename": f"crypto_strategy_{clean_host}.py",
        "code": code
    }

@app.get("/api/v1/reports/board-brief", tags=["Reports"])
async def get_board_brief(
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    assets = _serialize_assets(session)
    qtri_scores = [a["qtri_score"] for a in assets]
    mosca_states = [(a.get("mosca") or {}).get("risk_state") for a in assets]
    mosca_states = [s for s in mosca_states if s]
    rating_score = calculate_cyber_rating(qtri_scores, mosca_states) if qtri_scores else 0

    status = "F — Insecure"
    if rating_score > 700: status = "A — Excellent"
    elif rating_score > 400: status = "B/C — Good"
    
    rating = {"score": rating_score, "status": status, "asset_count": len(assets)}
    
    # Get the latest completed scan date
    latest_job = session.exec(
        select(DBScanJob).where(DBScanJob.status == "COMPLETED").order_by(DBScanJob.completed_at.desc())
    ).first()
    scan_date = latest_job.completed_at[:10] if latest_job and latest_job.completed_at else None
    
    pdf_buffer = generate_board_brief_pdf(assets, rating, scan_date=scan_date)
    return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={
        "Content-Disposition": "attachment; filename=Q_Guardian_Board_Brief.pdf"
    })

@app.get("/api/v1/cbom/export/pdf", tags=["Reports"])
async def get_cbom_pdf(
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    assets = _serialize_assets(session)
    if not assets:
        raise HTTPException(status_code=404, detail="No assets found to generate CBOM")
        
    pdf_buffer = CBOMGenerator.export_pdf(assets)
    return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={
        "Content-Disposition": "attachment; filename=Q_Guardian_CBOM.pdf"
    })

@app.get("/api/v1/compliance/rbi", tags=["Compliance"])
async def get_rbi_compliance(
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    assets = _serialize_assets(session)
    return map_to_rbi_controls(assets)

@app.get("/api/v1/compliance/frameworks", tags=["Compliance"])
async def get_compliance_frameworks(
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    """
    Cross-framework regulatory mapping: RBI CSF 2.0, NIST IR 8547 PQC
    transition milestones, and India DST/TEC (National Quantum Mission) flags.
    """
    assets = _serialize_assets(session)
    return map_to_all_frameworks(assets)

class ChatMessage(BaseModel):
    message: str

from app.engines.chatbot import handle_chat_message
from app.engines.threat_intel import fetch_threat_intel

@app.post("/api/v1/chat", tags=["Chat"])
async def chat_with_bot(
    req: ChatMessage,
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    assets = _serialize_assets(session)
    context = {"assets": assets}
    response = handle_chat_message(req.message, context)
    return {"reply": response}

@app.get("/api/v1/threat-intel", tags=["Intel"])
async def get_threat_intel(
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    return fetch_threat_intel()

# ─── Static Source Scanner ────────────────────────────────────────────────────
class SourceScanRequest(BaseModel):
    target_path: str          # Absolute or relative path to a file or directory
    job_label: Optional[str] = None

class SemgrepScanRequest(BaseModel):
    target_path: str
    job_label: Optional[str] = None

class ContainerScanRequest(BaseModel):
    image_or_path: str        # Container image tag, tarball, or Dockerfile path
    job_label: Optional[str] = None

class BinaryScanRequest(BaseModel):
    filepath: str             # Path to ELF/PE/Mach-O binary (or 'SAMPLE' for demo)
    job_label: Optional[str] = None

def _save_discovered_assets_to_db(assets: list, job_uuid: str):
    """Persist multi-source discovered assets into DB using the unified schema."""
    with Session(engine) as session:
        for a in assets:
            # Real Mosca clocks (X+Y>Z) fed from the actual scanner surface:
            # X = migration complexity from algorithm/key-size/primitive,
            # Y = tier shelf-life, Z = CRQC horizon.
            try:
                mosca = calculate_mosca_clocks(
                    derive_migration_complexity(a),
                    a.get("sensitivity_tier", "S3"),
                    is_pqc=a.get("is_pqc", False),
                )
            except Exception:
                mosca = {
                    "risk_state": "CRITICAL" if a.get("qtri_score", 50) < 30
                        else ("WARNING" if a.get("qtri_score", 50) < 60 else "MONITOR")
                }
            db_asset = DBAsset(
                asset_uuid=str(uuid.uuid4()),
                job_uuid=job_uuid,
                hostname=a["hostname"],
                tls_version=a["tls_version"],
                algorithm=a["algorithm"],
                key_size=a["key_size"],
                cipher_suite=a["cipher_suite"],
                forward_secrecy=a["forward_secrecy"],
                cert_valid=a["cert_valid"],
                cert_expiry=a["cert_expiry"],
                sensitivity_tier=a["sensitivity_tier"],
                is_pqc=a["is_pqc"],
                policy_compliant=a["policy_compliant"],
                qtri_score=a["qtri_score"],
                source_type=a.get("source_type", "static_code"),
                asset_type=a.get("asset_type", "library"),
                evidence_file=a.get("evidence_file"),
                evidence_line=a.get("evidence_line"),
                evidence_offset=a.get("evidence_offset"),
                evidence_function=a.get("evidence_function"),
                primitive=a.get("primitive", "unknown"),
                mode=a.get("mode"),
                parameter_set_identifier=a.get("parameter_set_identifier"),
                classical_security_level=a.get("classical_security_level", 0),
                nist_quantum_security_level=a.get("nist_quantum_security_level", 0),
                oid=a.get("oid"),
                divergence_flag=a.get("divergence_flag"),
                mosca_data=json.dumps(mosca),
                hndl_data=json.dumps(a["hndl"]) if a.get("hndl") else None,
                last_scanned=datetime.now().isoformat()
            )
            session.add(db_asset)
        session.commit()

        # Record a CBOM history snapshot for this scan job so the GUI can diff
        # "before vs after" across the two most recent scanner runs.
        try:
            snapshot = [
                {
                    "name": a.get("hostname"),
                    "algorithm": a.get("algorithm"),
                    "source_type": a.get("source_type"),
                    "key_size": a.get("key_size"),
                    "qtri_score": a.get("qtri_score"),
                    "is_pqc": bool(a.get("is_pqc")),
                }
                for a in assets
            ]
            history = DBCBOMHistory(
                scan_uuid=job_uuid,
                total_assets=len(snapshot),
                pqc_assets=sum(1 for s in snapshot if s["is_pqc"]),
                critical_risks=sum(1 for s in snapshot if s.get("qtri_score") is not None and s["qtri_score"] < 30),
                cbom_json_data=json.dumps(snapshot),
            )
            session.add(history)
            session.commit()
        except Exception as e:
            print(f"CBOM history snapshot failed for {job_uuid}: {e}")

_save_static_assets_to_db = _save_discovered_assets_to_db

@app.post("/api/v1/scan/source", tags=["Scan"])
async def scan_source(
    req: SourceScanRequest,
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    """AST-based static source code scanner. Accepts a file or directory path."""
    try:
        target = resolve_scan_path(req.target_path)
    except TargetNotAllowed as e:
        raise HTTPException(status_code=400, detail=str(e))

    if os.path.isdir(target):
        # Offload the (potentially large) directory walk off the event loop.
        assets = await run_in_threadpool(scan_directory_static, target)
    elif os.path.isfile(target):
        assets = await run_in_threadpool(scan_file_static, target)
    else:
        raise HTTPException(status_code=404, detail="Path not found.")

    job_uuid = str(uuid.uuid4())
    await run_in_threadpool(_save_discovered_assets_to_db, assets, job_uuid)
    cbom = CBOMGenerator.generate_json(assets)

    return {
        "status": "completed",
        "job_id": job_uuid,
        "scan_type": "static_source",
        "target": target,
        "assets_found": len(assets),
        "cbom_spec_version": cbom.get("specVersion", "1.6"),
        "findings_summary": [
            {
                "hostname": a["hostname"],
                "algorithm": a["algorithm"],
                "rule_id": a.get("evidence_function", ""),
                "file": a.get("evidence_file"),
                "line": a.get("evidence_line"),
                "qtri_score": a["qtri_score"],
                "recommendation": a.get("recommendation", "")
            }
            for a in assets
        ]
    }

@app.post("/api/v1/scan/semgrep", tags=["Scan"])
async def scan_semgrep_endpoint(
    req: SemgrepScanRequest,
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    """Industrial Semgrep rule scanner based on OWASP crypto ruleset (rules/crypto.yml)."""
    try:
        target = resolve_scan_path(req.target_path)
    except TargetNotAllowed as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not os.path.exists(target):
        raise HTTPException(status_code=404, detail="Path not found.")

    assets = await run_in_threadpool(scan_semgrep, target)
    job_uuid = str(uuid.uuid4())
    await run_in_threadpool(_save_discovered_assets_to_db, assets, job_uuid)
    cbom = CBOMGenerator.generate_json(assets)

    return {
        "status": "completed",
        "job_id": job_uuid,
        "scan_type": "static-source",
        "target": target,
        "assets_found": len(assets),
        "cbom_spec_version": cbom.get("specVersion", "1.6"),
        "findings_summary": [
            {
                "hostname": a["hostname"],
                "algorithm": a["algorithm"],
                "rule_id": a.get("evidence_function", ""),
                "file": a.get("evidence_file"),
                "line": a.get("evidence_line"),
                "qtri_score": a["qtri_score"],
                "recommendation": a.get("recommendation", "")
            }
            for a in assets
        ]
    }

@app.post("/api/v1/scan/container", tags=["Scan"])
async def scan_container_endpoint(
    req: ContainerScanRequest,
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    """Container image scanner using Trivy/Syft, or tag-inference heuristic fallback."""
    target = req.image_or_path.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Image tag or path is required.")

    # If the target is a local path (Dockerfile/tar), confine it; image refs pass through.
    if os.path.exists(target):
        try:
            target = resolve_scan_path(target)
        except TargetNotAllowed as e:
            raise HTTPException(status_code=400, detail=str(e))

    assets = await run_in_threadpool(scan_container, target)
    job_uuid = str(uuid.uuid4())
    await run_in_threadpool(_save_discovered_assets_to_db, assets, job_uuid)
    cbom = CBOMGenerator.generate_json(assets)

    return {
        "status": "completed",
        "job_id": job_uuid,
        "scan_type": "container",
        "target": target,
        "assets_found": len(assets),
        "cbom_spec_version": cbom.get("specVersion", "1.6"),
        "findings_summary": [
            {
                "hostname": a["hostname"],
                "algorithm": a["algorithm"],
                "rule_id": a.get("evidence_function", ""),
                "file": a.get("evidence_file"),
                "qtri_score": a["qtri_score"],
                "recommendation": a.get("recommendation", "")
            }
            for a in assets
        ]
    }

@app.post("/api/v1/scan/binary", tags=["Scan"])
async def scan_binary_endpoint(
    req: BinaryScanRequest,
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    """Deep binary cryptographic scanner with ML-KEM NTT constants and S-Box signature detection."""
    raw = req.filepath.strip()
    if raw.upper() in ["SAMPLE", "DEMO", "MOCK"]:
        target = generate_sample_crypto_binary(os.path.join(os.getcwd(), "sample_pqc_target.bin"))
    else:
        try:
            target = resolve_scan_path(raw)
        except TargetNotAllowed as e:
            raise HTTPException(status_code=400, detail=str(e))
        if not os.path.isfile(target):
            raise HTTPException(status_code=404, detail="Binary file not found.")

    assets = await run_in_threadpool(scan_binary, target)
    job_uuid = str(uuid.uuid4())
    await run_in_threadpool(_save_discovered_assets_to_db, assets, job_uuid)
    cbom = CBOMGenerator.generate_json(assets)

    return {
        "status": "completed",
        "job_id": job_uuid,
        "scan_type": "binary",
        "target": target,
        "assets_found": len(assets),
        "cbom_spec_version": cbom.get("specVersion", "1.6"),
        "findings_summary": [
            {
                "hostname": a["hostname"],
                "algorithm": a["algorithm"],
                "offset": f"0x{a.get('evidence_offset', 0):08X}" if a.get("evidence_offset") is not None else None,
                "evidence": a.get("evidence_function", ""),
                "qtri_score": a["qtri_score"],
                "is_pqc": a["is_pqc"],
                "recommendation": a.get("recommendation", "")
            }
            for a in assets
        ]
    }

class KMSIntakeRequest(BaseModel):
    records: Optional[List[dict]] = None
    use_sample_fixtures: bool = False

class HSMIntakeRequest(BaseModel):
    records: Optional[List[dict]] = None
    use_sample_fixtures: bool = False

@app.get("/api/v1/intake/samples", tags=["Intake"])
async def get_intake_samples(
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    """Retrieve pre-packaged demo fixtures for Cloud KMS and Banking HSM fleet."""
    return {
        "kms": get_sample_kms_fixtures(),
        "hsm": get_sample_hsm_fixtures()
    }

@app.post("/api/v1/intake/kms", tags=["Intake"])
async def intake_kms_endpoint(
    req: KMSIntakeRequest,
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    """Ingest caller-supplied Cloud KMS export records into the unified schema.

    No live cloud SDK is used. Set use_sample_fixtures=true to explicitly load the
    clearly-labeled SAMPLE fixtures; an empty body is a 400, never silent fakes."""
    if req.use_sample_fixtures:
        raw_records, data_source = get_sample_kms_fixtures(), "sample_fixture"
    elif req.records:
        raw_records, data_source = req.records, "user_import"
    else:
        raise HTTPException(status_code=400,
                            detail="Provide 'records' (your KMS export) or set use_sample_fixtures=true.")

    assets = ingest_kms_inventory(raw_records, data_source=data_source)
    job_uuid = str(uuid.uuid4())
    _save_discovered_assets_to_db(assets, job_uuid)
    cbom = CBOMGenerator.generate_json(assets)

    return {
        "status": "completed",
        "job_id": job_uuid,
        "intake_type": "cloud_kms",
        "data_source": data_source,
        "assets_ingested": len(assets),
        "cbom_spec_version": cbom.get("specVersion", "1.6"),
        "findings_summary": [
            {
                "hostname": a["hostname"],
                "algorithm": a["algorithm"],
                "provider": a.get("evidence_file", ""),
                "data_source": a.get("data_source", data_source),
                "qtri_score": a["qtri_score"],
                "is_pqc": a["is_pqc"],
                "policy_compliant": a["policy_compliant"],
                "recommendation": a.get("recommendation", "")
            }
            for a in assets
        ]
    }

@app.post("/api/v1/intake/hsm", tags=["Intake"])
async def intake_hsm_endpoint(
    req: HSMIntakeRequest,
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    """Ingest caller-supplied HSM fleet export records into the unified schema.

    No live HSM connection is made. Set use_sample_fixtures=true to load the
    clearly-labeled SAMPLE fixtures; an empty body is a 400, never silent fakes."""
    if req.use_sample_fixtures:
        raw_records, data_source = get_sample_hsm_fixtures(), "sample_fixture"
    elif req.records:
        raw_records, data_source = req.records, "user_import"
    else:
        raise HTTPException(status_code=400,
                            detail="Provide 'records' (your HSM export) or set use_sample_fixtures=true.")

    assets = ingest_hsm_inventory(raw_records, data_source=data_source)
    job_uuid = str(uuid.uuid4())
    _save_discovered_assets_to_db(assets, job_uuid)
    cbom = CBOMGenerator.generate_json(assets)

    return {
        "status": "completed",
        "job_id": job_uuid,
        "intake_type": "hardware_module",
        "data_source": data_source,
        "assets_ingested": len(assets),
        "cbom_spec_version": cbom.get("specVersion", "1.6"),
        "findings_summary": [
            {
                "hostname": a["hostname"],
                "algorithm": a["algorithm"],
                "make_model": a.get("evidence_file", ""),
                "data_source": a.get("data_source", data_source),
                "qtri_score": a["qtri_score"],
                "is_pqc": a["is_pqc"],
                "risk_state": a.get("mosca", {}).get("risk_state", "CRITICAL"),
                "recommendation": a.get("recommendation", "")
            }
            for a in assets
        ]
    }

@app.post("/api/v1/cbom/reconcile", tags=["Reports"])
async def reconcile_cbom_endpoint(
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    """Reconcile assets across static, binary, container, and network sources to detect divergence."""
    result = reconcile_assets(session)
    return result

@app.get("/api/v1/cbom/history", tags=["Reports"])
async def get_cbom_history(
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    """List the most recent CBOM scan snapshots (for before/after diffs)."""
    rows = session.exec(
        select(DBCBOMHistory).order_by(DBCBOMHistory.id.desc()).limit(10)
    ).all()
    return [
        {
            "scan_uuid": r.scan_uuid,
            "timestamp": r.timestamp,
            "total_assets": r.total_assets,
            "pqc_assets": r.pqc_assets,
            "critical_risks": r.critical_risks,
        }
        for r in rows
    ]

@app.get("/api/v1/cbom/diff", tags=["Reports"])
async def get_cbom_diff(
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    """
    Simple before/after CBOM diff between the two most recent scan snapshots.
    Components are keyed by (hostname, algorithm) so a repeat finding in the
    same location does not count as a change.
    """
    rows = session.exec(
        select(DBCBOMHistory).order_by(DBCBOMHistory.id.desc()).limit(2)
    ).all()
    if len(rows) < 2:
        return {
            "status": "insufficient_history",
            "detail": "Need at least two scan snapshots to build a diff. Run two scans.",
        }

    def _inventory(row) -> dict:
        try:
            items = json.loads(row.cbom_json_data)
        except Exception:
            items = []
        return {
            f"{it.get('name')}|{it.get('algorithm')}": it
            for it in items if it.get("name") and it.get("algorithm")
        }

    before, after = rows[1], rows[0]  # id DESC -> latest first
    before_map = _inventory(before)
    after_map = _inventory(after)
    added = [v for k, v in after_map.items() if k not in before_map]
    removed = [v for k, v in before_map.items() if k not in after_map]

    def _source_delta(items):
        delta = {}
        for it in items:
            src = it.get("source_type") or "network_live"
            delta[src] = delta.get(src, 0) + 1
        return delta

    return {
        "status": "completed",
        "before": {"scan_uuid": before.scan_uuid, "timestamp": before.timestamp, "total": before.total_assets},
        "after": {"scan_uuid": after.scan_uuid, "timestamp": after.timestamp, "total": after.total_assets},
        "net_change": len(after_map) - len(before_map),
        "added_count": len(added),
        "removed_count": len(removed),
        "added": sorted(added, key=lambda x: str(x.get("name"))),
        "removed": sorted(removed, key=lambda x: str(x.get("name"))),
        "added_by_source": _source_delta(added),
        "removed_by_source": _source_delta(removed),
    }

@app.get("/api/v1/cbom/divergence", tags=["Reports"])
async def get_divergent_assets(
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    """Fetch all assets flagged with multi-source divergence discrepancies."""
    statement = select(DBAsset).where(DBAsset.divergence_flag != None)
    flagged = session.exec(statement).all()
    return {
        "count": len(flagged),
        "divergent_assets": [
            {
                "asset_uuid": a.asset_uuid,
                "hostname": a.hostname,
                "source_type": a.source_type,
                "divergence_flag": a.divergence_flag,
                "algorithm": a.algorithm,
                "qtri_score": a.qtri_score,
                "last_scanned": a.last_scanned
            }
            for a in flagged
        ]
    }

@app.get("/api/v1/cbom/export/cyclonedx", tags=["Reports"])
async def export_cbom_cyclonedx(
    session: Session = Depends(get_session),
    current_user: dict = Depends(verify_token)  # 🔒 Protected
):
    """Export all discovered assets as a native CycloneDX 1.6 CBOM JSON document."""
    assets = _serialize_assets(session)
    if not assets:
        raise HTTPException(status_code=404, detail="No assets found. Run a scan first.")
    cbom = CBOMGenerator.generate_cyclonedx_1_6_json(assets)
    from fastapi.responses import JSONResponse
    return JSONResponse(content=cbom)

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
