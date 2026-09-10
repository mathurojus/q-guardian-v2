import os
from sqlmodel import Field, SQLModel, create_engine, Session, select
from typing import Optional, List
from datetime import datetime
import json

from app.settings import DATABASE_URL

# Try to connect to configured DATABASE_URL; fall back to SQLite if PostgreSQL driver is missing
try:
    if DATABASE_URL.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
    else:
        connect_args = {}
    engine = create_engine(DATABASE_URL, echo=False, connect_args=connect_args)
    # Test connection
    with engine.connect() as conn:
        pass
except Exception as e:
    print(f"[Warning] Database connection to {DATABASE_URL} failed ({e}). Falling back to local SQLite database: sqlite:///./qguardian.db")
    DATABASE_URL = "sqlite:///./qguardian.db"
    connect_args = {"check_same_thread": False}
    engine = create_engine(DATABASE_URL, echo=False, connect_args=connect_args)


class DBScanJob(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    job_uuid: str = Field(index=True)
    domain: str
    status: str = Field(default="PENDING") # PENDING, SCANNING, COMPLETED, FAILED
    progress: int = Field(default=0)
    current_step: str = Field(default="Initializing...")
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    
class DBAsset(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    asset_uuid: str = Field(index=True)
    job_uuid: str = Field(index=True)
    hostname: str
    tls_version: str = Field(default="1.3")
    algorithm: str
    key_size: int = Field(default=2048)
    cipher_suite: str = Field(default="UNKNOWN")
    forward_secrecy: bool = Field(default=True)
    cert_valid: bool = Field(default=True)
    cert_expiry: str = Field(default_factory=lambda: datetime.now().isoformat())
    sensitivity_tier: str = Field(default="S3")
    is_pqc: bool = Field(default=False)
    policy_compliant: bool = Field(default=True)
    qtri_score: int = Field(default=80)
    
    # 🌟 Multi-Source Discovered Asset Fields (v2)
    source_type: str = Field(default="network_live") # static_code, binary, container, cloud_kms, network_live
    asset_type: str = Field(default="service") # service, library, binary, secret, kms_key
    evidence_file: Optional[str] = None
    evidence_line: Optional[int] = None
    evidence_offset: Optional[int] = None
    evidence_function: Optional[str] = None
    
    # CycloneDX 1.6 Cryptographic Asset Properties
    primitive: Optional[str] = "key-agreement" # public-key-encryption, signature, key-agreement, hash, symmetric-cipher
    mode: Optional[str] = None
    parameter_set_identifier: Optional[str] = None
    classical_security_level: Optional[int] = 112
    nist_quantum_security_level: Optional[int] = 0 # 0=vulnerable/broken, 1..5=PQC levels
    oid: Optional[str] = None
    
    # Divergence and Maturity
    divergence_flag: Optional[str] = None # e.g. DIV_STATIC_1.3_VS_LIVE_1.0
    maturity_level: int = Field(default=1) # 1 to 5 Crypto-Agility Maturity Score
    
    # ── Classification & Governance (v2) ──
    business_impact: str = Field(default="Medium")   # High / Medium / Low
    data_lifetime_years: Optional[float] = None      # per-asset Mosca Y override
    provider: Optional[str] = None                   # AWS KMS / Azure Key Vault / HSM vendor
    region: Optional[str] = None
    usage: Optional[str] = None
    is_fixture: bool = Field(default=False)          # TRUE = demo/seed fixture row

    # Mosca data parsed as JSON

    mosca_data: str 
    
    # HNDL data parsed as JSON
    hndl_data: Optional[str] = None
    
    # Open ports JSON data
    open_ports_data: Optional[str] = None

    # Active Discovery: JSON-encoded list of paths
    discovered_endpoints_data: Optional[str] = None
    
    last_scanned: str

class DBAuditLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    username: str = Field(index=True)
    action: str = Field(index=True)
    target: str
    details: Optional[str] = None

class DBCBOMHistory(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    scan_uuid: str = Field(index=True)
    total_assets: int
    pqc_assets: int
    critical_risks: int
    cbom_json_data: str

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)
    
    # Auto-migrate SQLite/Postgres dbasset columns if table already existed from earlier versions
    new_columns = [
        ("source_type", "TEXT DEFAULT 'network_live'"),
        ("asset_type", "TEXT DEFAULT 'service'"),
        ("evidence_file", "TEXT"),
        ("evidence_line", "INTEGER"),
        ("evidence_offset", "INTEGER"),
        ("evidence_function", "TEXT"),
        ("primitive", "TEXT DEFAULT 'key-agreement'"),
        ("mode", "TEXT"),
        ("parameter_set_identifier", "TEXT"),
        ("classical_security_level", "INTEGER DEFAULT 112"),
        ("nist_quantum_security_level", "INTEGER DEFAULT 0"),
        ("oid", "TEXT"),
        ("divergence_flag", "TEXT"),
        ("maturity_level", "INTEGER DEFAULT 1"),
        ("open_ports_data", "TEXT"),
        ("discovered_endpoints_data", "TEXT"),
        ("business_impact", "TEXT DEFAULT 'Medium'"),
        ("data_lifetime_years", "REAL"),
        ("provider", "TEXT"),
        ("region", "TEXT"),
        ("usage", "TEXT"),
        ("is_fixture", "INTEGER DEFAULT 0")
    ]
    from sqlalchemy import text
    with engine.connect() as conn:
        for col_name, col_type in new_columns:
            try:
                conn.execute(text(f"ALTER TABLE dbasset ADD COLUMN {col_name} {col_type}"))
                conn.commit()
            except Exception:
                pass

def get_session():
    with Session(engine) as session:
        yield session
