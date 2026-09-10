import json
import re
from datetime import datetime
from io import BytesIO
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

try:
    from cyclonedx.model import Property
    from cyclonedx.model.bom import Bom
    from cyclonedx.model.component import Component, ComponentType
    from cyclonedx.model.crypto import CryptoProperties, CryptoAssetType, AlgorithmProperties, CryptoPrimitive
    from cyclonedx.output.json import JsonV1Dot6
    HAS_CYCLONEDX_LIB = True
except ImportError:
    HAS_CYCLONEDX_LIB = False

# Map the engine's primitive strings to the CycloneDX 1.6 crypto primitive enum.
_PRIMITIVE_ENUM = {
    "hash": "HASH",
    "symmetric-cipher": "BLOCK_CIPHER",
    "stream-cipher": "STREAM_CIPHER",
    "public-key-encryption": "PKE",
    "key-agreement": "KEY_AGREE",
    "signature": "SIGNATURE",
    "mac": "MAC",
    "kdf": "KDF",
    "random": "DRBG",
}
# Valid CycloneDX enum tokens for the hand-rolled fallback path.
_PRIMITIVE_TOKEN = {
    "hash": "hash", "symmetric-cipher": "block-cipher", "stream-cipher": "stream-cipher",
    "public-key-encryption": "pke", "key-agreement": "key-agree", "signature": "signature",
    "mac": "mac", "kdf": "kdf", "random": "drbg",
}
_PARAM_NIST_LEVEL = {
    "ML-KEM-512": 1, "ML-KEM-768": 3, "ML-KEM-1024": 5,
    "ML-DSA-44": 2, "ML-DSA-65": 3, "ML-DSA-87": 5,
    "FALCON-512": 1, "FALCON-1024": 5, "SLH-DSA": 2, "SPHINCS+": 2,
}


def _is_kem(algo_upper: str) -> bool:
    return "ML-KEM" in algo_upper or "KYBER" in algo_upper or re.search(r"\bKEM\b", algo_upper) is not None


def _primitive_enum(asset: dict):
    algo = str(asset.get("algorithm", "")).upper()
    if _is_kem(algo):
        return CryptoPrimitive.KEM
    name = _PRIMITIVE_ENUM.get(str(asset.get("primitive", "")).lower())
    if name:
        return getattr(CryptoPrimitive, name, CryptoPrimitive.UNKNOWN)
    # Fall back to keyword sniffing only if the engine gave no primitive.
    if "MD5" in algo or "SHA" in algo:
        return CryptoPrimitive.HASH
    if "AES" in algo or "DES" in algo or "RC4" in algo:
        return CryptoPrimitive.BLOCK_CIPHER
    if "RSA" in algo:
        return CryptoPrimitive.PKE
    if re.search(r"DSA|DILITHIUM|FALCON|SLH-DSA|SPHINCS", algo):
        return CryptoPrimitive.SIGNATURE
    return CryptoPrimitive.UNKNOWN


def _asset_type_enum(asset: dict):
    algo = str(asset.get("algorithm", "")).upper()
    prim = str(asset.get("primitive", "")).lower()
    if prim == "protocol" or "TLS" in algo or "SSL" in algo:
        return CryptoAssetType.PROTOCOL
    if prim == "related-crypto-material" or "CA-CERT" in algo or "CERTIFICATE" in algo or "PRIVATE-KEY" in algo or "PRIVATE KEY" in algo:
        return CryptoAssetType.RELATED_CRYPTO_MATERIAL
    return CryptoAssetType.ALGORITHM


def _nist_level(asset: dict):
    v = asset.get("nist_quantum_security_level")
    if v is not None:
        try:
            return int(v)
        except (TypeError, ValueError):
            pass
    ps = str(asset.get("parameter_set_identifier") or asset.get("algorithm", "")).upper()
    for token, lvl in _PARAM_NIST_LEVEL.items():
        if token in ps:
            return lvl
    return None  # omit rather than fabricate a category


def _component_properties(asset: dict) -> list:
    """Attach per-asset source context as CycloneDX 1.6 custom properties
    so every CBOM component stays traceable to its discovery vector
    (network-tls / static-source / container-image / binary)."""
    props = []
    for key, val in [
        ("sourceType", asset.get("source_type")),
        ("assetType", asset.get("asset_type")),
        ("sensitivityTier", asset.get("sensitivity_tier")),
        ("primitive", asset.get("primitive")),
        ("mode", asset.get("mode")),
        ("classicalSecurityLevel", asset.get("classical_security_level")),
        ("nistQuantumSecurityLevel", asset.get("nist_quantum_security_level")),
        ("qtriScore", asset.get("qtri_score")),
        ("isPqc", asset.get("is_pqc")),
        ("divergenceFlag", asset.get("divergence_flag")),
        ("evidenceFile", asset.get("evidence_file")),
        ("evidenceLine", asset.get("evidence_line")),
        ("evidenceOffset", asset.get("evidence_offset")),
    ]:
        if val is not None and val != "":
            props.append(Property(name=f"qguardian:{key}", value=str(val)))
    return props

class CBOMGenerator:
    @staticmethod
    def generate_cyclonedx_1_6_json(assets: list) -> dict:
        """
        Generates 100% compliant CycloneDX 1.6 CBOM JSON using cyclonedx-python-lib.
        Falls back to structured CycloneDX 1.6 dict if lib is unavailable.
        """
        if HAS_CYCLONEDX_LIB:
            bom = Bom()
            for asset in assets:
                algo_name = asset.get("algorithm", "UNKNOWN")
                hostname = asset.get("hostname", "unnamed_asset")

                asset_type = _asset_type_enum(asset)
                param = asset.get("parameter_set_identifier") or (
                    str(asset["key_size"]) if asset.get("key_size") else None)
                csl = asset.get("classical_security_level")
                try:
                    csl = int(csl) if csl is not None else None
                except (TypeError, ValueError):
                    csl = None

                # algorithmProperties only belongs on assetType=algorithm.
                algo_props = None
                if asset_type == CryptoAssetType.ALGORITHM:
                    algo_props = AlgorithmProperties(
                        primitive=_primitive_enum(asset),
                        parameter_set_identifier=str(param) if param else None,
                        classical_security_level=csl,
                        nist_quantum_security_level=_nist_level(asset),
                    )

                props = _component_properties(asset)
                comp = Component(
                    name=f"{hostname}:{algo_name}",
                    type=ComponentType.CRYPTOGRAPHIC_ASSET,
                    version=str(asset.get("key_size") or ""),
                    properties=props if props else None,
                    crypto_properties=CryptoProperties(
                        asset_type=asset_type,
                        algorithm_properties=algo_props,
                        oid=asset.get("oid") or None,
                    ),
                )
                bom.components.add(comp)
            outputter = JsonV1Dot6(bom)
            return json.loads(outputter.output_as_string())
        else:
            # Native fallback dict — kept schema-valid for environments without
            # cyclonedx-python-lib installed.
            components = []
            for asset in assets:
                prim_token = "unknown"
                if _is_kem(str(asset.get("algorithm", "")).upper()):
                    prim_token = "kem"
                else:
                    prim_token = _PRIMITIVE_TOKEN.get(str(asset.get("primitive", "")).lower(), "unknown")
                param = asset.get("parameter_set_identifier") or (
                    str(asset["key_size"]) if asset.get("key_size") else None)
                algo_props = {"primitive": prim_token}
                if param:
                    algo_props["parameterSetIdentifier"] = str(param)
                nql = _nist_level(asset)
                if nql is not None:
                    algo_props["nistQuantumSecurityLevel"] = nql
                if asset.get("classical_security_level") is not None:
                    try:
                        algo_props["classicalSecurityLevel"] = int(asset["classical_security_level"])
                    except (TypeError, ValueError):
                        pass

                crypto_props = {"assetType": "algorithm", "algorithmProperties": algo_props}
                if asset.get("oid"):
                    crypto_props["oid"] = str(asset["oid"])

                # Build occurrence with only non-null keys (schema requires int/str).
                occ = {"location": asset.get("evidence_file") or asset.get("hostname") or "unknown"}
                if asset.get("evidence_line") is not None:
                    try:
                        occ["line"] = int(asset["evidence_line"])
                    except (TypeError, ValueError):
                        pass
                if asset.get("evidence_function"):
                    occ["symbol"] = str(asset["evidence_function"])

                components.append({
                    "type": "cryptographic-asset",
                    "name": asset.get("hostname", "unnamed_asset"),
                    "version": str(asset.get("key_size") or ""),
                    "cryptoProperties": crypto_props,
                    "evidence": {"occurrences": [occ]},
                })
            return {
                "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "tools": [{"name": "Q-Guardian Enterprise CBOM Engine", "version": "2.0"}],
                },
                "components": components,
            }

    @staticmethod
    def generate_json(assets: list):
        return CBOMGenerator.generate_cyclonedx_1_6_json(assets)

    @staticmethod
    def export_pdf(assets: list):
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), topMargin=30)
        elements = []
        styles = getSampleStyleSheet()
        
        # Enterprise Primary Style
        indigo_primary = colors.Color(79/255, 70/255, 229/255) # Indigo #4F46E5
        
        # Title
        styles.add(ParagraphStyle(name='QGTitle', fontSize=18, textColor=indigo_primary, spaceAfter=10, fontName='Helvetica-Bold'))
        elements.append(Paragraph("Q-GUARDIAN ENTERPRISE | Cryptographic Bill of Materials (CBOM)", styles['QGTitle']))
        elements.append(Paragraph(f"Specification: CycloneDX 1.6 Native Standard", styles['Normal']))
        elements.append(Paragraph(f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Inventory Table
        elements.append(Paragraph("1. Cryptographic Asset Inventory", styles['Heading2']))
        data = [["Asset / Source", "Source Type", "Algorithm", "Key Size", "TLS Version", "PQC Ready"]]
        for asset in assets:
            data.append([
                asset.get("hostname", "N/A"),
                asset.get("source_type", "network_live"),
                asset.get("algorithm", "UNKNOWN"),
                str(asset.get("key_size") or "N/A"),
                asset.get("tls_version", "N/A"),
                "YES (PQC)" if asset.get("is_pqc") else "NO (Legacy)"
            ])
        
        t = Table(data, hAlign='LEFT', colWidths=[180, 100, 100, 70, 70, 80])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), indigo_primary),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        elements.append(t)
        elements.append(Spacer(1, 25))
        
        # Risk Table
        elements.append(Paragraph("2. Risk & Quantum Preparedness Summary", styles['Heading2']))
        risk_data = [["Asset / Hostname", "Sensitivity Tier", "QTRI Score", "Mosca Risk Window", "Policy Status"]]
        for asset in assets:
            mosca = asset.get("mosca", {})
            if isinstance(mosca, str):
                try: mosca = json.loads(mosca)
                except: mosca = {}
                
            risk_data.append([
                asset.get("hostname", "N/A"),
                asset.get("sensitivity_tier", "S3"),
                str(asset.get("qtri_score", 0)),
                mosca.get("risk_state", "SAFE"),
                "COMPLIANT" if asset.get("policy_compliant") else "NON-COMPLIANT"
            ])
            
        rt = Table(risk_data, hAlign='LEFT', colWidths=[180, 100, 80, 110, 110])
        rt.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#06B6D4")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        elements.append(rt)
        
        # Footer
        elements.append(Spacer(1, 40))
        elements.append(Paragraph("Notes: Generated by Q-Guardian v2.0 Enterprise CBOM Platform. Aligned with CycloneDX 1.6 & NIST IR 8547.", styles['Italic']))
        elements.append(Paragraph("RESTRICTED: CRITICAL INFRASTRUCTURE SECURITY AUDIT DOCUMENT", styles['Normal']))
        
        doc.build(elements)
        buffer.seek(0)
        return buffer
