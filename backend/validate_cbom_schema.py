"""
Checklist item #1: validate Q-Guardian CBOM export against the official
CycloneDX 1.6 JSON schema (https://cyclonedx.org/schema/bom-1.6.schema.json).
"""
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.engines.sample_binary import generate_sample_crypto_binary
from app.engines.binary_scanner import scan_binary
from app.engines.container_scanner import scan_container
from app.engines.source_scanner import scan_semgrep
from app.engines.cbom import CBOMGenerator

SCHEMA_URL = "https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json"
SCHEMA_CACHE = os.path.join(os.path.dirname(__file__), "bom-1.6.schema.json")


def build_sample_assets():
    """Assemble assets from all three scanner families, mirroring a real multi-source run."""
    assets = []
    assets += scan_semgrep(os.path.join(os.path.dirname(__file__), "app", "engines", "sample_target.py"))
    assets += scan_container("nginx:1.24-alpine")
    sample_bin = generate_sample_crypto_binary("schema_check_target.bin")
    try:
        assets += scan_binary(sample_bin)
    finally:
        if os.path.exists(sample_bin):
            os.remove(sample_bin)
    return assets


def main():
    assets = build_sample_assets()
    print(f"Sample assets: {len(assets)} (static-source, container, binary)")

    cbom = CBOMGenerator.generate_cyclonedx_1_6_json(assets)
    print(f"specVersion: {cbom.get('specVersion')}  bomFormat: {cbom.get('bomFormat')}")
    print(f"components: {len(cbom.get('components', []))}")

    schema_path = SCHEMA_CACHE
    if not os.path.exists(schema_path):
        if os.getenv("ALLOW_NETWORK_SCHEMA_FETCH", "").lower() != "true":
            raise SystemExit(
                f"BLOCKED: {schema_path} is missing and network fetch is disabled "
                f"(this check must stay offline/hermetic for CI). Commit the schema file, "
                f"or set ALLOW_NETWORK_SCHEMA_FETCH=true to fetch it once from {SCHEMA_URL}."
            )
        print(f"Fetching official schema from {SCHEMA_URL} ...")
        req = urllib.request.Request(SCHEMA_URL, headers={"User-Agent": "q-guardian-schema-check"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            with open(schema_path, "wb") as f:
                f.write(resp.read())
        print("Schema cached locally.")

    import jsonschema
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    jsonschema.validate(instance=cbom, schema=schema)
    print("\nPASS: CBOM validates cleanly against the official CycloneDX 1.6 JSON schema.")

    # Structural spot-checks the schema enforces via cryptoProperties.
    # assetType legitimately varies (algorithm vs protocol vs related-crypto-material)
    # — only components typed 'algorithm' are required to carry algorithmProperties.
    crypto_comps = [c for c in cbom["components"] if "cryptoProperties" in c]
    print(f"components with cryptoProperties: {len(crypto_comps)}")
    assert crypto_comps, "no cryptoProperties found"
    asset_types = {c["cryptoProperties"]["assetType"] for c in crypto_comps}
    print(f"assetTypes present: {sorted(asset_types)}")
    assert all(
        "algorithmProperties" in c["cryptoProperties"]
        for c in crypto_comps if c["cryptoProperties"]["assetType"] == "algorithm"
    ), "algorithm-typed components missing algorithmProperties"
    print("cryptoProperties structure OK.")


if __name__ == "__main__":
    main()
