"""
Local RAG Advisor for Q-Guardian-v2
====================================
Retrieval-Augmented answering built on LangChain + FAISS that runs FULLY
offline — no external LLM, no API keys, no model downloads (air-gapped
banking constraint). Retrieval uses a deterministic hashing embedder over
the project knowledge base (README, Manual, rule docs, playbook/compliance
corpus) plus the live asset inventory, then composes a grounded answer with
source citations.

Dependencies (optional at import time):
  faiss-cpu, langchain-core, langchain-community, langchain-text-splitters
If they are missing the module degrades to `available = False` and the
rule-based chatbot keeps serving.
"""

import hashlib
import math
import os
import re
from collections import Counter
from typing import Dict, List, Optional

# Static seed corpus — duplicates the built-in KB so the vector index is
# meaningful even before repository docs change.
SEED_FACTS = [
    ("kb", "MOSCA models the timeline until classical encryption is broken by a CRQC using X + Y > Z: X migration complexity, Y data shelf life, Z years until a cryptographically relevant quantum computer. When X + Y > Z the asset risk state is CRITICAL."),
    ("kb", "HNDL (Harvest Now, Decrypt Later) means adversaries record encrypted traffic today to decrypt after fault-tolerant quantum computers arrive. Perfect Forward Secrecy (PFS) mitigates HNDL exposure."),
    ("kb", "PQC (Post-Quantum Cryptography) covers ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205), standardized by NIST in 2024."),
    ("kb", "QTRI (Quantum Transition Resilience Index) scores an asset 0-100. Below 30 is CRITICAL, 30-60 WARNING, above 60 MONITOR/stable."),
    ("kb", "NIST IR 8547 transition milestones: T1 crypto discovery/inventory by Dec 2027, T2 prioritize and start migration 2028, T3 priority migration complete 2030, T4 full enterprise migration 2033."),
    ("kb", "India DST National Quantum Mission (NQM) runs 2023-2031; Indian financial and telecom assets should be quantum-safe before the NQM scale-up window closes. TEC publishes quantum-safe cryptography guidance for telecom-grade infrastructure."),
    ("kb", "RBI CSF 2.0 cryptography controls: Annexure 1 Section 4.2 mandates strong TLS; Section 5.1 mandates strong algorithms and key sizes; Annexure 4 Section 2.3 covers perfect forward secrecy."),
    ("kb", "AES-ECB is an unauthenticated block cipher mode that leaks plaintext patterns; replace with AES-GCM (NIST SP 800-38D) or ChaCha20-Poly1305."),
    ("kb", "MD5 and SHA-1 are legacy hash functions; migrate to SHA-256/SHA-3 (FIPS 180-4 / FIPS 202)."),
    ("kb", "DES/3DES/RC4 are legacy symmetric ciphers; replace with AES-256-GCM."),
    ("kb", "Sub-2048-bit RSA is classically breakable; RSA-2048+ is interim while migrating to ML-KEM-768 hybrid key exchange (X25519MLKEM768)."),
    ("kb", "DSA/ECDSA signatures are Shor-vulnerable; migrate to ML-DSA-65 (FIPS 204) or hybrid ECDSA P-256 + ML-DSA dual signatures."),
    ("kb", "Source scanners tag findings as static-source with evidence file and line; binary scanner (LIEF) tags offsets; container scanner (Trivy/Syft) tags images and packages."),
    ("kb", "Divergence flags mark declared vs actual drift, e.g. DIV_STATIC_TLS1.3_VS_LIVE_1.2 means source declares TLS 1.3 but the live endpoint negotiates legacy TLS."),
]

EMBED_DIM = 512

try:
    from langchain_core.embeddings import Embeddings as _LCEmbeddings
    _EMBEDDINGS_BASE = _LCEmbeddings
except Exception:  # pragma: no cover
    _EMBEDDINGS_BASE = object


class HashingEmbeddings(_EMBEDDINGS_BASE):
    """
    Deterministic, dependency-light embedder: bag of word/bigram counts hashed
    into a fixed-dimension L2-normalized vector. Subclasses
    langchain_core.embeddings.Embeddings so FAISS treats it as a model object.
    """
    def __init__(self, dim: int = EMBED_DIM):
        super().__init__()
        self.dim = dim

    def _vectorize(self, text: str) -> List[float]:
        tokens = re.findall(r"[a-z0-9]+", text.lower())
        grams = list(tokens) + [f"{tokens[i]}_{tokens[i + 1]}" for i in range(len(tokens) - 1)]
        counts = Counter(grams)
        vec = [0.0] * self.dim
        for gram, count in counts.items():
            idx = int(hashlib.md5(gram.encode("utf-8")).hexdigest(), 16) % self.dim
            vec[idx] += math.sqrt(count)
        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 0:
            vec = [v / norm for v in vec]
        return vec

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        return [self._vectorize(t) for t in texts]

    def embed_query(self, text: str) -> List[float]:
        return self._vectorize(text)


class RAGAdvisor:
    def __init__(self, root_dir: Optional[str] = None):
        self.available = False
        self._store = None
        self._static_docs = []
        self._asset_fingerprint = None
        self._reason = ""

        try:
            from langchain_core.documents import Document
            from langchain_text_splitters import RecursiveCharacterTextSplitter
            from langchain_community.vectorstores import FAISS
            self._FAISS = FAISS
            self._Document = Document
        except Exception as exc:  # pragma: no cover - dependency gate
            self._reason = f"langchain unavailable: {exc}"
            return

        root = root_dir or os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        docs = []
        for rel, label in [
            ("README.md", "README.md"),
            ("Manual.md", "Manual.md"),
            ("docsx.txt", "docsx.txt"),
            ("backend/rules/crypto.yml", "rules/crypto.yml"),
        ]:
            path = os.path.join(root, *rel.split("/"))
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        docs.append({"source": label, "text": f.read()})
                except Exception:
                    continue

        for fact in SEED_FACTS:
            docs.append({"source": "q-guardian knowledge base", "text": fact[1]})

        splitter = RecursiveCharacterTextSplitter(chunk_size=900, chunk_overlap=120)
        for doc in docs:
            for chunk in splitter.split_text(doc["text"]):
                self._static_docs.append(self._Document(
                    page_content=chunk,
                    metadata={"source": doc["source"]},
                ))

        try:
            self._store = FAISS.from_documents(self._static_docs, HashingEmbeddings())
            self.available = True
        except Exception as exc:
            self._reason = f"faiss build failed: {exc}"

    # ── asset-aware index refresh ────────────────────────────────────────────
    def _asset_lines(self, assets: List[dict]) -> List[str]:
        lines = []
        for a in assets or []:
            mosca = a.get("mosca") or {}
            if isinstance(mosca, str):
                try:
                    import json
                    mosca = json.loads(mosca)
                except Exception:
                    mosca = {}
            lines.append(
                f"{a.get('hostname')} is a {a.get('source_type')} asset using {a.get('algorithm')} "
                f"({a.get('key_size')} bit, {a.get('primitive')}) TLS {a.get('tls_version')} with "
                f"QTRI {a.get('qtri_score')} and Mosca risk state {mosca.get('risk_state', 'SAFE')}"
                f"{' flagged divergence ' + str(a.get('divergence_flag')) if a.get('divergence_flag') else ''}."
            )
        return lines

    def _refresh_for_assets(self, assets: List[dict]):
        fingerprint = hash(tuple(sorted(self._asset_lines(assets))))
        if fingerprint == self._asset_fingerprint:
            return
        docs = list(self._static_docs)
        for line in self._asset_lines(assets):
            docs.append(self._Document(page_content=line, metadata={"source": "live asset inventory"}))
        try:
            self._store = self._FAISS.from_documents(docs, HashingEmbeddings())
            self._asset_fingerprint = fingerprint
        except Exception:
            pass  # keep the previous store on rebuild failure

    def answer(self, query: str, assets: Optional[List[dict]] = None, k: int = 4) -> Optional[dict]:
        if not self.available or self._store is None:
            return None
        try:
            self._refresh_for_assets(assets or [])
            results = self._store.similarity_search_with_score(query, k=k)
        except Exception:
            return None

        if not results:
            return None

        # Grounding gate: the top passage must actually share query vocabulary,
        # otherwise we refuse rather than answer off-topic noise.
        _STOP = {"the", "a", "an", "and", "or", "for", "with", "what", "how",
                 "does", "do", "is", "are", "we", "our", "about", "which",
                 "give", "from", "of", "to", "in", "it", "on", "that", "when",
                 "use", "using", "used", "asset", "assets", "should", "can"}
        q_tokens = {t for t in re.findall(r"[a-z0-9]{3,}", query.lower()) if t not in _STOP}
        best_doc, best_score = results[0]
        doc_tokens = set(re.findall(r"[a-z0-9]{3,}", best_doc.page_content.lower()))
        overlap = len(q_tokens & doc_tokens)
        if not q_tokens or overlap < 2 or best_score > 1.75:
            return None

        seen = set()
        snippets = []
        for doc, score in results:
            key = (doc.metadata.get("source", ""), doc.page_content[:80])
            if key in seen:
                continue
            seen.add(key)
            text = doc.page_content.strip()
            snippets.append({
                "source": doc.metadata.get("source", "unknown"),
                "score": round(float(score), 3),
                "text": text[:500],
            })

        sources = sorted({s["source"] for s in snippets})
        answer_parts = ["[GROUNDED — LOCAL RAG]", f"Retrieved {len(snippets)} relevant passages from: {', '.join(sources)}."]
        for s in snippets[:k]:
            answer_parts.append(f"• [{s['source']}] {s['text']}")
        answer_parts.append("Answers are grounded in the Q-Guardian knowledge base and current scan inventory (no external LLM).")
        return {"answer": "\n".join(answer_parts), "snippets": snippets, "sources": sources}


_advisor: Optional[RAGAdvisor] = None


def get_advisor() -> RAGAdvisor:
    global _advisor
    if _advisor is None:
        _advisor = RAGAdvisor()
    return _advisor
