import re
from datetime import datetime

# Local built-in knowledge base (No external models used)
KNOWLEDGE_BASE = {
    "mosca": "MOSCA (Migration Ownership and Security Cryptographic Assessment) models the timeline until classical encryption is broken by CRQC. It uses the formula X + Y > Z (where X is migration time, Y is data shelf life, Z is time to CRQC).",
    "hndl": "HNDL (Harvest Now, Decrypt Later) refers to adversaries recording encrypted network traffic today, with the intent to decrypt it once fault-tolerant quantum computers become available. Using Perfect Forward Secrecy (PFS) mitigates this risk.",
    "pqc": "PQC (Post-Quantum Cryptography) refers to new cryptographic algorithms like ML-KEM (FIPS 203) and ML-DSA (FIPS 204) designed to be secure against both quantum and classical computers.",
    "rbi": "The RBI Cybersecurity Framework (CSF) mandates strong encryption policies. Using protocols like TLS 1.3 and replacing legacy RSA-1024/RSA-2048 keys with 4096-bit or PQC hybrid algorithms ensures alignment with upcoming RBI directives.",
    "qtri": "QTRI (Quantum Readiness Transition Index) is a proprietary scoring mechanism from 0-100 that evaluates an asset's cryptographic health, including TLS versions, key sizes, and forward secrecy adoption.",
    "tls": "TLS (Transport Layer Security) is the protocol securing web traffic. TLS 1.3 is recommended because it mandates Perfect Forward Secrecy (PFS) and drops support for weak legacy ciphers.",
}

INTENTS = {
    r"\b(what is|explain|define|meaning of)\s*(mosca)\b": "mosca",
    r"\b(what is|explain|define|meaning of)\s*(hndl)\b": "hndl",
    r"\b(what is|explain|define|meaning of)\s*(pqc)\b": "pqc",
    r"\b(what is|explain|define|meaning of)\s*(qtri)\b": "qtri",
    r"\b(rbi|compliance|compliant|regulatory)\b": "rbi",
    r"\b(tls|ssl|https)\b": "tls",
    r"\b(scan status|latest scan|results?|how many assets)\b": "scan_status",
    r"\b(top risks?|critical|vulnerable|worst)\b": "risk_summary",
    r"\b(hello|hi|hey|help)\b": "greeting"
}

class RuleBasedChatbot:
    def __init__(self):
        self.kb = KNOWLEDGE_BASE
        
    def get_intent(self, user_msg: str) -> str:
        text = user_msg.lower()
        for pattern, intent in INTENTS.items():
            if re.search(pattern, text):
                return intent
        return "unknown"
        
    def process_message(self, user_msg: str, scan_context: dict = None) -> str:
        intent = self.get_intent(user_msg)
        
        if intent in self.kb:
            return self.kb[intent]
            
        if intent == "scan_status":
            if not scan_context or not scan_context.get("assets"):
                return "I don't have any recent scan results available. Please trigger a scan first."
            asset_count = len(scan_context["assets"])
            return f"The latest scan discovered {asset_count} cryptographic assets. You can view the full inventory on the Posture Dashboard."
            
        if intent == "risk_summary":
            if not scan_context or not scan_context.get("assets"):
                return "I cannot analyze risks without a recent scan. Trigger a domain scan from the top bar."
            
            critical = [a for a in scan_context["assets"] if a.get("mosca", {}).get("risk_state") == "CRITICAL"]
            if critical:
                hostnames = ", ".join([c["hostname"] for c in critical[:3]])
                return f"I found {len(critical)} critically vulnerable assets. Top risks include: {hostnames}. These assets have an immediate risk window (Z < X + Y) based on MOSCA countdown."
            return "Good news! I did not find any critical assets in the latest scan."
            
        if intent == "greeting":
            return "Hello! I am Q-Guardian's built-in intelligence assistant. I analyze scans locally. You can ask me about MOSCA, HNDL, PQC, RBI compliance, or ask for a summary of the latest scan results."

        # Grounded local RAG fallback: the FAISS index over the knowledge base
        # + live inventory answers open-ended questions with source citations.
        try:
            from app.engines.rag_advisor import get_advisor
            advisor = get_advisor()
            if advisor.available:
                rag = advisor.answer(user_msg, (scan_context or {}).get("assets"))
                if rag:
                    return rag["answer"]
        except Exception:
            pass

        return "I'm a rule-based cybersecurity assistant built specifically for Q-Guardian. I can explain quantum security concepts (MOSCA, HNDL, PQC), discuss RBI compliance, or summarize recent scan data. Could you rephrase your question?"

# Global chatbot instance
bot_instance = RuleBasedChatbot()

def handle_chat_message(message: str, dynamic_context: dict) -> str:
    return bot_instance.process_message(message, dynamic_context)
