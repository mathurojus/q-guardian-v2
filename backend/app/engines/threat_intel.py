import requests
import xml.etree.ElementTree as ET
from datetime import datetime

# URLs for major quantum computing and cybersecurity feeds (all free, no key).
FEEDS = {
    "IBM Quantum": "https://www.ibm.com/blogs/research/category/quantum-computing/feed/",
    "NIST news": "https://www.nist.gov/news-events/news/rss.xml",
    "Google AI": "https://blog.google/technology/ai/rss/",
    "CSO Online": "https://www.csoonline.com/category/cybersecurity/feed/"
}

# A descriptive User-Agent avoids default-python-requests UA blocks.
HEADERS = {"User-Agent": "Q-Guardian-ThreatIntel/2.0 (+quantum-risk-research)"}

# Shown (clearly labeled) when every feed is unreachable, so an air-gapped demo
# is not blank. These are static examples, marked sample=True.
FALLBACK_INTEL = [
    {"source": "NIST (sample)", "title": "NIST finalizes FIPS 203/204/205 post-quantum standards",
     "date": "Reference", "relevance": "Standards update", "sample": True},
    {"source": "GRI (sample)", "title": "Quantum Threat Timeline: expert CRQC estimates trend earlier",
     "date": "Reference", "relevance": "Quantum-related", "sample": True},
    {"source": "Advisory (sample)", "title": "Harvest-Now-Decrypt-Later: record-now risk for long-lived data",
     "date": "Reference", "relevance": "Quantum-related", "sample": True},
]


def _relevance(title_text: str) -> str:
    """Classify a headline's RELEVANCE to PQC (a tag, not an asserted action)."""
    t = title_text.lower()
    if "quantum" in t or "pqc" in t or "post-quantum" in t:
        return "Quantum-related"
    if "vulnerability" in t or "breach" in t or "cve" in t or "exploit" in t:
        return "Vulnerability disclosure"
    if "standard" in t or "nist" in t or "fips" in t:
        return "Standards update"
    return "General security"


def parse_rss_feed(source_name, content, items_limit=2):
    items = []
    try:
        root = ET.fromstring(content)
        for item in root.findall(".//item")[:items_limit]:
            title = item.find("title")
            pub_date = item.find("pubDate")
            title_text = title.text if title is not None else "Unknown Update"
            date_text = pub_date.text if pub_date is not None else datetime.now().strftime("%a, %d %b %Y")
            items.append({
                "source": source_name,
                "title": title_text,
                "date": date_text[:16],
                "relevance": _relevance(title_text),
                "sample": False,
            })
    except Exception as e:
        print(f"Error parsing feed {source_name}: {e}")
    return items


# In-memory cache to avoid rate limiting
intel_cache = []
last_fetched = None


def fetch_threat_intel(force_refresh=False):
    global intel_cache, last_fetched

    # Refresh cache every 6 hours
    if not force_refresh and intel_cache and last_fetched:
        if (datetime.now() - last_fetched).total_seconds() < 21600:
            return intel_cache

    fresh_intel = []
    for source, url in FEEDS.items():
        try:
            r = requests.get(url, timeout=5, headers=HEADERS)
            if r.status_code == 200:
                fresh_intel.extend(parse_rss_feed(source, r.text))
        except Exception as e:
            print(f"Failed fetching from {source}: {e}")

    if fresh_intel:
        intel_cache = fresh_intel[:6]
        last_fetched = datetime.now()
        return intel_cache

    # Nothing fetched and nothing cached (offline/air-gapped): return labeled samples.
    return intel_cache or FALLBACK_INTEL
