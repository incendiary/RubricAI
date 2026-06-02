"""PoC/exploit availability heuristic derived from NVD references.

Scans NVD reference URLs for known exploit publication domains.
Confidence is based on how many strong-signal domains are matched.
"""

from . import nvd

_HIGH_CONFIDENCE_DOMAINS = {
    "exploit-db.com",
    "packetstormsecurity.com",
}

_MEDIUM_CONFIDENCE_PATTERNS = (
    "github.com",
    "exploit",
    "poc",
    "proof-of-concept",
)


def _classify(refs: list[str]) -> dict:
    high_matches = [r for r in refs if any(d in r for d in _HIGH_CONFIDENCE_DOMAINS)]
    if high_matches:
        return {"available": True, "confidence": "high", "references": high_matches}

    medium_matches = [
        r for r in refs if any(p in r.lower() for p in _MEDIUM_CONFIDENCE_PATTERNS)
    ]
    if medium_matches:
        return {
            "available": True,
            "confidence": "medium",
            "references": medium_matches[:3],
        }

    return {"available": False, "confidence": "unknown", "references": []}


async def fetch(cve_id: str) -> dict:
    """Return PoC availability assessment for *cve_id*."""
    record = await nvd.fetch(cve_id)
    if not record:
        return {"available": False, "confidence": "unknown", "references": []}

    refs = [r.get("url", "") for r in record.get("references", []) if r.get("url")]
    return _classify(refs)
