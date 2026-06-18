"""intel.lookup MCP tool — fetches public intel signals for a list of CVEs."""

import asyncio
from datetime import UTC, datetime
from typing import Any

from ..fetchers import epss as epss_fetcher
from ..fetchers import kev as kev_fetcher
from ..fetchers import nvd as nvd_fetcher
from ..fetchers import poc as poc_fetcher
from ..intel_derive import derive_finding_context
from ..schemas.intel import (
    CvssInfo,
    EpssInfo,
    IntelResult,
    KevInfo,
    PocInfo,
    VendorInfo,
)

_ALL_SOURCES = {"kev", "epss", "cvss", "poc", "vendor"}


async def lookup(cves: list[str], include: list[str] | None = None) -> dict[str, Any]:
    """Fetch intel signals for one or more CVE IDs.

    Args:
        cves: List of CVE identifiers (e.g. ``["CVE-2024-1234"]``).
        include: Subset of signals to fetch. Defaults to all signals.

    Returns:
        ``{"results": [IntelResult, ...]}`` as serialisable dicts.
    """
    sources = set(include) if include else _ALL_SOURCES

    results = await asyncio.gather(
        *[_lookup_one(cve, sources) for cve in cves],
        return_exceptions=False,
    )
    return {
        "results": [
            {
                **r.model_dump(mode="json"),
                "derived_finding_context": derive_finding_context(r),
            }
            for r in results
        ]
    }


async def _lookup_one(cve_id: str, sources: set[str]) -> IntelResult:
    fetches = {}
    if "kev" in sources:
        fetches["kev"] = kev_fetcher.fetch(cve_id)
    if "epss" in sources:
        fetches["epss"] = epss_fetcher.fetch(cve_id)
    if "cvss" in sources or "poc" in sources or "vendor" in sources:
        fetches["nvd"] = nvd_fetcher.fetch(cve_id)

    raw = dict(
        zip(
            fetches.keys(),
            await asyncio.gather(*fetches.values()),
            strict=False,
        )
    )

    kev_raw = raw.get("kev")
    epss_raw = raw.get("epss")
    nvd_record = raw.get("nvd")

    # CVSS (derived from NVD record)
    cvss = None
    if "cvss" in sources and nvd_record:
        cvss_raw = await nvd_fetcher.fetch_cvss(cve_id)
        if cvss_raw:
            cvss = CvssInfo.model_validate(cvss_raw)

    # PoC (uses cached NVD record — no extra HTTP call)
    poc = None
    if "poc" in sources:
        poc_raw = await poc_fetcher.fetch(cve_id)
        poc = PocInfo.model_validate(poc_raw)

    # Vendor (advisory links from NVD references)
    vendor = None
    if "vendor" in sources and nvd_record:
        vendor = _extract_vendor(nvd_record)

    active_sources: list[str] = []
    if kev_raw:
        active_sources.append("CISA_KEV")
    if epss_raw:
        active_sources.append("FIRST_EPSS")
    if nvd_record:
        active_sources.append("NVD")

    # Extract English CVE description from NVD record
    description: str | None = None
    if nvd_record:
        description = next(
            (
                d["value"]
                for d in nvd_record.get("descriptions", [])
                if d.get("lang") == "en"
            ),
            None,
        )

    # Automatable signal (for BOD 26-04) — extracted from Vulnrichment / CVSS vector
    automatable: bool | None = None
    if nvd_record:
        automatable = nvd_fetcher.extract_automatable(nvd_record)

    return IntelResult(
        cve_or_id=cve_id,
        retrieved_at=datetime.now(tz=UTC),
        sources=active_sources or ["none"],
        description=description,
        kev=KevInfo.model_validate(kev_raw) if kev_raw else None,
        epss=EpssInfo.model_validate(epss_raw) if epss_raw else None,
        cvss=cvss,
        poc=poc,
        vendor=vendor,
        automatable=automatable,
    )


def _extract_vendor(nvd_record: dict) -> VendorInfo:
    refs = nvd_record.get("references", [])
    advisory_refs = [
        r["url"]
        for r in refs
        if any(
            tag in r.get("tags", [])
            for tag in ("Vendor Advisory", "Patch", "Mitigation")
        )
    ]
    return VendorInfo(advisory_refs=advisory_refs)
