from datetime import date as Date  # noqa: N812 — alias prevents field-name shadowing
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class KevInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    listed: bool
    due_date: Date | None = None
    notes: str | None = None


class EpssInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: float = Field(ge=0, le=1)
    percentile: float = Field(ge=0, le=1)
    date: Date | None = None


class CvssInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base: float = Field(ge=0, le=10)
    vector: str | None = None
    version: Literal["2.0", "3.0", "3.1", "4.0", "unknown"] = "unknown"


class PocInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    available: bool
    confidence: Literal["low", "medium", "high", "unknown"] = "unknown"
    references: list[str] = Field(default_factory=list)


class VendorInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    patch_available: bool | None = None
    advisory_refs: list[str] = Field(default_factory=list)


class IntelResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_or_id: str
    retrieved_at: datetime
    sources: list[str]
    description: str | None = None  # English CVE description from NVD
    kev: KevInfo | None = None
    epss: EpssInfo | None = None
    cvss: CvssInfo | None = None
    poc: PocInfo | None = None
    vendor: VendorInfo | None = None
