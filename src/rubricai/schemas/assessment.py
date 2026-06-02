from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RemediationTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    days: int | None = None  # None means "patch train" — no fixed SLA
    basis: str | None = None


class ScoreBreakdown(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intel_escalation: list[str] = Field(default_factory=list)
    reachability: str | None = None
    utility: str | None = None
    mitigation_effect: Literal["none", "partial", "strong", "unknown"] = "unknown"


class Assessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_version: str
    lane: Literal["critical", "high", "medium", "low"]
    target: RemediationTarget
    score_breakdown: ScoreBreakdown | None = None
    rationale: list[str]
    actions: list[str] = Field(default_factory=list)
    evidence_gaps: list[str]
