from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AttackerUtilityType = Literal[
    "rce",
    "auth_bypass",
    "priv_esc",
    "data_access",
    "tampering",
    "dos",
    "lateral_movement",
    "other",
]


class Component(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str | None = None
    type: Literal[
        "library", "service", "os", "firmware", "application", "appliance", "unknown"
    ] = "unknown"


class Environment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage: Literal["prod", "non_prod", "unknown"] = "unknown"
    hosting: Literal["on_prem", "cloud", "saas", "hybrid", "unknown"] = "unknown"


class EntryPoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str
    protocol: str | None = None
    port: int | None = Field(None, ge=1, le=65535)
    route: str | None = None


class Preconditions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auth_required: bool = False
    user_interaction: bool = False
    privileges_required: Literal["none", "low", "high", "unknown"] = "unknown"
    attack_complexity: Literal["low", "high", "unknown"] = "unknown"


class DataImpact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sensitive_access: bool = False
    notes: str | None = None


class Mitigation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal[
        "waf_rule",
        "acl_segmentation",
        "disable_feature",
        "vendor_workaround",
        "virtual_patching",
        "increased_monitoring",
        "rate_limiting",
        "other",
    ]
    description: str
    evidence: list[str] = Field(default_factory=list)
    causal_claim: str | None = None


class EvidencePointer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal[
        "ticket",
        "change",
        "screenshot",
        "config_excerpt",
        "log_excerpt",
        "document",
        "link",
        "other",
    ]
    ref: str
    notes: str | None = None


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    cve_or_id: str
    title: str | None = None
    component: Component
    environment: Environment | None = None
    entry_point: EntryPoint
    reachability: Literal[
        "internet_exposed", "constrained_external", "internal", "local_only"
    ]
    preconditions: Preconditions | None = None
    attacker_utility: list[AttackerUtilityType] = Field(min_length=1)
    data_impact: DataImpact | None = None
    mitigations: list[Mitigation] = Field(default_factory=list)
    evidence_pointers: list[EvidencePointer] = Field(default_factory=list)
