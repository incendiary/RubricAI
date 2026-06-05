from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field


class BomEntry(BaseModel):
    """A single entry in the Bill of Materials."""

    model_config = ConfigDict(extra="allow")

    name: str
    version: str
    type: str | None = None  # library, service, os, firmware, application, etc.
    vendor: str | None = None
    notes: str | None = None
    last_checked: str | None = None  # ISO timestamp of last CVE scan


class EnvironmentState(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: str = "1"
    version: int = 1
    created_at: str = Field(default_factory=lambda: datetime.now(tz=UTC).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(tz=UTC).isoformat())

    # Known components in this environment
    components: list[dict] = Field(default_factory=list)

    # Bill of Materials — installed software stack for CVE monitoring
    bom: list[BomEntry] = Field(default_factory=list)

    # Network topology — reachability context
    network: dict = Field(default_factory=dict)

    # Standing mitigations that apply across multiple findings
    standing_mitigations: list[dict] = Field(default_factory=list)

    # Free-form context the AI has gathered about this environment
    context_notes: str = ""

    # Append-only log of what each session learned
    session_log: list[dict] = Field(default_factory=list)
