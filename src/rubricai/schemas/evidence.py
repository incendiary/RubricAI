from typing import Literal

from pydantic import BaseModel, ConfigDict


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim: str
    type: Literal[
        "firewall_policy",
        "network_config",
        "acl_rule",
        "waf_config",
        "screenshot",
        "screenshot_description",
        "log_extract",
        "other",
    ]
    content: str | None = None
    analyst_note: str | None = None
    verified: bool = False
    # Absolute path to a stored file (screenshot, config export, etc.)
    file_path: str | None = None
