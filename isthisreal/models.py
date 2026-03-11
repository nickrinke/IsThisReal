from pydantic import BaseModel
from enum import Enum


class RiskLevel(str, Enum):
    RED = "red"
    YELLOW = "yellow"
    GREEN = "green"


class ParsedEmail(BaseModel):
    """Parsed email data ready for analysis.

    When a user forwards an email to Is This Real?, `sender_address` is the
    ORIGINAL sender (extracted from the forwarded body), and
    `forwarder_address` is the user who forwarded it (who gets the reply).
    """
    sender_address: str
    sender_display_name: str = ""
    forwarder_address: str = ""  # the user who forwarded — reply goes here
    recipient_address: str
    subject: str = ""
    body_plain: str = ""
    body_html: str = ""
    raw_headers: str = ""
    spf_result: str = ""
    dkim_result: str = ""
    dmarc_result: str = ""
    attachment_count: int = 0
    attachment_types: list[str] = []


class LinkFinding(BaseModel):
    display_text: str
    actual_url: str
    domain: str
    suspicious: bool
    reason: str = ""


class Finding(BaseModel):
    """A single red/yellow flag found during analysis."""
    category: str  # sender, link, content, attachment, auth
    severity: RiskLevel
    summary: str  # short plain-language explanation


class AnalysisResult(BaseModel):
    """Aggregated results from all deterministic checks."""
    findings: list[Finding] = []
    links_checked: list[LinkFinding] = []
    sender_domain: str = ""
    claimed_brand: str = ""

    @property
    def overall_risk(self) -> RiskLevel:
        if any(f.severity == RiskLevel.RED for f in self.findings):
            return RiskLevel.RED
        if any(f.severity == RiskLevel.YELLOW for f in self.findings):
            return RiskLevel.YELLOW
        return RiskLevel.GREEN


class Verdict(BaseModel):
    """Final verdict sent back to the user."""
    risk_level: RiskLevel
    summary: str  # 1-2 sentence plain-language verdict
    details: list[str]  # bullet points explaining each flag
    recommendation: str  # what to do next
