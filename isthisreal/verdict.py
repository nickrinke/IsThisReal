import logging
import anthropic
from .config import get_settings
from .models import AnalysisResult, Finding, RiskLevel, Verdict

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are Is This Real?, an email safety assistant that helps non-technical people 
understand whether an email is a scam or phishing attempt.

You will receive the results of automated security checks on a forwarded email. 
Your job is to synthesize these findings into a clear, simple verdict.

IMPORTANT: The automated checks sometimes flag legitimate emails by mistake — 
for example, newsletter short links (like youtu.be or boxd.it) may trigger 
domain mismatch warnings. Use your judgment. If the email is clearly legitimate 
(a real newsletter, a real company, normal content), override the automated 
risk level and mark it as green. You are the final word on the risk level.

Rules:
- Write at a 6th-grade reading level. No jargon.
- Be direct and confident. Don't hedge with "possibly" or "might be" — if there are red flags, say so.
- Use short sentences.
- Explain each finding in one plain sentence a grandparent would understand.
- If the automated checks were wrong (false positive), explain why the email is actually safe.
- Give a clear recommendation: delete it, ignore it, or it looks okay.
- Never tell the user to click any links in the original email.
- If the email looks safe, still remind them to be cautious.

Respond in this exact JSON format:
{
  "risk_level": "red" or "yellow" or "green",
  "summary": "1-2 sentence overall verdict",
  "details": ["plain-language explanation of each finding"],
  "recommendation": "what to do next"
}

Respond with ONLY the JSON. No markdown, no backticks, no preamble."""


def _score_findings(analysis: AnalysisResult) -> int:
    """Score findings to decide whether to escalate to Claude.
    RED = 10 points, YELLOW = 5 points."""
    score = 0
    for f in analysis.findings:
        if f.severity == RiskLevel.RED:
            score += 10
        elif f.severity == RiskLevel.YELLOW:
            score += 5
    return score


def synthesize_verdict(analysis: AnalysisResult, subject: str, sender: str) -> Verdict:
    """
    Generate a plain-language verdict from analysis findings.

    Only calls the Claude API when the deterministic checks found something
    worth explaining (score >= ESCALATION_THRESHOLD). Clean emails and
    low-signal emails get a canned response — no API cost.
    """
    score = _score_findings(analysis)
    settings = get_settings()

    # Clean or very low signal — skip the API call entirely
    threshold = settings.escalation_threshold
    if score < threshold:
        logger.info(f"Score {score} below threshold {threshold}, using fallback verdict (no API call)")
        return _fallback_verdict(analysis)

    # Findings worth explaining — escalate to Claude for plain-language synthesis
    logger.info(f"Score {score} >= threshold {threshold}, escalating to Claude API")
    findings_text = _format_findings(analysis, subject, sender)

    try:
        client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=500,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": findings_text}],
        )

        raw = response.content[0].text
        return _parse_response(raw, analysis.overall_risk)

    except Exception as e:
        logger.error(f"Claude API error: {e}")
        return _fallback_verdict(analysis)


def _format_findings(analysis: AnalysisResult, subject: str, sender: str) -> str:
    """Format analysis results into a prompt for Claude."""
    lines = [
        f"Email subject: {subject}",
        f"Sender: {sender}",
        f"Sender domain: {analysis.sender_domain}",
    ]

    if analysis.claimed_brand:
        lines.append(f"Email claims to be from: {analysis.claimed_brand}")

    lines.append(f"\nOverall risk level: {analysis.overall_risk.value.upper()}")
    lines.append(f"Number of findings: {len(analysis.findings)}")

    if analysis.findings:
        lines.append("\nFindings:")
        for i, f in enumerate(analysis.findings, 1):
            lines.append(f"  {i}. [{f.severity.value.upper()}] [{f.category}] {f.summary}")

    suspicious_links = [l for l in analysis.links_checked if l.suspicious]
    if suspicious_links:
        lines.append(f"\nSuspicious links found: {len(suspicious_links)}")
        for link in suspicious_links:
            lines.append(f"  - {link.reason}")

    if not analysis.findings:
        lines.append("\nNo red or yellow flags found. The email appears clean based on automated checks.")

    return "\n".join(lines)


def _parse_response(raw: str, risk_level: RiskLevel) -> Verdict:
    """Parse Claude's JSON response into a Verdict.
    
    Claude can override the deterministic risk level — it's the final word.
    """
    import json

    try:
        cleaned = raw.strip().removeprefix("```json").removesuffix("```").strip()
        data = json.loads(cleaned)

        # Claude can override the risk level
        claude_risk = data.get("risk_level", "").lower()
        if claude_risk in ("red", "yellow", "green"):
            final_risk = RiskLevel(claude_risk)
            if final_risk != risk_level:
                logger.info(f"Claude overrode risk level: {risk_level.value} -> {final_risk.value}")
        else:
            final_risk = risk_level

        return Verdict(
            risk_level=final_risk,
            summary=data.get("summary", "Analysis complete."),
            details=data.get("details", []),
            recommendation=data.get("recommendation", "Be cautious with this email."),
        )
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning(f"Failed to parse Claude response: {e}")
        return Verdict(
            risk_level=risk_level,
            summary=raw[:200],
            details=[],
            recommendation="Be cautious with this email.",
        )


def _fallback_verdict(analysis: AnalysisResult) -> Verdict:
    """Build a basic verdict without Claude if the API call fails."""
    risk = analysis.overall_risk
    details = [f.summary for f in analysis.findings]

    if risk == RiskLevel.RED:
        summary = "This email has serious red flags and is very likely a scam."
        recommendation = "Delete this email. Do not click any links or download any attachments."
    elif risk == RiskLevel.YELLOW:
        summary = "This email has some warning signs. Be careful."
        recommendation = "Don't click any links in this email. If you think it might be real, go directly to the company's website by typing the address yourself."
    else:
        summary = "This email looks okay based on our checks."
        recommendation = "It passed our automated checks, but always be cautious with unexpected emails."

    return Verdict(
        risk_level=risk,
        summary=summary,
        details=details,
        recommendation=recommendation,
    )
