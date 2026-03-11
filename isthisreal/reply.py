"""
Builds the verdict reply email (HTML) and sends it via Graph API.
"""
import logging
from .graph import send_reply
from .models import RiskLevel, Verdict

logger = logging.getLogger(__name__)

RISK_DISPLAY = {
    RiskLevel.RED: {"emoji": "\U0001f6d1", "label": "HIGH RISK - LIKELY A SCAM", "color": "#DC2626"},
    RiskLevel.YELLOW: {"emoji": "\u26a0\ufe0f", "label": "CAUTION - SOME WARNING SIGNS", "color": "#D97706"},
    RiskLevel.GREEN: {"emoji": "\u2705", "label": "LOOKS OKAY", "color": "#16A34A"},
}


def send_verdict_reply(to_email: str, original_subject: str, verdict: Verdict) -> bool:
    """Send the verdict back to the user as a reply email via Graph API."""
    display = RISK_DISPLAY[verdict.risk_level]
    html_body = _build_html(verdict, display, original_subject)
    subject = f"Is This Real? Result: {display['label']}"

    return send_reply(
        to_address=to_email,
        subject=subject,
        html_body=html_body,
    )


def _build_html(verdict: Verdict, display: dict, original_subject: str) -> str:
    details_html = ""
    for detail in verdict.details:
        details_html += f"""
        <tr>
            <td style="padding: 8px 0; border-bottom: 1px solid #E5E7EB; font-size: 15px; color: #374151;">
                {detail}
            </td>
        </tr>"""

    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin: 0; padding: 0; background-color: #F3F4F6; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="padding: 24px;">
        <tr>
            <td align="center">
                <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 540px; background: #FFFFFF; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
                    <tr>
                        <td style="background-color: {display['color']}; padding: 24px; text-align: center;">
                            <div style="font-size: 36px; margin-bottom: 8px;">{display['emoji']}</div>
                            <div style="color: #FFFFFF; font-size: 18px; font-weight: 700; letter-spacing: 0.5px;">
                                {display['label']}
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 20px 24px 0;">
                            <div style="font-size: 12px; color: #9CA3AF; text-transform: uppercase; letter-spacing: 0.5px;">Email checked</div>
                            <div style="font-size: 14px; color: #6B7280; margin-top: 4px;">"{original_subject}"</div>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 20px 24px;">
                            <div style="font-size: 16px; color: #111827; line-height: 1.5; font-weight: 500;">
                                {verdict.summary}
                            </div>
                        </td>
                    </tr>
                    {"" if not verdict.details else f'''
                    <tr>
                        <td style="padding: 0 24px;">
                            <div style="font-size: 13px; color: #9CA3AF; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px;">What we found</div>
                            <table width="100%" cellpadding="0" cellspacing="0">
                                {details_html}
                            </table>
                        </td>
                    </tr>
                    '''}
                    <tr>
                        <td style="padding: 20px 24px;">
                            <div style="background-color: #F9FAFB; border-radius: 8px; padding: 16px;">
                                <div style="font-size: 13px; color: #9CA3AF; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px;">What to do</div>
                                <div style="font-size: 15px; color: #111827; font-weight: 500;">{verdict.recommendation}</div>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 16px 24px; text-align: center; border-top: 1px solid #E5E7EB;">
                            <div style="font-size: 12px; color: #9CA3AF;">
                                Is This Real? — Helping you spot scam emails<br>
                                This is an automated analysis and may not catch everything. When in doubt, don't click.
                            </div>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>"""
