"""
Microsoft Graph API client for reading and replying to mail.

Reads unread messages from the configured mailbox, and sends
reply emails with the Is This Real? verdict.
"""
import logging
from typing import Any

import requests

from .auth import get_access_token
from .config import get_settings
from .forward import extract_forwarded
from .models import ParsedEmail

logger = logging.getLogger(__name__)


def _headers() -> dict[str, str]:
    token = get_access_token()
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _mailbox_url() -> str:
    settings = get_settings()
    return f"{settings.graph_url}/users/{settings.isthisreal_mailbox}"


# ──────────────────────────────────────────────
# Read mail
# ──────────────────────────────────────────────

def fetch_unread_messages() -> list[dict[str, Any]]:
    """Fetch unread messages from the Is This Real? mailbox."""
    settings = get_settings()
    url = (
        f"{settings.graph_url}/users/{settings.isthisreal_mailbox}"
        f"/mailFolders/inbox/messages"
    )
    params = {
        "$filter": "isRead eq false",
        "$top": settings.max_messages_per_poll,
        "$select": "id,subject,from,sender,body,internetMessageHeaders,hasAttachments",
        "$orderby": "receivedDateTime desc",
    }

    resp = requests.get(url, headers=_headers(), params=params)
    resp.raise_for_status()
    data = resp.json()
    return data.get("value", [])


def get_message_attachments(message_id: str) -> list[dict[str, Any]]:
    """Get attachment metadata for a message."""
    settings = get_settings()
    url = (
        f"{settings.graph_url}/users/{settings.isthisreal_mailbox}"
        f"/messages/{message_id}/attachments"
    )
    params = {"$select": "name,contentType,size"}

    resp = requests.get(url, headers=_headers(), params=params)
    resp.raise_for_status()
    return resp.json().get("value", [])


def mark_as_read(message_id: str) -> None:
    """Mark a message as read so we don't process it again."""
    settings = get_settings()
    url = (
        f"{settings.graph_url}/users/{settings.isthisreal_mailbox}"
        f"/messages/{message_id}"
    )
    resp = requests.patch(url, headers=_headers(), json={"isRead": True})
    resp.raise_for_status()


# ──────────────────────────────────────────────
# Parse Graph message into our model
# ──────────────────────────────────────────────

def parse_graph_message(msg: dict[str, Any]) -> ParsedEmail:
    """Convert a Graph API message object into a ParsedEmail.

    If the message is a forwarded email, extracts the ORIGINAL sender
    and body from the forwarded content. The forwarder (our user) is
    stored in forwarder_address so we know who to reply to.
    """
    # The Graph API 'from' is whoever sent the message to the Is This Real? mailbox
    # — that's the forwarder (our user), not the original suspicious sender.
    envelope_sender = msg.get("from", {}).get("emailAddress", {})
    forwarder_address = envelope_sender.get("address", "")
    forwarder_name = envelope_sender.get("name", "")

    # Body
    body = msg.get("body", {})
    body_content = body.get("content", "")
    body_type = body.get("contentType", "text")

    body_html = body_content if body_type == "html" else ""
    body_plain = body_content if body_type == "text" else ""

    if body_html and not body_plain:
        from bs4 import BeautifulSoup
        body_plain = BeautifulSoup(body_html, "html.parser").get_text(
            separator="\n", strip=True
        )

    subject = msg.get("subject", "")

    # --- Try to extract the original forwarded email ---
    forwarded = extract_forwarded(body_plain, subject)

    if forwarded.is_forwarded and forwarded.original_sender_address:
        # We found the original sender — use their info for analysis
        sender_address = forwarded.original_sender_address
        sender_display = forwarded.original_sender_name
        # Use the original body for analysis if we extracted it
        analysis_body = forwarded.original_body or body_plain
        # Use original subject if extracted, otherwise strip FW: prefix
        analysis_subject = forwarded.original_subject or subject
        logger.info(
            f"Forwarded email: forwarder={forwarder_address}, "
            f"original_sender={sender_address}"
        )
    else:
        # Not a forward (or couldn't extract) — treat the envelope sender
        # as the sender to analyze. This handles the case where someone
        # emails Is This Real? directly (e.g., a test or a non-forwarded query).
        sender_address = forwarder_address
        sender_display = forwarder_name
        analysis_body = body_plain
        analysis_subject = subject
        forwarder_address = forwarder_address  # reply still goes to them

    # Internet message headers (SPF/DKIM/DMARC)
    headers = msg.get("internetMessageHeaders", []) or []
    headers_dict = {h["name"].lower(): h["value"] for h in headers}
    raw_headers = "\n".join(f"{h['name']}: {h['value']}" for h in headers)

    spf, dkim, dmarc = _extract_auth_from_headers(headers_dict)

    # Attachments
    attachment_types = []
    attachment_count = 0
    if msg.get("hasAttachments"):
        try:
            attachments = get_message_attachments(msg["id"])
            attachment_count = len(attachments)
            attachment_types = [a.get("contentType", "unknown") for a in attachments]
        except Exception as e:
            logger.warning(f"Failed to fetch attachments for {msg['id']}: {e}")

    return ParsedEmail(
        sender_address=sender_address,
        sender_display_name=sender_display,
        forwarder_address=forwarder_address,
        recipient_address="",
        subject=analysis_subject,
        body_plain=analysis_body,
        body_html=body_html,
        raw_headers=raw_headers,
        spf_result=spf,
        dkim_result=dkim,
        dmarc_result=dmarc,
        attachment_count=attachment_count,
        attachment_types=attachment_types,
    )


def _extract_auth_from_headers(headers: dict[str, str]) -> tuple[str, str, str]:
    """Extract SPF/DKIM/DMARC from internet message headers."""
    import re

    spf = dkim = dmarc = ""

    auth_results = headers.get("authentication-results", "")

    spf_match = re.search(r"spf=(\w+)", auth_results)
    if spf_match:
        spf = spf_match.group(1)

    dkim_match = re.search(r"dkim=(\w+)", auth_results)
    if dkim_match:
        dkim = dkim_match.group(1)

    dmarc_match = re.search(r"dmarc=(\w+)", auth_results)
    if dmarc_match:
        dmarc = dmarc_match.group(1)

    return spf, dkim, dmarc


# ──────────────────────────────────────────────
# Send reply
# ──────────────────────────────────────────────

def send_reply(to_address: str, subject: str, html_body: str) -> bool:
    """Send an email from the Is This Real? mailbox via Graph API."""
    settings = get_settings()
    url = (
        f"{settings.graph_url}/users/{settings.isthisreal_mailbox}"
        f"/sendMail"
    )

    payload = {
        "message": {
            "subject": subject,
            "body": {
                "contentType": "HTML",
                "content": html_body,
            },
            "toRecipients": [
                {
                    "emailAddress": {"address": to_address}
                }
            ],
        },
        "saveToSentItems": False,
    }

    try:
        resp = requests.post(url, headers=_headers(), json=payload)
        resp.raise_for_status()
        logger.info(f"Reply sent to {to_address}")
        return True
    except requests.HTTPError as e:
        logger.error(f"Failed to send reply to {to_address}: {e} — {e.response.text}")
        return False
