"""
Extract the original sender and content from a forwarded email.

When a user forwards an email to Is This Real?, the Graph API message shows:
  - from: the forwarder (our user / grandma)
  - body: contains the original email embedded in quoted text
  - subject: usually "FW: <original subject>" or "Fwd: <original subject>"

This module extracts the original sender, subject, and body from the
forwarded content so the analyzer can check the ACTUAL suspicious email,
not grandma's forwarding wrapper.

Supports forwarding formats from:
  - Outlook / Microsoft 365 ("From: ... Sent: ... To: ... Subject: ...")
  - Gmail ("---------- Forwarded message ----------")
  - Apple Mail ("Begin forwarded message:")
  - Yahoo Mail ("--- Forwarded Message ---" or "----- Forwarded Message -----")
  - Generic (fallback "From:" line detection)
"""
import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ForwardedContent:
    """Extracted content from a forwarded email."""
    original_sender_address: str = ""
    original_sender_name: str = ""
    original_subject: str = ""
    original_body: str = ""
    is_forwarded: bool = False


# ──────────────────────────────────────────────
# Main extraction function
# ──────────────────────────────────────────────

def extract_forwarded(plain_text: str, subject: str = "") -> ForwardedContent:
    """
    Attempt to extract the original email from forwarded content.

    Tries each known format in order. Returns ForwardedContent with
    is_forwarded=False if no forwarding pattern is detected.
    """
    result = ForwardedContent()

    # Check subject for forwarding prefix
    fw_subject = _strip_fw_prefix(subject)
    if fw_subject != subject:
        result.original_subject = fw_subject
        result.is_forwarded = True

    # Try each forwarding format
    for extractor in [
        _extract_outlook,
        _extract_gmail,
        _extract_apple_mail,
        _extract_yahoo,
        _extract_generic,
    ]:
        extracted = extractor(plain_text)
        if extracted:
            result.is_forwarded = True
            result.original_sender_address = extracted.get("sender_address", "")
            result.original_sender_name = extracted.get("sender_name", "")
            if extracted.get("subject"):
                result.original_subject = extracted["subject"]
            result.original_body = extracted.get("body", "")
            logger.info(
                f"Forwarded email detected (format: {extractor.__name__}), "
                f"original sender: {result.original_sender_address}"
            )
            return result

    # No forwarding pattern found — might be a direct email to Is This Real?
    if not result.is_forwarded:
        logger.debug("No forwarding pattern detected, treating as direct email")

    return result


# ──────────────────────────────────────────────
# Subject prefix stripping
# ──────────────────────────────────────────────

def _strip_fw_prefix(subject: str) -> str:
    """Strip FW:/Fwd:/FWD: prefix (possibly nested) from subject."""
    return re.sub(r"^(\s*(fw|fwd|fw)\s*:\s*)+", "", subject, flags=re.IGNORECASE).strip()


# ──────────────────────────────────────────────
# Outlook / Microsoft 365
# ──────────────────────────────────────────────
# Format:
#   ________________________________
#   From: John Doe <john@example.com>
#   Sent: Monday, January 1, 2024 10:00 AM
#   To: Jane Doe <jane@example.com>
#   Subject: Your account is suspended
#
#   <original body>

_OUTLOOK_PATTERN = re.compile(
    r"(?:_{3,}|-{3,})\s*\n"                         # separator line
    r"(?:From:\s*(?P<from_line>.+?))\s*\n"           # From:
    r"(?:Sent:\s*.+?\n)"                             # Sent:
    r"(?:To:\s*.+?\n)"                               # To:
    r"(?:(?:Cc:\s*.+?\n)?)?"                         # Cc: (optional)
    r"(?:Subject:\s*(?P<subject>.+?))\s*\n"          # Subject:
    r"\s*\n?"                                        # blank line
    r"(?P<body>[\s\S]*)",                            # rest is body
    re.IGNORECASE,
)


def _extract_outlook(text: str) -> dict | None:
    match = _OUTLOOK_PATTERN.search(text)
    if not match:
        return None
    from_line = match.group("from_line").strip()
    addr, name = _parse_from_line(from_line)
    return {
        "sender_address": addr,
        "sender_name": name,
        "subject": match.group("subject").strip(),
        "body": match.group("body").strip(),
    }


# ──────────────────────────────────────────────
# Gmail
# ──────────────────────────────────────────────
# Format:
#   ---------- Forwarded message ---------
#   From: John Doe <john@example.com>
#   Date: Mon, Jan 1, 2024 at 10:00 AM
#   Subject: Your account is suspended
#   To: <jane@example.com>
#
#   <original body>

_GMAIL_PATTERN = re.compile(
    r"-{5,}\s*Forwarded message\s*-{5,}\s*\n"
    r"(?:From:\s*(?P<from_line>.+?))\s*\n"
    r"(?:Date:\s*.+?\n)"
    r"(?:Subject:\s*(?P<subject>.+?))\s*\n"
    r"(?:To:\s*.+?\n)"
    r"\s*\n?"
    r"(?P<body>[\s\S]*)",
    re.IGNORECASE,
)


def _extract_gmail(text: str) -> dict | None:
    match = _GMAIL_PATTERN.search(text)
    if not match:
        return None
    from_line = match.group("from_line").strip()
    addr, name = _parse_from_line(from_line)
    return {
        "sender_address": addr,
        "sender_name": name,
        "subject": match.group("subject").strip(),
        "body": match.group("body").strip(),
    }


# ──────────────────────────────────────────────
# Apple Mail
# ──────────────────────────────────────────────
# Format:
#   Begin forwarded message:
#
#   From: John Doe <john@example.com>
#   Subject: Your account is suspended
#   Date: January 1, 2024 at 10:00:00 AM EST
#   To: Jane Doe <jane@example.com>
#
#   <original body>

_APPLE_PATTERN = re.compile(
    r"Begin forwarded message:\s*\n\s*\n?"
    r"(?:From:\s*(?P<from_line>.+?))\s*\n"
    r"(?:Subject:\s*(?P<subject>.+?))\s*\n"
    r"(?:Date:\s*.+?\n)"
    r"(?:To:\s*.+?\n)"
    r"(?:(?:Reply-To:\s*.+?\n)?)?"
    r"\s*\n?"
    r"(?P<body>[\s\S]*)",
    re.IGNORECASE,
)


def _extract_apple_mail(text: str) -> dict | None:
    match = _APPLE_PATTERN.search(text)
    if not match:
        return None
    from_line = match.group("from_line").strip()
    addr, name = _parse_from_line(from_line)
    return {
        "sender_address": addr,
        "sender_name": name,
        "subject": match.group("subject").strip(),
        "body": match.group("body").strip(),
    }


# ──────────────────────────────────────────────
# Yahoo Mail
# ──────────────────────────────────────────────
# Format:
#   ----- Forwarded Message -----
#   From: John Doe <john@example.com>
#   To: Jane Doe <jane@example.com>
#   Sent: Monday, January 1, 2024 at 10:00:00 AM EST
#   Subject: Your account is suspended
#
#   <original body>

_YAHOO_PATTERN = re.compile(
    r"-{3,}\s*Forwarded Message\s*-{3,}\s*\n"
    r"(?:From:\s*(?P<from_line>.+?))\s*\n"
    r"(?:To:\s*.+?\n)"
    r"(?:Sent:\s*.+?\n)"
    r"(?:Subject:\s*(?P<subject>.+?))\s*\n"
    r"\s*\n?"
    r"(?P<body>[\s\S]*)",
    re.IGNORECASE,
)


def _extract_yahoo(text: str) -> dict | None:
    match = _YAHOO_PATTERN.search(text)
    if not match:
        return None
    from_line = match.group("from_line").strip()
    addr, name = _parse_from_line(from_line)
    return {
        "sender_address": addr,
        "sender_name": name,
        "subject": match.group("subject").strip(),
        "body": match.group("body").strip(),
    }


# ──────────────────────────────────────────────
# Generic fallback
# ──────────────────────────────────────────────
# Looks for any "From:" line that contains an email address,
# preceded by some kind of separator or forwarding marker.

_GENERIC_PATTERN = re.compile(
    r"(?:[-_=]{3,}|forwarded|original message)\s*\n"
    r"[\s\S]{0,200}?"                               # allow some noise
    r"From:\s*(?P<from_line>.+?)\s*\n"
    r"(?:[\s\S]{0,500}?"                             # look for subject nearby
    r"Subject:\s*(?P<subject>.+?)\s*\n)?"
    r"[\s\S]*?\n\s*\n"                               # skip to blank line
    r"(?P<body>[\s\S]*)",
    re.IGNORECASE,
)


def _extract_generic(text: str) -> dict | None:
    match = _GENERIC_PATTERN.search(text)
    if not match:
        return None
    from_line = match.group("from_line").strip()
    addr, name = _parse_from_line(from_line)
    if not addr:
        return None  # don't match if we can't find an actual email
    return {
        "sender_address": addr,
        "sender_name": name,
        "subject": (match.group("subject") or "").strip(),
        "body": match.group("body").strip(),
    }


# ──────────────────────────────────────────────
# Shared helpers
# ──────────────────────────────────────────────

def _parse_from_line(from_line: str) -> tuple[str, str]:
    """
    Parse a From: line into (email_address, display_name).

    Handles formats like:
      - "John Doe <john@example.com>"
      - "<john@example.com>"
      - "john@example.com"
      - "john@example.com (John Doe)"
    """
    # "Name <email>" or "<email>"
    match = re.match(r"^(.*?)\s*<([^>]+)>", from_line)
    if match:
        name = match.group(1).strip().strip('"').strip("'")
        addr = match.group(2).strip()
        return addr, name

    # "email (Name)"
    match = re.match(r"^(\S+@\S+)\s*\((.+?)\)", from_line)
    if match:
        return match.group(1).strip(), match.group(2).strip()

    # Bare email
    match = re.search(r"[\w.+-]+@[\w.-]+\.\w+", from_line)
    if match:
        return match.group(0), ""

    return "", ""
