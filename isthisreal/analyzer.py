import logging
import re
from urllib.parse import urlparse

import tldextract
from bs4 import BeautifulSoup
from Levenshtein import distance as levenshtein_distance

from .models import AnalysisResult, Finding, LinkFinding, ParsedEmail, RiskLevel

logger = logging.getLogger(__name__)

# Well-known brands and their legitimate domains
KNOWN_BRANDS: dict[str, set[str]] = {
    "microsoft": {"microsoft.com", "office.com", "live.com", "outlook.com", "hotmail.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "amazon": {"amazon.com", "aws.amazon.com"},
    "paypal": {"paypal.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "meta.com", "fb.com"},
    "instagram": {"instagram.com"},
    "bank of america": {"bankofamerica.com"},
    "chase": {"chase.com"},
    "wells fargo": {"wellsfargo.com"},
    "usps": {"usps.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "irs": {"irs.gov"},
    "social security": {"ssa.gov"},
}


# Known legitimate URL shorteners and branded short domains
# These should NOT trigger link mismatch warnings
KNOWN_SHORTENERS = {
    "bit.ly", "bitly.com",
    "t.co",                    # Twitter/X
    "youtu.be",                # YouTube
    "goo.gl",                  # Google
    "ow.ly",                   # Hootsuite
    "buff.ly",                 # Buffer
    "tinyurl.com",
    "is.gd",
    "v.gd",
    "rb.gy",
    "cutt.ly",
    "shorturl.at",
    "lnkd.in",                # LinkedIn
    "amzn.to", "amzn.com",    # Amazon
    "boxd.it",                 # Letterboxd
    "spoti.fi",                # Spotify
    "redd.it",                 # Reddit
    "fb.me",                   # Facebook
    "instagr.am",              # Instagram
    "pin.it",                  # Pinterest
    "snap.as",                 # Snapchat
    "mzl.la",                  # Mozilla
    "aka.ms",                  # Microsoft
    "apple.co",                # Apple
    "open.spotify.com",
    "shor.by",
    "linktr.ee",               # Linktree
    "mailchi.mp",              # Mailchimp
}

# Dangerous attachment MIME types
DANGEROUS_ATTACHMENTS = {
    "application/x-msdownload",          # .exe
    "application/x-msdos-program",
    "application/x-executable",
    "application/vnd.ms-excel.sheet.macroEnabled.12",  # .xlsm
    "application/vnd.ms-word.document.macroEnabled.12",  # .docm
    "application/x-javascript",
    "application/hta",
    "application/x-ms-shortcut",          # .lnk
    "application/x-bat",
    "application/x-vbs",
}

DANGEROUS_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".hta", ".lnk", ".ps1", ".msi"}

# Urgency / threat phrases
URGENCY_PATTERNS = [
    r"your account.{0,30}(suspend|terminat|deactivat|clos|lock|restrict)",
    r"(verify|confirm|update).{0,20}(your|account|identity|information)",
    r"(immediate|urgent|important).{0,20}(action|attention|response|notice)",
    r"within\s+\d+\s+(hour|minute|day)",
    r"(failure to|if you (don.?t|do not)).{0,30}(result|lead|caus)",
    r"unusual.{0,20}(activity|sign.?in|login|transaction)",
    r"(click|act|respond).{0,10}(now|immediately|right away)",
    r"(won|winner|selected|congratulations).{0,20}(prize|reward|gift)",
]

CREDENTIAL_PATTERNS = [
    r"(enter|provide|confirm|verify).{0,20}(password|credential|ssn|social security)",
    r"(credit card|card number|cvv|expir)",
    r"(sign.?in|log.?in).{0,20}(here|below|link|button)",
]


def analyze(email_data: ParsedEmail) -> AnalysisResult:
    """Run all deterministic checks on a parsed email."""
    result = AnalysisResult()

    sender_ext = tldextract.extract(email_data.sender_address.split("@")[-1])
    result.sender_domain = f"{sender_ext.domain}.{sender_ext.suffix}"

    # --- Sender checks ---
    _check_sender_brand_mismatch(email_data, result)
    _check_sender_typosquat(email_data, result)

    # --- Authentication checks ---
    _check_auth(email_data, result)

    # --- Link checks ---
    _check_links(email_data, result)

    # --- Content checks ---
    _check_urgency(email_data, result)
    _check_credential_requests(email_data, result)

    # --- Attachment checks ---
    _check_attachments(email_data, result)

    return result


def _check_sender_brand_mismatch(email_data: ParsedEmail, result: AnalysisResult):
    """Check if sender claims to be a known brand but domain doesn't match."""
    text_to_check = f"{email_data.sender_display_name} {email_data.subject} {email_data.body_plain[:500]}"
    text_lower = text_to_check.lower()

    for brand, legit_domains in KNOWN_BRANDS.items():
        if brand in text_lower:
            result.claimed_brand = brand
            if result.sender_domain not in legit_domains:
                result.findings.append(Finding(
                    category="sender",
                    severity=RiskLevel.RED,
                    summary=f"This email mentions {brand.title()} but comes from '{result.sender_domain}', not an official {brand.title()} domain.",
                ))
                return


def _check_sender_typosquat(email_data: ParsedEmail, result: AnalysisResult):
    """Check if sender domain is suspiciously similar to a known brand domain."""
    for brand, legit_domains in KNOWN_BRANDS.items():
        for legit in legit_domains:
            legit_base = legit.split(".")[0]
            sender_base = result.sender_domain.split(".")[0]

            if sender_base == legit_base:
                continue  # exact match, not a typosquat

            dist = levenshtein_distance(sender_base.lower(), legit_base.lower())
            if 0 < dist <= 2 and len(sender_base) > 3:
                result.findings.append(Finding(
                    category="sender",
                    severity=RiskLevel.RED,
                    summary=f"The sender's domain '{result.sender_domain}' looks like a misspelling of '{legit}' ({brand.title()}). This is a common scam trick.",
                ))
                return


def _check_auth(email_data: ParsedEmail, result: AnalysisResult):
    """Check SPF/DKIM/DMARC results."""
    fail_results = {"fail", "softfail", "none"}

    if email_data.spf_result.lower() in fail_results:
        result.findings.append(Finding(
            category="auth",
            severity=RiskLevel.RED if email_data.spf_result.lower() == "fail" else RiskLevel.YELLOW,
            summary=f"SPF check {email_data.spf_result}: the sending server isn't authorized to send email for this domain.",
        ))

    if email_data.dkim_result.lower() in fail_results:
        result.findings.append(Finding(
            category="auth",
            severity=RiskLevel.YELLOW,
            summary=f"DKIM check {email_data.dkim_result}: the email's digital signature couldn't be verified.",
        ))

    if email_data.dmarc_result.lower() in fail_results:
        result.findings.append(Finding(
            category="auth",
            severity=RiskLevel.RED if email_data.dmarc_result.lower() == "fail" else RiskLevel.YELLOW,
            summary=f"DMARC check {email_data.dmarc_result}: this email doesn't pass the domain's anti-spoofing policy.",
        ))


def _check_links(email_data: ParsedEmail, result: AnalysisResult):
    """Analyze links in the email body."""
    links = _extract_links(email_data.body_html or email_data.body_plain)

    for link in links:
        finding = LinkFinding(
            display_text=link["display"],
            actual_url=link["href"],
            domain=link["domain"],
            suspicious=False,
        )

        # Check: display text looks like a URL but points somewhere else
        display_ext = tldextract.extract(link["display"])
        href_ext = tldextract.extract(link["href"])

        href_full_domain = f"{href_ext.domain}.{href_ext.suffix}" if href_ext.suffix else href_ext.domain

        if display_ext.domain and display_ext.domain != href_ext.domain:
            # Skip known URL shorteners — these legitimately have mismatched display/href
            if href_full_domain not in KNOWN_SHORTENERS:
                finding.suspicious = True
                finding.reason = f"The link says '{link['display'][:60]}' but actually goes to '{link['domain']}'."
                result.findings.append(Finding(
                    category="link",
                    severity=RiskLevel.RED,
                    summary=finding.reason,
                ))

        # Check: link domain is a typosquat of a known brand
        if href_full_domain not in KNOWN_SHORTENERS:
            for brand, legit_domains in KNOWN_BRANDS.items():
                for legit in legit_domains:
                    legit_base = legit.split(".")[0]
                    href_base = href_ext.domain.lower()
                    dist = levenshtein_distance(href_base, legit_base)
                    if 0 < dist <= 2 and href_base != legit_base and len(href_base) > 3:
                        finding.suspicious = True
                        finding.reason = f"Link goes to '{link['domain']}' which looks like a misspelling of '{legit}'."
                        result.findings.append(Finding(
                            category="link",
                            severity=RiskLevel.RED,
                            summary=finding.reason,
                        ))
                        break

        # Check: IP address URLs
        if re.match(r"https?://\d+\.\d+\.\d+\.\d+", link["href"]):
            finding.suspicious = True
            finding.reason = "Link goes to a raw IP address instead of a normal website name."
            result.findings.append(Finding(
                category="link",
                severity=RiskLevel.RED,
                summary=finding.reason,
            ))

        # Check: plain HTTP (not HTTPS)
        if link["href"].startswith("http://"):
            finding.suspicious = True
            finding.reason = "Link uses 'http://' which is not secure. Anything you type on that page (passwords, personal info) can be stolen. Do not click it."
            result.findings.append(Finding(
                category="link",
                severity=RiskLevel.RED,
                summary=finding.reason,
            ))

        result.links_checked.append(finding)


def _extract_links(body: str) -> list[dict]:
    """Extract links with display text and href from HTML or plain text."""
    links = []

    if "<" in body and ">" in body:
        soup = BeautifulSoup(body, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href.startswith(("http://", "https://")):
                continue
            display = a.get_text(strip=True) or href
            parsed = urlparse(href)
            ext = tldextract.extract(href)
            domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else parsed.netloc
            links.append({"display": display, "href": href, "domain": domain})
    else:
        # Plain text: find bare URLs
        for match in re.finditer(r"https?://[^\s<>\"]+", body):
            url = match.group()
            ext = tldextract.extract(url)
            parsed = urlparse(url)
            domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else parsed.netloc
            links.append({"display": url, "href": url, "domain": domain})

    return links


def _check_urgency(email_data: ParsedEmail, result: AnalysisResult):
    """Check for urgency/threat language patterns."""
    text = f"{email_data.subject} {email_data.body_plain}".lower()

    matches = []
    for pattern in URGENCY_PATTERNS:
        if re.search(pattern, text):
            matches.append(pattern)

    if len(matches) >= 2:
        result.findings.append(Finding(
            category="content",
            severity=RiskLevel.RED,
            summary="This email uses multiple pressure tactics (threats, urgency, deadlines) to rush you into acting without thinking.",
        ))
    elif len(matches) == 1:
        result.findings.append(Finding(
            category="content",
            severity=RiskLevel.YELLOW,
            summary="This email uses pressure language (urgency or threats) which is common in scam emails.",
        ))


def _check_credential_requests(email_data: ParsedEmail, result: AnalysisResult):
    """Check for requests for passwords, credit cards, SSN, etc."""
    text = f"{email_data.subject} {email_data.body_plain}".lower()

    for pattern in CREDENTIAL_PATTERNS:
        if re.search(pattern, text):
            result.findings.append(Finding(
                category="content",
                severity=RiskLevel.RED,
                summary="This email asks for sensitive information (passwords, credit card numbers, or personal data). Legitimate companies don't ask for this over email.",
            ))
            return


def _check_attachments(email_data: ParsedEmail, result: AnalysisResult):
    """Flag dangerous attachment types."""
    for mime_type in email_data.attachment_types:
        if mime_type in DANGEROUS_ATTACHMENTS:
            result.findings.append(Finding(
                category="attachment",
                severity=RiskLevel.RED,
                summary=f"This email has a potentially dangerous attachment ({mime_type}). Don't open it.",
            ))
