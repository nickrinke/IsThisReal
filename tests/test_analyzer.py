"""Tests for the Is This Real? analysis engine."""
from isthisreal.models import ParsedEmail, RiskLevel
from isthisreal.analyzer import analyze


def _make_email(**kwargs) -> ParsedEmail:
    """Helper to create a ParsedEmail with sensible defaults."""
    defaults = {
        "sender_address": "info@example.com",
        "sender_display_name": "",
        "recipient_address": "user@gmail.com",
        "subject": "Hello",
        "body_plain": "This is a normal email.",
        "body_html": "",
        "raw_headers": "",
        "spf_result": "pass",
        "dkim_result": "pass",
        "dmarc_result": "pass",
        "attachment_count": 0,
        "attachment_types": [],
    }
    defaults.update(kwargs)
    return ParsedEmail(**defaults)


class TestSenderBrandMismatch:
    def test_microsoft_from_wrong_domain(self):
        email = _make_email(
            sender_address="support@mikerosoct.net",
            subject="Your Microsoft Account Needs Attention",
        )
        result = analyze(email)
        assert result.overall_risk == RiskLevel.RED
        assert any("Microsoft" in f.summary for f in result.findings)

    def test_microsoft_from_legit_domain(self):
        email = _make_email(
            sender_address="noreply@microsoft.com",
            subject="Your Microsoft Account Update",
        )
        result = analyze(email)
        brand_findings = [f for f in result.findings if f.category == "sender"]
        assert len(brand_findings) == 0

    def test_paypal_from_wrong_domain(self):
        email = _make_email(
            sender_address="service@paypa1.com",
            body_plain="Your PayPal account has been limited.",
        )
        result = analyze(email)
        assert result.overall_risk == RiskLevel.RED


class TestTyposquat:
    def test_microsft_typo(self):
        email = _make_email(sender_address="info@microsft.com")
        result = analyze(email)
        typo_findings = [
            f for f in result.findings
            if "misspelling" in f.summary.lower() or "typo" in f.summary.lower()
        ]
        assert len(typo_findings) > 0

    def test_amaz0n_typo(self):
        email = _make_email(sender_address="orders@amaz0n.com")
        result = analyze(email)
        assert any(f.category == "sender" for f in result.findings)


class TestAuthChecks:
    def test_spf_fail(self):
        email = _make_email(spf_result="fail")
        result = analyze(email)
        assert any("SPF" in f.summary for f in result.findings)

    def test_dmarc_fail(self):
        email = _make_email(dmarc_result="fail")
        result = analyze(email)
        assert any("DMARC" in f.summary for f in result.findings)

    def test_all_pass(self):
        email = _make_email(spf_result="pass", dkim_result="pass", dmarc_result="pass")
        result = analyze(email)
        auth_findings = [f for f in result.findings if f.category == "auth"]
        assert len(auth_findings) == 0


class TestLinkAnalysis:
    def test_mismatched_link(self):
        email = _make_email(
            body_html='<a href="https://evil-site.com/login">https://microsoft.com/account</a>',
        )
        result = analyze(email)
        assert any(f.category == "link" for f in result.findings)
        assert result.overall_risk == RiskLevel.RED

    def test_ip_address_link(self):
        email = _make_email(
            body_html='<a href="http://192.168.1.1/phish">Click here</a>',
        )
        result = analyze(email)
        assert any("IP address" in f.summary for f in result.findings)

    def test_http_link_flagged(self):
        email = _make_email(
            body_html='<a href="http://example.com/login">Login here</a>',
        )
        result = analyze(email)
        assert any("http://" in f.summary for f in result.findings)
        http_finding = [f for f in result.findings if "http://" in f.summary][0]
        assert http_finding.severity == RiskLevel.RED

    def test_https_link_not_flagged_for_http(self):
        email = _make_email(
            body_html='<a href="https://example.com/login">Login here</a>',
        )
        result = analyze(email)
        http_findings = [f for f in result.findings if "http://" in f.summary]
        assert len(http_findings) == 0


class TestContentAnalysis:
    def test_urgency_language(self):
        email = _make_email(
            body_plain="Your account will be suspended within 24 hours. Click now to verify your identity immediately.",
        )
        result = analyze(email)
        assert any(f.category == "content" for f in result.findings)

    def test_credential_request(self):
        email = _make_email(
            body_plain="Please enter your password to confirm your identity and update your credit card on file.",
        )
        result = analyze(email)
        assert result.overall_risk == RiskLevel.RED
        assert any("sensitive information" in f.summary.lower() for f in result.findings)

    def test_clean_email(self):
        email = _make_email(
            subject="Team lunch Friday",
            body_plain="Hey, want to grab lunch this Friday? Let me know!",
        )
        result = analyze(email)
        assert result.overall_risk == RiskLevel.GREEN


class TestAttachments:
    def test_exe_attachment(self):
        email = _make_email(
            attachment_count=1,
            attachment_types=["application/x-msdownload"],
        )
        result = analyze(email)
        assert any(f.category == "attachment" for f in result.findings)
        assert result.overall_risk == RiskLevel.RED

    def test_safe_attachment(self):
        email = _make_email(
            attachment_count=1,
            attachment_types=["application/pdf"],
        )
        result = analyze(email)
        attachment_findings = [f for f in result.findings if f.category == "attachment"]
        assert len(attachment_findings) == 0
