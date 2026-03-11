"""Tests for forwarded email extraction."""
from isthisreal.forward import extract_forwarded


class TestOutlookFormat:
    def test_standard_outlook(self):
        text = """Hey, can you check this for me?

________________________________
From: Microsoft Support <support@mikerosoct.net>
Sent: Monday, March 10, 2025 9:15 AM
To: Grandma Jones <grandma@gmail.com>
Subject: Your account has been suspended

Dear Customer,

Your Microsoft account has been suspended due to unusual activity.
Click here to verify your identity immediately.

Thanks,
Microsoft Support Team"""

        result = extract_forwarded(text, "FW: Your account has been suspended")
        assert result.is_forwarded is True
        assert result.original_sender_address == "support@mikerosoct.net"
        assert result.original_sender_name == "Microsoft Support"
        assert result.original_subject == "Your account has been suspended"
        assert "unusual activity" in result.original_body

    def test_outlook_with_dashes(self):
        text = """Check this out

-----Original Message-----
From: PayPal <service@paypa1.com>
Sent: Tuesday, March 11, 2025 2:30 PM
To: User <user@outlook.com>
Subject: Action required on your account

Your PayPal account needs verification."""

        result = extract_forwarded(text)
        assert result.is_forwarded is True
        assert result.original_sender_address == "service@paypa1.com"

    def test_outlook_with_cc(self):
        text = """FYI

________________________________
From: Scammer <scam@evil.com>
Sent: Wednesday, March 12, 2025 8:00 AM
To: Victim <victim@gmail.com>
Cc: Other <other@gmail.com>
Subject: Urgent notice

You have won a prize!"""

        result = extract_forwarded(text)
        assert result.is_forwarded is True
        assert result.original_sender_address == "scam@evil.com"
        assert "won a prize" in result.original_body


class TestGmailFormat:
    def test_standard_gmail(self):
        text = """---------- Forwarded message ---------
From: Amazon Orders <orders@amaz0n-support.com>
Date: Mon, Mar 10, 2025 at 3:45 PM
Subject: Your order has been cancelled
To: <user@gmail.com>

Your recent order #12345 has been cancelled.
Click below to dispute this cancellation."""

        result = extract_forwarded(text)
        assert result.is_forwarded is True
        assert result.original_sender_address == "orders@amaz0n-support.com"
        assert result.original_sender_name == "Amazon Orders"
        assert result.original_subject == "Your order has been cancelled"
        assert "dispute" in result.original_body


class TestAppleMailFormat:
    def test_standard_apple_mail(self):
        text = """Begin forwarded message:

From: Netflix <billing@netfl1x-account.com>
Subject: Payment failed - update your billing info
Date: March 10, 2025 at 11:30:00 AM EST
To: user@icloud.com

We were unable to process your payment.
Please update your billing information to avoid service interruption."""

        result = extract_forwarded(text)
        assert result.is_forwarded is True
        assert result.original_sender_address == "billing@netfl1x-account.com"
        assert "Payment failed" in result.original_subject


class TestYahooFormat:
    def test_standard_yahoo(self):
        text = """----- Forwarded Message -----
From: IRS <refund@irs-gov.net>
To: taxpayer@yahoo.com
Sent: Monday, March 10, 2025 at 1:00:00 PM EST
Subject: Tax refund pending - action required

You have a pending tax refund of $4,382.00.
Click here to claim your refund."""

        result = extract_forwarded(text)
        assert result.is_forwarded is True
        assert result.original_sender_address == "refund@irs-gov.net"
        assert "tax refund" in result.original_subject.lower()


class TestSubjectParsing:
    def test_fw_prefix(self):
        result = extract_forwarded("Some body text", "FW: Suspicious email")
        assert result.original_subject == "Suspicious email"
        assert result.is_forwarded is True

    def test_fwd_prefix(self):
        result = extract_forwarded("Some body text", "Fwd: Suspicious email")
        assert result.original_subject == "Suspicious email"

    def test_nested_fw(self):
        result = extract_forwarded("Some body text", "FW: FW: RE: FW: Original subject")
        assert result.original_subject == "RE: FW: Original subject"

    def test_no_prefix(self):
        result = extract_forwarded("Just a normal email body", "Normal subject")
        # No FW prefix, no forwarding pattern in body
        assert result.is_forwarded is False


class TestFromLineParsing:
    def test_name_and_angle_brackets(self):
        text = """---------- Forwarded message ---------
From: John Doe <john@example.com>
Date: Mon, Mar 10, 2025 at 3:45 PM
Subject: Test
To: <user@gmail.com>

Body here."""
        result = extract_forwarded(text)
        assert result.original_sender_address == "john@example.com"
        assert result.original_sender_name == "John Doe"

    def test_bare_email_in_brackets(self):
        text = """---------- Forwarded message ---------
From: <noreply@suspicious.com>
Date: Mon, Mar 10, 2025 at 3:45 PM
Subject: Test
To: <user@gmail.com>

Body."""
        result = extract_forwarded(text)
        assert result.original_sender_address == "noreply@suspicious.com"

    def test_bare_email_no_brackets(self):
        text = """---------- Forwarded message ---------
From: scammer@evil.net
Date: Mon, Mar 10, 2025 at 3:45 PM
Subject: Test
To: <user@gmail.com>

Body."""
        result = extract_forwarded(text)
        assert result.original_sender_address == "scammer@evil.net"


class TestNotForwarded:
    def test_direct_email(self):
        """Direct emails to Is This Real? (not forwarded) should return is_forwarded=False."""
        result = extract_forwarded(
            "Hi, is this email address real? Thanks, Bob",
            "Question about an email"
        )
        assert result.is_forwarded is False
        assert result.original_sender_address == ""

    def test_empty_body(self):
        result = extract_forwarded("", "")
        assert result.is_forwarded is False
