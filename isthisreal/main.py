"""
Is This Real? — Email phishing detection for non-technical users.

Two run modes:
  1. Poll mode (default): continuously polls the mailbox for unread messages
  2. Server mode: FastAPI server with a /test/analyze endpoint for local dev

Usage:
  python -m isthisreal.main              # poll mode
  python -m isthisreal.main --server     # server mode
"""
import argparse
import logging
import time
import sys

from .config import get_settings
from .graph import fetch_unread_messages, mark_as_read, parse_graph_message
from .analyzer import analyze
from .verdict import synthesize_verdict
from .reply import send_verdict_reply

settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Poll mode — main loop
# ──────────────────────────────────────────────

def process_message(msg: dict) -> None:
    """Process a single Graph API message: parse → analyze → reply."""
    message_id = msg["id"]
    subject = msg.get("subject", "(no subject)")

    try:
        # 1. Parse (extracts original sender from forwarded content)
        parsed = parse_graph_message(msg)

        # Reply goes to the forwarder (our user), analysis targets the original sender
        reply_to = parsed.forwarder_address or parsed.sender_address

        logger.info(
            f"Processing: '{subject}' | "
            f"original_sender={parsed.sender_address}, reply_to={reply_to}"
        )

        # 2. Analyze (runs against the original sender, not the forwarder)
        analysis = analyze(parsed)
        logger.info(
            f"  {len(analysis.findings)} findings, risk={analysis.overall_risk.value}"
        )

        # 3. Verdict
        verdict = synthesize_verdict(
            analysis=analysis,
            subject=parsed.subject,
            sender=parsed.sender_address,
        )
        logger.info(f"  Verdict: {verdict.risk_level.value} — {verdict.summary[:80]}")

        # 4. Reply to the forwarder (grandma), not the original sender
        sent = send_verdict_reply(
            to_email=reply_to,
            original_subject=parsed.subject,
            verdict=verdict,
        )
        if sent:
            logger.info(f"  Reply sent to {reply_to}")
        else:
            logger.warning(f"  Failed to send reply to {reply_to}")

        # 5. Mark as read
        mark_as_read(message_id)

    except Exception as e:
        logger.exception(f"Error processing message {message_id}: {e}")
        # Still mark as read to avoid reprocessing broken messages
        try:
            mark_as_read(message_id)
        except Exception:
            pass


def poll_loop() -> None:
    """Continuously poll the mailbox for unread messages."""
    logger.info(
        f"Is This Real? polling started — mailbox: {settings.isthisreal_mailbox}, "
        f"interval: {settings.poll_interval_seconds}s"
    )

    while True:
        try:
            messages = fetch_unread_messages()
            if messages:
                logger.info(f"Found {len(messages)} unread message(s)")
                for msg in messages:
                    process_message(msg)
            else:
                logger.debug("No unread messages")
        except Exception as e:
            logger.exception(f"Poll cycle error: {e}")

        time.sleep(settings.poll_interval_seconds)


# ──────────────────────────────────────────────
# Server mode — FastAPI for local testing
# ──────────────────────────────────────────────

def create_app():
    """Create FastAPI app for test/dev mode."""
    from fastapi import FastAPI, Request, HTTPException
    from .models import ParsedEmail

    app = FastAPI(
        title="Is This Real?",
        description="Email phishing detection for non-technical users",
        version="0.1.0",
    )

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "isthisreal"}

    @app.post("/test/analyze")
    async def test_analyze(request: Request):
        """
        Test endpoint: POST email fields as JSON, get back raw analysis + verdict.
        No Graph API or mailbox needed.
        """
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON")

        parsed = ParsedEmail(
            sender_address=body.get("sender_address", "unknown@example.com"),
            sender_display_name=body.get("sender_display_name", ""),
            recipient_address=body.get("recipient_address", ""),
            subject=body.get("subject", ""),
            body_plain=body.get("body_plain", ""),
            body_html=body.get("body_html", ""),
            raw_headers=body.get("raw_headers", ""),
            spf_result=body.get("spf_result", ""),
            dkim_result=body.get("dkim_result", ""),
            dmarc_result=body.get("dmarc_result", ""),
            attachment_count=body.get("attachment_count", 0),
            attachment_types=body.get("attachment_types", []),
        )

        analysis = analyze(parsed)
        verdict = synthesize_verdict(
            analysis=analysis,
            subject=parsed.subject,
            sender=parsed.sender_address,
        )

        return {
            "analysis": {
                "sender_domain": analysis.sender_domain,
                "claimed_brand": analysis.claimed_brand,
                "overall_risk": analysis.overall_risk.value,
                "findings": [f.model_dump() for f in analysis.findings],
                "links_checked": [l.model_dump() for l in analysis.links_checked],
            },
            "verdict": verdict.model_dump(),
        }

    return app


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Is This Real?")
    parser.add_argument(
        "--server",
        action="store_true",
        help="Run in server mode (FastAPI test endpoint) instead of poll mode",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for server mode (default: 8000)",
    )
    args = parser.parse_args()

    if args.server:
        import uvicorn
        app = create_app()
        uvicorn.run(app, host="0.0.0.0", port=args.port)
    else:
        poll_loop()


if __name__ == "__main__":
    main()
