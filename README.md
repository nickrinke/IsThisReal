# Is This Real?

Email phishing detection for non-technical users. Forward a suspicious email to a shared mailbox and get a plain-language reply explaining exactly why it's safe or sketchy.

Built on Microsoft 365 (Graph API) and Claude. Deploy it for any organization or offer it as a service.

## How It Works

1. User forwards a suspicious email to `isthisreal@yourdomain.com`
2. Is This Real? polls the shared mailbox via Microsoft Graph API
3. Deterministic analysis checks headers, links, sender info, and content patterns
4. Claude API synthesizes findings into a plain-language verdict
5. Is This Real? auto-replies with a simple red/yellow/green risk assessment

## Architecture

```
User forwards suspicious email
            │
            ▼
Shared Mailbox (isthisreal@yourdomain.com)
            │
            ▼
Graph API Poller (MSAL client credentials)
            │
            ▼
Email Parser (sender, headers, body, links, attachments)
            │
            ▼
Analysis Engine
  ├── Sender verification (domain mismatch, typosquat detection)
  ├── Auth checks (SPF / DKIM / DMARC from headers)
  ├── Link analysis (URL vs display text, domain spoofing, IP links)
  ├── Content analysis (urgency language, credential requests)
  └── Attachment flagging (dangerous file types)
            │
            ▼
Claude API (plain-language synthesis @ 6th-grade reading level)
            │
            ▼
Graph API sendMail (reply to the user)
```

## Supported Environments

| Environment | Graph Base URL | Authority Host |
|-------------|---------------|----------------|
| Commercial | `https://graph.microsoft.com` | `https://login.microsoftonline.com` |
| GCC | `https://graph.microsoft.com` | `https://login.microsoftonline.com` |
| GCC-High | `https://graph.microsoft.us` | `https://login.microsoftonline.us` |

## Setup

### 1. Entra ID App Registration

Register an application in your tenant:

- **API Permissions** (Application, not Delegated):
  - `Mail.ReadWrite` — read messages and mark them as read
  - `Mail.Send` — send verdict replies
- **Grant admin consent** for the permissions
- **Create a client secret** and note the value

### 2. Shared Mailbox

Create a shared mailbox (e.g., `isthisreal@yourdomain.com`) in Exchange admin center. No license required for shared mailboxes.

### 3. Environment Variables

```bash
cp .env.example .env
# Edit .env with your tenant ID, client ID, client secret, mailbox, and Anthropic key
```

### 4. Install & Run

```bash
pip install -r requirements.txt

# Poll mode (production) — continuously monitors the mailbox
python -m isthisreal

# Server mode (development) — FastAPI test endpoint, no mailbox needed
python -m isthisreal --server
```

### 5. Docker

```bash
docker build -t isthisreal .
docker run --env-file .env isthisreal

# Or with docker-compose
docker compose up -d
```

## Development

The `--server` flag starts a FastAPI instance with a `/test/analyze` endpoint. POST email fields as JSON to test the analysis engine without needing a mailbox:

```bash
curl -X POST http://localhost:8000/test/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "sender_address": "support@mikerosoct.net",
    "subject": "Your Microsoft Account Needs Attention",
    "body_plain": "Your account will be suspended in 24 hours. Click here to verify your identity immediately.",
    "spf_result": "fail"
  }'
```

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

## License

MIT
