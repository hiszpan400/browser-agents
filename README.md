# Browser Agents

A hardened FastAPI orchestrator that routes natural-language goals to specialized browser automation agents — locally or via cloud APIs.

---

## What it does

Send a natural-language goal via HTTP POST. The server selects the right agent, executes the task in an isolated Chrome session, and returns the result as JSON.

```bash
curl -X POST http://localhost:8900/task \
  -H "X-API-Key: your_key" \
  -H "Content-Type: application/json" \
  -d '{"goal": "Search for the cheapest flight from Warsaw to London next Friday"}'
```

Response:
```json
{
  "result": "Found: LOT Polish Airlines, PLN 380, departs 07:10",
  "agent": "jev",
  "elapsed_ms": 7100
}
```

---

## Security layers

The server is designed for LAN deployment with 10 explicit security controls:

| Layer | What it does |
|---|---|
| API key auth | `X-API-Key` header required on every request |
| LAN binding | Binds to a specific interface — not `0.0.0.0` |
| Domain ACL | 40 blocked domains (social media, banking, admin panels) |
| Keyword scan | Rejects goals containing sensitive patterns |
| URL extraction | Validates embedded URLs against the ACL |
| Goal length cap | 400-character maximum |
| Rate limiting | 10 requests/minute per IP |
| Isolated profile | Dedicated Chrome profile — no cookies from main browser |
| Timeout + steps | Configurable per-task limits |
| Audit log | Structured JSON log of every request and result |

---

## Agents

The orchestrator supports three pluggable browser agents. Each lives in `agents/` as a separate project with its own dependencies:

| Agent | Model | Strengths | Source |
|---|---|---|---|
| **Jev Ultrafast** | TypeSafe Jev | Dynamic indexed action space, 7s Google Flights demo | [browser-use/jev-ultrafast](https://github.com/browser-use/jev-ultrafast) |
| **Ghost Browser** | Gemma4 27B (Ollama) | Fully local, no API costs, ranked 3rd on Stealth Bench V1 | [ddangkong/ghost-browser](https://github.com/ddangkong/ghost-browser) |
| **Laya Ultrafast** | Laya MLX | Typed-decision model, Apple Silicon optimized | [ipenywis/laya-ultrafast](https://github.com/ipenywis/laya-ultrafast) |

Agent selection: pass `"agent": "jev"` / `"ghost"` / `"laya"` / `"auto"` in the request body.

---

## Setup

**Prerequisites:** Python 3.12+, [uv](https://docs.astral.sh/uv/), Chrome with remote debugging enabled

```bash
# 1. Clone
git clone https://github.com/hiszpan400/browser-agents.git
cd browser-agents

# 2. Install deps
uv sync

# 3. Configure
cp .env.example .env
# Edit .env — set API keys and HOST

# 4. Install agents (each is an independent project)
git clone https://github.com/browser-use/jev-ultrafast.git agents/jev_ultrafast
git clone https://github.com/ddangkong/ghost-browser.git agents/ghost_browser
git clone https://github.com/ipenywis/laya-ultrafast.git agents/laya_ultrafast

# 5. Start Chrome with remote debugging
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --remote-debugging-port=9222 \
  --user-data-dir=/tmp/browser-agents-profile

# 6. Run the server
uv run python server.py
```

Full setup walkthrough: [SETUP.md](SETUP.md)

---

## API

### `POST /task`

| Field | Type | Description |
|---|---|---|
| `goal` | string | Natural-language task description (max 400 chars) |
| `agent` | string | `"jev"` \| `"ghost"` \| `"laya"` \| `"auto"` (default: `"auto"`) |

Headers: `X-API-Key: <your key>`, `Content-Type: application/json`

### `GET /health`

Returns server status and available agents.

### `GET /agents`

Lists configured agents and their current availability.

---

## Configuration

All configuration is via environment variables. See [`.env.example`](.env.example) for the full reference.

Key settings:

```env
BROWSER_AGENTS_API_KEY=  # Required — shared secret for auth
HOST=127.0.0.1           # Bind address
PORT=8900
RATE_LIMIT_PER_MINUTE=10
MAX_TIMEOUT=180
MAX_STEPS=10
```

---

## License

MIT
