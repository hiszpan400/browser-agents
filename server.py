"""
Browser Agents — FastAPI service (hardened v3)
Security layers:
  1. API key auth (X-API-Key header)
  2. LAN-only binding (configure HOST in .env, not 0.0.0.0)
  3. ACL: 40 blocked domains + sensitive keyword scan
  4. URL extraction from goal text + ACL
  5. Max goal length (400 chars)
  6. Rate limiting (10 req/min per IP)
  7. Isolated Chrome profile (no main browser sessions/cookies)
  8. Server-side timeout + steps cap
  9. Chrome session cleanup between tasks
 10. Structured JSON audit log
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

load_dotenv(Path(__file__).parent / ".env")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("browser-agents")

app = FastAPI(title="Browser Agents", version="3.0")

# CORS — configure allowed origins via CORS_ORIGINS env var (comma-separated)
_cors_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-Key", "Content-Type"],
)

# ── Config ────────────────────────────────────────────────────────────────────
OLLAMA_HOST   = os.getenv("GHOST_OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL  = os.getenv("GHOST_MODEL", "qwen2.5:7b")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
LAYA_DIR      = Path(__file__).parent / "agents" / "laya_ultrafast"
JEV_DIR       = Path(__file__).parent / "agents" / "jev_ultrafast"
TYPESAFE_API_KEY = os.getenv("TYPESAFE_API_KEY", "")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
CHROME_PROFILE_DIR = Path(__file__).parent / "chrome-profile"
CHROME_PROFILE_DIR.mkdir(exist_ok=True)

API_KEY           = os.getenv("BROWSER_AGENTS_API_KEY", "")
RATE_LIMIT        = int(os.getenv("RATE_LIMIT_PER_MINUTE", "10"))
MAX_TIMEOUT       = int(os.getenv("MAX_TIMEOUT", "180"))
MAX_STEPS         = int(os.getenv("MAX_STEPS", "10"))
MAX_GOAL_LENGTH   = int(os.getenv("MAX_GOAL_LENGTH", "400"))
AUDIT_LOG_PATH    = os.getenv("AUDIT_LOG", "/tmp/browser-agents-audit.jsonl")

# ── Rate limiter (in-memory, per IP) ─────────────────────────────────────────
_rate_buckets: dict[str, list[float]] = defaultdict(list)

def _check_rate_limit(ip: str) -> None:
    now = time.time()
    window = _rate_buckets[ip]
    # Evict entries older than 60s
    _rate_buckets[ip] = [t for t in window if now - t < 60]
    if len(_rate_buckets[ip]) >= RATE_LIMIT:
        raise HTTPException(429, f"Rate limit: max {RATE_LIMIT} requests/minute")
    _rate_buckets[ip].append(now)

# ── Audit logger ──────────────────────────────────────────────────────────────
def _audit(event: str, data: dict) -> None:
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **data}
    try:
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass

# ── ACL ───────────────────────────────────────────────────────────────────────
BLOCKED_DOMAINS: set[str] = {
    # Banking / fintech
    "pkobp.pl", "mbank.pl", "ing.pl", "santander.pl", "bnpparibas.pl",
    "aliorbank.pl", "pekao.com.pl", "millennium.pl", "revolut.com",
    "paypal.com", "payu.pl", "binance.com", "coinbase.com", "kraken.com",
    # Auth / identity
    "accounts.google.com", "login.microsoftonline.com", "auth0.com",
    "okta.com", "onelogin.com", "signin.aws.amazon.com",
    # Cloud admin panels
    "console.cloud.google.com", "console.aws.amazon.com",
    "portal.azure.com", "cloud.oracle.com",
    "dash.cloudflare.com", "hetzner.com", "digitalocean.com",
    "app.hetzner.cloud", "app.netlify.com", "vercel.com",
    # Sensitive Google
    "mail.google.com", "gmail.com", "drive.google.com",
    "photos.google.com", "myaccount.google.com", "contacts.google.com",
    # Password managers
    "vault.bitwarden.com", "lastpass.com", "1password.com",
    "dashlane.com",
    # Telegram / chat admin
    "web.telegram.org", "my.telegram.org",
    # Network / DNS admin
    "app.tailscale.com", "admin.cloudflare.com",
    # GitHub (tokens/secrets)
    "github.com",
    # Local services — add your LAN IPs via BLOCKED_LOCAL_IPS env var
    "localhost", "127.0.0.1",
}

BLOCKED_GOAL_PATTERNS: list[str] = [
    r"passw(ord|ort|wd)",
    r"has[łl][oa]",
    r"secret[_\s]?key",
    r"api[_\s-]?key",
    r"\btoken\b",
    r"cookie[s]?",
    r"localStorage",
    r"sessionStorage",
    r"document\.cookie",
    r"\.env\b",
    r"ssh\s+(key|priv)",
    r"kredytow[aą]",
    r"przelew",
    r"banking",
    r"log(in|uj)\s+.{0,40}(gmail|google|telegram|bank|paypal)",
    r"zaloguj\s+.{0,40}(gmail|google|telegram|bank)",
    r"wyślij\s+(email|mail|przelew)",
    r"send\s+(email|mail|money|transfer)",
    r"wget|curl\s+.{0,60}(http|ftp)",  # exfiltration via shell
    r"\|\s*(nc|netcat|curl|wget)\b",
]

_BLOCKED_RE = re.compile("|".join(BLOCKED_GOAL_PATTERNS), re.IGNORECASE)
_URL_RE     = re.compile(r"https?://([^\s/\"'<>]+)", re.IGNORECASE)


def _domain_from(raw: str) -> str:
    """Extract bare domain from URL or hostname string."""
    if raw.startswith("http"):
        return urlparse(raw).netloc.lower().lstrip("www.")
    return raw.lower().lstrip("www.")


def _check_acl(goal: str, url: Optional[str]) -> None:
    """Raise HTTP 403 on policy violation. Logs every blocked attempt."""
    import unicodedata
    goal_norm = unicodedata.normalize("NFKC", goal)

    def _block(reason: str) -> None:
        _audit("acl_block", {"reason": reason, "goal": goal[:80], "url": url})
        raise HTTPException(403, f"BLOCKED: {reason}")

    # 1. Explicit URL param
    if url:
        domain = _domain_from(url)
        for bd in BLOCKED_DOMAINS:
            if domain == bd or domain.endswith("." + bd):
                _block(f"domain '{domain}' is on the security blocklist")

    # 2. URLs embedded in goal text
    for match in _URL_RE.finditer(goal_norm):
        domain = _domain_from(match.group(0))
        for bd in BLOCKED_DOMAINS:
            if domain == bd or domain.endswith("." + bd):
                _block(f"goal contains blocked domain '{domain}'")

    # 3. Domain names mentioned without protocol
    for bd in BLOCKED_DOMAINS:
        if bd in goal_norm.lower():
            _block(f"goal mentions blocked domain '{bd}'")

    # 4. Sensitive keywords (check both original + NFKC-normalized)
    m = _BLOCKED_RE.search(goal_norm) or _BLOCKED_RE.search(goal)
    if m:
        _block(f"goal contains sensitive keyword '{m.group()}'")


# ── Auth middleware ───────────────────────────────────────────────────────────
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)
    if API_KEY:
        key = request.headers.get("X-API-Key", "")
        if key != API_KEY:
            _audit("auth_fail", {"ip": request.client.host if request.client else "unknown",
                                  "path": request.url.path})
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "Unauthorized"}, status_code=401)
    return await call_next(request)


# ── Models ────────────────────────────────────────────────────────────────────
class TaskRequest(BaseModel):
    goal: str
    url: Optional[str] = None
    agent: Optional[str] = "auto"
    timeout: Optional[int] = 120

    @field_validator("goal")
    @classmethod
    def goal_length(cls, v: str) -> str:
        if len(v) > MAX_GOAL_LENGTH:
            raise ValueError(f"goal too long: {len(v)} > {MAX_GOAL_LENGTH} chars")
        return v.strip()


class TaskResult(BaseModel):
    status: str
    result: str
    agent_used: str
    elapsed_ms: Optional[int] = None


# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    available_agents = ["ghost", "laya", "browser_use"]
    if JEV_DIR.exists() and TYPESAFE_API_KEY:
        available_agents.insert(0, "jev")
    elif JEV_DIR.exists():
        available_agents.insert(0, "jev (no key)")
    return {
        "status": "ok",
        "agents": available_agents,
        "ollama": OLLAMA_HOST,
        "chrome_profile": "isolated",
        "acl": f"{len(BLOCKED_DOMAINS)} blocked domains",
        "auth": "required" if API_KEY else "disabled",
        "jev_ready": bool(JEV_DIR.exists() and TYPESAFE_API_KEY),
    }


@app.post("/task", response_model=TaskResult)
async def run_task(req: TaskRequest, request: Request):
    ip = request.client.host if request.client else "unknown"

    # Rate limit
    _check_rate_limit(ip)

    # ACL
    _check_acl(req.goal, req.url)

    agent = req.agent or "auto"
    if agent == "auto":
        # Etap 3: smart routing — jev for research, laya for navigation, ghost fallback
        if JEV_DIR.exists() and TYPESAFE_API_KEY:
            agent = _route_agent(req.goal)
        elif LAYA_DIR.exists():
            agent = "laya"
        else:
            agent = "ghost"

    timeout = min(req.timeout or 120, MAX_TIMEOUT)

    _audit("task_start", {"ip": ip, "agent": agent, "goal": req.goal[:80], "url": req.url})

    start = time.time()
    try:
        if agent == "jev":
            result = await _run_jev(req.goal, req.url, timeout)
        elif agent == "ghost":
            result = await _run_ghost(req.goal, req.url, timeout)
        elif agent == "laya":
            result = await _run_laya(req.goal, req.url, timeout)
        elif agent == "browser_use":
            result = await _run_browser_use(req.goal, req.url, timeout)
        else:
            raise HTTPException(400, f"Unknown agent: {agent}")
    except HTTPException:
        raise
    except asyncio.TimeoutError:
        _audit("task_timeout", {"agent": agent, "goal": req.goal[:80]})
        raise HTTPException(504, f"Agent '{agent}' timed out after {timeout}s")
    except Exception as e:
        _audit("task_error", {"agent": agent, "error": str(e)[:200]})
        log.error("Agent error: %s", e)
        raise HTTPException(500, f"Agent '{agent}' error: {str(e)[:400]}")

    elapsed = int((time.time() - start) * 1000)
    _audit("task_done", {"agent": agent, "elapsed_ms": elapsed, "goal": req.goal[:80]})
    log.info("task_done agent=%s elapsed=%dms", agent, elapsed)
    return TaskResult(status="done", result=result, agent_used=agent, elapsed_ms=elapsed)


# ── Etap 3: Smart agent routing ───────────────────────────────────────────────
_JEV_PATTERNS = re.compile(
    r"(cen[ay]|kosztuje|najtaniej|najtańsz|ofert[ay]|promocj[ay]|rabat"
    r"|lot[uó]w?|przelot|bilet|rezerwac|lotnisko|hotel|nocleg|airbnb"
    r"|wiadomoś|news|aktualnoś|co nowego|ostatnio"
    r"|kurs|walut[ay]|dolar|euro|bitcoin|kryptowalut"
    r"|pogoda|prognoza|temperatur"
    r"|sprawdź.*cen|znajdź.*najtańsz|porównaj.*cen"
    r"|flight|price|hotel|booking|news|weather|currency)",
    re.IGNORECASE,
)
_LAYA_PATTERNS = re.compile(
    r"(home.?assistant|lovelace|hacs|dashboard|konfiguracja|automations"
    r"|formularz|wypełnij|zaloguj.*stron|kliknij|nawiguj|idź na stron)",
    re.IGNORECASE,
)

def _route_agent(goal: str) -> str:
    """Route to best agent: jev for research/info, laya for UI nav, ghost fallback."""
    if _JEV_PATTERNS.search(goal):
        return "jev"
    if _LAYA_PATTERNS.search(goal) and LAYA_DIR.exists():
        return "laya"
    # Default: jev if key available (faster, more accurate than ghost)
    if TYPESAFE_API_KEY:
        return "jev"
    return "laya" if LAYA_DIR.exists() else "ghost"


# ── Agent runners ─────────────────────────────────────────────────────────────
def _llm():
    # Use Gemini Flash if API key available (fast, reliable tool calling)
    # Fallback to Ollama when no key (offline mode)
    if GEMINI_API_KEY:
        from browser_use.llm.google.chat import ChatGoogle
        return ChatGoogle(model="gemini-2.5-flash-lite", api_key=GEMINI_API_KEY)
    from browser_use.llm.ollama.chat import ChatOllama
    return ChatOllama(
        model=OLLAMA_MODEL,
        host=OLLAMA_HOST,
        ollama_options={"temperature": 0, "num_ctx": 32768, "think": False},
    )


def _isolated_profile(headless: bool = True):
    from browser_use import BrowserProfile
    return BrowserProfile(
        user_data_dir=CHROME_PROFILE_DIR,
        headless=headless,
    )


async def _clear_chrome_session() -> None:
    """Remove cookies/cache from the isolated profile after each task."""
    import shutil
    for subdir in ("Default/Cookies", "Default/Cache", "Default/Local Storage",
                   "Default/Session Storage", "Default/IndexedDB"):
        target = CHROME_PROFILE_DIR / subdir
        if target.exists():
            try:
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            except Exception as e:
                log.warning("Could not clear %s: %s", target, e)


async def _run_ghost(goal: str, url: Optional[str], timeout: int) -> str:
    """ghost-browser: browser-use + Ollama, isolated profile, session cleared after."""
    from browser_use import Agent
    task = f"Go to {url}. Then: {goal}" if url else goal
    agent = Agent(task=task, llm=_llm(), browser_profile=_isolated_profile(headless=False),
                  use_vision=False, max_actions_per_step=1)
    try:
        result = await asyncio.wait_for(agent.run(max_steps=MAX_STEPS), timeout=timeout)
        return _extract_result(result)
    finally:
        await _clear_chrome_session()


async def _run_browser_use(goal: str, url: Optional[str], timeout: int) -> str:
    """browser-use: Playwright headless, isolated profile, session cleared after."""
    from browser_use import Agent
    task = f"Go to {url}. Then: {goal}" if url else goal
    agent = Agent(task=task, llm=_llm(), browser_profile=_isolated_profile(headless=True),
                  use_vision=False, max_actions_per_step=1)
    try:
        result = await asyncio.wait_for(agent.run(max_steps=MAX_STEPS), timeout=timeout)
        return _extract_result(result)
    finally:
        await _clear_chrome_session()


CHROME_CDP_PROFILE = Path("/tmp/chrome-cdp-laya-profile")
CHROME_CDP_PORT = int(os.getenv("CHROME_CDP_PORT", "9222"))


_PL_CITIES = {
    "wrocław": "Wroclaw", "wrocławia": "Wroclaw", "wrocławiu": "Wroclaw",
    "warszaw": "Warsaw", "warszawy": "Warsaw", "warszawie": "Warsaw",
    "krakow": "Krakow", "krakowa": "Krakow", "krakowie": "Krakow",
    "kraków": "Krakow", "krakówa": "Krakow",
    "gdańsk": "Gdansk", "gdańska": "Gdansk",
    "gdynia": "Gdynia", "łódź": "Lodz", "poznań": "Poznan",
    "amsterdam": "Amsterdam", "amsterdamu": "Amsterdam",
    "londyn": "London", "londynu": "London",
    "paryż": "Paris", "paryża": "Paris",
    "berlin": "Berlin", "berlina": "Berlin",
    "rzym": "Rome", "Rzym": "Rome",
    "madryt": "Madrid", "lizbona": "Lisbon",
    "barcelona": "Barcelona", "barcelony": "Barcelona",
    "wiedeń": "Vienna", "wiednia": "Vienna",
    "praga": "Prague", "pragi": "Prague",
    "dublin": "Dublin",
}
_PL_MONTHS = {
    "styczeń": ("January", 1), "stycznia": ("January", 1), "styczen": ("January", 1),
    "luty": ("February", 2), "lutego": ("February", 2),
    "marzec": ("March", 3), "marca": ("March", 3),
    "kwiecień": ("April", 4), "kwietnia": ("April", 4), "kwiecien": ("April", 4),
    "maj": ("May", 5), "maja": ("May", 5),
    "czerwiec": ("June", 6), "czerwca": ("June", 6),
    "lipiec": ("July", 7), "lipca": ("July", 7),
    "sierpień": ("August", 8), "sierpnia": ("August", 8), "sierpien": ("August", 8),
    "wrzesień": ("September", 9), "września": ("September", 9), "wrzesien": ("September", 9),
    "październik": ("October", 10), "października": ("October", 10), "pazdziernik": ("October", 10), "pazdziernika": ("October", 10),
    "listopad": ("November", 11), "listopada": ("November", 11),
    "grudzień": ("December", 12), "grudnia": ("December", 12), "grudzien": ("December", 12),
}

def _rule_translate_flight(goal: str) -> Optional[str]:
    """Rule-based Polish→English flight goal translation (no API needed)."""
    import datetime, re
    g = goal.lower()
    # Extract origin (z/ze + city)
    origin = None
    for token in re.split(r'\s+', g):
        city = _PL_CITIES.get(token)
        if city:
            # Check if preceded by "z" or "ze"
            idx = g.find(token)
            before = g[:idx].strip()
            if before.endswith((" z", " ze", "z", "ze")):
                origin = city
                break
    # Extract destination (do + city)
    dest = None
    for token in re.split(r'\s+', g):
        city = _PL_CITIES.get(token)
        if city and city != origin:
            idx = g.find(token)
            before = g[:idx].strip()
            if before.endswith(" do"):
                dest = city
                break
    if not origin or not dest:
        return None
    # Extract date
    today = datetime.date.today()
    date_str = None
    for word in re.split(r'\s+', g):
        if word in _PL_MONTHS:
            eng_month, month_num = _PL_MONTHS[word]
            year = today.year if month_num >= today.month else today.year + 1
            date_str = f"{eng_month} 15, {year}"
            break
    if not date_str:
        default = today + datetime.timedelta(days=30)
        date_str = default.strftime("%B %d, %Y")
    translated = (
        f"On Google Flights, search for one-way flights from {origin} to {dest} on {date_str} "
        f"for 1 adult economy. Fill in the origin, destination and date fields, click Search, "
        f"then stop once you can see a list of specific flights with prices. Do not click any flight or book anything."
    )
    log.info("laya: rule-translated goal: %s", translated[:120])
    return translated


async def _translate_goal_for_laya(goal: str) -> str:
    """Translate non-English (Polish) flight queries to English for laya's text model."""
    # Only translate if non-ASCII chars or known Polish flight keywords
    needs_translation = any(ord(c) > 127 for c in goal) or any(
        w in goal.lower() for w in ("loty", "lot ", "przelot", "bilet"))
    if not needs_translation:
        return goal
    # Try rule-based first (fast, no API)
    ruled = _rule_translate_flight(goal)
    if ruled:
        return ruled
    # Fallback to Gemini if rule-based couldn't parse
    if not GEMINI_API_KEY:
        return goal
    import urllib.request
    import json as _json
    import datetime
    default_date = (datetime.date.today() + datetime.timedelta(days=30)).strftime("%B %d, %Y")
    prompt = (
        f"Translate this flight search query to an English laya browser-agent goal for Google Flights. "
        f"Format: 'On Google Flights, search for one-way flights from [CITY] to [CITY] on [DATE] for 1 adult economy. "
        f"Fill in the origin, destination and date fields, click Search, then stop once you can see a list of specific flights with prices. Do not click any flight or book anything.'\n"
        f"Rules:\n"
        f"- If no date mentioned, use: {default_date}\n"
        f"- Use full city names (e.g. Wroclaw, not WRO)\n"
        f"- If month only (e.g. 'October'), pick the 15th of that month\n"
        f"Query: {goal}\n"
        f"Return ONLY the translated goal, nothing else."
    )
    body = _json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0, "maxOutputTokens": 150}
    }).encode()
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key={GEMINI_API_KEY}"
    try:
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = _json.loads(r.read())
            translated = data["candidates"][0]["content"]["parts"][0]["text"].strip()
            log.info("laya: translated goal: %s", translated[:100])
            return translated
    except Exception as e:
        log.warning("laya: goal translation failed: %s — using original", e)
        return goal


def _get_cdp_ws() -> str:
    """Return CDP WebSocket URL, launching headless Chrome if needed."""
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://localhost:{CHROME_CDP_PORT}/json/version", timeout=2) as r:
            data = json.loads(r.read())
            return data.get("webSocketDebuggerUrl", "")
    except Exception:
        pass
    # Launch Chrome with remote debugging
    CHROME_CDP_PROFILE.mkdir(parents=True, exist_ok=True)
    chrome_paths = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ]
    chrome = next((p for p in chrome_paths if Path(p).exists()), None)
    if not chrome:
        raise RuntimeError("Chrome not found for laya CDP mode")
    import subprocess
    subprocess.Popen(
        [chrome, f"--remote-debugging-port={CHROME_CDP_PORT}",
         f"--user-data-dir={CHROME_CDP_PROFILE}",
         "--no-first-run", "--no-default-browser-check",
         "--disable-sync", "--disable-extensions",
         "--disable-background-networking"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    import time; time.sleep(3)
    try:
        with urllib.request.urlopen(f"http://localhost:{CHROME_CDP_PORT}/json/version", timeout=5) as r:
            data = json.loads(r.read())
            return data.get("webSocketDebuggerUrl", "")
    except Exception as e:
        raise RuntimeError(f"Chrome CDP not ready after launch: {e}")


async def _run_laya(goal: str, url: Optional[str], timeout: int) -> str:
    """laya-ultrafast: local MLX decisions, connects to Chrome via CDP (no API quota)."""
    if not LAYA_DIR.exists():
        raise RuntimeError(f"laya-ultrafast not found at {LAYA_DIR}")

    cdp_ws = _get_cdp_ws()
    if not cdp_ws:
        raise RuntimeError("Could not get Chrome CDP WebSocket URL")
    log.info("laya: connecting to Chrome CDP at %s", cdp_ws)
    # Translate Polish/non-English goals so qwen2.5:7b can parse flight parameters
    goal = await _translate_goal_for_laya(goal)

    import urllib.parse as _up
    start_url = url or f"https://duckduckgo.com/?q={_up.quote_plus(goal[:120])}&ia=web"
    # Kill any stale browser-harness daemon (can linger from crashed tasks)
    import subprocess as sp
    sp.run(["pkill", "-9", "-f", "browser.harness.*daemon"], capture_output=True)
    await asyncio.sleep(0.5)

    env_content = (
        f"DECISION_MODEL=laya\n"
        f"LAYA_MODEL={os.getenv('LAYA_MODEL', 'aac6fef/laya-typed-decisions-mlx')}\n"
        f"TEXT_MODEL_BASE_URL={os.getenv('TEXT_MODEL_BASE_URL', 'http://localhost:11434/v1')}\n"
        f"TEXT_MODEL={os.getenv('TEXT_MODEL', 'qwen2.5:7b')}\n"
        f"TEXT_MODEL_REASONING=none\n"
        f"BU_CDP_WS={cdp_ws}\n"
    )
    (LAYA_DIR / ".env").write_text(env_content)

    # Simple synchronous runner — avoids asyncio event loop conflicts with browser-harness
    script = (
        "from laya_ultrafast import Agent\n"
        f"with Agent({start_url!r}, {goal!r}) as a:\n"
        "    results = list(a.run())\n"
        "    last = results[-1] if results else {}\n"
        "    final = last.get('result') or ''\n"
        "    page_text = (last.get('page') or {}).get('text', '')[:800]\n"
        "    status = last.get('status', 'done')\n"
        "    url = (last.get('page') or {}).get('url', '')\n"
        "    print(final or page_text or status)\n"
        "    import sys; sys.stderr.write(f'status={status} url={url}\\n')\n"
    )

    proc = await asyncio.create_subprocess_exec(
        "uv", "run", "--env-file", ".env", "python", "-c", script,
        cwd=str(LAYA_DIR),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise

    stderr_txt = stderr.decode(errors="replace")
    log.info("laya stderr: %s", stderr_txt[-200:])
    if proc.returncode != 0:
        raise RuntimeError(f"laya failed: {stderr_txt[-400:]}")
    return stdout.decode(errors="replace").strip() or "completed"


async def _run_jev(goal: str, url: Optional[str], timeout: int) -> str:
    """jev-ultrafast: TypeSafe Jev model for action selection, OpenRouter for text generation."""
    if not JEV_DIR.exists():
        raise RuntimeError(f"jev-ultrafast not found at {JEV_DIR}")
    if not TYPESAFE_API_KEY:
        raise RuntimeError("TYPESAFE_API_KEY not set — cannot use jev agent")

    cdp_ws = _get_cdp_ws()
    if not cdp_ws:
        raise RuntimeError("Could not get Chrome CDP WebSocket URL for jev")
    log.info("jev: connecting to Chrome CDP at %s", cdp_ws)

    import urllib.parse as _up
    import re as _re
    if url:
        start_url = url
    elif _re.search(r'kurs|waluta|euro|dolar|frank|funt|jen\b|zlot|wymiana.*walut', goal, _re.I):
        start_url = "https://waluty.com.pl/"
    elif _re.search(r'lot[yóu]|przelot|bilet.*lotn|najtansz.*lot|najtańsz.*lot', goal, _re.I):
        # DDG web search for flights — booking sites use heavy JS that exceeds jev's model budget
        start_url = f"https://duckduckgo.com/?q={_up.quote_plus(goal[:120])}&ia=web"
    elif _re.search(r'cen[ay]|kosztuje|kosztował|ile za\b', goal, _re.I):
        start_url = f"https://duckduckgo.com/?q={_up.quote_plus(goal[:120])}&ia=shopping"
    else:
        start_url = f"https://duckduckgo.com/?q={_up.quote_plus(goal[:120])}&ia=web"
    # Tell jev to extract the specific answer from the visible page
    is_flight = bool(_re.search(r'lot[yóu]|przelot|bilet', goal, _re.I))
    if is_flight:
        enhanced_goal = (
            f"{goal}. "
            "Read the search results and report the cheapest flight price visible (e.g. 'od 240 zł'). "
            "Do NOT click into booking sites — just read the prices shown in search snippets. Reply in Polish."
        )
    else:
        enhanced_goal = (
            f"{goal}. "
            "Find and report the specific number, rate or price. "
            "If it's not visible on the current page, click the most relevant link. Reply in Polish."
        )
    text_model_key = OPENROUTER_API_KEY or GEMINI_API_KEY or TYPESAFE_API_KEY

    env_content = (
        f"TYPESAFE_API_KEY={TYPESAFE_API_KEY}\n"
        f"TYPESAFE_MODEL={os.getenv('TYPESAFE_MODEL', 'jev-latest')}\n"
        f"TEXT_MODEL_API_KEY={text_model_key}\n"
        f"TEXT_MODEL_BASE_URL={os.getenv('TEXT_MODEL_BASE_URL', 'https://openrouter.ai/api/v1')}\n"
        f"TEXT_MODEL={os.getenv('TEXT_MODEL', 'inception/mercury-2.5')}\n"
        f"TEXT_MODEL_REASONING=none\n"
        f"BU_CDP_WS={cdp_ws}\n"
    )
    (JEV_DIR / ".env").write_text(env_content)

    import subprocess as sp
    sp.run(["pkill", "-9", "-f", "browser.harness.*daemon"], capture_output=True)
    await asyncio.sleep(0.3)

    script = (
        "import os, sys\n"
        f"os.chdir({str(JEV_DIR)!r})\n"
        "from jev_ultrafast import Agent\n"
        f"with Agent({start_url!r}, {enhanced_goal!r}) as a:\n"
        "    results = list(a.run())\n"
        "    last = results[-1] if results else {}\n"
        "    final = last.get('result') or ''\n"
        "    page_text = (last.get('page') or {}).get('text', '')[:1200]\n"
        "    status = last.get('status', 'done')\n"
        "    steps = [r.get('action', '') for r in results if r.get('action')]\n"
        "    print(final or page_text or status)\n"
        "    sys.stderr.write(f'status={status} steps={len(steps)}\\n')\n"
    )

    proc = await asyncio.create_subprocess_exec(
        "uv", "run", "--env-file", ".env", "python", "-c", script,
        cwd=str(JEV_DIR),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise

    stderr_txt = stderr.decode(errors="replace")
    log.info("jev stderr: %s", stderr_txt[-200:])
    if proc.returncode != 0:
        log.warning("jev failed (rc=%d): %s", proc.returncode, stderr_txt[-300:])
        raise RuntimeError(f"jev failed (rc={proc.returncode}): {stderr_txt[-200:]}")
    return stdout.decode(errors="replace").strip() or "completed"


def _extract_result(result) -> str:
    if result is None:
        return "no result"
    # Try final_result() first (set when agent calls done action)
    if hasattr(result, "final_result"):
        final = result.final_result()
        if final:
            return str(final)
    # Extract useful steps from AgentHistoryList
    if hasattr(result, "all_results"):
        steps = []
        for action in result.all_results:
            content = getattr(action, "extracted_content", None)
            if content and content not in ("None", "") and not content.startswith("🔗 Navigated"):
                steps.append(content)
        if steps:
            return "\n\n".join(steps[-6:])  # last 6 meaningful steps
    text = str(result)
    return text[:2000] + "…" if len(text) > 2000 else text


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8900))
    host = os.getenv("HOST", "127.0.0.1")
    log.info("Browser Agents v3 | %s:%d | auth=%s | acl=%d domains",
             host, port, "on" if API_KEY else "off", len(BLOCKED_DOMAINS))
    uvicorn.run(app, host=host, port=port, log_level="info")
