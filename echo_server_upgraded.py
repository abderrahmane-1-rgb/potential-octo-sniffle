#!/usr/bin/env python3
"""ECHO AI server (upgraded).

Serves the ECHO AI page and the chat API:

    GET  /                          the page
    GET  /api/echo/health           feature detection / status
    GET  /api/echo/keys             masked view of server-held keys
    POST /api/echo/keys             store a key on the server (loopback only)
    PATCH/DELETE /api/echo/keys/ID  enable/disable or remove a stored key (loopback only)
    POST /api/echo/models           probe every configured key, list usable models
    POST /api/echo/verify           send one tiny real request to prove a key works
    POST /api/echo/stream           chat, server-sent events (preferred)
    POST /api/echo                  chat, single JSON reply (fallback route)

Design rules (see README_ECHO_UPGRADE.md):
  * No secret is ever placed in a page, URL, log line or error message.
  * Every failure is classified (auth / billing / rate_limit / timeout / network /
    provider / bad_response ...) and reported as such; a fallback is never presented
    as a normal model answer.
  * Nothing the model or the user types is ever executed on the server.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import base64
import secrets
import hmac
import ipaddress
import json
import operator
import os
import queue
import random
import re
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from xml.sax.saxutils import escape as xml_escape
from collections import deque
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = "2.2"
ROOT = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def _load_dotenv():
    """Tiny .env reader so GROQ_API_KEY=... style keys are picked up with no extra setup."""
    try:
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip("\"'"))
    except OSError:
        pass


_load_dotenv()


def _env_int(name, default, lo, hi):
    try:
        return max(lo, min(hi, int(os.environ.get(name, default))))
    except (TypeError, ValueError):
        return default


def _env_flag(name):
    """True / False when set to something recognisable, None when unset."""
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return None
    return v.strip().lower() in ("1", "true", "yes", "on")


MAX_TOKENS = _env_int("ECHO_MAX_TOKENS", 2400, 64, 16000)
MAX_MESSAGE_CHARS = 64_000          # one user turn (text + inlined text files)
MAX_JSON_BODY = 1_000_000           # models / verify / keys / non-stream chat
MAX_STREAM_BODY = 4_000_000         # chat with up to 3 inline images
MAX_HISTORY_MESSAGES = 40
MAX_HISTORY_CHARS = 48_000          # total history budget, newest messages win
MAX_HISTORY_MSG_CHARS = 16_000      # one history message
MAX_CONCURRENT_CHATS = _env_int("ECHO_MAX_CONCURRENT", 6, 1, 64)
CHAT_RATE_PER_MIN = _env_int("ECHO_RATE_PER_MIN", 60, 5, 6000)
ADMIN_RATE_PER_MIN = _env_int("ECHO_ADMIN_RATE_PER_MIN", 30, 5, 600)
DEAD_TTL = 300                      # seconds a rejected key stays out of routing
VERIFIED_TTL = 3600
# Remote key management is enabled only when BOTH secrets are configured. Use a long
# unique ECHO_ADMIN_PASSWORD and a random ECHO_MASTER_KEY (32+ chars) in the host's
# secret/environment settings. The master key encrypts the vault at rest.
ECHO_ADMIN_PASSWORD = os.environ.get("ECHO_ADMIN_PASSWORD", "")
ECHO_MASTER_KEY = os.environ.get("ECHO_MASTER_KEY", "")
VAULT_FILE = str(ROOT / "echo_vault.enc")
_VAULT_SESSIONS = {}
_VAULT_SESSION_LOCK = threading.RLock()
_VAULT_SESSION_TTL = 8 * 60 * 60

# Free third-party gateways receive the text of your messages. Set ECHO_DISABLE_FREE=1
# to never use them (and never call Pollinations or Wikipedia either).
DISABLE_FREE = bool(_env_flag("ECHO_DISABLE_FREE"))
POLLINATIONS_API_KEY = os.environ.get("POLLINATIONS_API_KEY", "").strip()

# Private/loopback base URLs (e.g. a local Ollama) are allowed for keys configured on the
# server. For base URLs typed in the browser they are only allowed when the server itself
# is bound to loopback (set in main()) or when ECHO_ALLOW_PRIVATE_BASES=1.
ALLOW_PRIVATE_BASES = bool(_env_flag("ECHO_ALLOW_PRIVATE_BASES"))
BOUND_HOST = "127.0.0.1"
LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1", "[::1]"}
EXTRA_ALLOWED_HOSTS = {h.strip().lower() for h in os.environ.get("ECHO_ALLOWED_HOSTS", "").split(",") if h.strip()}
# Only configure trusted proxies when the app is reachable exclusively through them.
# A proxy must overwrite/append X-Forwarded-For correctly; arbitrary client headers are ignored.
TRUSTED_PROXY_NETWORKS = []
for _network in os.environ.get("ECHO_TRUSTED_PROXIES", "").split(","):
    _network = _network.strip()
    if _network:
        try:
            TRUSTED_PROXY_NETWORKS.append(ipaddress.ip_network(_network, strict=False))
        except ValueError:
            sys.stderr.write("Ignoring invalid ECHO_TRUSTED_PROXIES network: %s\n" % _network[:80])

POLLINATIONS_URL = "https://text.pollinations.ai/"
SYSTEM = """You are ECHO AI, a futuristic but useful conversational assistant inside a cinematic kinetic web interface.
Be genuinely helpful, concise, and practical. Use Markdown. If asked for code, provide working code in fenced code blocks with a language tag. If asked to write, produce polished writing. If asked to analyze, give clear structured feedback. Reply in the language the user writes in. If you are unsure or lack information, say so plainly instead of guessing. Do not mention that you are a demo unless the user asks about implementation."""
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

_state_lock = threading.RLock()     # guards the caches below


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------
def trim(s: str, n: int) -> str:
    s = re.sub(r"\s+", " ", s or "").strip()
    return s[:n]


_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET_PATTERNS = re.compile(
    r"(Bearer\s+[A-Za-z0-9._~+/=\-]{8,}"
    r"|sk-[A-Za-z0-9_\-]{12,}|gsk_[A-Za-z0-9]{12,}|AIza[0-9A-Za-z_\-]{16,}"
    r"|xai-[A-Za-z0-9]{12,}|csk-[A-Za-z0-9]{12,}|AQ\.[A-Za-z0-9_\-]{12,})")


def redact(text, secrets=()):
    """Remove anything that looks like (or is exactly) a secret from a string."""
    s = str(text or "")
    for sec in secrets or ():
        if sec and len(sec) >= 6:
            s = s.replace(sec, "[key]")
    return _SECRET_PATTERNS.sub("[key]", s)


def mask_key(value):
    s = str(value or "")
    return s[:6] + "…" + s[-4:] if len(s) > 12 else "•" * len(s)


def key_id(key, base):
    return hashlib.sha1((key + "|" + (base or "").rstrip("/")).encode()).hexdigest()[:12]


# --- safe arithmetic (replaces eval) ----------------------------------------
_BIN_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
            ast.Div: operator.truediv, ast.Mod: operator.mod, ast.FloorDiv: operator.floordiv,
            ast.Pow: operator.pow}
_UN_OPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def safe_arithmetic(expr: str):
    """Evaluate +-*/%** and parentheses on plain numbers. Anything else raises ValueError.
    Uses the ast module, never eval()."""
    if len(expr) > 200:
        raise ValueError("too long")
    tree = ast.parse(expr, mode="eval")

    def ev(node, depth=0):
        if depth > 40:
            raise ValueError("too deep")
        if isinstance(node, ast.Expression):
            return ev(node.body, depth + 1)
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            return node.value
        if isinstance(node, ast.UnaryOp) and type(node.op) in _UN_OPS:
            return _UN_OPS[type(node.op)](ev(node.operand, depth + 1))
        if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
            a, b = ev(node.left, depth + 1), ev(node.right, depth + 1)
            if isinstance(node.op, ast.Pow) and (abs(b) > 64 or abs(a) > 1e6):
                raise ValueError("power too large")
            return _BIN_OPS[type(node.op)](a, b)
        raise ValueError("unsupported expression")

    val = ev(tree)
    if isinstance(val, float) and (val != val or val in (float("inf"), float("-inf"))):
        raise ValueError("not finite")
    return val


def fmt_number(val):
    if isinstance(val, float):
        if val == int(val) and abs(val) < 1e15:
            return str(int(val))
        return format(val, ".12g")
    return str(val)


def local_fallback(message: str, history=None, files=None) -> str:
    """Honest offline responder. No canned 'answers' pretending to be model output.
    It only does work it can genuinely do offline (arithmetic, via a safe evaluator),
    otherwise it says the model network is unreachable and offers a retry.
    """
    m = (message or "").strip()
    expr_src = re.sub(r"^(what\s+is|calculate|compute|solve)\s+", "", m.lower()).strip(" ?=")
    if re.fullmatch(r"[\d\s+\-*/().,%^]+", expr_src) and any(op in expr_src for op in "+-*/%^"):
        try:
            val = safe_arithmetic(expr_src.replace("^", "**").replace(",", ""))
            return "**%s = %s**" % (m.rstrip("?= "), fmt_number(val))
        except (ValueError, SyntaxError, ZeroDivisionError, OverflowError, RecursionError):
            pass
    return (
        "I could not reach a language model for that one.\n\n"
        "Every live route failed, and I am not going to invent an answer.\n\n"
        "- **Send it again** — free gateways are rate limited and usually recover within seconds.\n"
        "- Or add your own model key in **Settings → Model routing** for a dependable route."
    )


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------
KIND_TEXT = {
    "auth": "the provider rejected the API key",
    "billing": "the provider reports no credit / billing problem",
    "rate_limit": "rate limited by the provider",
    "timeout": "the provider took too long to answer",
    "network": "could not reach the provider",
    "not_found": "model or endpoint not found at the provider",
    "bad_request": "the provider rejected the request",
    "provider": "the provider had an internal error",
    "bad_response": "the provider sent an unusable response",
    "blocked": "the configured address is not allowed",
    "empty": "the provider returned no text",
}


class UpstreamError(Exception):
    def __init__(self, kind, message="", status=None, retry_after=None):
        super().__init__(message or KIND_TEXT.get(kind, kind))
        self.kind = kind
        self.status = status
        self.retry_after = retry_after


def classify_http(code):
    if code in (401, 403):
        return "auth"
    if code == 402:
        return "billing"
    if code == 404:
        return "not_found"
    if code == 408 or code == 504:
        return "timeout"
    if code == 429:
        return "rate_limit"
    if code in (400, 413, 422):
        return "bad_request"
    return "provider" if code >= 500 else "bad_request"


def upstream_from_exception(exc, secrets=()):
    """Turn any urllib / socket / json exception into an UpstreamError."""
    if isinstance(exc, UpstreamError):
        return exc
    if isinstance(exc, urllib.error.HTTPError):
        detail = ""
        try:
            raw = exc.read(2000).decode("utf-8", "replace")
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                parsed = parsed[0] if parsed else {}
            err = parsed.get("error") if isinstance(parsed, dict) else None
            detail = (err.get("message") if isinstance(err, dict) else err) or ""
            detail = str(detail)
        except Exception:  # noqa: BLE001 - body is optional
            detail = ""
        ra = None
        try:
            ra = float(exc.headers.get("Retry-After")) if exc.headers.get("Retry-After") else None
        except (TypeError, ValueError):
            ra = None
        kind = classify_http(exc.code)
        msg = "HTTP %d" % exc.code + (": " + redact(detail, secrets)[:200] if detail else "")
        return UpstreamError(kind, msg, status=exc.code, retry_after=ra)
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return UpstreamError("timeout", "timed out")
    if isinstance(exc, urllib.error.URLError):
        if isinstance(getattr(exc, "reason", None), (socket.timeout, TimeoutError)):
            return UpstreamError("timeout", "timed out")
        return UpstreamError("network", type(getattr(exc, "reason", exc)).__name__)
    if isinstance(exc, (json.JSONDecodeError, UnicodeDecodeError)):
        return UpstreamError("bad_response", "not valid JSON")
    if isinstance(exc, (ConnectionError, OSError)):
        return UpstreamError("network", type(exc).__name__)
    return UpstreamError("provider", type(exc).__name__)


def summarize_errors(errors):
    """['3 rate limited', '2 timeouts'] style one-liner from a list of error dicts."""
    counts = {}
    for e in errors or []:
        counts[e.get("kind", "provider")] = counts.get(e.get("kind", "provider"), 0) + 1
    labels = {"auth": "rejected key", "billing": "no credit", "rate_limit": "rate limited",
              "timeout": "timed out", "network": "unreachable", "not_found": "model not found",
              "bad_request": "request rejected", "provider": "provider error",
              "bad_response": "unusable response", "empty": "empty reply", "blocked": "blocked address"}
    return ", ".join("%d %s" % (n, labels.get(k, k)) for k, n in sorted(counts.items(), key=lambda kv: -kv[1]))


# ---------------------------------------------------------------------------
# Base-URL validation (SSRF guard)
# ---------------------------------------------------------------------------
_base_cache = {}


def _resolve(host, port):
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("Could not resolve host %r." % host)
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        ips.append(ip)
    if not ips:
        raise ValueError("Could not resolve host %r." % host)
    return ips


def validate_base_url(raw, trusted=False):
    """Return a normalised base URL or raise ValueError with a user-readable reason.

    * only http(s), no embedded credentials
    * link-local / metadata / multicast / reserved addresses are always refused
    * private & loopback addresses need `trusted` (server-configured) or ALLOW_PRIVATE_BASES
    * plain http is only accepted for private/loopback hosts (never send a key in clear over the internet)
    Residual risk (documented): DNS can change between this check and the request.
    """
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("empty base URL")
    raw = re.sub(r"/chat/completions/?$", "", raw.rstrip("/"))
    p = urllib.parse.urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Base URL must start with https:// (or http:// for a local server).")
    if p.username or p.password:
        raise ValueError("Base URL must not contain credentials.")
    try:
        port = p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        raise ValueError("Base URL has an invalid port.")
    ck = (raw, bool(trusted), ALLOW_PRIVATE_BASES)
    with _state_lock:
        hit = _base_cache.get(ck)
    if hit and time.time() - hit < 120:
        return raw
    ips = _resolve(p.hostname, port)
    any_private = False
    for ip in ips:
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise ValueError("Base URL points to a link-local or reserved address, which is never allowed.")
        if not ip.is_global:
            any_private = True
    if any_private and not (trusted or ALLOW_PRIVATE_BASES):
        raise ValueError("Base URL points to a private or loopback address. "
                         "Put the key in echo_keys.json, or start the server with ECHO_ALLOW_PRIVATE_BASES=1.")
    if p.scheme == "http" and not all(not ip.is_global for ip in ips):
        raise ValueError("Plain http:// is only accepted for local servers; use https:// for %s." % p.hostname)
    with _state_lock:
        _base_cache[ck] = time.time()
        if len(_base_cache) > 200:
            _base_cache.clear()
    return raw


# ---------------------------------------------------------------------------
# Conversation building
# ---------------------------------------------------------------------------
def build_system_prompt():
    now = datetime.now().astimezone()
    return SYSTEM + "\nCurrent date: %s." % now.strftime("%A, %B %d, %Y")


def _clean_text(s):
    s = str(s or "").replace("\r\n", "\n").replace("\r", "\n")
    s = _CTRL.sub("", s)
    return re.sub(r"\n{4,}", "\n\n\n", s)


def build_messages(message: str, history, files):
    """Multi-turn chat messages, bounded and normalised.

    * only well-formed {role, content} items; roles limited to user/assistant
    * newest messages win when the character budget is exceeded
    * whitespace and code formatting inside history is preserved (the original collapsed it)
    * consecutive same-role turns are merged and a leading assistant turn is dropped, which
      several providers reject
    """
    picked, budget = [], MAX_HISTORY_CHARS
    items = history if isinstance(history, list) else []
    for h in reversed(items[-MAX_HISTORY_MESSAGES:]):
        if not isinstance(h, dict):
            continue
        content = _clean_text(h.get("content"))
        if not content.strip():
            continue
        if len(content) > MAX_HISTORY_MSG_CHARS:
            half = MAX_HISTORY_MSG_CHARS // 2
            content = content[:half] + "\n…[middle of an earlier message trimmed]…\n" + content[-half:]
        if picked and budget - len(content) < 0:
            break
        budget -= len(content)
        picked.append({"role": "assistant" if h.get("role") == "assistant" else "user", "content": content})
    picked.reverse()
    merged = []
    for m in picked:
        if merged and merged[-1]["role"] == m["role"]:
            merged[-1]["content"] += "\n\n" + m["content"]
        else:
            merged.append(dict(m))
    while merged and merged[0]["role"] == "assistant":
        merged.pop(0)
    file_line = ""
    if isinstance(files, list) and files:
        file_line = "\n\nAttached file metadata: " + json.dumps(files[:8], ensure_ascii=False)[:1500]
    last = _clean_text(message) + file_line
    if merged and merged[-1]["role"] == "user":      # previous user turn never got an answer
        merged[-1]["content"] += "\n\n" + last
    else:
        merged.append({"role": "user", "content": last})
    return [{"role": "system", "content": build_system_prompt()}] + merged


def build_prompt(message: str, history, files) -> str:
    """Flat prompt for the Pollinations GET route, which has no chat-message format."""
    turns = []
    for m in build_messages(message, history, files)[1:-1][-10:]:
        turns.append("%s: %s" % (m["role"].upper(), m["content"][:700]))
    last = build_messages(message, [], files)[-1]["content"]
    return "%s\n\nConversation so far:\n%s\n\nUSER: %s\n\nECHO AI:" % (
        build_system_prompt(), "\n".join(turns) or "No previous turns.", last)


# ---------------------------------------------------------------------------
# Response normalisation
# ---------------------------------------------------------------------------
class ThinkFilter:
    """Strip <think>...</think> blocks that some open models put inline in `content`,
    including when a tag is split across streamed chunks."""
    OPEN, CLOSE = "<think>", "</think>"

    def __init__(self):
        self.buf, self.inside = "", False

    @staticmethod
    def _partial(s, tag):
        for k in range(min(len(tag) - 1, len(s)), 0, -1):
            if s.endswith(tag[:k]):
                return k
        return 0

    def feed(self, chunk):
        self.buf += chunk
        out = []
        while True:
            if self.inside:
                i = self.buf.find(self.CLOSE)
                if i < 0:
                    k = self._partial(self.buf, self.CLOSE)
                    self.buf = self.buf[len(self.buf) - k:] if k else ""
                    break
                self.buf = self.buf[i + len(self.CLOSE):].lstrip("\n")
                self.inside = False
            else:
                i = self.buf.find(self.OPEN)
                if i < 0:
                    k = self._partial(self.buf, self.OPEN)
                    out.append(self.buf[:len(self.buf) - k])
                    self.buf = self.buf[len(self.buf) - k:] if k else ""
                    break
                out.append(self.buf[:i])
                self.buf = self.buf[i + len(self.OPEN):]
                self.inside = True
        return "".join(out)

    def flush(self):
        rest = "" if self.inside else self.buf
        self.buf, self.inside = "", False
        return rest


def content_text(value):
    """`content` may be a string or a list of parts depending on the gateway."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join((p.get("text") or "") if isinstance(p, dict) else str(p or "") for p in value)
    return ""


def extract_completion(data):
    """(text, finish_reason, model) from a non-streaming chat-completions body, or raise."""
    if not isinstance(data, dict):
        raise UpstreamError("bad_response", "unexpected response shape")
    err = data.get("error")
    if err:
        msg = err.get("message") if isinstance(err, dict) else err
        raise UpstreamError("provider", redact(str(msg))[:200])
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise UpstreamError("bad_response", "no choices in response")
    ch = choices[0]
    msg = ch.get("message") if isinstance(ch.get("message"), dict) else {}
    text = content_text(msg.get("content")) or content_text(ch.get("text"))
    f = ThinkFilter()
    text = (f.feed(text) + f.flush()).strip()
    if not text:
        raise UpstreamError("empty", "empty model response")
    return text, ch.get("finish_reason"), data.get("model") or None


def post_chat(url, model, messages, headers=None, timeout=45, temperature=0.7, max_tokens=None,
              attempts=2, secrets=()):
    """Non-streaming chat call. Retries once, with backoff, on rate-limit / 5xx / timeout / network
    errors; auth, billing and bad-request errors are final."""
    payload = {"model": model, "messages": messages, "temperature": temperature,
               "max_tokens": max_tokens or MAX_TOKENS}
    h = {"Content-Type": "application/json", "User-Agent": UA}
    if headers:
        h.update(headers)
    body = json.dumps(payload).encode("utf-8")
    last = None
    for attempt in range(max(1, attempts)):
        try:
            req = urllib.request.Request(url, data=body, headers=h, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read(2_000_000).decode("utf-8", "replace"))
            text, finish, used = extract_completion(data)
            return text, used or model, finish
        except Exception as exc:  # noqa: BLE001 - classified below
            last = upstream_from_exception(exc, secrets)
            if last.kind in ("auth", "billing", "bad_request", "not_found", "blocked") or attempt + 1 >= attempts:
                break
            delay = min(last.retry_after if last.retry_after else 0.8 * (attempt + 1), 4.0)
            time.sleep(delay + random.random() * 0.3)
    raise last or UpstreamError("provider", "unknown error")


# ---------------------------------------------------------------------------
# Keyless / free gateways (third-party: they receive your message text)
# ---------------------------------------------------------------------------
KEYLESS_PROVIDERS = [
    {"name": "kilo", "url": "https://api.kilo.ai/api/gateway/v1/chat/completions",
     "model": "kilo-auto/free", "headers": {}, "timeout": 60},
    {"name": "llm7", "url": "https://api.llm7.io/v1/chat/completions",
     "model": "deepseek-v4-pro", "headers": {"Authorization": "Bearer unused"}, "timeout": 45},
    {"name": "ovh", "url": "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1/chat/completions",
     "model": "Meta-Llama-3_3-70B-Instruct", "headers": {}, "timeout": 40},
]

OVH_URL = "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1/chat/completions"
# Each OVHcloud model has its OWN per-IP rate-limit bucket, so racing several of them
# in parallel raises the odds that one answers immediately.
STREAM_PROVIDERS = [
    {"name": "ovh", "url": OVH_URL, "model": "Meta-Llama-3_3-70B-Instruct", "headers": {}},
    {"name": "ovh", "url": OVH_URL, "model": "Mistral-Small-3.2-24B-Instruct-2506", "headers": {}},
    {"name": "ovh", "url": OVH_URL, "model": "gpt-oss-120b", "headers": {}},
    {"name": "ovh", "url": OVH_URL, "model": "Qwen3.5-397B-A17B", "headers": {}},
    {"name": "ovh", "url": OVH_URL, "model": "gpt-oss-20b", "headers": {}},
    {"name": "kilo", "url": "https://api.kilo.ai/api/gateway/v1/chat/completions",
     "model": "kilo-auto/free", "headers": {}},
    {"name": "llm7", "url": "https://api.llm7.io/v1/chat/completions",
     "model": "deepseek-v4-pro", "headers": {"Authorization": "Bearer unused"}},
    {"name": "llm7", "url": "https://api.llm7.io/v1/chat/completions",
     "model": "DeepSeek-V4.1-Flash", "headers": {"Authorization": "Bearer unused"}},
    {"name": "kilo", "url": "https://api.kilo.ai/api/gateway/v1/chat/completions",
     "model": "nvidia/nemotron-3-super-120b-a12b:free", "headers": {}},
]

# Models worth waiting an extra second for. Used when the client asks for "smart" priority.
STRONG_MODELS = {
    "kilo-auto/free", "nvidia/nemotron-3-super-120b-a12b:free", "deepseek-v4-pro",
    "Qwen3.5-397B-A17B", "gpt-oss-120b", "Meta-Llama-3_3-70B-Instruct",
}


def free_stream_providers():
    return [] if DISABLE_FREE else STREAM_PROVIDERS


def free_keyless_providers():
    return [] if DISABLE_FREE else KEYLESS_PROVIDERS


def select_providers(priority):
    pool = free_stream_providers()
    if priority == "smart":
        strong = [p for p in pool if p["model"] in STRONG_MODELS]
        return strong or list(pool)
    return list(pool)


def extract_topic(message: str) -> str:
    q = (message or "").strip().lower()
    q = re.sub(r"\b(in|with)\s+\d+\s+(bullet|bullets|points|sentences)\b", "", q)
    q = re.sub(r"^(please\s+)?(tell me about|what is|who is|explain|describe|define|give me an overview of|teach me about)\s+", "", q).strip()
    q = re.sub(r"[?.!]+$", "", q).strip()
    return q[:120]


def call_wikipedia_summary(message: str) -> str:
    """Last resort that is NOT a language model. The caller labels it as such."""
    topic = extract_topic(message)
    if not topic or len(topic) < 3:
        raise RuntimeError("no topic")
    search_url = "https://en.wikipedia.org/w/api.php?" + urllib.parse.urlencode({
        "action": "opensearch", "search": topic, "limit": 1, "namespace": 0, "format": "json"})
    req = urllib.request.Request(search_url, headers={"User-Agent": "ECHO-AI/%s" % VERSION})
    with urllib.request.urlopen(req, timeout=8) as r:
        data = json.loads(r.read(200000).decode("utf-8", "replace"))
    titles = data[1] if isinstance(data, list) and len(data) > 1 else []
    if not titles:
        raise RuntimeError("no wikipedia title")
    title = titles[0]
    url = "https://en.wikipedia.org/api/rest_v1/page/summary/" + urllib.parse.quote(title.replace(" ", "_"), safe="")
    req = urllib.request.Request(url, headers={"User-Agent": "ECHO-AI/%s" % VERSION})
    with urllib.request.urlopen(req, timeout=8) as r:
        summary = json.loads(r.read(400000).decode("utf-8", "replace"))
    extract = (summary.get("extract") or "").strip()
    if len(extract) < 80:
        raise RuntimeError("weak wikipedia extract")
    sentences = re.split(r"(?<=[.!?])\s+", extract)
    banner = ("> **No language model was reachable.** This is the closest Wikipedia article to your "
              "question, not an AI answer — it may not address what you asked.\n\n")
    if "bullet" in message.lower() or re.search(r"\b\d+\s+(points|sentences)\b", message.lower()):
        return banner + "## " + title + "\n\n" + "\n".join("- " + b for b in sentences[:4] if b) + "\n\n_Source: Wikipedia summary._"
    return banner + "## " + title + "\n\n" + extract + "\n\n_Source: Wikipedia summary._"


def call_pollinations(message: str, history, files) -> str:
    """Anonymous GET route, heavily rate limited. NOTE: the prompt travels in the URL."""
    prompt = build_prompt(message, history, files)[:3600]
    url = POLLINATIONS_URL + urllib.parse.quote(prompt, safe="") + "?" + urllib.parse.urlencode({"referrer": "echo-ai"})
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read(120000).decode("utf-8", "replace").strip()
    except Exception as exc:  # noqa: BLE001
        raise upstream_from_exception(exc)
    if not text or "<html" in text.lower():
        raise UpstreamError("empty", "empty model response")
    return text


# ---------------------------------------------------------------------------
# Provider profiles and key handling
# ---------------------------------------------------------------------------
GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/openai"
PROVIDER_BASES = {
    "groq": "https://api.groq.com/openai/v1", "gemini": GEMINI_BASE,
    "openrouter": "https://openrouter.ai/api/v1", "deepseek": "https://api.deepseek.com/v1",
    "openai": "https://api.openai.com/v1", "cerebras": "https://api.cerebras.ai/v1",
    "mistral": "https://api.mistral.ai/v1", "together": "https://api.together.xyz/v1",
    "xai": "https://api.x.ai/v1", "anthropic": "https://api.anthropic.com/v1",
}
KNOWN_BASES = set(PROVIDER_BASES.values())
ENV_KEYS = {"GROQ_API_KEY": "groq", "GEMINI_API_KEY": "gemini", "GOOGLE_API_KEY": "gemini",
            "OPENROUTER_API_KEY": "openrouter", "DEEPSEEK_API_KEY": "deepseek",
            "CEREBRAS_API_KEY": "cerebras", "MISTRAL_API_KEY": "mistral",
            "TOGETHER_API_KEY": "together", "XAI_API_KEY": "xai", "ANTHROPIC_API_KEY": "anthropic"}
KEY_PREFIXES = [("gsk_", "groq"), ("sk-or-", "openrouter"), ("sk-ant-", "anthropic"),
                ("AIza", "gemini"), ("AQ.", "gemini"), ("xai-", "xai"), ("csk-", "cerebras"),
                ("sk-proj-", "openai")]
NON_CHAT = re.compile(r"embed|whisper|tts|speech|transcri|moderation|guard|image|imagen|veo|dall|"
                      r"rerank|audio|live|aqa|robotics|computer-use|ocr", re.I)

# tier 1 = fast and with a real daily quota, so these race each other.
# tier 2 = usable but hard rate-capped, so they are held back as sequential fallbacks.
KEY_PROFILES = [
    {"match": "api.groq.com", "label": "groq", "tier": 1,
     "fallbacks": ["openai/gpt-oss-120b", "openai/gpt-oss-20b", "qwen/qwen3.8-27b"]},
    {"match": "generativelanguage.googleapis.com", "label": "gemini", "tier": 1,
     "fallbacks": ["gemini-3.1-flash-lite", "gemini-flash-lite-latest", "gemini-flash-latest"]},
    {"match": "openrouter.ai", "label": "openrouter", "tier": 2,
     "fallbacks": ["nvidia/nemotron-3-ultra-550b-a55b:free",
                   "nvidia/nemotron-3-super-120b-a12b:free",
                   "google/gemma-4-31b-it:free"]},
    {"match": "api.deepseek.com", "label": "deepseek", "tier": 2, "fallbacks": ["deepseek-chat"]},
    {"match": "api.openai.com", "label": "openai", "tier": 2, "fallbacks": ["gpt-4o-mini"]},
    {"match": "api.cerebras.ai", "label": "cerebras", "tier": 1, "fallbacks": []},
    {"match": "api.mistral.ai", "label": "mistral", "tier": 2, "fallbacks": []},
    {"match": "api.together.xyz", "label": "together", "tier": 2, "fallbacks": []},
    {"match": "api.x.ai", "label": "xai", "tier": 2, "fallbacks": []},
    {"match": "api.anthropic.com", "label": "anthropic", "tier": 2, "fallbacks": []},
]
DEFAULT_PROFILE = {"label": "your-model", "tier": 1, "fallbacks": []}


def profile_for(base):
    for prof in KEY_PROFILES:
        if prof["match"] in (base or ""):
            return prof
    return DEFAULT_PROFILE


def detect_key(key):
    """Guess (provider label, base URL) from the key's shape. ('', '') if unknown."""
    for prefix, label in KEY_PREFIXES:
        if key.startswith(prefix):
            return label, PROVIDER_BASES[label]
    if re.fullmatch(r"sk-[0-9a-f]{32}", key):
        return "deepseek", PROVIDER_BASES["deepseek"]
    if key.startswith("sk-"):
        return "openai", PROVIDER_BASES["openai"]
    return "", ""


# --- caches (guarded by _state_lock) ---------------------------------------
_models_cache = {}   # key_id -> {"at", "status", "models", "kind", "message"}
_dead = {}           # key_id -> retry-after timestamp (auth/billing failure seen at runtime)
_verified = {}       # key_id -> timestamp of a successful real chat test
AUTH_DEAD = ("HTTP 401", "HTTP 402", "HTTP 403")


def _cached_models(key, base):
    with _state_lock:
        c = _models_cache.get(key_id(key, base or ""))
        return list(c["models"]) if c and c["status"] == "ok" else []


def is_dead(key, base):
    kid = key_id(key, base or "")
    with _state_lock:
        c = _models_cache.get(kid)
        return ((c is not None and c["status"] in AUTH_DEAD and time.time() - c["at"] < DEAD_TTL)
                or _dead.get(kid, 0) > time.time())


def mark_dead(prov):
    auth = (prov.get("headers") or {}).get("Authorization", "")
    base = prov["url"].rsplit("/chat/completions", 1)[0]
    if auth.startswith("Bearer ") and auth != "Bearer unused":
        with _state_lock:
            _dead[key_id(auth[7:], base)] = time.time() + DEAD_TTL


def _expand_key(key, base, model, label=None, tier=None):
    """One configured key -> one provider entry per candidate model, best first."""
    prof = profile_for(base)
    found = _cached_models(key, base)
    extra = prof["fallbacks"] or found[:3]
    model = model or (extra[0] if extra else "")
    if not model:
        return []
    models = [model] + [m for m in extra if m != model]
    use_tier = tier if tier in (1, 2) else prof["tier"]
    return [{"name": label or prof["label"], "url": base + "/chat/completions", "model": m,
             "tier": use_tier, "headers": {"Authorization": "Bearer " + key}}
            for m in models]


# --- server-held keys: echo_keys.json -----------------------------------------
KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "echo_keys.json")
_key_cache = {"mtime": None, "keys": []}
_keyfile_lock = threading.Lock()


def load_key_file():
    """Keys from echo_keys.json, re-read whenever the file changes. Never serialised to the browser."""
    try:
        mtime = os.path.getmtime(KEY_FILE)
    except OSError:
        with _state_lock:
            _key_cache["mtime"], _key_cache["keys"] = None, []
        return load_vault_key_file()
    with _state_lock:
        if _key_cache["mtime"] == mtime:
            cached = list(_key_cache["keys"])
            return cached + load_vault_key_file()
    rows = []
    try:
        with open(KEY_FILE, "r", encoding="utf-8") as fh:
            blob = json.load(fh)
        for row in (blob.get("keys") or [])[:24]:
            if isinstance(row, str):
                row = {"apiKey": row}
            if isinstance(row, dict) and str(row.get("apiKey") or "").strip():
                rows.append({
                    "apiKey": str(row["apiKey"]).strip(),
                    "baseUrl": str(row.get("baseUrl") or "").strip() or None,
                    "model": str(row.get("model") or "").strip() or None,
                    "provider": str(row.get("provider") or "").strip() or None,
                    "enabled": bool(row.get("enabled", True)),
                    "tier": row.get("tier") if row.get("tier") in (1, 2) else None,
                    "note": str(row.get("note") or "")[:300],
                    "_source": str(row.get("_source") or "file"),
                })
    except Exception as exc:  # noqa: BLE001 - a broken key file must not take the server down
        sys.stderr.write("echo_keys.json could not be read: %s\n" % type(exc).__name__)
        rows = []
    with _state_lock:
        _key_cache["mtime"], _key_cache["keys"] = mtime, rows
    return list(rows) + load_vault_key_file()


def _vault_fernet():
    if len(ECHO_MASTER_KEY) < 32:
        return None
    try:
        from cryptography.fernet import Fernet
        material = hashlib.sha256(ECHO_MASTER_KEY.encode("utf-8")).digest()
        return Fernet(base64.urlsafe_b64encode(material))
    except Exception:
        return None


def vault_available():
    return bool(ECHO_ADMIN_PASSWORD and len(ECHO_ADMIN_PASSWORD) >= 16 and _vault_fernet())


def load_vault_key_file():
    """Decrypt server-only key vault; secrets are never returned by this helper to the UI."""
    if not os.path.exists(VAULT_FILE):
        return []
    fernet = _vault_fernet()
    if not fernet:
        return []
    try:
        with open(VAULT_FILE, "rb") as fh:
            raw = fernet.decrypt(fh.read(2_000_000))
        blob = json.loads(raw.decode("utf-8"))
        rows = []
        for row in (blob.get("keys") or [])[:24]:
            if isinstance(row, dict) and str(row.get("apiKey") or "").strip():
                rows.append({
                    "apiKey": str(row["apiKey"]).strip(),
                    "baseUrl": str(row.get("baseUrl") or "").strip() or None,
                    "model": str(row.get("model") or "").strip() or None,
                    "provider": str(row.get("provider") or "").strip() or None,
                    "enabled": bool(row.get("enabled", True)),
                    "tier": row.get("tier") if row.get("tier") in (1, 2) else None,
                    "note": "Encrypted server vault", "_source": "vault",
                })
        return rows
    except Exception as exc:
        sys.stderr.write("ECHO encrypted vault could not be read: %s\n" % type(exc).__name__)
        return []


def _read_vault_blob():
    if not os.path.exists(VAULT_FILE):
        return {"keys": []}
    fernet = _vault_fernet()
    if not fernet:
        raise RuntimeError("Secure vault is not configured. Set ECHO_MASTER_KEY (32+ characters).")
    try:
        with open(VAULT_FILE, "rb") as fh:
            raw = fernet.decrypt(fh.read(2_000_000))
        blob = json.loads(raw.decode("utf-8"))
        if not isinstance(blob, dict) or not isinstance(blob.get("keys", []), list):
            raise ValueError("invalid vault format")
        return blob
    except Exception as exc:
        raise RuntimeError("Encrypted vault could not be unlocked; check ECHO_MASTER_KEY or restore a backup.") from exc


def _write_vault_blob(blob):
    fernet = _vault_fernet()
    if not fernet:
        raise RuntimeError("Secure vault is unavailable. Configure ECHO_ADMIN_PASSWORD and ECHO_MASTER_KEY.")
    payload = fernet.encrypt(json.dumps(blob, ensure_ascii=False).encode("utf-8"))
    parent = os.path.dirname(os.path.abspath(VAULT_FILE))
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".echo-vault.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
        try: os.chmod(tmp, 0o600)
        except OSError: pass
        os.replace(tmp, VAULT_FILE)
    finally:
        if os.path.exists(tmp):
            try: os.unlink(tmp)
            except OSError: pass
    with _state_lock:
        _key_cache["mtime"] = None


def store_vault_key(row):
    key = str(row.get("apiKey") or "").strip()
    if not (8 <= len(key) <= 400) or re.search(r"\s", key):
        raise ValueError("That does not look like an API key.")
    provider = str(row.get("provider") or "").strip()[:40]
    if provider and provider not in PROVIDER_BASES and provider != "custom":
        raise ValueError("Unknown provider.")
    base_in = str(row.get("baseUrl") or "").strip()[:300]
    base, label = resolve_base(key, base_in, provider if provider != "custom" else "")
    if not base:
        raise ValueError("Provider could not be detected. Choose a provider or enter a base URL.")
    base = validate_base_url(base, trusted=base.rstrip("/") in KNOWN_BASES)
    model = str(row.get("model") or "").strip()[:120]
    with _keyfile_lock:
        blob = _read_vault_blob()
        kid = key_id(key, base)
        new = {"apiKey": key, "enabled": True}
        if provider and provider != "custom": new["provider"] = provider
        elif label: new["provider"] = label
        if base_in: new["baseUrl"] = base_in
        if model: new["model"] = model
        hit = next((i for i, old in enumerate(blob["keys"]) if _entry_key_id(old) == kid), None)
        if hit is None:
            if len(blob["keys"]) >= 24: raise ValueError("The secure vault already holds 24 keys.")
            blob["keys"].append(new)
        else:
            merged = dict(blob["keys"][hit]); merged.update(new); blob["keys"][hit] = merged
        _write_vault_blob(blob)
    with _state_lock: _dead.pop(kid, None)
    return next((r for r in key_rows_for_ui() if r["id"] == kid), None)


def modify_vault_key(kid, enabled=None, delete=False):
    with _keyfile_lock:
        blob = _read_vault_blob()
        hit = next((i for i, old in enumerate(blob["keys"]) if _entry_key_id(old) == kid), None)
        if hit is None: return False
        if delete: blob["keys"].pop(hit)
        elif enabled is not None: blob["keys"][hit]["enabled"] = bool(enabled)
        _write_vault_blob(blob)
    return True


def env_key_specs():
    """Keys supplied through environment variables, as (key, base, model, label, tier)."""
    specs = []
    k = os.getenv("ECHO_API_KEY") or os.getenv("OPENAI_API_KEY")
    if k:
        base = os.getenv("ECHO_BASE_URL") or os.getenv("OPENAI_BASE_URL")
        if not base and not detect_key(k.strip())[1]:
            base = PROVIDER_BASES["openai"]       # documented default for ECHO_API_KEY / OPENAI_API_KEY
        specs.append((k, base, os.getenv("ECHO_MODEL") or os.getenv("OPENAI_MODEL"), None, None))
    for var, label in ENV_KEYS.items():
        if os.getenv(var):
            specs.append((os.getenv(var), PROVIDER_BASES.get(label), None, label, None))
    for n in range(2, 10):
        if os.getenv("ECHO_API_KEY_%d" % n):
            specs.append((os.getenv("ECHO_API_KEY_%d" % n), os.getenv("ECHO_BASE_URL_%d" % n),
                          os.getenv("ECHO_MODEL_%d" % n), None, None))
    return specs


def sanitize_keys(raw):
    """Clamp a client-supplied key list to something safe to hand the provider layer."""
    out = []
    if not isinstance(raw, list):
        return out
    for row in raw[:12]:
        if not isinstance(row, dict):
            continue
        key = str(row.get("apiKey") or "").strip()[:400]
        if not key or re.search(r"\s", key):
            continue
        out.append({
            "apiKey": key,
            "baseUrl": str(row.get("baseUrl") or "").strip()[:300] or None,
            "model": str(row.get("model") or "").strip()[:120] or None,
            "provider": str(row.get("provider") or "").strip()[:40] or None,
            "enabled": bool(row.get("enabled", True)),
        })
    return out


def resolve_base(key, base, label):
    """Where this key is allowed to be sent. '' means we cannot tell, so it is sent nowhere."""
    det_label, det_base = detect_key(key)
    return (str(base or "").strip() or PROVIDER_BASES.get(label or "", "") or det_base), (label or det_label)


def user_key_providers(override, raw_out=None, include_dead=False):
    """Every bring-your-own key the caller configured, expanded into provider entries.

    Sources, in order: the caller's `keys` list, the legacy single apiKey/baseUrl/model fields,
    echo_keys.json on the server, then environment variables.

    `raw_out` receives one row per distinct key describing what we know about it, including
    keys that are rejected, unconfigured or have an invalid address -- the original dropped
    rejected keys from this list, so they vanished from the UI for ten minutes.
    A key whose provider cannot be determined is sent NOWHERE (the original defaulted
    to OpenAI, leaking unknown-provider keys to an unrelated company).
    """
    override = override or {}
    entries, seen = [], set()

    def add(key, base, model, enabled=True, label=None, tier=None, source="browser", trusted=False):
        key = str(key or "").strip()
        if not key:
            return
        base, label = resolve_base(key, base, label)
        row = None
        if raw_out is not None:
            b = (base or "").rstrip("/")
            row = next((r for r in raw_out if r["key"] == key and r["base"] == b), None)
            if row is None:
                row = {"key": key, "base": b, "label": label or (profile_for(b)["label"] if b else ""),
                       "model": model, "tier": tier, "source": source, "error": None,
                       "dead": False, "enabled": enabled}
                raw_out.append(row)
        if not enabled:
            return
        if not base:
            if row is not None:
                row["error"] = ("unconfigured", "Provider could not be detected from this key. "
                                "Choose a provider or enter a base URL, then add it again.")
            return
        try:
            base = validate_base_url(base, trusted=trusted or base.rstrip("/") in KNOWN_BASES)
        except ValueError as exc:
            if row is not None:
                row["error"] = ("blocked", str(exc))
            return
        sig = (key, base, str(model or "").strip())
        if sig in seen:
            return
        seen.add(sig)
        dead = is_dead(key, base)
        if row is not None:
            row["base"] = base
            row["dead"] = dead
        if dead and not include_dead:
            return
        exp = _expand_key(key, base, model, label, tier)
        if not exp and row is not None and not row["error"]:
            row["error"] = ("needs_model", "Enter a model name for this endpoint.")
        for e in exp:
            e["source"] = "key"
        entries.extend(exp)

    for row in (override.get("keys") or [])[:12]:
        if isinstance(row, dict) and row.get("enabled", True):
            add(row.get("apiKey"), row.get("baseUrl"), row.get("model"), True, row.get("provider") or None)
    add(override.get("apiKey"), override.get("baseUrl"), override.get("model"))
    for row in load_key_file():
        add(row.get("apiKey"), row.get("baseUrl"), row.get("model"),
            row.get("enabled", True), row.get("provider"), row.get("tier"), source="server", trusted=True)
    for key, base, model, label, tier in env_key_specs():
        add(key, base, model, True, label, tier, source="server", trusted=True)
    return entries


def key_rows_for_ui():
    """What the browser is allowed to know about server-held keys: never the key itself."""
    out = []
    for row in load_key_file():
        base, label = resolve_base(row["apiKey"], row.get("baseUrl"), row.get("provider"))
        prof = profile_for(base)
        out.append({
            "id": key_id(row["apiKey"], base),
            "provider": row.get("provider") or label or prof["label"],
            "masked": mask_key(row["apiKey"]),
            "model": row.get("model") or (prof["fallbacks"][0] if prof["fallbacks"] else ""),
            "enabled": row.get("enabled", True),
            "tier": row.get("tier") or prof["tier"],
            "note": row.get("note") or "",
            "source": row.get("_source", "file"), "locked": False,
        })
    for key, base, model, label, tier in env_key_specs():
        base, label = resolve_base(key, base, label)
        prof = profile_for(base)
        out.append({
            "id": key_id(key, base), "provider": label or prof["label"], "masked": mask_key(key),
            "model": model or (prof["fallbacks"][0] if prof["fallbacks"] else ""),
            "enabled": True, "tier": prof["tier"],
            "note": "From an environment variable; change it where the server is started.",
            "source": "env", "locked": True,
        })
    return out


# --- writing echo_keys.json (loopback clients only; see the handler) --------------
def _read_key_blob():
    try:
        with open(KEY_FILE, "r", encoding="utf-8") as fh:
            blob = json.load(fh)
        if isinstance(blob, dict) and isinstance(blob.get("keys", []), list):
            blob.setdefault("keys", [])
            return blob
    except FileNotFoundError:
        pass
    except Exception:  # noqa: BLE001
        raise RuntimeError("echo_keys.json exists but is not valid JSON; fix or remove it first")
    return {"keys": []}


def _write_key_blob(blob):
    fd, tmp = tempfile.mkstemp(dir=str(ROOT), prefix=".echo_keys.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(blob, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, KEY_FILE)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
    with _state_lock:
        _key_cache["mtime"] = None


def _entry_key_id(entry):
    row = {"apiKey": entry} if isinstance(entry, str) else entry
    if not isinstance(row, dict) or not str(row.get("apiKey") or "").strip():
        return None
    k = str(row["apiKey"]).strip()
    base, _ = resolve_base(k, row.get("baseUrl"), row.get("provider"))
    return key_id(k, base)


def store_key(row):
    """Add or update one key in echo_keys.json. Returns the UI row. Raises ValueError for bad input."""
    key = str(row.get("apiKey") or "").strip()
    if not (8 <= len(key) <= 400) or re.search(r"\s", key):
        raise ValueError("That does not look like an API key.")
    provider = str(row.get("provider") or "").strip()[:40]
    if provider and provider not in PROVIDER_BASES and provider != "custom":
        raise ValueError("Unknown provider.")
    base_in = str(row.get("baseUrl") or "").strip()[:300]
    base, label = resolve_base(key, base_in, provider if provider != "custom" else "")
    if not base:
        raise ValueError("Provider could not be detected from this key. Choose a provider or enter a base URL.")
    base = validate_base_url(base, trusted=base.rstrip("/") in KNOWN_BASES)
    model = str(row.get("model") or "").strip()[:120]
    with _keyfile_lock:
        blob = _read_key_blob()
        if len(blob["keys"]) >= 24:
            raise ValueError("The server key file already holds the maximum of 24 keys.")
        kid = key_id(key, base)
        entry = None
        for e in blob["keys"]:
            if _entry_key_id(e) == kid:
                entry = e
        new = {"apiKey": key, "enabled": True}
        if provider and provider != "custom":
            new["provider"] = provider
        elif label:
            new["provider"] = label
        if base_in:
            new["baseUrl"] = base_in
        if model:
            new["model"] = model
        if entry is None:
            blob["keys"].append(new)
        else:
            idx = blob["keys"].index(entry)
            merged = dict(entry) if isinstance(entry, dict) else {"apiKey": entry}
            merged.update(new)
            blob["keys"][idx] = merged
        _write_key_blob(blob)
    with _state_lock:
        _dead.pop(kid, None)
    return next((r for r in key_rows_for_ui() if r["id"] == kid), None)


def modify_key(kid, enabled=None, delete=False):
    with _keyfile_lock:
        blob = _read_key_blob()
        hit = None
        for e in blob["keys"]:
            if _entry_key_id(e) == kid:
                hit = e
        if hit is None:
            return False
        if delete:
            blob["keys"].remove(hit)
        elif enabled is not None:
            idx = blob["keys"].index(hit)
            row = dict(hit) if isinstance(hit, dict) else {"apiKey": hit}
            row["enabled"] = bool(enabled)
            blob["keys"][idx] = row
        _write_key_blob(blob)
    return True


# ---------------------------------------------------------------------------
# Streaming engine
# ---------------------------------------------------------------------------
class ClientGone(Exception):
    """Raised when the browser disconnects mid-stream."""


def _stream_one(prov, messages, out_q, stop_event, timeout=70, secrets=()):
    """Stream one provider into the shared queue until told to stop."""
    name = prov["name"]
    think = ThinkFilter()
    clean_end, finish = False, None
    try:
        body = json.dumps({"model": prov["model"], "messages": messages, "stream": True,
                           "temperature": 0.7, "max_tokens": MAX_TOKENS}).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": UA, "Accept": "text/event-stream"}
        headers.update(prov.get("headers") or {})
        req = urllib.request.Request(prov["url"], data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ctype = (r.headers.get("Content-Type") or "").lower()
            if "json" in ctype and "event-stream" not in ctype:
                # the gateway ignored stream=true and answered in one piece
                text, finish, used = extract_completion(json.loads(r.read(2_000_000).decode("utf-8", "replace")))
                out_q.put(("token", name, used or prov["model"], text))
                out_q.put(("done", name, None, {"clean": True, "finish": finish}))
                return
            for raw in r:
                if stop_event.is_set():
                    return
                line = raw.decode("utf-8", "replace").strip()
                if not line or line.startswith(":") or not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    clean_end = True
                    break
                try:
                    j = json.loads(payload)
                except Exception:  # noqa: BLE001 - skip a malformed event, keep the stream
                    continue
                if not isinstance(j, dict):
                    continue
                if j.get("error"):
                    err = j["error"]
                    raise UpstreamError("provider", redact((err.get("message") if isinstance(err, dict) else err) or "", secrets)[:200])
                choices = j.get("choices")
                choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
                delta = content_text((choice.get("delta") or {}).get("content"))
                if delta:
                    delta = think.feed(delta)
                    if delta:
                        out_q.put(("token", name, j.get("model") or prov["model"], delta))
                if choice.get("finish_reason"):
                    finish = choice["finish_reason"]
                    clean_end = True
        tail = think.flush()
        if tail:
            out_q.put(("token", name, prov["model"], tail))
        out_q.put(("done", name, None, {"clean": clean_end, "finish": finish}))
    except Exception as exc:  # noqa: BLE001 - classified, never silently swallowed
        e = upstream_from_exception(exc, secrets)
        if e.kind in ("auth", "billing") and e.status in (401, 402, 403):
            mark_dead(prov)
        out_q.put(("error", name, None, {"kind": e.kind, "message": str(e)}))


def race_stream(messages, emit, providers, errors_out=None, info=None, heartbeat=None, secrets=()):
    """Start every provider at once; the first to emit real text wins and the rest are dropped.

    `emit(obj)` writes one SSE event; `heartbeat()` is called about every 2 s while waiting so a
    vanished browser is noticed (and the upstream requests stopped) before the first token.
    Returns True if a model produced text. `info` is filled with what happened to the winner:
    provider, model, finish, interrupted (error dict) and stalled (no completion signal).
    """
    providers = list(providers)
    if not providers:
        return False
    info = info if info is not None else {}
    out_q: "queue.Queue" = queue.Queue()
    stops, by_name = {}, {}
    for idx, prov in enumerate(providers):
        tagged = dict(prov, name="%s#%d" % (prov["name"], idx))
        stops[tagged["name"]] = threading.Event()
        by_name[tagged["name"]] = prov
        threading.Thread(target=_stream_one, args=(tagged, messages, out_q, stops[tagged["name"]], 70, secrets),
                         daemon=True).start()

    winner, got_text, last_token_at = None, False, None
    finished = set()
    started = time.time()
    deadline = started + 120
    IDLE_AFTER_TEXT = 12.0     # some gateways keep the socket open and never send [DONE]
    NO_WINNER_GIVEUP = 40.0
    last_beat = time.time()
    try:
        while time.time() < deadline:
            try:
                kind, name, model, data = out_q.get(timeout=0.5)
            except queue.Empty:
                now = time.time()
                if heartbeat and now - last_beat >= 2.0:
                    last_beat = now
                    heartbeat()
                if len(finished) >= len(providers):
                    break
                if got_text and last_token_at and now - last_token_at > IDLE_AFTER_TEXT:
                    info["stalled"] = True      # winner went quiet without a completion signal
                    break
                if winner is None and now - started > NO_WINNER_GIVEUP:
                    if errors_out is not None:
                        errors_out.append({"kind": "timeout", "message": "no provider answered in time"})
                    break
                continue
            if kind == "token":
                if winner is None:
                    winner = name
                    for other, ev in stops.items():
                        if other != name:
                            ev.set()
                    p = by_name[name]
                    info["provider"], info["model"] = p["name"], model
                    emit({"type": "meta", "provider": p["name"], "model": model,
                          "source": p.get("source", "free")})
                if name == winner:
                    got_text = True
                    last_token_at = time.time()
                    emit({"type": "token", "v": data})
            else:
                finished.add(name)
                if kind == "error":
                    err = dict(data or {}, model=by_name[name].get("model"))
                    if name == winner:
                        info["interrupted"] = err
                    if errors_out is not None:
                        errors_out.append(err)
                elif name == winner:
                    info["finish"] = (data or {}).get("finish")
                    if not (data or {}).get("clean"):
                        info["stalled"] = True
                if name == winner:
                    break
                if winner is None and len(finished) >= len(providers):
                    break
    finally:
        for ev in stops.values():
            ev.set()
    return got_text


def run_user_keys(messages, emit, providers, errors_out=None, info=None, heartbeat=None, secrets=()):
    """Spend the user's own keys in the cheapest order that still feels instant.

    The primary model of every tier-1 key races in parallel, so the fastest provider the user
    owns sets the latency floor. Only if those all come back empty do the alternate models and
    the rate-capped tier-2 keys get tried, one at a time.
    """
    primary, backup, held, seen_keys = [], [], [], set()
    for prov in providers:
        if prov.get("tier", 1) != 1:
            held.append(prov)
            continue
        sig = (prov["url"], tuple(sorted((prov.get("headers") or {}).items())))
        if sig in seen_keys:
            backup.append(prov)
        else:
            seen_keys.add(sig)
            primary.append(prov)
    if primary and race_stream(messages, emit, primary, errors_out, info, heartbeat, secrets):
        return True
    for prov in backup + held:
        if race_stream(messages, emit, [prov], errors_out, info, heartbeat, secrets):
            return True
    return False


# ---------------------------------------------------------------------------
# Non-streaming chain, model discovery and verification
# ---------------------------------------------------------------------------
def call_configured(messages, override=None, secrets=()):
    """A real OpenAI-compatible provider from the user's keys, tried in order."""
    provs = user_key_providers(override)
    if not provs:
        raise UpstreamError("auth", "no usable API key configured")
    errors = []
    for prov in provs:
        try:
            text, model, finish = post_chat(prov["url"], prov["model"], messages,
                                            headers=prov.get("headers") or {}, timeout=75, secrets=secrets)
            return text, model, finish
        except UpstreamError as exc:
            if exc.kind in ("auth", "billing"):
                mark_dead(prov)
            errors.append({"kind": exc.kind, "message": str(exc), "model": prov["model"]})
    raise UpstreamError(errors[0]["kind"] if errors else "provider", summarize_errors(errors))


def call_keyless(messages):
    errors = []
    for prov in free_keyless_providers():
        try:
            text, model, finish = post_chat(prov["url"], prov["model"], messages,
                                            headers=prov["headers"], timeout=prov["timeout"], attempts=1)
            return text, prov["name"], model, finish
        except UpstreamError as exc:
            errors.append({"kind": exc.kind, "message": str(exc)})
    raise UpstreamError("network", "all free gateways failed (%s)" % summarize_errors(errors))


def generate_reply(message, history, files, override=None, chosen=None, secrets=()):
    """Full non-streaming chain, real models first.

    Returns a dict: reply, provider, model, fallback (True when the text is NOT a language-model
    answer), errors (list of {kind, message}).
    """
    messages = build_messages(message, history, files)
    errors = []

    def ok(text, provider, model, finish=None):
        return {"reply": text, "provider": provider, "model": model, "fallback": False,
                "finish": finish, "errors": errors}

    if chosen:
        try:
            text, model, finish = post_chat(chosen["url"], chosen["model"], messages,
                                            headers=chosen.get("headers") or {}, timeout=75, secrets=secrets)
            return ok(text, chosen["name"], model, finish)
        except UpstreamError as exc:
            errors.append({"kind": exc.kind, "message": str(exc), "model": chosen["model"]})
    try:
        text, model, finish = call_configured(messages, override, secrets)
        return ok(text, "openai-compatible", model, finish)
    except UpstreamError as exc:
        if "no usable API key" not in str(exc):
            errors.append({"kind": exc.kind, "message": str(exc)})
    try:
        text, provider, model, finish = call_keyless(messages)
        return ok(text, provider, model, finish)
    except UpstreamError as exc:
        if not DISABLE_FREE:
            errors.append({"kind": exc.kind, "message": str(exc)})
    if not DISABLE_FREE:
        try:
            return ok(call_pollinations(message, history, files), "pollinations", "pollinations")
        except UpstreamError as exc:
            errors.append({"kind": exc.kind, "message": "pollinations: " + str(exc)})
        try:
            return {"reply": call_wikipedia_summary(message), "provider": "knowledge", "model": "wikipedia",
                    "fallback": True, "finish": None, "errors": errors}
        except Exception:  # noqa: BLE001
            pass
    return {"reply": local_fallback(message, history, files), "provider": "built-in", "model": "offline",
            "fallback": True, "finish": None, "errors": errors}


def fetch_models(key, base, timeout=8):
    """(status, models, kind, message). status is 'ok' or 'HTTP nnn' / an exception name."""
    req = urllib.request.Request(base.rstrip("/") + "/models",
                                 headers={"Authorization": "Bearer " + key, "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read(3_000_000).decode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001
        e = upstream_from_exception(exc, (key,))
        status = "HTTP %d" % e.status if e.status else e.kind
        return status, [], e.kind, str(e)
    rows = data.get("data") if isinstance(data, dict) else data
    ids = set()
    for m in rows or []:
        mid = m.get("id") if isinstance(m, dict) else m
        if isinstance(mid, str):
            mid = mid[7:] if mid.startswith("models/") else mid
            if not NON_CHAT.search(mid):
                ids.add(mid)
    if "openrouter.ai" in base:   # thousands of paid models: only list the free ones
        ids = {i for i in ids if i.endswith(":free")}
    return "ok", sorted(ids)[:80], "ok", ""


def models_payload(override=None, force=False):
    """Probe every configured key in parallel and report what each can actually run.

    Each group carries `state`:
      verified    the provider accepted the key (model listing worked, or a chat test succeeded)
      rejected    the provider refused the key (401/402/403)
      unverified  saved, but the provider could not be reached or has no model-list route
      unconfigured / blocked / needs_model   cannot be used until fixed (message says how)
    A saved configuration is never reported as verified unless something proved it.
    """
    raw = []
    user_key_providers(override, raw, include_dead=True)
    now = time.time()
    todo = []
    for r in raw:
        if r["error"] or not r["base"]:
            continue
        kid = key_id(r["key"], r["base"])
        if force:
            with _state_lock:
                _dead.pop(kid, None)
                _models_cache.pop(kid, None)
        with _state_lock:
            c = _models_cache.get(kid)
        if not c or now - c["at"] > 600:
            todo.append((kid, r))

    def probe(kid, r):
        status, models, kind, message = fetch_models(r["key"], r["base"])
        with _state_lock:
            _models_cache[kid] = {"at": time.time(), "status": status, "models": models,
                                  "kind": kind, "message": message}
            if status == "ok":
                _dead.pop(kid, None)

    threads = [threading.Thread(target=probe, args=t, daemon=True) for t in todo]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    groups = []
    for r in raw:
        base = r["base"] or ""
        prof = profile_for(base)
        if r["error"] or not base:
            kind, msg = r["error"] or ("unconfigured", "Provider could not be detected from this key.")
            groups.append({"keyId": key_id(r["key"], base), "provider": r["label"] or "unknown",
                           "masked": mask_key(r["key"]), "status": "ok", "detail": kind,
                           "state": kind, "verified": False, "kind": kind, "message": msg,
                           "source": r["source"], "models": []})
            continue
        kid = key_id(r["key"], base)
        with _state_lock:
            c = dict(_models_cache.get(kid) or {"status": "pending", "models": [], "kind": "pending", "message": ""})
            chat_ok = _verified.get(kid, 0) > now - VERIFIED_TTL
            dead = c["status"] in AUTH_DEAD or _dead.get(kid, 0) > now
        models = c["models"]
        if not models and not dead:   # provider has no /models route: fall back to known ids
            models = [m for m in ([r["model"]] + prof["fallbacks"]) if m]
        if chat_ok and not dead:
            state, message = "verified", "A real test request succeeded."
        elif dead:
            state, message = "rejected", c.get("message") or KIND_TEXT["auth"]
        elif c["status"] == "ok":
            state, message = "verified", "The provider accepted this key."
        elif c["status"] == "pending":
            state, message = "unverified", "Still checking…"
        else:
            state = "unverified"
            message = "Saved, but could not be confirmed (%s). Use Verify to run a real test." % (
                KIND_TEXT.get(c.get("kind"), c.get("kind") or "unknown"))
        groups.append({"keyId": kid, "provider": r["label"], "masked": mask_key(r["key"]),
                       "status": "dead" if dead else "ok", "detail": c["status"],
                       "state": state, "verified": state == "verified", "kind": c.get("kind"),
                       "message": message, "source": r["source"], "models": [] if dead else models})
    free = []
    for p in free_stream_providers() + free_keyless_providers():
        if p["model"] not in free:
            free.append(p["model"])
    return {"groups": groups, "free": free, "freeEnabled": not DISABLE_FREE}


def resolve_selected(sel, override):
    """The one provider entry the user picked in the UI, or None to use Auto."""
    if not isinstance(sel, dict):
        return None
    model = str(sel.get("model") or "")[:160]
    kid = str(sel.get("keyId") or "")
    if not model:
        return None
    if kid == "free":
        return next((dict(p, source="free") for p in free_stream_providers() + free_keyless_providers()
                     if p["model"] == model), None)
    raw = []
    user_key_providers(override, raw)
    for r in raw:
        if r["base"] and not r["error"] and key_id(r["key"], r["base"]) == kid:
            return {"name": r["label"], "url": r["base"] + "/chat/completions", "model": model,
                    "headers": {"Authorization": "Bearer " + r["key"]}, "source": "key", "tier": 1}
    return None


def verify_key(kid, override):
    """One tiny real chat request, so 'saved' can be told apart from 'works'."""
    raw = []
    user_key_providers(override, raw, include_dead=True)
    row = next((r for r in raw if r["base"] and not r["error"] and key_id(r["key"], r["base"]) == kid), None)
    if row is None:
        bad = next((r for r in raw if r["error"] and key_id(r["key"], r["base"] or "") == kid), None)
        if bad:
            return {"ok": False, "kind": bad["error"][0], "message": bad["error"][1]}
        return {"ok": False, "kind": "not_found", "message": "That key is no longer configured."}
    cands = _expand_key(row["key"], row["base"], row["model"], row["label"], row["tier"])
    if not cands:
        return {"ok": False, "kind": "needs_model", "message": "Enter a model name for this endpoint first."}
    prov, started = cands[0], time.time()
    try:
        _text, model, _fin = post_chat(prov["url"], prov["model"],
                                       [{"role": "user", "content": "Reply with the single word: ok"}],
                                       headers=prov["headers"], timeout=25, max_tokens=24, attempts=1,
                                       secrets=(row["key"],))
        with _state_lock:
            _verified[kid] = time.time()
            _dead.pop(kid, None)
        return {"ok": True, "kind": "ok", "model": model,
                "latency_ms": int((time.time() - started) * 1000),
                "message": "A real test request succeeded."}
    except UpstreamError as exc:
        with _state_lock:
            _verified.pop(kid, None)
        if exc.kind in ("auth", "billing"):
            mark_dead(prov)
        return {"ok": False, "kind": exc.kind, "model": prov["model"],
                "message": redact("%s (%s)" % (KIND_TEXT.get(exc.kind, exc.kind), exc), (row["key"],))}


# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------
VISION_RE = re.compile(r"gemini|gpt-4o|gpt-4\.1|gpt-4-turbo|gpt-5|o4-mini|vision|-vl\b|llava|pixtral|claude|llama-4|gemma-3|qwen[^/]*vl|mistral-(small|medium)-3", re.I)


def is_vision(model):
    """Heuristic by model name: only these get image pixels, everyone else gets text only."""
    return bool(VISION_RE.search(model or ""))


def clean_images(raw):
    out = []
    for img in (raw if isinstance(raw, list) else [])[:3]:
        url = str((img or {}).get("dataUrl") or "") if isinstance(img, dict) else ""
        if re.match(r"data:image/(png|jpeg|jpg|webp|gif);base64,", url) and len(url) < 900_000:
            out.append({"name": str(img.get("name") or "image")[:80], "dataUrl": url})
    return out


def with_images(messages, images):
    out = [dict(m) for m in messages]
    parts = [{"type": "text", "text": out[-1]["content"]}]
    parts += [{"type": "image_url", "image_url": {"url": i["dataUrl"]}} for i in images]
    out[-1]["content"] = parts
    return out


# ---------------------------------------------------------------------------
# Abuse limits
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self):
        self.hits, self.lock = {}, threading.Lock()

    def allow(self, ip, limit, window=60.0):
        now = time.time()
        with self.lock:
            q = self.hits.setdefault(ip, deque())
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return max(1, int(window - (now - q[0])) + 1)
            q.append(now)
            # Prune stale clients instead of clearing every bucket: a burst of spoofed
            # addresses must not erase other users' active rate-limit history.
            if len(self.hits) > 2000:
                stale = [k for k, hits in self.hits.items() if not hits or now - hits[-1] > window]
                for key in stale:
                    self.hits.pop(key, None)
                if len(self.hits) > 2000:
                    oldest = min(self.hits, key=lambda key: self.hits[key][-1] if self.hits[key] else 0)
                    if oldest != ip:
                        self.hits.pop(oldest, None)
            return 0


_limiter = RateLimiter()
_chat_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CHATS)


class RequestError(Exception):
    def __init__(self, status, kind, message, headers=None):
        super().__init__(message)
        self.status, self.kind, self.headers = status, kind, headers or {}


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
PAGE_CANDIDATES = ["echo_ai_upgraded.html", "index.html", "ECHO_AI_PRO.html"]
PAGE = "index.html"


def _peer_is_loopback(addr):
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        return ip.is_loopback
    except ValueError:
        return False


class EchoHandler(SimpleHTTPRequestHandler):
    # Keep the banner generic; avoid disclosing the Python version in Server headers.
    server_version = "ECHO"
    sys_version = ""
    timeout = 30     # a stalled client cannot hold a worker forever (applies per socket operation)

    BLOCKED_FILES = {"echo_keys.json", "echo_vault.enc", ".env"}
    STATIC_EXT = {".html", ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
                  ".ico", ".woff", ".woff2", ".ttf", ".txt", ".mp3", ".wav", ".webmanifest"}

    # ---- plumbing -------------------------------------------------------
    def translate_path(self, path):
        # Only web assets inside ROOT: no ../ escapes, no .py / .json / dotfiles.
        path = urllib.parse.unquote(urllib.parse.urlparse(path).path)
        if path in ("", "/"):
            path = "/" + PAGE
        target = (ROOT / path.lstrip("/")).resolve()
        try:
            target.relative_to(ROOT)
        except ValueError:
            return str(ROOT / "__forbidden__")
        if target.suffix.lower() not in self.STATIC_EXT or target.name.startswith("."):
            return str(ROOT / "__forbidden__")
        return str(target)

    def send_header(self, keyword, value):
        if keyword.lower() == "cache-control":
            self._has_cc = True
        super().send_header(keyword, value)

    def end_headers(self):
        if not getattr(self, "_has_cc", False):
            super().send_header("Cache-Control", "no-store")
        self._has_cc = False
        super().send_header("X-Content-Type-Options", "nosniff")
        super().send_header("X-Frame-Options", "DENY")
        super().send_header("Referrer-Policy", "no-referrer")
        super().send_header("Permissions-Policy", "camera=(), geolocation=(), payment=(), microphone=()")
        super().send_header("Cross-Origin-Opener-Policy", "same-origin")
        super().send_header("X-Permitted-Cross-Domain-Policies", "none")
        # The current single-file UI uses inline scripts/styles and a Matter.js CDN.
        # This CSP is a useful defense-in-depth baseline, not a replacement for nonces.
        super().send_header("Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data: blob: https:; connect-src 'self'; "
            "media-src 'self' data: blob:; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'; form-action 'self'")
        if self.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower() == "https":
            super().send_header("Strict-Transport-Security", "max-age=31536000")
        super().end_headers()

    def log_message(self, fmt, *args):
        try:
            sys.stderr.write("%s - %s\n" % (self.address_string(), redact(fmt % args)))
        except Exception:  # noqa: BLE001
            pass

    def _json(self, status, obj, headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _fail(self, status, kind, message, headers=None, **extra):
        self._json(status, dict({"error": {"kind": kind, "message": message}}, **extra), headers)

    def _client_ip(self):
        peer = self.client_address[0]
        try:
            peer_ip = ipaddress.ip_address(peer.split("%", 1)[0])
        except ValueError:
            return peer
        # Trust forwarded addresses only when the direct peer belongs to an explicitly
        # configured proxy network. Walk right-to-left through the chain to skip trusted
        # proxies; never trust X-Forwarded-For from arbitrary Internet clients.
        if not any(peer_ip in network for network in TRUSTED_PROXY_NETWORKS):
            return str(peer_ip)
        forwarded = self.headers.get("X-Forwarded-For", "")
        chain = []
        for raw in forwarded.split(","):
            try:
                chain.append(ipaddress.ip_address(raw.strip().split("%", 1)[0]))
            except ValueError:
                continue
        chain.append(peer_ip)
        index = len(chain) - 1
        while index > 0 and any(chain[index] in network for network in TRUSTED_PROXY_NETWORKS):
            index -= 1
        return str(chain[index])

    # ---- request guards -------------------------------------------------
    def _host_ok(self):
        """Refuse unexpected Host headers when bound to loopback (DNS-rebinding defence)."""
        if BOUND_HOST not in ("127.0.0.1", "localhost", "::1"):
            return True
        host = (self.headers.get("Host") or "").strip().lower()
        name = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
        return name in LOOPBACK_NAMES or name in EXTRA_ALLOWED_HOSTS or host in EXTRA_ALLOWED_HOSTS

    def _origin_ok(self):
        """Browsers must be calling us from our own page: same Origin as Host, never cross-site."""
        origin = self.headers.get("Origin")
        if origin:
            return urllib.parse.urlparse(origin).netloc.lower() == (self.headers.get("Host") or "").lower()
        return self.headers.get("Sec-Fetch-Site", "same-origin") in ("same-origin", "none")

    def _guard(self, api=False):
        """Returns True to continue. Sends the error response and returns False otherwise."""
        if not self._host_ok():
            self._fail(421, "bad_host", "Unexpected Host header.")
            return False
        if api and not self._origin_ok():
            self._fail(403, "cross_site", "Cross-site requests are not allowed.")
            return False
        return True

    def _admin_ok(self):
        """Key management is only for whoever runs the server."""
        if _peer_is_loopback(self._client_ip()):
            return True
        self._fail(403, "forbidden", "Keys can only be managed from the machine running the server.")
        return False

    def _vault_cookie_name(self):
        return "echo_vault_session"

    def _vault_session(self):
        cookie = self.headers.get("Cookie", "")
        token = ""
        for part in cookie.split(";"):
            name, sep, value = part.strip().partition("=")
            if name == self._vault_cookie_name() and sep:
                token = value
                break
        now = time.time()
        with _VAULT_SESSION_LOCK:
            for key, expiry in list(_VAULT_SESSIONS.items()):
                if expiry < now: _VAULT_SESSIONS.pop(key, None)
            return bool(token and token in _VAULT_SESSIONS and _VAULT_SESSIONS[token] >= now)

    def _vault_admin_ok(self):
        if not vault_available():
            self._fail(503, "vault_unconfigured", "Secure key vault is disabled. Configure ECHO_ADMIN_PASSWORD (16+ chars), ECHO_MASTER_KEY (32+ chars), and install requirements.")
            return False
        if self._vault_session(): return True
        self._fail(401, "vault_locked", "Unlock the secure server vault first.")
        return False

    def _read_json(self, cap):
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            raise RequestError(411, "bad_request", "Content-Length is required.")
        try:
            length = int(raw_len)
        except ValueError:
            raise RequestError(400, "bad_request", "Invalid Content-Length.")
        if length < 0:
            raise RequestError(400, "bad_request", "Invalid Content-Length.")
        if length > cap:
            raise RequestError(413, "too_large", "Request is too large (limit %d KB)." % (cap // 1000))
        raw = self.rfile.read(length) if length else b""
        if len(raw) < length:
            raise RequestError(400, "bad_request", "Request body was cut short.")
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RequestError(400, "bad_json", "Request body is not valid JSON.")
        if not isinstance(data, dict):
            raise RequestError(400, "bad_json", "Request body must be a JSON object.")
        return data

    def _throttle(self, limit):
        wait = _limiter.allow(self._client_ip(), limit)
        if wait:
            raise RequestError(429, "rate_limit", "Too many requests. Try again in %d s." % wait,
                               {"Retry-After": str(wait)})

    # ---- verbs ----------------------------------------------------------
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, POST, PATCH, DELETE, OPTIONS")
        self.end_headers()

    def do_HEAD(self):
        if not self._guard():
            return
        if self._is_blocked(self.path):
            self.send_error(404)
            return
        super().do_HEAD()

    def _is_blocked(self, path):
        name = os.path.basename(urllib.parse.urlparse(path).path).lower()
        return name in self.BLOCKED_FILES or name.startswith(".env")

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if not self._guard(api=path.startswith("/api/")):
            return
        if self._is_blocked(path):
            self.send_error(404)
            return
        if path == "/api/echo/health":
            self._json(200, {"ok": True, "version": VERSION, "time": int(time.time()),
                             "keyWrite": _peer_is_loopback(self._client_ip()),
                             "vaultAvailable": vault_available(), "vaultUnlocked": self._vault_session(),
                             "freeGateways": not DISABLE_FREE, "imageGeneration": bool(POLLINATIONS_API_KEY and not DISABLE_FREE),
                             "maxTokens": MAX_TOKENS, "limits": {"message": MAX_MESSAGE_CHARS}})
            return
        if path == "/api/echo/keys":
            # Masked previews only. The real key strings never leave this process.
            self._json(200, {"keys": [r for r in key_rows_for_ui() if r.get("source") != "vault"],
                             "writable": _peer_is_loopback(self._client_ip()), "file": "echo_keys.json"})
            return
        if path == "/api/echo/vault/status":
            self._json(200, {"available": vault_available(), "unlocked": self._vault_session()})
            return
        if path == "/api/echo/vault/keys":
            if not self._vault_admin_ok(): return
            self._json(200, {"keys": [r for r in key_rows_for_ui() if r.get("source") == "vault"]})
            return
        if path.startswith("/api/"):
            self._fail(404, "not_found", "Unknown API route.")
            return
        super().do_GET()

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if not self._guard(api=True):
            return
        try:
            if path == "/api/echo/vault/login":
                self._throttle(5)
                if not vault_available():
                    raise RequestError(503, "vault_unconfigured", "Set ECHO_ADMIN_PASSWORD (16+ chars), ECHO_MASTER_KEY (32+ chars), and install requirements.")
                origin = self.headers.get("Origin", "")
                is_https_origin = origin.lower().startswith("https://")
                if not _peer_is_loopback(self._client_ip()) and not is_https_origin:
                    raise RequestError(400, "https_required", "Unlocking the remote vault requires HTTPS. Configure TLS on your hosting platform first.")
                data = self._read_json(10_000)
                supplied = str(data.get("password") or "")
                if not hmac.compare_digest(supplied.encode("utf-8"), ECHO_ADMIN_PASSWORD.encode("utf-8")):
                    raise RequestError(401, "bad_password", "Incorrect vault password.")
                token = secrets.token_urlsafe(32)
                with _VAULT_SESSION_LOCK: _VAULT_SESSIONS[token] = time.time() + _VAULT_SESSION_TTL
                secure = "; Secure" if (self.headers.get("X-Forwarded-Proto", "").lower() == "https" or self.headers.get("Origin", "").startswith("https://")) else ""
                self._json(200, {"ok": True, "unlocked": True}, {"Set-Cookie": self._vault_cookie_name() + "=" + token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" + str(_VAULT_SESSION_TTL) + secure})
            elif path == "/api/echo/vault/logout":
                cookie = self.headers.get("Cookie", "")
                for part in cookie.split(";"):
                    name, sep, value = part.strip().partition("=")
                    if name == self._vault_cookie_name() and sep:
                        with _VAULT_SESSION_LOCK: _VAULT_SESSIONS.pop(value, None)
                self._json(200, {"ok": True}, {"Set-Cookie": self._vault_cookie_name() + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"})
            elif path == "/api/echo/vault/keys":
                if not self._vault_admin_ok(): return
                self._throttle(ADMIN_RATE_PER_MIN)
                data = self._read_json(20_000)
                try: row = store_vault_key(data)
                except ValueError as e: raise RequestError(400, "bad_request", str(e))
                except RuntimeError as e: raise RequestError(409, "conflict", str(e))
                self._json(201, {"ok": True, "key": row, "keys": [r for r in key_rows_for_ui() if r.get("source") == "vault"]})
            elif path == "/api/echo/models":
                self._throttle(ADMIN_RATE_PER_MIN)
                self.handle_models()
            elif path == "/api/echo/verify":
                self._throttle(ADMIN_RATE_PER_MIN)
                self.handle_verify()
            elif path == "/api/echo/keys":
                self._throttle(ADMIN_RATE_PER_MIN)
                self.handle_key_add()
            elif path == "/api/echo/stream":
                self._throttle(CHAT_RATE_PER_MIN)
                self.handle_stream()
            elif path == "/api/echo/image":
                self._throttle(max(3, CHAT_RATE_PER_MIN // 4))
                self.handle_image_generation()
            elif path == "/api/echo/slides":
                self._throttle(max(3, CHAT_RATE_PER_MIN // 4))
                self.handle_slide_generation()
            elif path == "/api/echo":
                self._throttle(CHAT_RATE_PER_MIN)
                self.handle_json()
            else:
                self._fail(404, "not_found", "Unknown API route.")
        except RequestError as e:
            self._fail(e.status, e.kind, str(e), e.headers)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_PATCH(self):
        self._key_item("PATCH")

    def do_DELETE(self):
        self._key_item("DELETE")

    def handle_image_generation(self):
        if DISABLE_FREE:
            raise RequestError(503, "disabled", "Image generation is disabled by ECHO_DISABLE_FREE=1.")
        if not POLLINATIONS_API_KEY:
            raise RequestError(503, "image_key_missing", "Set POLLINATIONS_API_KEY in the server environment to enable image generation. The provider may require available credits.")
        data = self._read_json(12_000)
        prompt = trim(str(data.get("prompt", "")), 1800)
        if not prompt:
            raise RequestError(400, "bad_request", "Describe the image you want to generate.")
        url = "https://gen.pollinations.ai/image/" + urllib.parse.quote(prompt, safe="") + "?" + urllib.parse.urlencode({"width": 1024, "height": 1024, "model": "black-forest-labs/flux.1-schnell"})
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "image/png,image/jpeg,image/webp,*/*", "Authorization": "Bearer " + POLLINATIONS_API_KEY})
        try:
            with urllib.request.urlopen(req, timeout=75) as response:
                content_type = (response.headers.get("Content-Type") or "").split(";", 1)[0].lower()
                payload = response.read(10_000_001)
        except Exception as exc:  # noqa: BLE001
            raise RequestError(502, "image_provider", "Image generation failed or the image provider is unavailable. Try again later.") from exc
        if len(payload) > 10_000_000:
            raise RequestError(502, "image_too_large", "The generated image was too large to return.")
        if content_type not in ("image/png", "image/jpeg", "image/webp"):
            raise RequestError(502, "image_provider", "The image provider did not return an image. It may be unavailable right now.")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Disposition", "inline; filename=echo-generated-image")
        self.end_headers()
        self.wfile.write(payload)

    def handle_slide_generation(self):
        data = self._read_json(100_000)
        slides = data.get("slides")
        if not isinstance(slides, list) or not slides or len(slides) > 15:
            raise RequestError(400, "bad_request", "Provide between 1 and 15 slides.")
        clean = []
        for slide in slides:
            if not isinstance(slide, dict):
                continue
            st = trim(str(slide.get("title", "Slide")), 160) or "Slide"
            bullets = slide.get("bullets", [])
            if not isinstance(bullets, list):
                bullets = [str(bullets)]
            clean.append({"title": st, "bullets": [trim(str(b), 500) for b in bullets[:8] if str(b).strip()]})
        if not clean:
            raise RequestError(400, "bad_request", "No valid slides were provided.")
        try:
            payload = make_pptx({"title": trim(str(data.get("title", "ECHO Presentation")), 160), "slides": clean})
        except (ValueError, TypeError, KeyError) as exc:
            raise RequestError(400, "bad_request", "The slide outline could not be converted to PowerPoint.") from exc
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.openxmlformats-officedocument.presentationml.presentation")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Content-Disposition", 'attachment; filename="echo-presentation.pptx"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    # ---- key management -------------------------------------------------
    def _key_item(self, verb):
        path = urllib.parse.urlparse(self.path).path
        vm = re.fullmatch(r"/api/echo/vault/keys/([0-9a-f]{12})", path)
        if vm:
            if not self._guard(api=True): return
            if not self._vault_admin_ok(): return
            try:
                self._throttle(ADMIN_RATE_PER_MIN)
                if verb == "DELETE": done = modify_vault_key(vm.group(1), delete=True)
                else:
                    data = self._read_json(10_000)
                    if "enabled" not in data: raise RequestError(400, "bad_request", "Expected enabled true or false.")
                    done = modify_vault_key(vm.group(1), enabled=bool(data["enabled"]))
                if not done:
                    self._fail(404, "not_found", "That key is not in the secure vault."); return
                self._json(200, {"ok": True, "keys": [r for r in key_rows_for_ui() if r.get("source") == "vault"]})
            except RequestError as e: self._fail(e.status, e.kind, str(e), e.headers)
            except RuntimeError as e: self._fail(409, "conflict", str(e))
            return
        m = re.fullmatch(r"/api/echo/keys/([0-9a-f]{12})", path)
        if not self._guard(api=True):
            return
        if not m:
            self._fail(404, "not_found", "Unknown API route.")
            return
        if not self._admin_ok():
            return
        try:
            self._throttle(ADMIN_RATE_PER_MIN)
            if verb == "DELETE":
                done = modify_key(m.group(1), delete=True)
            else:
                data = self._read_json(10_000)
                if "enabled" not in data:
                    raise RequestError(400, "bad_request", "Expected {\"enabled\": true|false}.")
                done = modify_key(m.group(1), enabled=bool(data["enabled"]))
            if not done:
                self._fail(404, "not_found", "That key is not stored on the server (environment keys are read-only).")
                return
            self._json(200, {"ok": True, "keys": key_rows_for_ui()})
        except RequestError as e:
            self._fail(e.status, e.kind, str(e), e.headers)
        except RuntimeError as e:
            self._fail(409, "conflict", str(e))

    def handle_key_add(self):
        if not self._admin_ok():
            return
        data = self._read_json(20_000)
        try:
            row = store_key(data)
        except ValueError as e:
            raise RequestError(400, "bad_request", str(e))
        except RuntimeError as e:
            raise RequestError(409, "conflict", str(e))
        except OSError as e:
            raise RequestError(500, "provider", "Could not write echo_keys.json (%s)." % type(e).__name__)
        self._json(201, {"ok": True, "key": row, "keys": key_rows_for_ui()})

    # ---- discovery / verification ---------------------------------------
    def handle_models(self):
        data = self._read_json(MAX_JSON_BODY)
        override = {"keys": sanitize_keys(data.get("keys"))}
        self._json(200, models_payload(override, bool(data.get("refresh"))))

    def handle_verify(self):
        data = self._read_json(MAX_JSON_BODY)
        kid = str(data.get("keyId") or "")
        if not re.fullmatch(r"[0-9a-f]{12}", kid):
            raise RequestError(400, "bad_request", "keyId is required.")
        override = {"keys": sanitize_keys(data.get("keys"))}
        self._json(200, verify_key(kid, override))

    # ---- chat -----------------------------------------------------------
    def _chat_request(self, cap):
        data = self._read_json(cap)
        message = str(data.get("message", ""))[:MAX_MESSAGE_CHARS]
        override = {
            "apiKey": str(data.get("apiKey") or "")[:400] or None,
            "baseUrl": str(data.get("baseUrl") or "")[:300] or None,
            "model": str(data.get("model") or "")[:120] or None,
            "keys": sanitize_keys(data.get("keys")),
        }
        secrets = [override["apiKey"]] + [k["apiKey"] for k in override["keys"]]
        files = data.get("files") if isinstance(data.get("files"), list) else []
        history = data.get("conversationHistory") if isinstance(data.get("conversationHistory"), list) else []
        return data, message, history, files, override, [s for s in secrets if s]

    def handle_stream(self):
        """Server-sent events: the first token reaches the browser as soon as a model produces it."""
        data, message, history, files, override, secrets = self._chat_request(MAX_STREAM_BODY)
        images = clean_images(data.get("images"))
        if not message.strip() and not images:
            raise RequestError(400, "bad_request", "Message is empty.")
        if not _chat_slots.acquire(blocking=False):
            raise RequestError(429, "busy", "The server is busy with other chats. Try again in a moment.",
                               {"Retry-After": "3"})
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()

            def emit(obj):
                try:
                    self.wfile.write(("data: " + json.dumps(obj, ensure_ascii=False) + "\n\n").encode("utf-8"))
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    raise ClientGone()

            def heartbeat():
                try:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    raise ClientGone()

            try:
                self._stream_chat(message, history, files, images, override, secrets, data, emit, heartbeat)
            except ClientGone:
                return
            except Exception as exc:  # noqa: BLE001
                sys.stderr.write("stream failed: %s\n" % type(exc).__name__)
                try:
                    emit({"type": "error", "kind": "provider", "message": "The server hit an internal error."})
                    emit({"type": "done"})
                except ClientGone:
                    pass
        finally:
            _chat_slots.release()

    def _stream_chat(self, message, history, files, images, override, secrets, data, emit, heartbeat):
        priority = str(data.get("priority") or "smart")
        messages = build_messages(message, history, files)
        image_messages = with_images(messages, images) if images else None
        dropped = []

        def route(provs):
            """Pixels go only to models that can see them; everyone else gets text plus an honest note."""
            if image_messages:
                seeing = [p for p in provs if is_vision(p.get("model", ""))]
                if seeing:
                    return image_messages, seeing
                if not dropped:
                    dropped.append(1)
                    messages[-1]["content"] += ("\n\n[The user attached %d image(s) that you cannot see. "
                                                "Do not describe them.]" % len(images))
                    emit({"type": "notice", "kind": "no_vision",
                          "message": "No vision-capable model is available for this request, so the image was not sent."})
            return messages, provs

        errors, info, answered = [], {}, False
        chosen = resolve_selected(data.get("selected"), override)
        if chosen:
            m_, p_ = route([chosen])
            answered = race_stream(m_, emit, p_, errors, info, heartbeat, secrets)
            if not answered:
                emit({"type": "notice", "kind": errors[-1]["kind"] if errors else "provider",
                      "message": "%s could not answer (%s). Switching to Auto." % (
                          chosen["model"], KIND_TEXT.get(errors[-1]["kind"], "no response") if errors else "no response")})
        mine = user_key_providers(override)
        if mine and not answered:
            key_errors = []
            m_, p_ = route(mine)
            answered = run_user_keys(m_, emit, p_, key_errors, info, heartbeat, secrets)
            if not answered:
                errors.extend(key_errors)
                emit({"type": "notice", "kind": key_errors[0]["kind"] if key_errors else "provider",
                      "message": "Your configured API key could not answer (%s). Falling back to free models."
                                 % (summarize_errors(key_errors) or "no response")})
        if not answered and free_stream_providers():
            free_errors = []
            m_, p_ = route(select_providers(priority))
            answered = race_stream(m_, emit, p_, free_errors, info, heartbeat, secrets)
            errors.extend(free_errors)
        if answered:
            if info.get("interrupted"):
                kind = info["interrupted"].get("kind", "provider")
                emit({"type": "interrupted", "kind": kind,
                      "message": "The reply was cut off: %s." % KIND_TEXT.get(kind, kind)})
            elif info.get("finish") == "length":
                emit({"type": "truncated",
                      "message": "The model stopped because it reached the length limit."})
            elif info.get("stalled"):
                emit({"type": "incomplete",
                      "message": "The model stopped sending text without a completion signal; the reply may be cut off."})
        else:
            # Every streaming route failed: fall back to the non-streaming chain (which may also fail).
            out = generate_reply(message, history, files, override, None, secrets)
            errors.extend(out["errors"])
            emit({"type": "meta", "provider": out["provider"], "model": out["model"],
                  "source": "fallback" if out["fallback"] else "free"})
            if out["fallback"]:
                emit({"type": "fallback", "kind": "no_model",
                      "message": "No language model answered (%s)." % (summarize_errors(errors) or "no route available")})
            emit({"type": "token", "v": out["reply"]})
        emit({"type": "done"})

    def handle_json(self):
        """Non-streaming JSON reply, used as the fallback route. Failures keep the old shape
        ({reply, provider, model, at}) and add ok / fallback / errors."""
        data, message, history, files, override, secrets = self._chat_request(MAX_JSON_BODY)
        if not message.strip() and not files:
            self._json(200, {"reply": "Send me a message and I’ll respond.", "provider": "local",
                             "model": "none", "at": int(time.time()), "ok": True, "fallback": False})
            return
        if not _chat_slots.acquire(blocking=False):
            raise RequestError(429, "busy", "The server is busy with other chats. Try again in a moment.",
                               {"Retry-After": "3"})
        try:
            chosen = resolve_selected(data.get("selected"), override)
            out = generate_reply(message, history, files, override, chosen, secrets)
        finally:
            _chat_slots.release()
        self._json(200, {"reply": out["reply"], "provider": out["provider"], "model": out["model"],
                         "at": int(time.time()), "ok": not out["fallback"], "fallback": out["fallback"],
                         "truncated": out.get("finish") == "length",
                         "errors": [{"kind": e.get("kind"), "message": redact(e.get("message", ""), secrets)}
                                    for e in out["errors"][:6]]})


# ---------------------------------------------------------------------------
# Creation tools: generated images and simple PowerPoint decks
# ---------------------------------------------------------------------------
def _pptx_text(text):
    return xml_escape(str(text or "").replace("\x00", "")[:2000])


def make_pptx(deck):
    """Create a minimal, editable PowerPoint file using only the standard library."""
    slides = deck.get("slides")
    if not isinstance(slides, list) or not slides:
        raise ValueError("A presentation needs at least one slide.")
    slides = slides[:15]

    def shape(shape_id, name, x, y, cx, cy, paragraphs, font_size, bold=False, bullets=False):
        runs = []
        for i, para in enumerate(paragraphs):
            ppr = '<a:pPr algn="l" marL="285750" indent="-190500"><a:buChar char="•"/></a:pPr>' if bullets else '<a:pPr algn="l"/>'
            runs.append('<a:p>%s<a:r><a:rPr lang="en-US" sz="%d" b="%d"><a:solidFill><a:srgbClr val="F4F7FF"/></a:solidFill><a:latin typeface="Aptos"/></a:rPr><a:t xml:space="preserve">%s</a:t></a:r><a:endParaRPr lang="en-US" sz="%d"/></a:p>' % (ppr, font_size, 1 if bold else 0, _pptx_text(para), font_size))
        return '<p:sp><p:nvSpPr><p:cNvPr id="%d" name="%s"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x="%d" y="%d"/><a:ext cx="%d" cy="%d"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom><a:noFill/><a:ln><a:noFill/></a:ln></p:spPr><p:txBody><a:bodyPr wrap="square" lIns="0" tIns="0" rIns="0" bIns="0"/><a:lstStyle/>%s</p:txBody></p:sp>' % (shape_id, name, x, y, cx, cy, ''.join(runs))

    content_types = ['<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>', '<Default Extension="xml" ContentType="application/xml"/>', '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>', '<Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>', '<Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>', '<Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>']
    content_types += ['<Override PartName="/ppt/slides/slide%d.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>' % (i + 1) for i in range(len(slides))]
    root_rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/></Relationships>'
    theme = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="ECHO"><a:themeElements><a:clrScheme name="ECHO"><a:dk1><a:srgbClr val="080D1B"/></a:dk1><a:lt1><a:srgbClr val="FFFFFF"/></a:lt1><a:dk2><a:srgbClr val="121A2D"/></a:dk2><a:lt2><a:srgbClr val="F4F7FF"/></a:lt2><a:accent1><a:srgbClr val="7C8CFF"/></a:accent1><a:accent2><a:srgbClr val="50E3C2"/></a:accent2><a:accent3><a:srgbClr val="FF6D9E"/></a:accent3><a:accent4><a:srgbClr val="F6C85F"/></a:accent4><a:accent5><a:srgbClr val="9C7BFF"/></a:accent5><a:accent6><a:srgbClr val="53B8FF"/></a:accent6><a:hlink><a:srgbClr val="7C8CFF"/></a:hlink><a:folHlink><a:srgbClr val="9C7BFF"/></a:folHlink></a:clrScheme><a:fontScheme name="ECHO"><a:majorFont><a:latin typeface="Aptos Display"/></a:majorFont><a:minorFont><a:latin typeface="Aptos"/></a:minorFont></a:fontScheme><a:fmtScheme name="ECHO"><a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst><a:lnStyleLst><a:ln w="6350"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln></a:lnStyleLst><a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst><a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme></a:theme>'
    presentation = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst><p:sldIdLst>%s</p:sldIdLst><p:sldSz cx="12192000" cy="6858000" type="wide"/><p:notesSz cx="6858000" cy="9144000"/></p:presentation>' % ''.join('<p:sldId id="%d" r:id="rId%d"/>' % (256 + i, i + 2) for i in range(len(slides)))
    presentation_rels = '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>%s</Relationships>' % ''.join('<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide%d.xml"/>' % (i + 2, i + 1) for i in range(len(slides)))
    master = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:bg><p:bgPr><a:solidFill><a:srgbClr val="080D1B"/></a:solidFill><a:effectLst/></p:bgPr></p:bg><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree></p:cSld><p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/><p:sldLayoutIdLst><p:sldLayoutId id="1" r:id="rId1"/></p:sldLayoutIdLst><p:txStyles><p:titleStyle/><p:bodyStyle/><p:otherStyle/></p:txStyles></p:sldMaster>'
    master_rels = '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/></Relationships>'
    layout = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank" preserve="1"><p:cSld name="Blank"><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>'
    layout_rels = '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/></Relationships>'
    import io
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">%s</Types>' % ''.join(content_types))
        z.writestr('_rels/.rels', root_rels)
        z.writestr('ppt/presentation.xml', presentation)
        z.writestr('ppt/_rels/presentation.xml.rels', presentation_rels)
        z.writestr('ppt/theme/theme1.xml', theme)
        z.writestr('ppt/slideMasters/slideMaster1.xml', master)
        z.writestr('ppt/slideMasters/_rels/slideMaster1.xml.rels', master_rels)
        z.writestr('ppt/slideLayouts/slideLayout1.xml', layout)
        z.writestr('ppt/slideLayouts/_rels/slideLayout1.xml.rels', layout_rels)
        for i, slide in enumerate(slides, 1):
            st = str(slide.get('title') or ('Slide %d' % i))[:160]
            bullets = slide.get('bullets', [])
            if not isinstance(bullets, list): bullets = [str(bullets)]
            bullets = [str(x)[:500] for x in bullets[:8] if str(x).strip()]
            title_shape = shape(2, 'Title', 760000, 480000, 10600000, 1050000, [st], 3000, True)
            body_shape = shape(3, 'Body', 1000000, 1900000, 10300000, 4200000, bullets or [' '], 2100, False, True)
            slide_xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:bg><p:bgPr><a:solidFill><a:srgbClr val="080D1B"/></a:solidFill><a:effectLst/></p:bgPr></p:bg><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>%s%s</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>' % (title_shape, body_shape)
            z.writestr('ppt/slides/slide%d.xml' % i, slide_xml)
            z.writestr('ppt/slides/_rels/slide%d.xml.rels' % i, '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/></Relationships>')
    return out.getvalue()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    global BOUND_HOST, PAGE, ALLOW_PRIVATE_BASES
    ap = argparse.ArgumentParser(description="ECHO AI server")
    ap.add_argument("--host", default="127.0.0.1",
                    help="address to listen on (default 127.0.0.1; use 0.0.0.0 to reach it from your phone/LAN)")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--page", default=None, help="HTML file to serve at / (default: first of %s)" % ", ".join(PAGE_CANDIDATES))
    args = ap.parse_args()

    BOUND_HOST = args.host
    page = args.page or next((c for c in PAGE_CANDIDATES if (ROOT / c).is_file()), "index.html")
    PAGE = page
    if not (ROOT / PAGE).is_file():
        sys.stderr.write("warning: %s not found next to the server; / will 404\n" % PAGE)
    loopback = args.host in ("127.0.0.1", "localhost", "::1")
    if _env_flag("ECHO_ALLOW_PRIVATE_BASES") is None:
        ALLOW_PRIVATE_BASES = loopback      # local Ollama etc. is fine when only you can reach the server
    if not loopback:
        print("WARNING: listening on %s. Anyone who can reach this port may consume configured provider quota. "
              "Key management stays limited to this machine; add authentication and per-user quotas before "
              "offering a public multi-user service." % args.host, file=sys.stderr)
        if _env_flag("ECHO_DISABLE_FREE") is None:
            # Public hosts must explicitly opt in before sending visitors' prompts to keyless gateways.
            global DISABLE_FREE
            DISABLE_FREE = True
            print("Public-bind safe default: free third-party gateways are disabled. Set ECHO_DISABLE_FREE=0 "
                  "only after reviewing provider privacy, terms, and abuse/cost controls.", file=sys.stderr)
        if len(ECHO_ADMIN_PASSWORD) < 16 or len(ECHO_MASTER_KEY) < 32:
            print("NOTICE: owner vault is not configured; set ECHO_ADMIN_PASSWORD and ECHO_MASTER_KEY "
                  "in the host's private secret settings if you need the encrypted key vault.", file=sys.stderr)
    if DISABLE_FREE:
        print("Free third-party gateways are disabled (ECHO_DISABLE_FREE=1).")
    threading.Thread(target=models_payload, daemon=True).start()   # validate keys at boot
    httpd = ThreadingHTTPServer((args.host, args.port), EchoHandler)
    print("ECHO AI server %s running at http://%s:%d  (serving %s)" % (VERSION, args.host, args.port, PAGE))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
