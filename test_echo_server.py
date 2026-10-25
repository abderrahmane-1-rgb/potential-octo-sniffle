#!/usr/bin/env python3
"""Offline tests for echo_server_upgraded.py.

Starts a fake OpenAI-compatible provider and the ECHO server on loopback ports and exercises
real HTTP requests. No internet and no real API key is needed.

    python3 test_echo_server.py -v
"""
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import echo_server_upgraded as S  # noqa: E402

GOOD, BAD, RATE, CUT, SLOW = "good-key-0000000001", "bad-key-00000000001", "rate-key-0000000001", "cut-key-00000000001", "slow-key-0000000001"
LEAK = {"seen": []}


class Fake(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _auth(self):
        return (self.headers.get("Authorization") or "")[7:]

    def do_GET(self):
        key = self._auth()
        LEAK["seen"].append(key)
        if self.path.endswith("/models"):
            if key == BAD:
                return self._send(401, {"error": {"message": "invalid key " + key}})
            return self._send(200, {"data": [{"id": "fake-model"}, {"id": "text-embedding-x"}]})
        self._send(404, {})

    def _send(self, code, obj, extra=None):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        key = self._auth()
        LEAK["seen"].append(key)
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        LEAK.setdefault("bodies", []).append(body)
        if key == BAD:
            return self._send(401, {"error": {"message": "bad key " + key}})
        if key == RATE:
            return self._send(429, {"error": {"message": "slow down"}}, {"Retry-After": "0"})
        if not body.get("stream"):
            return self._send(200, {"model": "fake-model", "choices": [{"message": {"content": "<think>x</think>hello there"}, "finish_reason": "stop"}]})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()

        def ev(o):
            self.wfile.write(("data: " + json.dumps(o) + "\n\n").encode())
            self.wfile.flush()
        ev({"model": "fake-model", "choices": [{"delta": {"content": "<thi"}}]})
        ev({"model": "fake-model", "choices": [{"delta": {"content": "nk>secret</think>Hel"}}]})
        ev({"model": "fake-model", "choices": [{"delta": {"content": "lo"}}]})
        if key == CUT:
            self.wfile.write(b"data: {\"error\": {\"message\": \"upstream died\"}}\n\n")
            self.wfile.flush()
            return
        ev({"model": "fake-model", "choices": [{"delta": {"content": " world"}, "finish_reason": "stop"}]})
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


def serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def request(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    h = dict(headers or {})
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    c.request(method, path, body=data, headers=h)
    r = c.getresponse()
    raw = r.read()
    return r.status, dict(r.getheaders()), raw


def sse(raw):
    return [json.loads(l[6:]) for l in raw.decode().split("\n") if l.startswith("data: ")]


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        S.DISABLE_FREE = True               # never touch the internet in tests
        S.ALLOW_PRIVATE_BASES = True
        cls.fake = serve(Fake)
        cls.base = "http://127.0.0.1:%d/v1" % cls.fake.server_address[1]
        cls.tmp = tempfile.mkdtemp()
        S.KEY_FILE = os.path.join(cls.tmp, "echo_keys.json")
        S.PAGE = "echo_ai_upgraded.html"
        cls.srv = serve(S.EchoHandler)
        cls.port = cls.srv.server_address[1]

    def setUp(self):
        S._limiter.hits.clear()
        S._dead.clear()
        S._models_cache.clear()
        S._verified.clear()
        LEAK["seen"].clear()
        LEAK["bodies"] = []

    def keys(self, *ks):
        return [{"apiKey": k, "baseUrl": self.base, "model": "fake-model", "provider": "custom"} for k in ks]

    def chat(self, **kw):
        body = dict({"message": "hi", "conversationHistory": []}, **kw)
        return request(self.port, "POST", "/api/echo/stream", body)


class SafeMath(unittest.TestCase):
    def test_arith_ok(self):
        self.assertEqual(S.safe_arithmetic("2+3*4"), 14)
        self.assertEqual(S.safe_arithmetic("(1+2)**3"), 27)

    def test_arith_rejects_code(self):
        for bad in ["__import__('os').system('id')", "open('x')", "().__class__", "9**9**9", "a+1", "1;2"]:
            with self.assertRaises((ValueError, SyntaxError)):
                S.safe_arithmetic(bad)

    def test_fallback_is_honest(self):
        self.assertIn("= 14", S.local_fallback("what is 2+3*4?"))
        txt = S.local_fallback("tell me about cats")
        self.assertIn("could not reach", txt)
        self.assertNotIn("As an AI", txt)


class Messages(unittest.TestCase):
    def test_preserves_code_whitespace(self):
        h = [{"role": "user", "content": "x"}, {"role": "assistant", "content": "```py\nif a:\n    b\n```"}]
        m = S.build_messages("next", h, [])
        self.assertIn("    b", m[2]["content"])

    def test_bounded_and_alternating(self):
        h = [{"role": "user" if i % 2 == 0 else "assistant", "content": "m%d " % i + "z" * 5000} for i in range(100)]
        m = S.build_messages("last", h, [])
        self.assertLessEqual(sum(len(x["content"]) for x in m[1:]), S.MAX_HISTORY_CHARS + S.MAX_MESSAGE_CHARS)
        roles = [x["role"] for x in m[1:]]
        self.assertEqual(roles[0], "user")
        self.assertTrue(all(a != b for a, b in zip(roles, roles[1:])))
        self.assertEqual(m[-1]["role"], "user")
        self.assertTrue(m[-1]["content"].endswith("last"))

    def test_garbage_history(self):
        m = S.build_messages("q", [None, 3, {"role": "x"}, {"content": ["a"]}, {"role": "user", "content": "ok"}], [])
        self.assertEqual(m[-1]["role"], "user")

    def test_think_filter_split_tags(self):
        f = S.ThinkFilter()
        out = f.feed("a<thi") + f.feed("nk>hidden</th") + f.feed("ink>b") + f.flush()
        self.assertEqual(out, "ab")


class BaseUrl(unittest.TestCase):
    def test_blocks(self):
        S.ALLOW_PRIVATE_BASES = False
        try:
            for u in ["http://169.254.169.254/latest", "file:///etc/passwd", "ftp://x.y", "https://u:p@example.com",
                      "http://127.0.0.1:8000/v1", "http://example.com/v1"]:
                with self.assertRaises(ValueError, msg=u):
                    S.validate_base_url(u)
            self.assertEqual(S.validate_base_url("http://127.0.0.1:11434/v1", trusted=True), "http://127.0.0.1:11434/v1")
        finally:
            S.ALLOW_PRIVATE_BASES = True
        with self.assertRaises(ValueError):
            S.validate_base_url("http://169.254.169.254/x", trusted=True)

    def test_unknown_key_never_sent_to_openai(self):
        raw = []
        ents = S.user_key_providers({"keys": [{"apiKey": "totally-unknown-key-format-123"}]}, raw)
        self.assertEqual(ents, [])
        self.assertEqual(raw[0]["error"][0], "unconfigured")


class Http(Base):
    def test_page_and_static_rules(self):
        s, page_headers, page = request(self.port, "GET", "/")
        self.assertEqual(s, 200)
        self.assertIn(b"ECHO AI", page)
        self.assertIn("default-src 'self'", page_headers.get("Content-Security-Policy", ""))
        s, h, _ = request(self.port, "GET", "/echo_server_upgraded.py")
        self.assertEqual(s, 404)
        s, _, _ = request(self.port, "GET", "/echo_keys.json")
        self.assertEqual(s, 404)
        s, _, _ = request(self.port, "GET", "/../../etc/passwd")
        self.assertIn(s, (400, 404))
        s, h, _ = request(self.port, "GET", "/api/echo/health")
        self.assertEqual(s, 200)
        self.assertEqual(h.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(h.get("X-Frame-Options"), "DENY")
        self.assertIn("default-src 'self'", h.get("Content-Security-Policy", ""))
        self.assertIn("frame-ancestors 'none'", h.get("Content-Security-Policy", ""))
        self.assertEqual(h.get("Referrer-Policy"), "no-referrer")

    def test_host_header_and_origin(self):
        s, _, _ = request(self.port, "GET", "/api/echo/health", headers={"Host": "evil.example.com"})
        self.assertEqual(s, 421)
        s, _, _ = request(self.port, "POST", "/api/echo/models", {"keys": []}, {"Origin": "https://evil.example.com"})
        self.assertEqual(s, 403)

    def test_malformed_and_oversize(self):
        s, _, raw = request(self.port, "POST", "/api/echo/stream", b"{not json")
        self.assertEqual(s, 400)
        self.assertEqual(json.loads(raw)["error"]["kind"], "bad_json")
        s, _, _ = request(self.port, "POST", "/api/echo/stream", b"[1,2]")
        self.assertEqual(s, 400)
        # The server intentionally rejects an oversized Content-Length before reading the
        # body. Send headers only so the client does not race that early rejection by
        # trying to upload 1.2 MB after the server has already closed the connection.
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.putrequest("POST", "/api/echo")
        c.putheader("Host", "127.0.0.1:%d" % self.port)
        c.putheader("Content-Type", "application/json")
        c.putheader("Content-Length", "1200000")
        c.endheaders()
        r = c.getresponse()
        s = r.status
        r.read()
        c.close()
        self.assertEqual(s, 413)
        s, _, _ = request(self.port, "POST", "/api/echo/stream", {"message": "   "})
        self.assertEqual(s, 400)

    def test_slide_generation_returns_valid_powerpoint(self):
        import zipfile
        s, h, raw = request(self.port, "POST", "/api/echo/slides", {
            "title": "Test deck",
            "slides": [{"title": "Intro", "bullets": ["First point", "Second point"]},
                       {"title": "Conclusion", "bullets": ["Done"]}]
        })
        self.assertEqual(s, 200)
        self.assertIn("application/vnd.openxmlformats-officedocument.presentationml.presentation", h.get("Content-Type", ""))
        import io
        deck = zipfile.ZipFile(io.BytesIO(raw))
        self.assertIn("ppt/slides/slide1.xml", deck.namelist())
        self.assertIn("ppt/slides/slide2.xml", deck.namelist())
        self.assertIn("Intro", deck.read("ppt/slides/slide1.xml").decode())

    def test_image_generation_obeys_free_gateway_setting(self):
        s, _, raw = request(self.port, "POST", "/api/echo/image", {"prompt": "A blue flower"})
        self.assertEqual(s, 503)
        self.assertEqual(json.loads(raw)["error"]["kind"], "disabled")

    def test_image_generation_requires_provider_key(self):
        old_free, old_key = S.DISABLE_FREE, S.POLLINATIONS_API_KEY
        S.DISABLE_FREE, S.POLLINATIONS_API_KEY = False, ""
        try:
            status, _, raw = request(self.port, "POST", "/api/echo/image", {"prompt": "A blue flower"})
        finally:
            S.DISABLE_FREE, S.POLLINATIONS_API_KEY = old_free, old_key
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(raw)["error"]["kind"], "image_key_missing")

    def test_image_generation_returns_image_bytes_when_provider_succeeds(self):
        from unittest.mock import patch
        class FakeResponse:
            headers = {"Content-Type": "image/png"}
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, n=-1): return b"\x89PNG\r\n\x1a\nFAKEPNG"
        old_free, old_key = S.DISABLE_FREE, S.POLLINATIONS_API_KEY
        S.DISABLE_FREE, S.POLLINATIONS_API_KEY = False, "test-image-key"
        try:
            with patch.object(S.urllib.request, "urlopen", return_value=FakeResponse()) as mocked:
                status, headers, body = request(self.port, "POST", "/api/echo/image", {"prompt": "A blue flower"})
                self.assertIn("Bearer test-image-key", mocked.call_args.args[0].get_header("Authorization"))
        finally:
            S.DISABLE_FREE, S.POLLINATIONS_API_KEY = old_free, old_key
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "image/png")
        self.assertTrue(body.startswith(b"\x89PNG"))

    def test_json_route_compat_and_think_stripped(self):
        s, _, raw = request(self.port, "POST", "/api/echo", {"message": "hi", "keys": self.keys(GOOD)})
        d = json.loads(raw)
        self.assertEqual(s, 200)
        self.assertEqual(d["reply"], "hello there")
        self.assertEqual(d["model"], "fake-model")
        self.assertTrue(d["ok"] and not d["fallback"])
        for k in ("reply", "provider", "model", "at"):
            self.assertIn(k, d)

    def test_stream_happy_path(self):
        s, h, raw = self.chat(keys=self.keys(GOOD))
        ev = sse(raw)
        text = "".join(e["v"] for e in ev if e["type"] == "token")
        self.assertEqual(text, "Hello world")
        self.assertEqual(ev[0]["type"], "meta")
        self.assertEqual(ev[-1]["type"], "done")
        self.assertFalse(any(e["type"] in ("interrupted", "incomplete", "fallback") for e in ev))

    def test_stream_cut_midway_is_reported(self):
        _, _, raw = self.chat(keys=self.keys(CUT))
        ev = sse(raw)
        self.assertEqual("".join(e["v"] for e in ev if e["type"] == "token"), "Hello")
        self.assertTrue(any(e["type"] == "interrupted" for e in ev), ev)
        self.assertEqual(ev[-1]["type"], "done")

    def test_auth_failure_reports_honestly_and_no_secret_leak(self):
        _, _, raw = self.chat(keys=self.keys(BAD))
        ev = sse(raw)
        kinds = [e["type"] for e in ev]
        self.assertIn("notice", kinds)
        self.assertIn("fallback", kinds)
        self.assertNotIn(BAD, raw.decode())
        fb = next(e for e in ev if e["type"] == "fallback")
        self.assertIn("rejected key", fb["message"])
        meta = next(e for e in ev if e["type"] == "meta")
        self.assertEqual(meta["source"], "fallback")

    def test_rejected_key_stays_visible_and_recovers(self):
        s, _, raw = request(self.port, "POST", "/api/echo/models", {"keys": self.keys(BAD, GOOD)})
        g = {x["masked"]: x for x in json.loads(raw)["groups"]}
        self.assertEqual(len(g), 2)
        states = sorted(x["state"] for x in g.values())
        self.assertEqual(states, ["rejected", "verified"])
        # second call (cached rejected key) must STILL list it, which the original did not
        s, _, raw = request(self.port, "POST", "/api/echo/models", {"keys": self.keys(BAD, GOOD)})
        self.assertEqual(len(json.loads(raw)["groups"]), 2)
        # embedding models are filtered out
        good = next(x for x in json.loads(raw)["groups"] if x["state"] == "verified")
        self.assertEqual(good["models"], ["fake-model"])
        # keys never appear in the catalog
        self.assertNotIn(GOOD, raw.decode())

    def test_verify_endpoint(self):
        kid = S.key_id(GOOD, self.base)
        _, _, raw = request(self.port, "POST", "/api/echo/verify", {"keyId": kid, "keys": self.keys(GOOD)})
        self.assertTrue(json.loads(raw)["ok"])
        kid = S.key_id(BAD, self.base)
        _, _, raw = request(self.port, "POST", "/api/echo/verify", {"keyId": kid, "keys": self.keys(BAD)})
        d = json.loads(raw)
        self.assertFalse(d["ok"])
        self.assertEqual(d["kind"], "auth")
        self.assertNotIn(BAD, raw.decode())

    def test_rate_limit_error_classified_and_retried(self):
        _, _, raw = request(self.port, "POST", "/api/echo", {"message": "hi", "keys": self.keys(RATE)})
        d = json.loads(raw)
        self.assertTrue(d["fallback"])
        self.assertEqual(d["errors"][0]["kind"], "rate_limit")
        self.assertGreaterEqual(sum(1 for k in LEAK["seen"] if k == RATE), 2)   # retried once

    def test_selected_model_routes_to_that_key(self):
        kid = S.key_id(GOOD, self.base)
        _, _, raw = self.chat(keys=self.keys(BAD, GOOD), selected={"keyId": kid, "model": "fake-model"})
        ev = sse(raw)
        self.assertEqual("".join(e["v"] for e in ev if e["type"] == "token"), "Hello world")

    def test_key_store_roundtrip_and_masking(self):
        s, _, raw = request(self.port, "POST", "/api/echo/keys",
                            {"apiKey": GOOD, "baseUrl": self.base, "provider": "custom", "model": "fake-model"})
        self.assertEqual(s, 201, raw)
        self.assertNotIn(GOOD, raw.decode())
        s, _, raw = request(self.port, "GET", "/api/echo/keys")
        d = json.loads(raw)
        self.assertEqual(len(d["keys"]), 1)
        self.assertNotIn(GOOD, raw.decode())
        self.assertTrue(d["keys"][0]["masked"].startswith(GOOD[:6]))
        mode = os.stat(S.KEY_FILE).st_mode & 0o777
        self.assertEqual(mode, 0o600)
        # persisted key now powers chat with no browser-side key at all
        _, _, raw = self.chat()
        self.assertEqual("".join(e["v"] for e in sse(raw) if e["type"] == "token"), "Hello world")
        kid = d["keys"][0]["id"]
        s, _, raw = request(self.port, "PATCH", "/api/echo/keys/" + kid, {"enabled": False})
        self.assertEqual(json.loads(raw)["keys"][0]["enabled"], False)
        s, _, raw = request(self.port, "DELETE", "/api/echo/keys/" + kid)
        self.assertEqual(json.loads(raw)["keys"], [])

    def test_vault_auth_encryption_and_masking(self):
        old_password, old_master, old_file = S.ECHO_ADMIN_PASSWORD, S.ECHO_MASTER_KEY, S.VAULT_FILE
        vault_path = os.path.join(self.tmp, "test-echo-vault.enc")
        S.ECHO_ADMIN_PASSWORD = "test-owner-password-123456"
        S.ECHO_MASTER_KEY = "test-master-key-random-long-enough-123456789"
        S.VAULT_FILE = vault_path
        S._VAULT_SESSIONS.clear()
        try:
            self.assertTrue(S.vault_available())
            status, _, raw = request(self.port, "GET", "/api/echo/vault/keys")
            self.assertEqual(status, 401)
            status, _, _ = request(self.port, "POST", "/api/echo/vault/login", {"password": "wrong-password"})
            self.assertEqual(status, 401)
            status, headers, raw = request(self.port, "POST", "/api/echo/vault/login", {"password": S.ECHO_ADMIN_PASSWORD})
            self.assertEqual(status, 200)
            cookie = headers["Set-Cookie"].split(";", 1)[0]
            self.assertIn("HttpOnly", headers["Set-Cookie"])
            self.assertIn("SameSite=Strict", headers["Set-Cookie"])
            status, _, _ = request(self.port, "POST", "/api/echo/vault/keys",
                                   {"apiKey": GOOD, "baseUrl": self.base, "provider": "custom", "model": "fake-model"},
                                   {"Cookie": cookie})
            self.assertEqual(status, 201)
            encrypted = Path(vault_path).read_bytes()
            self.assertNotIn(GOOD.encode(), encrypted)
            status, _, raw = request(self.port, "GET", "/api/echo/vault/keys", headers={"Cookie": cookie})
            self.assertEqual(status, 200)
            payload = json.loads(raw)
            self.assertEqual(len(payload["keys"]), 1)
            self.assertNotIn("apiKey", payload["keys"][0])
            self.assertNotIn(GOOD, raw.decode())
            status, _, _ = request(self.port, "POST", "/api/echo/vault/logout", {}, {"Cookie": cookie})
            self.assertEqual(status, 200)
            status, _, _ = request(self.port, "GET", "/api/echo/vault/keys", headers={"Cookie": cookie})
            self.assertEqual(status, 401)
        finally:
            S._VAULT_SESSIONS.clear()
            S.ECHO_ADMIN_PASSWORD, S.ECHO_MASTER_KEY, S.VAULT_FILE = old_password, old_master, old_file
            try: os.unlink(vault_path)
            except FileNotFoundError: pass

    def test_key_store_rejects_bad_input(self):
        S.ALLOW_PRIVATE_BASES = False
        try:
            s, _, _ = request(self.port, "POST", "/api/echo/keys", {"apiKey": "abc"})
            self.assertEqual(s, 400)
            s, _, _ = request(self.port, "POST", "/api/echo/keys",
                              {"apiKey": GOOD, "baseUrl": "http://169.254.169.254/v1", "provider": "custom"})
            self.assertEqual(s, 400)
        finally:
            S.ALLOW_PRIVATE_BASES = True

    def test_rate_limiter_prunes_without_clearing_active_history(self):
        limiter = S.RateLimiter()
        now = time.time()
        limiter.hits = {"active-%d" % i: S.deque([now]) for i in range(2001)}
        self.assertEqual(limiter.allow("new-client", 5), 0)
        self.assertIn("active-2000", limiter.hits)
        self.assertLessEqual(len(limiter.hits), 2002)

    def test_rate_limiter(self):
        for _ in range(S.ADMIN_RATE_PER_MIN):
            request(self.port, "POST", "/api/echo/models", {"keys": []})
        s, h, _ = request(self.port, "POST", "/api/echo/models", {"keys": []})
        self.assertEqual(s, 429)
        self.assertIn("Retry-After", h)

    def test_redaction(self):
        t = S.redact("failed with Bearer sk-abcdefghijklmnop and gsk_abcdefghijklmnop12", ["custom-secret-value"])
        self.assertNotIn("abcdefghijklmnop", t)
        self.assertNotIn("custom-secret-value", S.redact("x custom-secret-value", ["custom-secret-value"]))

    def test_images_not_sent_to_text_models(self):
        img = {"name": "a.png", "dataUrl": "data:image/png;base64,AAAA"}
        _, _, raw = self.chat(keys=self.keys(GOOD), images=[img])
        ev = sse(raw)
        self.assertTrue(any(e["type"] == "notice" and e["kind"] == "no_vision" for e in ev))
        for b in LEAK["bodies"]:
            self.assertTrue(all(isinstance(m["content"], str) for m in b["messages"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
