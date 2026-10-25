# ECHO AI — polished release

A single-page animated interface with a Python standard-library server for chat routing, image generation, and PowerPoint export. The HTML needs no build step. **This is a tested starter release, not a security audit or a fully production-hardened public AI service.**

## Files

| File | Purpose |
|---|---|
| `echo_ai_upgraded.html` | Polished front end, including the upgraded title and chat animations |
| `echo_server_upgraded.py` | HTTP server and chat API; Python standard library only |
| `test_echo_server.py` | Offline API/security regression tests using a fake provider |
| `echo_keys.example.json` | Placeholder configuration example; contains no real credentials |
| `echo_ai_upgraded.html` Creator | Built-in image, document, code-file and PowerPoint creation panel |
| `.gitignore` | Excludes local secrets and Python cache files from Git |
| `Procfile` | Generic `$PORT` start command for Procfile-compatible hosts |
| `SECURITY.md` | Public-launch security checklist and known limitations |

There is intentionally **no `echo_keys.json` in this release**. Never upload that file or a `.env` file to a public repository.

## Run locally

Requires Python 3.10+. The core chat server uses the standard library; install `requirements.txt` to enable the encrypted owner vault.

```bash
python3 -m pip install -r requirements.txt
python3 echo_server_upgraded.py
```

Open `http://127.0.0.1:8000`. To use another port:

```bash
python3 echo_server_upgraded.py --port 8080
```

The server binds to loopback by default. To test from another device on your own trusted network, use `--host 0.0.0.0` and follow the security notes below.

## Configure a model

You can enter a provider key in the app's Settings, or configure server-side keys using environment variables such as `GROQ_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, or `OPENAI_API_KEY`. A local `echo_keys.json` can also be created from `echo_keys.example.json` for local use. Keep all real credentials out of source control.

Keys with no credits, invalid keys, exhausted free tiers, or unsupported models may not produce replies. This package cannot add credits to a provider account. Provider requests were not tested with live credentials as part of this release verification.

## Creation tools

Use the ✦ button beside the chat composer to open the Creator. It can request an image from the external Pollinations image service, ask the configured chat model to draft a document or source file and download it, or turn a model-generated JSON outline into an editable `.pptx` PowerPoint deck. Image generation sends the image prompt to Pollinations and requires `POLLINATIONS_API_KEY` set in the server environment (for example in the host secret manager or local `.env`); the provider may require available credits. Its availability, terms, and pricing can change. Set `ECHO_DISABLE_FREE=1` to disable third-party fallback services; that also disables this image route.

Document and code creation use your configured chat model, so a working model/key or an available free text route is required. Generated code is saved as a file and is **not executed** by ECHO. The `.pptx` file is assembled server-side using the Python standard library.

Optional environment settings:

- `POLLINATIONS_API_KEY` enables image generation. Keep it server-side; it is never sent to the browser.

- `ECHO_DISABLE_FREE=1` disables keyless free gateways. Without it, some fallback routes may send prompts to third-party services.
- `ECHO_MAX_TOKENS` sets the response-token ceiling.
- `ECHO_ALLOWED_HOSTS=host1,host2` adds Host values accepted while the server is bound to loopback.

## Publish / deploy

### Before making it public

1. **Choose the hosting platform** and test its HTTPS URL, domain, logs, and restart behaviour.
2. Keep `echo_keys.json`, `.env`, provider credentials, and any private test data out of Git. If a real key was ever committed or shared, revoke/rotate it even if its balance is zero.
3. Do not place paid provider keys on a public server without authentication, abuse controls, usage quotas, and monitoring. Visitors may otherwise consume the server's configured keys.
4. The current server's key-management endpoints are intentionally limited to loopback clients. For hosted use, configure server-side keys through the host's secret/environment-variable settings, not through the public UI.
5. Review where prompts and attachments go. Third-party model providers or enabled free gateways may process the submitted content. Publish a privacy notice that accurately reflects your actual configuration and data retention.
6. Pick a license before publishing the source publicly; this bundle does not assume a license for you.
7. The page loads Matter.js and fonts from third-party CDNs. A network/CDN failure can affect physics or typography; the rest of the page has fallback styling.

### Generic hosted start command

On a host that supplies a `PORT` environment variable, use:

```bash
python3 echo_server_upgraded.py --host 0.0.0.0 --port "$PORT" --page echo_ai_upgraded.html
```

Configure provider keys in the host's private secret manager. Use HTTPS through the hosting platform's reverse proxy. **Do not assume this small standard-library server alone is sufficient for a public, multi-user production service**: rate limits are in-memory and there is no user authentication or per-user quota system. `ECHO_TRUSTED_PROXIES` can be configured for proxy-aware IP limits; do so only with your host's documented proxy CIDRs. Add authentication and per-user quotas before offering it publicly.

## Verification performed for this release

- **31/31 offline Python server tests pass**, including malformed/oversized requests, key masking, origin/host checks, security headers, rate-limit pruning, encrypted vault authentication/encryption/masking, streaming, PowerPoint creation, and mocked image-provider behavior. Run `python3 test_echo_server.py -v` to reproduce the result for this build.
- Python compilation passes, and all inline JavaScript blocks pass `node --check` against this release artifact.
- The server adds a Content Security Policy baseline, anti-framing and MIME-sniffing headers, restrictive referrer policy, and optional trusted-proxy-aware client IP handling.
- The app uses a single-file frontend with inline scripts, so its CSP still permits inline script/style. Treat this as defense in depth, not a complete XSS mitigation.
- A real browser and live-provider smoke test on your target host is still required. Passing offline tests does not prove third-party provider availability or production readiness.

## Security notes

- Browser-saved API keys live in `localStorage` and are not encrypted. Any script running on the same page origin could read them. Use a trusted device and do not enter sensitive keys into an untrusted copy of the app.
- Server-held keys are only as safe as the host and its secret storage. Do not commit `echo_keys.json`.
- The Host/Origin checks reduce some cross-site and DNS-rebinding risks but are not a substitute for production security controls. Public deployments must use HTTPS, provider-side usage limits, monitoring, and preferably user authentication/per-user quotas.
- Public binds now default to disabling keyless/free third-party gateways unless `ECHO_DISABLE_FREE` is explicitly set. Setting `ECHO_DISABLE_FREE=0` opts back in and may send visitor prompts to external services; it also enables the image route when configured. Review that privacy/cost trade-off first.
- If running behind a reverse proxy, configure `ECHO_TRUSTED_PROXIES` only with the proxy CIDRs documented by your host. Never trust forwarded IP headers from arbitrary clients. Without this setting, limits use the direct peer IP.
- The app does not guarantee model availability, free provider usage, or unlimited requests.


## Secure owner-only API-key vault

The Settings panel includes an owner-only **Secure server vault**. Unlike the legacy browser key option, the secure vault stores API keys encrypted on the server and only returns masked previews to the browser.

### Required deployment secrets

Configure these in your hosting provider's **private environment/secret settings** (not in HTML, JavaScript, Git, or a public `.env` file):

- `ECHO_ADMIN_PASSWORD`: a unique random password with at least 16 characters.
- `ECHO_MASTER_KEY`: a unique random value with at least 32 characters. **Back this up securely**: changing it makes the existing encrypted vault unreadable.

Generate example values locally with:

```bash
python -c "import secrets; print('ECHO_ADMIN_PASSWORD=' + secrets.token_urlsafe(24)); print('ECHO_MASTER_KEY=' + secrets.token_urlsafe(48))"
```

Install the dependency with `pip install -r requirements.txt`. Then open ECHO AI → Settings → API keys, enter the owner password and unlock the vault. Choose **Secure server vault (encrypted)** before adding a key. The login uses an HttpOnly, SameSite=Strict session cookie that expires after eight hours; remote unlocking is refused unless the page is served over HTTPS. The encrypted data file `echo_vault.enc` is ignored by Git and must not be included in public release ZIPs.

### Important security notes

- Keep both environment secrets private. Anyone with the admin password can manage the keys; anyone with the master key and the vault file can decrypt stored keys.
- Store a secure backup of `ECHO_MASTER_KEY`. If it is lost or changed, the vault cannot be decrypted.
- Use HTTPS for public hosting, keep dependencies updated, and do not put API keys in browser storage. The older “this browser only” option is not encrypted and is not recommended.
- The vault protects keys at rest and prevents visitors from retrieving them through the app. It cannot protect a key from a compromised server, malicious server-side code, or a compromised owner browser.
