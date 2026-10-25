# ECHO AI security and publishing checklist

This project is a small self-hosted starter app. It is not a substitute for a security review, a managed authentication system, or provider-side spending limits.

## Before publishing

- [ ] Rotate any API keys that were previously shared, uploaded, or committed, even if their account balance is zero.
- [ ] Never commit `echo_keys.json`, `.env`, `echo_vault.enc`, API credentials, or real user data.
- [ ] Set `ECHO_ADMIN_PASSWORD` (unique random value, at least 16 characters) and `ECHO_MASTER_KEY` (unique random value, at least 32 characters) in your hosting provider's private secret manager if you use the owner vault.
- [ ] Keep a secure backup of `ECHO_MASTER_KEY`; losing it makes the vault unreadable.
- [ ] Use HTTPS. The host/reverse proxy must terminate TLS correctly.
- [ ] Set provider-side quotas/budget alerts and monitor usage. A shared server API key can be consumed by visitors.
- [ ] Add visitor authentication and per-user quotas before offering a public multi-user service with paid/shared provider keys.
- [ ] Review which external services receive prompts. Public binds default to disabling keyless/free routes; explicitly opting back in may send prompts to third parties.
- [ ] If behind a proxy, configure `ECHO_TRUSTED_PROXIES` only with the documented proxy CIDRs and ensure the proxy rewrites/extends `X-Forwarded-For` safely.
- [ ] Test image generation, model replies, file downloads, and vault login on the real deployment with low-cost test requests.

## What the built-in vault does

The owner vault encrypts API keys at rest and returns masked key previews. Its session cookie is HttpOnly and SameSite=Strict; remote login requires an HTTPS origin. This does not protect secrets from a compromised host, a compromised owner browser, malicious server code, or a stolen admin password/master key.

## Known limitations

- The single-file frontend has inline JavaScript and CSS, so the Content Security Policy permits inline scripts/styles. A nonce/hash-based CSP would be stronger.
- Rate limits are in-memory and per client IP; they reset on restart and are not a complete abuse-prevention or billing system.
- A reverse proxy must be configured correctly. Do not trust forwarded headers unless the direct peer is in `ECHO_TRUSTED_PROXIES`.
- The local server is not a full production hosting stack. Keep it behind a reputable HTTPS reverse proxy and add authentication, monitoring, backups, and incident response appropriate to your use case.
