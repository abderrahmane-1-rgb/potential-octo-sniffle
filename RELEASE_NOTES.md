# ECHO AI release hardening notes

## Included

- Refined entrance/reply motion and accessibility focus states; touch suggestions no longer enlarge on press.
- Preserved `prefers-reduced-motion` behavior and avoided adding continuous animation loops.
- Added security response headers: Content Security Policy baseline, `X-Frame-Options`, `X-Content-Type-Options`, restrictive referrer policy, Permissions Policy, and HSTS when the trusted proxy reports HTTPS.
- Reduced server banner detail and request socket timeout.
- Fixed rate-limit bookkeeping so a high number of distinct addresses does not clear all active buckets at once.
- Added optional trusted-proxy-aware client IP resolution through `ECHO_TRUSTED_PROXIES`; do not configure it unless the app is behind those trusted proxies.
- Public network binds now disable keyless/free third-party gateways by default. Setting `ECHO_DISABLE_FREE=0` is an explicit opt-in with privacy/cost implications.
- Added tests for security headers and vault authentication, encryption at rest, masked responses, logout, and rate-limit pruning.
- Added a security checklist and updated publishing instructions.

## Verification

- 31/31 offline server tests pass.
- Python compilation passes.
- All five inline JavaScript blocks pass `node --check`.
- HTML parser check found no duplicate IDs.
- Local HTTP page and health endpoint responded with the expected headers.
- A headless Chromium run could not complete in this environment, and live provider credentials were not tested. Perform visual/mobile and provider smoke tests on the actual deployment before announcing it publicly.

## Known production limitations

- No visitor login or per-user quotas; a public visitor can consume configured server-side provider quota within the rate limits.
- In-memory limits reset on restart and require correctly configured proxy trust to identify visitors behind a reverse proxy.
- The CSP permits inline scripts/styles because the current UI is a single HTML file.
- Third-party CDN fonts and Matter.js can fail if those services are unavailable.
