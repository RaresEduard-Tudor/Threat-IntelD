# Threat-IntelD — Security & Code Quality Audit

> Generated: 2026-03-05 | Last updated: 2026-03-05

---

## Remaining Issues

All identified issues have been resolved.

---

## Fixed Issues (for reference)

<details>
<summary>6 Critical + 6 High + 14 Medium + 7 Low issues resolved</summary>

### CRITICAL (all fixed)
1. SSRF DNS rebinding bypass — replaced `_is_ssrf_safe()` with `_resolve_and_check()` using `getaddrinfo`.
2. Screenshot JS execution — disabled JavaScript, removed `--no-sandbox`, added 5 MB size limit.
3. XSS in HTML export — added `escapeHtml()` to all interpolated values.
4. `reload=True` in production — gated behind `ENV=development`.
5. API key in URL query string — moved Safe Browsing API key to `X-Goog-Api-Key` header.
6. Silent global exception handler — added `logger.error()` with full traceback.

### HIGH (all fixed)
7. `target_url` rendered as `<a href>` — sanitized to reject `javascript:` scheme.
8. Cache key collision — added query-parameter sorting in `_canonical_url()`.
9. CORS `allow_headers=["*"]` — restricted to `["Content-Type", "Accept"]`.
10. No rate limit on GET endpoints — added `30/minute` limit to `/history`, `/trending`, `/report/{id}`.
11. Missing nginx security headers — added `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`.
12. ReDoS in URL heuristics — replaced greedy `.*` with `[^%]*` and capped input to 2048 chars.

### MEDIUM (all fixed)
13. Pinned dependency upper bounds in `requirements.txt`.
14. Added `AbortController` cleanup pattern in React `useEffect`.
15. Added error handling to `fetchTrending()`.
16. Added `console.warn` in silent API catch blocks (`history.ts`, `report.ts`).
17. Added `AbortSignal.timeout(30s)` to `analyze` fetch call.
18. Fixed `setTimeout` memory leak in `handleShare()` with `useRef` + cleanup.
19. Added `logging.getLogger(__name__)` and `logger.warning()` to all 8 check modules.
20. Added IPv6 guard in DNSBL check.
21. Added `@field_validator` for URL scheme on `AnalyzeRequest`.
22. Extracted scoring magic numbers to named constants.
23. Added accessibility: `<label>`, `aria-label`, `role="button"`, `tabIndex`, keyboard handlers.
24. Fixed test fixture to also clear `_history_store` and reset `_id_counter`.
25. In-memory history — confirmed as intentional design (no database by design).
26. Added runtime response type validation in `analyze.ts` and `report.ts`.

### LOW (all fixed)
27. Pinned Docker base images to specific versions (`python:3.13.5-slim-bookworm`, `node:20.19-alpine3.21`, `nginx:1.27.5-alpine3.21`).
28. Added `HEALTHCHECK` to both Dockerfiles.
29. Added gzip compression in nginx config.
30. Added `VITE_API_URL` type declaration in `vite-env.d.ts`.
31. Memoized `AssessmentBadge`, `CheckCard`, `ThreatScoreDonut` with `React.memo`.
32. `_id_counter` overflow — removed as non-issue (2⁶³ requests is unreachable).
33. Added test coverage for concurrent requests, DNS rebinding, shared-report XSS, and export XSS.

</details>
