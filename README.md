<div align="center">

# WebSentry

### Privacy-first website security scanner.

**13 scan categories · 150+ checks · Zero persistence · No login required.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-20.9%2B-green.svg)](https://nodejs.org)
[![Next.js](https://img.shields.io/badge/Next.js-16-black.svg)](https://nextjs.org)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange.svg)](https://workers.cloudflare.com)
[![Live Demo](https://img.shields.io/badge/Live_Demo-websentryx.vercel.app-brightgreen)](https://websentryx.vercel.app)

---

### [Try it live → websentryx.vercel.app](https://websentryx.vercel.app)

---

</div>

## What is WebSentry?

WebSentry is a full-stack, privacy-first website security scanner. Paste any public URL and get a real-time, comprehensive security report in seconds — **no accounts, no databases, no stored results**.

It runs on **Vercel** (Next.js frontend) and **Cloudflare Workers** (Hono API + scanner backend). The browser sends a target URL, the Worker validates it, performs bounded HTTP requests, probes for vulnerabilities, and streams results back via SSE.

**Developed by JOJIN JOHN**

---

## Features

### 13 Scan Categories

| # | Category | What It Checks |
|---|----------|----------------|
| 1 | **Security Headers** | CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, CORP, X-XSS-Protection (15+ header checks) |
| 2 | **TLS / HTTPS** | Certificate Transparency logs, HSTS preload status, certificate issuer/expiry, HTTPS enforcement |
| 3 | **DNS & Email** | A, AAAA, MX, NS, TXT, CAA records, SPF/DMARC policy analysis |
| 4 | **Cookies** | Secure, HttpOnly, SameSite attribute inspection |
| 5 | **CORS** | Preflight testing, Allow-Origin, Allow-Credentials analysis |
| 6 | **Exposed Paths** | 35+ sensitive paths: .git, .env, .DS_Store, debug endpoints, admin panels, config files |
| 7 | **Mixed Content** | HTTP resource detection on HTTPS pages |
| 8 | **Subresource Integrity** | External script/stylesheet SRI coverage |
| 9 | **JWT / Tokens** | Detect exposed JWT tokens in HTML, meta tags, and cookies |
| 10 | **Forms** | CSRF protection, form method analysis |
| 11 | **SEO** | Meta tags, Open Graph, canonical, viewport, heading structure |
| 12 | **Accessibility** | Alt text, form labels, heading hierarchy, ARIA landmarks, skip links |
| 13 | **Performance** | Page size, render-blocking resources, response time |
| 14 | **Infrastructure** | HTTP/2, HTTP/3, IPv6, DNSSEC detection |
| 15 | **Files** | robots.txt, security.txt parsing |
| 16 | **Technologies** | 80+ technology signatures (frameworks, CMS, CDN, analytics, JS libraries) |

### 150+ Security Checks

Every scan produces detailed findings with **severity**, **evidence**, and **recommendations**:

- **Critical** — Immediate security risk (exposed .env, .git, SQL dumps)
- **High** — Significant vulnerability (missing HSTS, exposed admin panels, JWT in source)
- **Medium** — Configuration concern (CSP unsafe-inline, missing SRI, debug endpoints)
- **Low** — Minor improvement (HTTP/1.1, missing Permissions-Policy)
- **Info** — Observation (SPF record, certificate validity, CT logs)

### Deterministic Security Score

A 0–100 score is calculated from findings severity, HTTPS status, and pass/fail results. No randomness.

---

## Privacy Model

| Feature | WebSentry |
|---------|-----------|
| Login required | No |
| Database | None |
| Scan history | None |
| Stored reports | None |
| KV / D1 / R2 | None |
| Target URL persisted | No |
| Results streamed | Yes (SSE) |

> **Note:** Operational infrastructure (Cloudflare, Vercel, DNS providers) can still have its own network logs. WebSentry minimizes its own data footprint but does not claim network traffic is invisible everywhere.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | Next.js 16, React 19, TypeScript |
| API / Worker | Hono, Cloudflare Workers |
| Styling | Custom CSS, dark mode |
| DNS Resolution | Cloudflare DoH (1.1.1.1/dns-query) |
| Deployment | Vercel (frontend), Cloudflare Workers (backend) |

---

## Project Structure

```text
websentry/
├── apps/
│   ├── web/              # Next.js frontend
│   │   ├── app/
│   │   │   ├── page.tsx          # Main scanner UI
│   │   │   └── globals.css       # Styles + dark mode
│   │   └── .env.local
│   └── worker/           # Hono API + scanners
│       ├── src/
│       │   ├── index.ts                 # Main orchestrator
│       │   ├── types/index.ts           # TypeScript interfaces
│       │   ├── lib/
│       │   │   ├── target.ts            # URL validation
│       │   │   └── fetch-safe.ts        # Bounded fetch + redirect detection
│       │   └── scanners/
│       │       ├── dns.ts               # DNS + SPF/DMARC
│       │       ├── headers.ts           # Security headers (deep CSP)
│       │       ├── tls.ts               # TLS + CT logs + HSTS preload
│       │       ├── cookies.ts           # Cookie attribute inspection
│       │       ├── cors.ts              # CORS preflight testing
│       │       ├── cors-detailed.ts     # CORS deep analysis
│       │       ├── files.ts             # robots.txt + security.txt
│       │       ├── technology.ts        # 80+ technology signatures
│       │       ├── paths.ts             # 35+ exposed path probes
│       │       ├── mixed-content.ts     # Mixed content detection
│       │       ├── forms.ts             # CSRF + form analysis
│       │       ├── seo.ts               # SEO meta tags + Open Graph
│       │       ├── accessibility.ts     # A11y checks
│       │       ├── performance.ts       # Performance metrics
│       │       ├── infrastructure.ts    # HTTP/2, IPv6, DNSSEC
│       │       ├── sri.ts              # Subresource Integrity
│       │       ├── source-exposure.ts   # Version/source leakage
│       │       ├── jwt.ts              # JWT token detection
│       │       └── score.ts            # Deterministic scoring
│       └── wrangler.toml
├── package.json
└── README.md
```

---

## Quick Start

### Prerequisites

- **Node.js 20.9+**
- **npm**
- A **Cloudflare** account
- A **Vercel** account

### 1. Deploy the Worker

```bash
cd apps/worker
npm install
npx wrangler login
npx wrangler deploy
```

Wrangler prints the Worker URL:

```
https://websentry-api.<your-subdomain>.workers.dev
```

Verify:

```bash
curl https://websentry-api.<your-subdomain>.workers.dev/health
```

```json
{"ok":true,"service":"websentry-api"}
```

### 2. Configure the Frontend

Create `apps/web/.env.local`:

```
NEXT_PUBLIC_API_URL=https://websentry-api.<your-subdomain>.workers.dev
```

Then:

```bash
cd apps/web
npm install
npm run dev
```

Open **http://localhost:3000**.

### 3. Deploy to Vercel

1. Import the repository into Vercel
2. Set **Root Directory** to `apps/web`
3. Add environment variable:

   | Key | Value |
   |---|---|
   | `NEXT_PUBLIC_API_URL` | `https://websentry-api.<your-subdomain>.workers.dev` |

4. Deploy

### 4. Push to GitHub

```bash
git init && git add -A && git commit -m "Initial commit"
git remote add origin https://github.com/your-username/websentry.git
git push -u origin main
```

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check → `{"ok":true}` |
| `/api/scan` | POST | Start scan. Body: `{"url":"https://example.com"}`. Returns SSE stream. |

### SSE Events

| Event | Payload |
|---|---|
| `scan` | Scan started |
| `progress` | Intermediate check complete |
| `result` | Full report (final event) |
| `error` | Error message |

---

## Operational Limits

WebSentry is a **public-web scanner**, not a general network scanner:

- Only accepts `http://` and `https://` URLs
- Ports limited to **80** and **443**
- Private/reserved IP ranges blocked
- Redirect count and destination validated
- Response size bounded (2MB)
- Request timeout enforced

---

## License

MIT — use freely, deploy freely, scan responsibly.

---

<div align="center">

**Developed by [JOJIN JOHN](https://github.com/jojin1709)**

</div>
