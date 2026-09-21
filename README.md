<div align="center">

# WebSentry

### Privacy-first, ephemeral website security monitor for the modern web.

**Real-time scanning. Zero persistence. No login required.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-20.9%2B-green.svg)](https://nodejs.org)
[![Next.js](https://img.shields.io/badge/Next.js-16-black.svg)](https://nextjs.org)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange.svg)](https://workers.cloudflare.com)

---

**WebSentry** analyzes any public website and produces a detailed security report in seconds. No databases. No scan history. No accounts. Just paste a URL and get answers.

It checks DNS records, HTTP configuration, security headers, cookie flags, CORS policies, robots.txt, security.txt, HTTPS enforcement, and technology signatures — then scores the result deterministically.

**This repository is WebSentry: the full stack, run locally or deploy to Vercel + Cloudflare Workers.**

**Developed by JOJIN JOHN**

---

</div>

## Table of Contents

- [Table of Contents](#table-of-contents)
- [What is WebSentry?](#what-is-websentry)
  - [Why WebSentry Exists](#why-websentry-exists)
  - [Privacy-First Design](#privacy-first-design)
- [Key Capabilities](#key-capabilities)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
  - [Prerequisites](#prerequisites)
  - [Deploy the Worker](#1-deploy-the-worker)
  - [Configure the Frontend](#2-configure-the-frontend)
  - [Deploy to Vercel](#3-deploy-the-frontend-to-vercel)
  - [Test a Real Scan](#4-test-a-real-scan)
- [Local Development](#local-development)
- [API Reference](#api-reference)
- [Runtime Notes](#runtime-notes)
- [Operational Limits](#operational-limits)
- [No-Storage Model](#no-storage-model)
- [Authorized Use](#authorized-use)
- [License](#license)

---

## What is WebSentry?

WebSentry is a privacy-first website security monitor that performs comprehensive configuration and security-header analysis against any public URL. It runs as a serverless application on **Vercel** (Next.js frontend) and **Cloudflare Workers** (Hono API + scanner backend).

### Why WebSentry Exists

Most website security scanners require accounts, store scan history, and persist target data. WebSentry takes the opposite approach: paste a URL, get a real-time report, and nothing is saved. It is designed for developers, security-conscious teams, and anyone who wants quick visibility into a site's security posture without the overhead of a SaaS platform.

### Privacy-First Design

- **No login** — no accounts, no cookies, no sessions stored.
- **No database** — no PostgreSQL, Redis, KV, D1, or Durable Objects.
- **No scan history** — results stream to the browser and disappear when the tab closes.
- **No persistent target storage** — the URL you scan is never written to disk.

> [!IMPORTANT]
> This does **not** mean that Cloudflare, Vercel, DNS providers, or the target website can never have operational or network logs. WebSentry is designed to minimize its own data footprint, not to make requests invisible at every infrastructure layer.

---

## Key Capabilities

| Category | Checks |
| --- | --- |
| **DNS** | A, AAAA, MX, NS, TXT, CAA records |
| **HTTP** | Status code, response timing, content type, server header |
| **TLS / HTTPS** | HTTPS reachability, HSTS posture, redirect enforcement |
| **Security Headers** | CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, CORP |
| **Cookies** | Secure, HttpOnly, SameSite flag inspection |
| **CORS** | Cross-origin response inspection |
| **Files** | robots.txt, /.well-known/security.txt |
| **Technology** | Signature-based technology detection |
| **Scoring** | Deterministic security score from observed findings |
| **Real-time** | SSE stream with scan, progress, result, and error events |

---

## Project Structure

```text
websentry/
├── apps/
│   ├── web/          # Next.js 16 frontend (Vercel)
│   └── worker/       # Hono API + scanner (Cloudflare Workers)
├── docs/
├── package.json
└── README.md
```

---

## Quick Start

### Prerequisites

- **Node.js 20.9+**
- **npm**
- A **Cloudflare** account (for the Worker)
- A **Vercel** account (for the frontend)

### 1. Deploy the Worker

```bash
cd apps/worker
npm install
npx wrangler login
npx wrangler deploy
```

Wrangler will print the Worker URL:

```text
https://websentry-api.<your-subdomain>.workers.dev
```

Verify it:

```bash
curl https://websentry-api.<your-subdomain>.workers.dev/health
```

```json
{"ok":true,"service":"websentry-api"}
```

### 2. Configure the Frontend

Create `apps/web/.env.local`:

```env
NEXT_PUBLIC_API_URL=https://websentry-api.<your-subdomain>.workers.dev
```

Then:

```bash
cd apps/web
npm install
npm run dev
```

Open **http://localhost:3000**.

### 3. Deploy the Frontend to Vercel

1. Import the repository into Vercel.
2. Set the **Root Directory** to `apps/web`.
3. Add this environment variable in the Vercel dashboard:

   | Key | Value |
   |---|---|
   | `NEXT_PUBLIC_API_URL` | `https://websentry-api.<your-subdomain>.workers.dev` |

4. Deploy.

### 4. Test a Real Scan

The browser sends:

```http
POST /api/scan
Content-Type: application/json

{"url":"https://example.com"}
```

The response is an **SSE stream** with events:

```text
event: scan        — scan started
event: progress    — intermediate update
event: result      — final report
event: error       — something went wrong
```

The `result` event contains the complete ephemeral security report.

---

## Local Development

Run both services locally:

**Worker:**

```bash
cd apps/worker
npm install
npx wrangler dev --port 8787
```

**Frontend** (with local worker):

```bash
echo "NEXT_PUBLIC_API_URL=http://localhost:8787" > apps/web/.env.local

cd apps/web
npm install
npm run dev
```

Open **http://localhost:3000**. The frontend will call the local worker at `http://localhost:8787`.

---

## API Reference

| Endpoint | Method | Description |
| --- | --- | --- |
| `/health` | GET | Health check. Returns `{"ok":true,"service":"websentry-api"}` |
| `/api/scan` | POST | Start a scan. Body: `{"url":"https://example.com"}`. Returns an SSE stream. |

---

## Runtime Notes

> [!NOTE]
> **TLS / Certificate Internals:** The scanner intentionally does **not** provide low-level certificate internals from a Workers-only runtime. The TLS section reports HTTPS reachability and HSTS posture and explicitly labels certificate internals as not inspected.

> [!NOTE]
> **Technology Detection:** Technology detection is signature-based and should be treated as an **observation**, not proof of a complete technology inventory.

---

## Operational Limits

WebSentry is a **public-web scanner**, not a general network scanner:

- Only accepts `http://` and `https://` URLs.
- Ports are limited to **80** and **443**.
- Private/reserved IP ranges are blocked before outbound requests.
- Redirect destinations are validated and redirect counts are limited.
- Response size is bounded and a request timeout is enforced.

For public production deployments, configure **Cloudflare's edge/WAF/rate-limiting** controls for abuse protection. The application itself does not create a persistent rate-limit database.

---

## No-Storage Model

The application code does **not** create KV, D1, R2, Durable Objects, PostgreSQL, Redis, or any other persistence binding. Results are held in the Worker request and streamed back to the browser.

---

## Authorized Use

> [!WARNING]
> Only scan websites you own or are explicitly authorized to assess. WebSentry is designed for **defensive security review** and configuration visibility; it does not implement credential attacks, exploit delivery, destructive testing, or arbitrary port scanning.

---

## License

WebSentry is released under the [MIT License](LICENSE).

---

<div align="center">

**Built with care by [JOJIN JOHN](https://github.com/jojin1709)**

</div>
