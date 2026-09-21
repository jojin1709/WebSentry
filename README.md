# WebSentry

Privacy-first, ephemeral website security monitor built for **Vercel + Cloudflare Workers**.

## What is included

- No login
- No application database
- No scan history
- No persistent target storage
- Real-time SSE scan progress
- URL/domain validation
- SSRF protections for private/reserved IP ranges
- Redirect validation and redirect limits
- Bounded response size and request timeout
- DNS: A, AAAA, MX, NS, TXT, CAA
- HTTP status, response timing, content type, server header
- HTTPS enforcement observation
- Security headers: CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, CORP
- Cookie flag inspection: Secure, HttpOnly, SameSite
- CORS response inspection
- robots.txt inspection
- /.well-known/security.txt inspection
- Technology signature detection
- Transparent finding evidence and recommendations
- Deterministic security score based on observed findings
- Clean responsive UI

## Runtime note

The scanner intentionally does **not** pretend to provide low-level certificate internals from a Workers-only runtime. The TLS section reports HTTPS reachability and HSTS posture and explicitly labels certificate internals as not inspected.

Likewise, technology detection is signature-based and should be treated as an observation, not proof of a complete technology inventory.

## Project structure

```text
websentry/
├── apps/
│   ├── web/       # Next.js frontend for Vercel
│   └── worker/    # Hono API + scanner for Cloudflare Workers
├── docs/
└── package.json
```

## Requirements

- Node.js 20.9+
- npm
- A Vercel account for the frontend
- A Cloudflare account for the Worker

Next.js 16 requires Node.js 20.9 or newer. The project pins Next.js 16.3.3, an Active LTS release as of the project creation date.

## 1. Deploy the Worker

```bash
cd apps/worker
npm install
npx wrangler login
npx wrangler deploy
```

Wrangler will print the Worker URL, for example:

```text
https://websentry-api.<your-subdomain>.workers.dev
```

You can test it:

```bash
curl https://websentry-api.<your-subdomain>.workers.dev/health
```

Expected response:

```json
{"ok":true,"service":"websentry-api"}
```

### Local Worker development

```bash
cd apps/worker
npm install
npx wrangler dev
```

## 2. Configure the frontend

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

Open:

```text
http://localhost:3000
```

## 3. Deploy the frontend to Vercel

Import the repository into Vercel and set the project Root Directory to:

```text
apps/web
```

Add this environment variable in Vercel:

```text
NEXT_PUBLIC_API_URL=https://websentry-api.<your-subdomain>.workers.dev
```

Deploy.

Vercel provides first-class Next.js deployment support, so the frontend can be deployed directly as a Next.js project.

## 4. Test a real scan

The browser calls:

```http
POST /api/scan
Content-Type: application/json

{"url":"https://example.com"}
```

The response is an SSE stream. Events include:

```text
event: scan
event: progress
event: result
event: error
```

The final `result` event contains the complete ephemeral report.

## Important operational limits

This is intentionally a public-web scanner, not a general network scanner. It only accepts `http://` and `https://` URLs and limits ports to 80/443.

The Worker blocks private/reserved IP ranges before outbound requests, validates redirect destinations, limits redirects, limits response size and applies a request timeout.

For a public production deployment, also configure Cloudflare's edge/WAF/rate-limiting controls for abuse protection. The application itself does not create a persistent rate-limit database because the project requirement is no persistent data storage.

## No-storage model

The application code does not create KV, D1, R2, Durable Objects, PostgreSQL, Redis, or another persistence binding. Results are held in the Worker request and streamed back to the browser.

This does **not** mean that Cloudflare, Vercel, DNS providers, or a target website can never have operational/network logs. Do not market the service as invisible or log-free at every infrastructure layer.

## Authorized use

Only scan websites you own or are explicitly authorized to assess. WebSentry is designed for defensive security review and configuration visibility; it does not implement credential attacks, exploit delivery, destructive testing, or arbitrary port scanning.
