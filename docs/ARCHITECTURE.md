# WebSentry Architecture

```text
Browser
  │
  ▼
Vercel / Next.js
  │
  │ POST /api/scan
  ▼
Cloudflare Worker / Hono
  │
  ├── Validate URL
  ├── Resolve + block private/reserved IPs
  ├── Safe HTTP fetch with manual redirects
  ├── DNS analysis
  ├── Header analysis
  ├── Cookie analysis
  ├── CORS analysis
  ├── robots.txt / security.txt
  ├── Technology signatures
  └── Score + findings
  │
  ▼
SSE stream
  │
  ▼
Browser report
```

There is intentionally no persistent application storage.

## Why SSE

The scanner can stream a real `progress` event after each completed check. The frontend does not need fake progress timers or a database-backed scan job.

## Why no Redis/queue

A scan is intentionally bounded and ephemeral. Introducing a queue would add persistent or semi-persistent infrastructure that is not necessary for this V1 requirement.

## Security boundary

The Worker is the security boundary. It must validate the target before every outbound request, including redirect targets.

The scanner uses manual redirects so a remote server cannot silently redirect the Worker to a new host without the new destination being validated first.
