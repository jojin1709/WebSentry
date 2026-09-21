import { Hono } from "hono";
import { cors } from "hono/cors";
import { normalizeTarget, validateTarget } from "./lib/target";
import { safeFetch } from "./lib/fetch-safe";
import { scanDns, dnsFindings } from "./scanners/dns";
import { scanHeaders } from "./scanners/headers";
import { scanCookies } from "./scanners/cookies";
import { scanCors } from "./scanners/cors";
import { scanRobots, scanSecurityTxt } from "./scanners/files";
import { detectTechnologies } from "./scanners/technology";
import { calculateScore, countSeverities } from "./scanners/score";
import { scanTls } from "./scanners/tls";
import { scanPaths } from "./scanners/paths";
import { scanMixedContent } from "./scanners/mixed-content";
import { scanForms } from "./scanners/forms";
import { scanSeo } from "./scanners/seo";
import { scanCorsDetailed } from "./scanners/cors-detailed";
import type { Finding, ScanResult } from "./types";

interface Env {
  MAX_BODY_BYTES?: string;
  MAX_REDIRECTS?: string;
  MAX_RESPONSE_BYTES?: string;
  FETCH_TIMEOUT_MS?: string;
}

const app = new Hono<{ Bindings: Env }>();

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET", "POST", "OPTIONS"],
  allowHeaders: ["Content-Type"],
  maxAge: 86400,
}));

app.get("/", (c) => c.json({ name: "WebSentry API", version: "3.0.0", storage: "none" }));
app.get("/health", (c) => c.json({ ok: true, service: "websentry-api" }));

function jsonHeaders() {
  return { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
}

function sseEvent(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

async function readLimitedText(response: Response, maxBytes: number): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let total = 0;
  let text = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error("Response exceeded the configured size limit.");
    }
    text += decoder.decode(value, { stream: true });
  }
  text += decoder.decode();
  return text;
}

function parseIntEnv(value: string | undefined, fallback: number, min: number, max: number): number {
  const n = Number.parseInt(value ?? "", 10);
  return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : fallback;
}

function createScanId() {
  return crypto.randomUUID();
}

app.post("/api/scan", async (c) => {
  const maxBodyBytes = parseIntEnv(c.env.MAX_BODY_BYTES, 4096, 512, 16384);
  const contentLength = Number(c.req.header("content-length") ?? 0);
  if (contentLength > maxBodyBytes) return c.json({ error: "Request body is too large." }, 413, jsonHeaders());

  let payload: { url?: string };
  try { payload = await c.req.json(); } catch { return c.json({ error: "Expected JSON body." }, 400, jsonHeaders()); }
  if (typeof payload.url !== "string" || payload.url.length > 2048) return c.json({ error: "Provide a valid URL up to 2048 characters." }, 400, jsonHeaders());

  let target: URL;
  try { target = normalizeTarget(payload.url); validateTarget(target); } catch (error) {
    return c.json({ error: error instanceof Error ? error.message : "Target validation failed." }, 400, jsonHeaders());
  }

  const scanId = createScanId();
  const maxRedirects = parseIntEnv(c.env.MAX_REDIRECTS, 5, 0, 10);
  const maxResponseBytes = parseIntEnv(c.env.MAX_RESPONSE_BYTES, 524288, 65536, 2097152);
  const timeoutMs = parseIntEnv(c.env.FETCH_TIMEOUT_MS, 8000, 2000, 15000);
  const started = Date.now();

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const encoder = new TextEncoder();
      const send = (event: string, data: unknown) => controller.enqueue(encoder.encode(sseEvent(event, data)));
      const checks: ScanResult["checks"] = [];
      const findings: Finding[] = [];
      const startedAt = new Date().toISOString();

      try {
        send("scan", { scanId, target: target.toString(), status: "started" });

        send("progress", { key: "dns", name: "DNS analysis", status: "running" });
        const dns = await scanDns(target.hostname);
        findings.push(...dnsFindings(dns));
        checks.push({ key: "dns", name: "DNS analysis", status: "complete", summary: `${dns.A.length} A, ${dns.AAAA.length} AAAA, ${dns.MX.length} MX records. SPF: ${dns.spf.found ? dns.spf.policy ?? "found" : "missing"}. DMARC: ${dns.dmarc.found ? dns.dmarc.policy ?? "found" : "missing"}.` });
        send("progress", { key: "dns", name: "DNS analysis", status: "complete", summary: checks.at(-1)?.summary });

        send("progress", { key: "http", name: "HTTP analysis", status: "running" });
        const fetched = await safeFetch(target, maxRedirects, timeoutMs);
        const response = fetched.response;
        const finalUrl = fetched.finalUrl;
        const body = await readLimitedText(response.clone(), maxResponseBytes);
        checks.push({ key: "http", name: "HTTP analysis", status: "complete", summary: `${response.status} ${response.statusText}` });
        send("progress", { key: "http", name: "HTTP analysis", status: "complete", summary: `${response.status} ${response.statusText}` });

        if (response.headers.get("server")) {
          findings.push({ id: "server-header", category: "Information Disclosure", severity: "info", status: "info", title: "Server header is exposed", evidence: response.headers.get("server")!.slice(0, 200), recommendation: "Consider whether detailed server identification is necessary." });
        }

        send("progress", { key: "headers", name: "Security headers", status: "running" });
        const headerFindings = scanHeaders(response);
        findings.push(...headerFindings);
        const passCount = headerFindings.filter((f) => f.status === "pass").length;
        const failCount = headerFindings.filter((f) => f.status === "fail").length;
        checks.push({ key: "headers", name: "Security headers", status: "complete", summary: `${passCount} headers present, ${failCount} issues found.` });
        send("progress", { key: "headers", name: "Security headers", status: "complete", summary: checks.at(-1)?.summary });

        send("progress", { key: "cookies", name: "Cookie security", status: "running" });
        const cookieScan = scanCookies(response);
        findings.push(...cookieScan.findings);
        checks.push({ key: "cookies", name: "Cookie security", status: "complete", summary: `${cookieScan.cookies.length} cookies observed.` });
        send("progress", { key: "cookies", name: "Cookie security", status: "complete", summary: checks.at(-1)?.summary });

        send("progress", { key: "cors", name: "CORS analysis", status: "running" });
        const corsFindings = scanCors(response);
        findings.push(...corsFindings);
        const corsDetail = await scanCorsDetailed(finalUrl, timeoutMs);
        findings.push(...corsDetail.findings);
        checks.push({ key: "cors", name: "CORS analysis", status: "complete", summary: corsDetail.cors.allowOrigin ? `Origin: ${corsDetail.cors.allowOrigin}` : corsFindings[0]?.title ?? "Completed." });
        send("progress", { key: "cors", name: "CORS analysis", status: "complete", summary: checks.at(-1)?.summary });

        send("progress", { key: "files", name: "robots.txt and security.txt", status: "running" });
        const [robots, securityTxt] = await Promise.all([
          scanRobots(finalUrl, timeoutMs, Math.min(maxResponseBytes, 262144)),
          scanSecurityTxt(finalUrl, timeoutMs, Math.min(maxResponseBytes, 262144)),
        ]);
        checks.push({ key: "files", name: "robots.txt and security.txt", status: "complete", summary: `${robots.found ? "robots.txt found" : "robots.txt not found"}; ${securityTxt.found ? "security.txt found" : "security.txt not found"}.` });
        send("progress", { key: "files", name: "robots.txt and security.txt", status: "complete", summary: checks.at(-1)?.summary });

        send("progress", { key: "technology", name: "Technology detection", status: "running" });
        const technologies = detectTechnologies(body, response.headers);
        checks.push({ key: "technology", name: "Technology detection", status: "complete", summary: technologies.length ? technologies.join(", ") : "No supported technology signatures detected." });
        send("progress", { key: "technology", name: "Technology detection", status: "complete", summary: checks.at(-1)?.summary });

        send("progress", { key: "tls", name: "TLS / HTTPS analysis", status: "running" });
        const tlsResult = await scanTls(target.hostname, finalUrl, response.headers.get("strict-transport-security"), timeoutMs);
        findings.push(...tlsResult.findings);
        checks.push({ key: "tls", name: "TLS / HTTPS analysis", status: "complete", summary: `HTTPS: ${tlsResult.tls.https ? "yes" : "no"}. HSTS: ${tlsResult.tls.hsts ? "yes" : "no"}. CT logs: ${tlsResult.tls.ctLogsFound ? "found" : "not found"}.` });
        send("progress", { key: "tls", name: "TLS / HTTPS analysis", status: "complete", summary: checks.at(-1)?.summary });

        send("progress", { key: "paths", name: "Exposed paths scan", status: "running" });
        const pathResult = await scanPaths(finalUrl, timeoutMs, maxResponseBytes);
        findings.push(...pathResult.findings);
        checks.push({ key: "paths", name: "Exposed paths scan", status: "complete", summary: `${pathResult.paths.length} sensitive path(s) detected.` });
        send("progress", { key: "paths", name: "Exposed paths scan", status: "complete", summary: checks.at(-1)?.summary });

        send("progress", { key: "content", name: "Content analysis", status: "running" });
        const mixedContent = scanMixedContent(body, finalUrl);
        findings.push(...mixedContent);
        const formResult = scanForms(body);
        findings.push(...formResult.findings);
        const seoResult = scanSeo(body);
        findings.push(...seoResult.findings);
        const contentSummary = [
          mixedContent.length ? `${mixedContent.length} mixed content` : "No mixed content",
          `${formResult.forms.length} form(s)`,
          seoResult.seo.title ? `Title: "${seoResult.seo.title.slice(0, 40)}"` : "No title",
        ].join(", ");
        checks.push({ key: "content", name: "Content analysis", status: "complete", summary: contentSummary });
        send("progress", { key: "content", name: "Content analysis", status: "complete", summary: contentSummary });

        const score = calculateScore(findings, tlsResult.tls.https);
        const result: ScanResult = {
          scanId,
          target: target.toString(),
          finalUrl: finalUrl.toString(),
          scannedAt: startedAt,
          durationMs: Date.now() - started,
          score,
          counts: countSeverities(findings),
          checks,
          findings,
          http: { status: response.status, statusText: response.statusText, responseTimeMs: fetched.elapsedMs, contentType: response.headers.get("content-type"), server: response.headers.get("server"), redirects: fetched.redirects },
          tls: tlsResult.tls,
          dns,
          cookies: cookieScan.cookies,
          technologies,
          files: { robots, securityTxt },
          exposedPaths: pathResult.paths,
          forms: formResult.forms,
          seo: seoResult.seo,
          corsDetail: corsDetail.cors,
        };
        send("result", result);
        send("scan", { scanId, status: "completed" });
      } catch (error) {
        send("error", { message: error instanceof Error ? error.message : "Scan failed." });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, { headers: { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-store, no-cache, must-revalidate", "connection": "keep-alive", "x-content-type-options": "nosniff" } });
});

export default app;
