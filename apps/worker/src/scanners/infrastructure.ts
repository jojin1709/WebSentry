import type { Finding } from "../types";

export interface InfraResult {
  http2: boolean | null;
  http3: boolean | null;
  ipv6: boolean;
  dnssec: boolean | null;
  serverTiming: string | null;
  altSvc: string | null;
}

async function checkHttp2(url: string, timeoutMs: number): Promise<boolean | null> {
  try {
    const res = await fetch(url, {
      method: "HEAD",
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
      headers: { "User-Agent": "WebSentry/1.0" },
    });
    return (res as any).version === "h2" || (res as any).ok;
  } catch {
    return null;
  }
}

export async function scanInfrastructure(
  hostname: string,
  finalUrl: URL,
  response: Response,
  dnsA: string[],
  timeoutMs: number,
): Promise<{ infra: InfraResult; findings: Finding[] }> {
  const findings: Finding[] = [];

  const altSvc = response.headers.get("alt-svc");
  const serverTiming = response.headers.get("server-timing");
  const http3 = altSvc?.toLowerCase().includes("h3") ?? false;
  const http2 = response.headers.get("x-http2") !== null || http3;

  if (http3) {
    findings.push({
      id: "infra-http3",
      category: "Infrastructure",
      severity: "info",
      status: "pass",
      title: "HTTP/3 (QUIC) supported",
      evidence: `Alt-Svc: ${altSvc}`,
      recommendation: "HTTP/3 provides improved performance and security.",
    });
  } else if (http2) {
    findings.push({
      id: "infra-http2",
      category: "Infrastructure",
      severity: "info",
      status: "pass",
      title: "HTTP/2 supported",
      evidence: "Server supports HTTP/2.",
      recommendation: "Consider upgrading to HTTP/3 for better performance.",
    });
  } else {
    findings.push({
      id: "infra-http1",
      category: "Infrastructure",
      severity: "low",
      status: "info",
      title: "HTTP/1.1 detected",
      evidence: "Server appears to use HTTP/1.1.",
      recommendation: "Consider upgrading to HTTP/2 or HTTP/3 for better performance.",
    });
  }

  const ipv6 = dnsA.length === 0;

  const DOH = "https://1.1.1.1/dns-query";
  let aaaaRecords: string[] = [];
  try {
    const res = await fetch(`${DOH}?name=${encodeURIComponent(hostname)}&type=AAAA`, {
      headers: { Accept: "application/dns-json" },
      cf: { cacheTtl: 60 },
    });
    if (res.ok) {
      const data = await res.json() as { Answer?: Array<{ type: number; data: string }> };
      aaaaRecords = (data.Answer || []).filter((a) => a.type === 28).map((a) => a.data);
    }
  } catch {}

  if (aaaaRecords.length > 0) {
    findings.push({
      id: "infra-ipv6",
      category: "Infrastructure",
      severity: "info",
      status: "pass",
      title: "IPv6 support detected",
      evidence: `AAAA records: ${aaaaRecords.join(", ")}`,
      recommendation: "IPv6 support is good for future-proofing.",
    });
  } else {
    findings.push({
      id: "infra-no-ipv6",
      category: "Infrastructure",
      severity: "info",
      status: "info",
      title: "No IPv6 support detected",
      evidence: "No AAAA records found.",
      recommendation: "Consider adding IPv6 support for better compatibility.",
    });
  }

  let dnssec: boolean | null = null;
  try {
    const res = await fetch(`${DOH}?name=${encodeURIComponent(hostname)}&type=A&do=1`, {
      headers: { Accept: "application/dns-json" },
      cf: { cacheTtl: 60 },
    });
    if (res.ok) {
      const data = await res.json() as { AD?: boolean };
      dnssec = data.AD ?? null;
      if (dnssec === true) {
        findings.push({
          id: "infra-dnssec",
          category: "Infrastructure",
          severity: "info",
          status: "pass",
          title: "DNSSEC is enabled",
          evidence: "DNS responses are DNSSEC signed (AD flag set).",
          recommendation: "DNSSEC protects against DNS spoofing and cache poisoning.",
        });
      } else if (dnssec === false) {
        findings.push({
          id: "infra-no-dnssec",
          category: "Infrastructure",
          severity: "low",
          status: "info",
          title: "DNSSEC is not enabled",
          evidence: "DNS responses are not DNSSEC signed.",
          recommendation: "Enable DNSSEC to protect against DNS spoofing attacks.",
        });
      }
    }
  } catch {}

  if (serverTiming) {
    findings.push({
      id: "infra-server-timing",
      category: "Infrastructure",
      severity: "low",
      status: "info",
      title: "Server-Timing header exposed",
      evidence: `Server-Timing: ${serverTiming.slice(0, 200)}`,
      recommendation: "Server-Timing can leak internal performance details. Consider removing in production.",
    });
  }

  return {
    infra: { http2, http3, ipv6: aaaaRecords.length > 0, dnssec, serverTiming, altSvc },
    findings,
  };
}
