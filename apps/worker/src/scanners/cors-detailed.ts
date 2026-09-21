import type { Finding } from "../types";

export interface CorsDetail {
  allowOrigin: string | null;
  allowMethods: string | null;
  allowHeaders: string | null;
  allowCredentials: string | null;
  maxAge: string | null;
  exposeHeaders: string | null;
  preflightRequired: boolean;
}

export async function scanCorsDetailed(
  targetUrl: URL,
  timeoutMs: number,
): Promise<{ cors: CorsDetail; findings: Finding[] }> {
  const findings: Finding[] = [];

  const cors: CorsDetail = {
    allowOrigin: null,
    allowMethods: null,
    allowHeaders: null,
    allowCredentials: null,
    maxAge: null,
    exposeHeaders: null,
    preflightRequired: false,
  };

  try {
    const preflightRes = await fetch(targetUrl.toString(), {
      method: "OPTIONS",
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        "Origin": "https://example.com",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "Content-Type",
      },
      cf: { cacheTtl: 0 },
    });

    cors.allowOrigin = preflightRes.headers.get("access-control-allow-origin");
    cors.allowMethods = preflightRes.headers.get("access-control-allow-methods");
    cors.allowHeaders = preflightRes.headers.get("access-control-allow-headers");
    cors.allowCredentials = preflightRes.headers.get("access-control-allow-credentials");
    cors.maxAge = preflightRes.headers.get("access-control-max-age");
    cors.exposeHeaders = preflightRes.headers.get("access-control-expose-headers");
    cors.preflightRequired = preflightRes.status === 204 || preflightRes.status === 200;

    if (cors.allowOrigin === "*" && cors.allowCredentials?.toLowerCase() === "true") {
      findings.push({
        id: "cors-preflight-wildcard-creds",
        category: "CORS",
        severity: "high",
        status: "fail",
        title: "CORS preflight returns wildcard with credentials",
        evidence: "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true.",
        recommendation: "Use explicit trusted origins instead of wildcard when credentials are allowed.",
      });
    } else if (cors.allowOrigin === "*") {
      findings.push({
        id: "cors-preflight-wildcard",
        category: "CORS",
        severity: "low",
        status: "warn",
        title: "CORS preflight allows all origins",
        evidence: "Access-Control-Allow-Origin is '*'.",
        recommendation: "Consider restricting CORS to specific trusted origins.",
      });
    } else if (cors.allowOrigin) {
      findings.push({
        id: "cors-preflight-explicit",
        category: "CORS",
        severity: "info",
        status: "pass",
        title: "CORS preflight uses explicit origin",
        evidence: `Access-Control-Allow-Origin: ${cors.allowOrigin}`,
        recommendation: "Review the allowed origin periodically.",
      });
    }

    if (cors.allowMethods) {
      const dangerousMethods = ["PUT", "DELETE", "PATCH"].filter((m) =>
        cors.allowMethods!.toUpperCase().includes(m)
      );
      if (dangerousMethods.length > 0) {
        findings.push({
          id: "cors-dangerous-methods",
          category: "CORS",
          severity: "medium",
          status: "warn",
          title: "CORS allows dangerous HTTP methods",
          evidence: `Access-Control-Allow-Methods includes: ${dangerousMethods.join(", ")}.`,
          recommendation: "Only allow the HTTP methods that are necessary for the application.",
        });
      }
    }
  } catch {
    // OPTIONS request failed - may not support CORS preflight
  }

  return { cors, findings };
}
