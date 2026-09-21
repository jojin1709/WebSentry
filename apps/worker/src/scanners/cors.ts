import type { Finding } from "../types";

export function scanCors(response: Response): Finding[] {
  const origin = response.headers.get("access-control-allow-origin");
  const credentials = response.headers.get("access-control-allow-credentials");
  if (!origin) return [{ id: "cors-none", category: "CORS", severity: "info", status: "info", title: "No Access-Control-Allow-Origin header observed", evidence: "The scanned response did not advertise cross-origin access.", recommendation: "If CORS is required, configure an explicit allowlist appropriate to the application." }];
  if (origin === "*" && credentials?.toLowerCase() === "true") return [{ id: "cors-wildcard-credentials", category: "CORS", severity: "high", status: "fail", title: "Wildcard CORS with credentials was observed", evidence: "Access-Control-Allow-Origin is '*' and Access-Control-Allow-Credentials is 'true'.", recommendation: "Use explicit trusted origins for credentialed CORS and avoid wildcard origins." }];
  if (origin === "*") return [{ id: "cors-wildcard", category: "CORS", severity: "low", status: "warn", title: "Wildcard CORS origin was observed", evidence: "Access-Control-Allow-Origin is '*'.", recommendation: "Confirm that public cross-origin access is intentional and does not expose sensitive responses." }];
  return [{ id: "cors-explicit", category: "CORS", severity: "info", status: "pass", title: "Explicit CORS origin was observed", evidence: origin, recommendation: "Review the allowlist and credential policy periodically." }];
}
