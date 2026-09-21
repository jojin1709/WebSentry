import type { Finding } from "../types";

export interface JwtInfo {
  found: boolean;
  locations: string[];
}

function isValidJwt(str: string): boolean {
  const parts = str.split(".");
  if (parts.length !== 3) return false;
  const [header, payload, sig] = parts;
  if (!header || !payload || !sig) return false;
  if (sig.length < 10 || sig.length > 200) return false;
  try {
    const h = JSON.parse(atob(header.replace(/-/g, "+").replace(/_/g, "/")));
    if (!h || typeof h !== "object") return false;
    if (h.typ && h.typ !== "JWT") return false;
    if (!h.alg) return false;
  } catch {
    return false;
  }
  try {
    const p = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
    if (!p || typeof p !== "object") return false;
    if (p.exp && typeof p.exp === "number") {
      const now = Math.floor(Date.now() / 1000);
      if (p.exp < now - 86400) return false;
    }
  } catch {
    return false;
  }
  return true;
}

export function scanJwt(html: string, cookies: string): { jwt: JwtInfo; findings: Finding[] } {
  const findings: Finding[] = [];
  const locations: string[] = [];
  const jwtPattern = /eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}/g;

  const htmlMatches = html.match(jwtPattern) || [];
  const validHtmlMatches = htmlMatches.filter(isValidJwt);
  if (validHtmlMatches.length > 0) {
    locations.push(`HTML body (${validHtmlMatches.length} token(s))`);
  }

  const cookieMatches = cookies.match(jwtPattern) || [];
  const validCookieMatches = cookieMatches.filter(isValidJwt);
  if (validCookieMatches.length > 0) {
    locations.push(`Cookies (${validCookieMatches.length} token(s))`);
  }

  const metaTokenPattern = /<meta[^>]+content=["'][^"']*\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}/i;
  const metaMatch = html.match(metaTokenPattern);
  if (metaMatch && isValidJwt(metaMatch[0].split('content="')[1]?.split('"')[0] || metaMatch[0].split("content='")[1]?.split("'")[0] || "")) {
    locations.push("Meta tag");
  }

  const found = locations.length > 0;

  if (found) {
    findings.push({
      id: "jwt-exposed",
      category: "JWT / Tokens",
      severity: "high",
      status: "fail",
      title: "JWT token(s) exposed in page source",
      evidence: `JWT tokens found in: ${locations.join(", ")}. Exposed JWTs can be stolen via XSS.`,
      recommendation: "Never embed JWT tokens in HTML source. Store them in httpOnly cookies or use short-lived tokens with refresh mechanisms.",
    });
  }

  return { jwt: { found, locations }, findings };
}
