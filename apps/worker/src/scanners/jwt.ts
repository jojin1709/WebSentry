import type { Finding } from "../types";

export interface JwtInfo {
  found: boolean;
  locations: string[];
}

export function scanJwt(html: string, cookies: string): { jwt: JwtInfo; findings: Finding[] } {
  const findings: Finding[] = [];
  const locations: string[] = [];
  const jwtPattern = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g;

  const htmlMatches = html.match(jwtPattern) || [];
  if (htmlMatches.length > 0) {
    locations.push(`HTML body (${htmlMatches.length} token(s))`);
  }

  const localStoragePattern = /localStorage|sessionStorage/i;
  if (localStoragePattern.test(html)) {
    if (htmlMatches.length > 0) {
      locations.push("Possible JWT in storage access code");
    }
  }

  const cookieMatches = cookies.match(jwtPattern) || [];
  if (cookieMatches.length > 0) {
    locations.push(`Cookies (${cookieMatches.length} token(s))`);
  }

  const metaTokenPattern = /<meta[^>]+content=["'][^"']*eyJ[A-Za-z0-9_-]/i;
  if (metaTokenPattern.test(html)) {
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
