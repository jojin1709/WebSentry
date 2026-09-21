import type { Finding } from "../types";

export interface CookieInfo { name: string; secure: boolean; httpOnly: boolean; sameSite: string | null; }

function splitSetCookie(header: string): string[] {
  return header.split(/,(?=\s*[^;,=\s]+\s*=)/g);
}

export function scanCookies(response: Response): { cookies: CookieInfo[]; findings: Finding[] } {
  const raw = response.headers.get("set-cookie");
  if (!raw) return { cookies: [], findings: [{ id: "cookies-none", category: "Cookies", severity: "info", status: "info", title: "No Set-Cookie header observed", evidence: "The response did not expose a Set-Cookie header.", recommendation: "If the site uses cookies on other routes, review those cookies separately." }] };
  const cookies: CookieInfo[] = [];
  const findings: Finding[] = [];
  for (const part of splitSetCookie(raw)) {
    const segments = part.split(";").map((x) => x.trim());
    const [name] = segments[0].split("=");
    if (!name) continue;
    const lower = segments.slice(1).map((x) => x.toLowerCase());
    const secure = lower.includes("secure");
    const httpOnly = lower.includes("httponly");
    const sameSite = segments.slice(1).find((x) => /^samesite=/i.test(x))?.split("=")[1] ?? null;
    cookies.push({ name, secure, httpOnly, sameSite });
    if (!secure && new URL(response.url).protocol === "https:") findings.push({ id: `cookie-${name}-secure`, category: "Cookies", severity: "medium", status: "fail", title: `${name} cookie is missing Secure`, evidence: "A cookie was observed over HTTPS without the Secure attribute.", recommendation: "Set Secure on sensitive cookies that should only travel over HTTPS." });
    if (!httpOnly) findings.push({ id: `cookie-${name}-httponly`, category: "Cookies", severity: "low", status: "warn", title: `${name} cookie is missing HttpOnly`, evidence: "The cookie is accessible to client-side scripts unless other browser controls apply.", recommendation: "Consider HttpOnly for session and other sensitive cookies that do not need JavaScript access." });
    if (!sameSite) findings.push({ id: `cookie-${name}-samesite`, category: "Cookies", severity: "low", status: "warn", title: `${name} cookie has no SameSite attribute`, evidence: "No SameSite attribute was observed.", recommendation: "Set an intentional SameSite policy for cookies, especially authentication cookies." });
  }
  return { cookies, findings };
}
