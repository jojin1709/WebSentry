import dns from "node:dns";
import { isIP } from "node:net";

const PRIVATE_V4 = [
  [/^10\./, "10.0.0.0/8"],
  [/^127\./, "127.0.0.0/8"],
  [/^169\.254\./, "169.254.0.0/16"],
  [/^192\.168\./, "192.168.0.0/16"],
  [/^172\.(1[6-9]|2\d|3[0-1])\./, "172.16.0.0/12"],
] as const;

function isPrivateIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  return normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb");
}

export function isBlockedIp(ip: string): boolean {
  if (isIP(ip) === 4) return PRIVATE_V4.some(([re]) => re.test(ip));
  if (isIP(ip) === 6) return isPrivateIPv6(ip);
  return true;
}

export async function resolvePublicAddresses(hostname: string): Promise<string[]> {
  const records = new Set<string>();
  try {
    const a = await dns.promises.resolve4(hostname);
    a.forEach((ip) => records.add(ip));
  } catch {}
  try {
    const aaaa = await dns.promises.resolve6(hostname);
    aaaa.forEach((ip) => records.add(ip));
  } catch {}
  const addresses = [...records];
  if (!addresses.length) throw new Error("The hostname could not be resolved.");
  if (addresses.some(isBlockedIp)) throw new Error("The target resolves to a private or reserved IP address.");
  return addresses;
}

export function normalizeTarget(input: string): URL {
  const raw = input.trim();
  if (!raw) throw new Error("Enter a URL or domain.");
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  const url = new URL(withScheme);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP and HTTPS targets are allowed.");
  if (url.username || url.password) throw new Error("URLs containing credentials are not allowed.");
  if (url.port && !["80", "443"].includes(url.port)) throw new Error("Only ports 80 and 443 are allowed.");
  if (!url.hostname || url.hostname.includes("..")) throw new Error("Invalid hostname.");
  if (isIP(url.hostname) && isBlockedIp(url.hostname)) throw new Error("Private or reserved IP targets are blocked.");
  url.hash = "";
  return url;
}

export async function validateTarget(url: URL): Promise<string[]> {
  if (isIP(url.hostname)) return isBlockedIp(url.hostname) ? Promise.reject(new Error("Private or reserved IP targets are blocked.")) : [url.hostname];
  return resolvePublicAddresses(url.hostname);
}
