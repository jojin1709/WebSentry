export function normalizeTarget(input: string): URL {
  const raw = input.trim();
  if (!raw) throw new Error("Enter a URL or domain.");
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  const url = new URL(withScheme);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP and HTTPS targets are allowed.");
  if (url.username || url.password) throw new Error("URLs containing credentials are not allowed.");
  if (url.port && !["80", "443"].includes(url.port)) throw new Error("Only ports 80 and 443 are allowed.");
  if (!url.hostname || url.hostname.includes("..")) throw new Error("Invalid hostname.");
  url.hash = "";
  return url;
}

export function validateTarget(url: URL): void {
  const h = url.hostname;
  if (/^(10|127|169\.254|192\.168)\./.test(h)) throw new Error("Private or reserved IP targets are blocked.");
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(h)) throw new Error("Private or reserved IP targets are blocked.");
  if (/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.test(h)) {
    const parts = h.split(".").map(Number);
    if (parts[0] === 0 || parts[0] === 127 || parts[0] >= 224) throw new Error("Private or reserved IP targets are blocked.");
  }
}
