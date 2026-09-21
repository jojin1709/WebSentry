import { normalizeTarget, validateTarget } from "./target";

export interface SafeFetchResult {
  response: Response;
  finalUrl: URL;
  redirects: string[];
  elapsedMs: number;
}

function timeoutSignal(ms: number): AbortSignal {
  return AbortSignal.timeout(ms);
}

export async function safeFetch(input: URL, maxRedirects: number, timeoutMs: number): Promise<SafeFetchResult> {
  let current = new URL(input.toString());
  const redirects: string[] = [];
  const started = Date.now();

  for (let i = 0; i <= maxRedirects; i++) {
    await validateTarget(current);
    const response = await fetch(current.toString(), {
      method: "GET",
      redirect: "manual",
      signal: timeoutSignal(timeoutMs),
      headers: {
        "User-Agent": "WebSentry/1.0 (+https://websentry.example)",
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
      },
      cf: { cacheTtl: 0 },
    });

    const location = response.headers.get("location");
    if (response.status >= 300 && response.status < 400 && location) {
      if (i === maxRedirects) throw new Error(`Redirect limit (${maxRedirects}) exceeded.`);
      const next = normalizeTarget(new URL(location, current).toString());
      redirects.push(next.toString());
      current = next;
      continue;
    }

    return { response, finalUrl: current, redirects, elapsedMs: Date.now() - started };
  }

  throw new Error("Unable to complete the request.");
}

export async function fetchText(url: URL, timeoutMs: number, maxBytes: number): Promise<{ response: Response; text: string }> {
  await validateTarget(url);
  const response = await fetch(url.toString(), {
    method: "GET",
    redirect: "manual",
    signal: timeoutSignal(timeoutMs),
    headers: { "User-Agent": "WebSentry/1.0 (+https://websentry.example)", "Accept": "text/plain,text/html,*/*;q=0.5" },
    cf: { cacheTtl: 0 },
  });
  if (!response.body) return { response, text: "" };
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
  return { response, text };
}
