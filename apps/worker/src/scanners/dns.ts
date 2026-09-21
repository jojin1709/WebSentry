const DOH = "https://1.1.1.1/dns-query";

async function resolveDoh(host: string, type: string): Promise<string[]> {
  try {
    const res = await fetch(`${DOH}?name=${encodeURIComponent(host)}&type=${type}`, {
      headers: { Accept: "application/dns-json" },
      cf: { cacheTtl: 60 },
    });
    if (!res.ok) return [];
    const data = await res.json() as { Answer?: Array<{ type: number; data: string }> };
    if (!data.Answer) return [];
    const typeNum = { A: 1, AAAA: 28, MX: 15, NS: 2, TXT: 16, CAA: 257 }[type] ?? 0;
    return data.Answer.filter((a) => a.type === typeNum).map((a) => a.data);
  } catch {
    return [];
  }
}

export interface DnsResult {
  A: string[]; AAAA: string[]; MX: string[]; NS: string[]; TXT: string[]; CAA: string[];
}

export async function scanDns(host: string): Promise<DnsResult> {
  const [A, AAAA, MX, NS, TXT, CAA] = await Promise.all([
    resolveDoh(host, "A"), resolveDoh(host, "AAAA"), resolveDoh(host, "MX"),
    resolveDoh(host, "NS"), resolveDoh(host, "TXT"), resolveDoh(host, "CAA"),
  ]);
  return { A, AAAA, MX, NS, TXT, CAA };
}
