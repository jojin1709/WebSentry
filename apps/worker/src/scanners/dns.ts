import dns from "node:dns";

export interface DnsResult {
  A: string[]; AAAA: string[]; MX: string[]; NS: string[]; TXT: string[]; CAA: string[];
}

async function resolve(host: string, type: "A" | "AAAA" | "MX" | "NS" | "TXT" | "CAA"): Promise<string[]> {
  try {
    const result = await dns.promises.resolve(host, type);
    if (type === "MX") return (result as Array<{ exchange: string; priority: number }>).map((x) => `${x.priority} ${x.exchange}`);
    if (type === "CAA") return (result as Array<{ critical: number; issue?: string; issuewild?: string; iodef?: string }>).map((x) => JSON.stringify(x));
    if (type === "TXT") return (result as string[][]).map((parts) => parts.join(""));
    return result as string[];
  } catch { return []; }
}

export async function scanDns(host: string): Promise<DnsResult> {
  const [A, AAAA, MX, NS, TXT, CAA] = await Promise.all([
    resolve(host, "A"), resolve(host, "AAAA"), resolve(host, "MX"), resolve(host, "NS"), resolve(host, "TXT"), resolve(host, "CAA"),
  ]);
  return { A, AAAA, MX, NS, TXT, CAA };
}
