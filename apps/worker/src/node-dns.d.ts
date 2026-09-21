declare module "node:dns" {
  type MXRecord = { exchange: string; priority: number };
  type CAARecord = { critical: number; issue?: string; issuewild?: string; iodef?: string };
  interface ResolvePromises {
    resolve4(hostname: string): Promise<string[]>;
    resolve6(hostname: string): Promise<string[]>;
    resolve(hostname: string, rrtype: "A" | "AAAA"): Promise<string[]>;
    resolve(hostname: string, rrtype: "MX"): Promise<MXRecord[]>;
    resolve(hostname: string, rrtype: "NS"): Promise<string[]>;
    resolve(hostname: string, rrtype: "TXT"): Promise<string[][]>;
    resolve(hostname: string, rrtype: "CAA"): Promise<CAARecord[]>;
  }
  const promises: ResolvePromises;
  const defaultExport: { promises: ResolvePromises };
  export = defaultExport;
}
