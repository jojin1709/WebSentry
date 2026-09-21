"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowRight, Check, CircleAlert, Clock3, Cookie, Download, FileText, Globe2, KeyRound, LockKeyhole, Radar, RefreshCw, Server, Settings2, ShieldAlert, ShieldCheck, ShieldX, Zap } from "lucide-react";

type Severity = "critical" | "high" | "medium" | "low" | "info";
type Finding = { id:string; category:string; severity:Severity; status:string; title:string; evidence:string; recommendation:string };
type Result = {
  scanId:string; target:string; finalUrl:string; scannedAt:string; durationMs:number; score:number;
  counts:Record<Severity,number>; checks:Array<{key:string;name:string;status:string;summary:string}>; findings:Finding[];
  http:{status:number;statusText:string;responseTimeMs:number;contentType:string|null;server:string|null;redirects:string[]};
  tls:{https:boolean;hsts:boolean;hstsMaxAge:number|null;hstsIncludeSubDomains:boolean;hstsPreload:boolean;hstsPreloadListed:boolean|null;ctLogsFound:boolean;certificateIssuer:string|null;certificateExpiry:string|null};
  dns:{A:string[];AAAA:string[];MX:string[];NS:string[];TXT:string[];CAA:string[];spf:{found:boolean;policy:string|null};dmarc:{found:boolean;policy:string|null;rua:string|null}};
  cookies:Array<{name:string;secure:boolean;httpOnly:boolean;sameSite:string|null}>;
  technologies:string[];
  files:{robots:{found:boolean;sitemapCount:number;disallowCount:number};securityTxt:{found:boolean;contactCount:number;expires:string|null}};
  exposedPaths:Array<{path:string;status:number;severity:string;title:string;description:string}>;
};

const API = process.env.NEXT_PUBLIC_API_URL || "";
const steps = [
  ["dns","DNS analysis"],["http","HTTP analysis"],["headers","Security headers"],["cookies","Cookie security"],
  ["cors","CORS analysis"],["files","robots.txt / security.txt"],["technology","Technology detection"],["tls","TLS / HTTPS"],["paths","Exposed paths"],
] as const;

const sidebarItems = [
  { id: "overview", icon: ShieldCheck, label: "Overview" },
  { id: "headers", icon: ShieldAlert, label: "Security headers" },
  { id: "tls", icon: LockKeyhole, label: "TLS / HTTPS" },
  { id: "dns", icon: Globe2, label: "DNS records" },
  { id: "email", icon: KeyRound, label: "Email security" },
  { id: "cookies", icon: Cookie, label: "Cookies" },
  { id: "cors", icon: Radar, label: "CORS" },
  { id: "redirects", icon: ArrowRight, label: "Redirects" },
  { id: "paths", icon: ShieldX, label: "Exposed paths" },
  { id: "files", icon: FileText, label: "robots.txt / security.txt" },
  { id: "tech", icon: Server, label: "Technologies" },
  { id: "findings", icon: CircleAlert, label: "All findings" },
];

export default function Home() {
  const [url,setUrl] = useState("");
  const [running,setRunning] = useState(false);
  const [error,setError] = useState("");
  const [progress,setProgress] = useState<Record<string,string>>({});
  const [result,setResult] = useState<Result|null>(null);
  const [dark,setDark] = useState(false);
  const [activeSection,setActiveSection] = useState("overview");
  const sectionRefs = useRef<Record<string,HTMLElement|null>>({});

  useEffect(() => {
    const saved = localStorage.getItem("websentry-dark");
    if (saved !== null) setDark(saved === "true");
    else setDark(window.matchMedia("(prefers-color-scheme: dark)").matches);
  }, []);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    localStorage.setItem("websentry-dark", String(dark));
  }, [dark]);

  const completed = Object.values(progress).filter(v => v === "complete").length;
  const percent = running ? Math.round((completed / steps.length) * 100) : result ? 100 : 0;

  const normalizeUrl = useCallback((input: string) => {
    const trimmed = input.trim();
    if (!trimmed) return "";
    if (/^https?:\/\//i.test(trimmed)) return trimmed;
    return `https://${trimmed}`;
  }, []);

  const validateUrl = useCallback((input: string) => {
    try {
      const url = new URL(normalizeUrl(input));
      if (!["http:", "https:"].includes(url.protocol)) return "Only HTTP and HTTPS URLs are supported.";
      if (!url.hostname) return "Please enter a valid domain or URL.";
      return null;
    } catch {
      return "Please enter a valid domain or URL (e.g. example.com).";
    }
  }, [normalizeUrl]);

  const scan = useCallback(async (scanUrl?: string) => {
    const target = scanUrl || url;
    setError(""); setResult(null); setProgress({}); setRunning(true);
    const validationError = validateUrl(target);
    if (validationError) { setError(validationError); setRunning(false); return; }
    try {
      if (!API) throw new Error("NEXT_PUBLIC_API_URL is not configured.");
      const response = await fetch(`${API.replace(/\/$/,"")}/api/scan`, { method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify({url: normalizeUrl(target)}) });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.error || `Worker returned HTTP ${response.status}.`);
      }
      if (!response.body) throw new Error("The scan stream was unavailable.");
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const {done,value} = await reader.read();
        if (done) break;
        buffer += decoder.decode(value,{stream:true});
        const parts = buffer.split("\n\n");
        buffer = parts.pop() || "";
        for (const part of parts) {
          const event = part.match(/^event:\s*(.+)$/m)?.[1]?.trim();
          const dataText = part.match(/^data:\s*(.+)$/m)?.[1];
          if (!event || !dataText) continue;
          const data = JSON.parse(dataText);
          if (event === "progress") setProgress(p => ({...p,[data.key]:data.status}));
          if (event === "result") setResult(data as Result);
          if (event === "error") throw new Error(data.message || "Scan failed.");
        }
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Scan failed.");
    } finally { setRunning(false); }
  }, [url, API, normalizeUrl, validateUrl]);

  function reset() { setResult(null); setError(""); setProgress({}); setUrl(""); setActiveSection("overview"); window.scrollTo({top:0,behavior:"smooth"}); }

  function exportJson() {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `websentry-${new URL(result.finalUrl).hostname}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function scrollToSection(id: string) {
    setActiveSection(id);
    sectionRefs.current[id]?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  return <main className="shell">
    <nav className="nav">
      <div className="brand"><span className="logo"><ShieldCheck size={19}/></span>WebSentry</div>
      <div className="navlinks"><a href="#features">Features</a><a href="#how">How it works</a><a href="#privacy">Privacy</a></div>
      <div className="navright">
        <button className="theme-toggle" onClick={() => setDark(d => !d)} aria-label="Toggle dark mode">{dark ? "☀️" : "🌙"}</button>
        <button className="navbutton" onClick={() => document.getElementById("scanner")?.scrollIntoView({behavior:"smooth"})}>Scan a Website</button>
      </div>
    </nav>

    <section className="hero" id="scanner">
      <div>
        <div className="eyebrow">Privacy-first website security</div>
        <h1>Know what your website <span className="gradient">exposes.</span></h1>
        <p>WebSentry performs a real, ephemeral security analysis of a public website. Inspect headers, HTTPS posture, cookies, CORS, DNS, TLS certificates, email security, exposed files, and detected technologies — without creating an account.</p>
        <div className="scanbar">
          <Globe2 size={20} style={{margin:"15px 0 0 13px",color:"var(--muted)"}}/>
          <input value={url} onChange={e=>setUrl(e.target.value)} onKeyDown={e=>{if(e.key==="Enter"&&!running)scan()}} placeholder="Enter a domain or URL (e.g. example.com)" aria-label="Website URL" />
          <button onClick={()=>scan()} disabled={running || !url.trim()}>{running ? "Scanning…" : <>Scan Now <ArrowRight size={17}/></>}</button>
        </div>
        <div className="trust"><span><ShieldCheck size={15}/>No account</span><span><Clock3 size={15}/>No scan history</span><span><Zap size={15}/>Live analysis</span><span><LockKeyhole size={15}/>Ephemeral results</span></div>
        {error && <div className="errorbox"><strong>Scan error:</strong> {error} {result && <button className="retry-btn" onClick={()=>scan()}>Retry <RefreshCw size={13}/></button>}</div>}
      </div>
      <div className="hero-art" aria-hidden="true">
        <div className="browser"><div className="browserbar"><span className="dot"/><span className="dot"/><span className="dot"/><div className="urlmock"/></div><div className="mockbody"><div className="mockcard"><div className="shield"><ShieldCheck/></div><div className="mocktitle">Security posture</div><div className="mockline"/><div className="mockline short"/><div className="checkrow"><span className="check"><Check size={11}/></span>HTTPS reachable</div><div className="checkrow"><span className="check"><Check size={11}/></span>Headers inspected</div><div className="checkrow"><span className="check"><Check size={11}/></span>Cookie flags parsed</div></div><div className="mockcard"><div className="mocktitle">Live checks</div><div className="mockline"/><div className="checkrow"><span className="check"><Check size={11}/></span>DNS records</div><div className="checkrow"><span className="check"><Check size={11}/></span>CORS policy</div><div className="checkrow"><span className="check"><Check size={11}/></span>Technology signatures</div><div className="checkrow"><span className="check"><Check size={11}/></span>robots.txt / security.txt</div></div></div></div>
      </div>
    </section>

    {(running || result) && <section className="section" id="report">
      {running && <div className="panel"><div className="scanhead"><div><h2>Scanning {url}</h2><div style={{color:"var(--muted)",fontSize:12,marginTop:4}}>Results are generated in real time and are not persisted by the application.</div></div><span className="statuspill">Live scan</span></div><div className="progressbody"><div className="progressbar"><div style={{width:`${Math.max(4,percent)}%`}}/></div><div className="progressmeta"><span>{completed} of {steps.length} checks complete</span><span>{percent}%</span></div><div className="steps">{steps.map(([key,name]) => <div className={`step ${progress[key]==="complete"?"done":progress[key]==="running"?"running":""}`} key={key}><div className="stepicon">{progress[key]==="complete"?<Check size={15}/>:progress[key]==="running"?<Radar size={15}/>:<span>•</span>}</div>{name}</div>)}</div></div></div>}
      {result && <Report result={result} onNew={reset} onExport={exportJson} activeSection={activeSection} onNavigate={scrollToSection} sectionRefs={sectionRefs}/>} 
    </section>}

    {!running && !result && <section className="section" id="features"><div className="panel" style={{padding:30}}><div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:16}}>{[
      [ShieldCheck,"Security headers","Deep CSP analysis, HSTS posture, X-Frame-Options and 15+ header checks."],[Globe2,"Network posture","DNS records, SPF/DMARC email security, redirects, HTTP status and response metadata."],[Cookie,"Cookie security","Inspect Secure, HttpOnly and SameSite attributes with detailed analysis."],[LockKeyhole,"TLS / HTTPS","Certificate Transparency logs, HSTS preload, certificate expiry and issuer details."],[KeyRound,"Email security","SPF, DMARC policy analysis and MX record validation."],[ShieldX,"Exposed paths","Detect .git, .env, .DS_Store, backup files, debug endpoints and sensitive paths."],[Settings2,"Web technologies","Detect 50+ frameworks, CMS, servers, analytics, CDNs and security tools."],[CircleAlert,"Findings","Detailed evidence and actionable recommendations for every issue found."],
    ].map(([Icon,title,text]) => <div className="card" key={String(title)}><Icon size={22} color="var(--blue)"/><div className="cardtitle" style={{marginTop:12}}>{String(title)}</div><div style={{color:"var(--muted)",fontSize:13,lineHeight:1.6}}>{String(text)}</div></div>)}</div></div></section>}

    <section className="section" id="how"><div className="panel" style={{padding:30}}><div className="eyebrow">How it works</div><h2 style={{fontSize:32,margin:"0 0 10px",letterSpacing:"-.04em"}}>A real scan, returned directly to your browser.</h2><p style={{color:"var(--muted)",maxWidth:760,lineHeight:1.7,marginTop:0}}>The browser sends the target to a Cloudflare Worker. The Worker validates the URL, blocks private/reserved targets, resolves DNS via Cloudflare DoH, performs bounded public HTTP requests, probes for exposed sensitive paths, checks Certificate Transparency logs, analyzes email security records, and streams each completed check back to the browser. There is no application database and no scan-history feature.</p></div></section>
    <section className="section" id="privacy"><div className="panel" style={{padding:30}}><div className="eyebrow">Privacy model</div><h2 style={{fontSize:32,margin:"0 0 10px",letterSpacing:"-.04em"}}>No login. No database. No stored reports.</h2><p style={{color:"var(--muted)",lineHeight:1.7,maxWidth:850}}>WebSentry does not intentionally persist scan results or target history. Operational infrastructure such as hosting and network providers can still have their own logs, so this site does not claim that network traffic is invisible everywhere.</p></div></section>
    <footer style={{padding:"30px 5vw 55px",textAlign:"center",color:"var(--muted)",fontSize:12}}>WebSentry · Use only on websites you own or are authorized to assess. · Developed by JOJIN JOHN</footer>
  </main>;
}

function Report({ result, onNew, onExport, activeSection, onNavigate, sectionRefs }: { result: Result; onNew: () => void; onExport: () => void; activeSection: string; onNavigate: (id: string) => void; sectionRefs: React.MutableRefObject<Record<string,HTMLElement|null>> }) {
  const [filter, setFilter] = useState<Severity | "all">("all");
  const filtered = useMemo(
    () => filter === "all" ? result.findings : result.findings.filter((f) => f.severity === filter),
    [filter, result.findings]
  );
  const scoreVar = Math.max(0, Math.min(100, result.score));
  const headerFindings = result.findings.filter((f) => f.category === "Security Headers");
  const tlsFindings = result.findings.filter((f) => f.category === "TLS");
  const emailFindings = result.findings.filter((f) => f.category === "Email Security");
  const pathFindings = result.findings.filter((f) => f.category === "Exposed Paths");

  const refCallback = useCallback((id: string) => (el: HTMLElement | null) => { sectionRefs.current[id] = el; }, [sectionRefs]);

  return (
    <div className="panel">
      <div className="results">
        <aside className="sidebar">
          {sidebarItems.map(({ id, icon: Icon, label }) => (
            <div className={`sideitem ${activeSection === id ? "active" : ""}`} key={id} onClick={() => onNavigate(id)}><Icon size={15} />{label}</div>
          ))}
        </aside>

        <div className="report">
          <div className="reporttop">
            <div>
              <h2>{new URL(result.finalUrl).hostname}</h2>
              <p>Scanned {new Date(result.scannedAt).toLocaleString()} · {result.durationMs} ms</p>
            </div>
            <div className="actions">
              <button className="export-btn" onClick={onExport}><Download size={13}/>Export JSON</button>
              <button className="secondary" onClick={onNew}>New Scan</button>
            </div>
          </div>

          <div ref={refCallback("overview")} id="sec-overview">
            <div className="cards">
              <div className="card">
                <div className="cardtitle">Security Score</div>
                <div className="score">
                  <div className="ring" style={{ "--score": scoreVar } as React.CSSProperties}><strong>{scoreVar}</strong></div>
                  <div><strong style={{ fontSize: 13 }}>/ 100</strong><div><small>Calculated from observed findings.</small></div></div>
                </div>
              </div>
              <div className="card">
                <div className="cardtitle">Findings</div>
                {(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => (
                  <div className="metric" key={s}><span style={{ textTransform: "capitalize" }}>{s}</span><span className={`badge ${s}`}>{result.counts[s]}</span></div>
                ))}
              </div>
              <div className="card">
                <div className="cardtitle">Quick Info</div>
                <div className="metric"><span>HTTP</span><strong>{result.http.status}</strong></div>
                <div className="metric"><span>HTTPS</span><strong>{result.tls.https ? "Yes" : "No"}</strong></div>
                <div className="metric"><span>HSTS</span><strong>{result.tls.hsts ? "Present" : "Missing"}</strong></div>
                <div className="metric"><span>Redirects</span><strong>{result.http.redirects.length}</strong></div>
                <div className="metric"><span>Server</span><strong>{result.http.server || "Not disclosed"}</strong></div>
              </div>
            </div>
          </div>

          <div ref={refCallback("headers")} id="sec-headers" className="section-title" style={{marginTop:24}}>Security Headers</div>
          <div className="cards">
            <div className="card" style={{gridColumn:"span 2"}}>
              <div className="cardtitle">Header Analysis</div>
              {headerFindings.map((f) => (
                <div className="metric" key={f.id}>
                  <span>{f.title.replace(" is missing", "").replace(" is present", "")}</span>
                  <span className={`badge ${f.status === "pass" ? "info" : f.severity}`}>{f.status === "pass" ? "Found" : "Missing"}</span>
                </div>
              ))}
            </div>
            <div className="card">
              <div className="cardtitle">Header Details</div>
              {headerFindings.filter(f => f.status !== "pass").length === 0 ? <div style={{color:"var(--muted)",fontSize:13}}>All checked headers are present.</div> : headerFindings.filter(f => f.status !== "pass").map(f => (
                <div key={f.id} style={{marginBottom:10}}>
                  <div style={{fontSize:12,fontWeight:700}}>{f.title}</div>
                  <div style={{fontSize:11,color:"var(--muted)",marginTop:2}}>{f.evidence}</div>
                </div>
              ))}
            </div>
          </div>

          <div ref={refCallback("tls")} id="sec-tls" className="section-title">TLS / HTTPS</div>
          <div className="cards">
            <div className="card">
              <div className="cardtitle">Certificate</div>
              <div className="metric"><span>HTTPS</span><strong>{result.tls.https ? "Yes" : "No"}</strong></div>
              <div className="metric"><span>CT Logs</span><strong>{result.tls.ctLogsFound ? "Found" : "Not found"}</strong></div>
              <div className="metric"><span>Issuer</span><strong style={{fontSize:11,wordBreak:"break-all"}}>{result.tls.certificateIssuer || "Unknown"}</strong></div>
              <div className="metric"><span>Expiry</span><strong>{result.tls.certificateExpiry || "Unknown"}</strong></div>
            </div>
            <div className="card">
              <div className="cardtitle">HSTS</div>
              <div className="metric"><span>Header</span><strong>{result.tls.hsts ? "Present" : "Missing"}</strong></div>
              <div className="metric"><span>max-age</span><strong>{result.tls.hstsMaxAge !== null ? `${result.tls.hstsMaxAge} (${Math.round(result.tls.hstsMaxAge / 86400)}d)` : "N/A"}</strong></div>
              <div className="metric"><span>includeSubDomains</span><strong>{result.tls.hstsIncludeSubDomains ? "Yes" : "No"}</strong></div>
              <div className="metric"><span>preload</span><strong>{result.tls.hstsPreload ? "Yes" : "No"}</strong></div>
              <div className="metric"><span>Preload list</span><strong>{result.tls.hstsPreloadListed === null ? "Unknown" : result.tls.hstsPreloadListed ? "Listed" : "Not listed"}</strong></div>
            </div>
            <div className="card">
              <div className="cardtitle">TLS Findings</div>
              {tlsFindings.length === 0 ? <div style={{color:"var(--muted)",fontSize:13}}>No TLS issues found.</div> : tlsFindings.map(f => (
                <div key={f.id} style={{marginBottom:8}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}><span style={{fontSize:12,fontWeight:700}}>{f.title}</span><span className={`badge ${f.severity}`}>{f.severity}</span></div>
                  <div style={{fontSize:11,color:"var(--muted)",marginTop:2}}>{f.evidence}</div>
                </div>
              ))}
            </div>
          </div>

          <div ref={refCallback("dns")} id="sec-dns" className="section-title">DNS Records</div>
          <div className="cards">
            <div className="card">
              <div className="cardtitle">DNS Records</div>
              {Object.entries(result.dns).filter(([k]) => !["spf","dmarc"].includes(k)).map(([key, values]) => {
                const arr = values as string[];
                return <div className="metric" key={key}><span>{key}</span><strong>{arr.length}</strong></div>;
              })}
            </div>
            <div className="card">
              <div className="cardtitle">SPF Record</div>
              <div className="metric"><span>Found</span><strong>{result.dns.spf.found ? "Yes" : "No"}</strong></div>
              {result.dns.spf.found && <div className="metric"><span>Policy</span><strong>{result.dns.spf.policy || "Unknown"}</strong></div>}
            </div>
            <div className="card">
              <div className="cardtitle">DMARC Record</div>
              <div className="metric"><span>Found</span><strong>{result.dns.dmarc.found ? "Yes" : "No"}</strong></div>
              {result.dns.dmarc.found && <>
                <div className="metric"><span>Policy</span><strong>{result.dns.dmarc.policy || "Unknown"}</strong></div>
                <div className="metric"><span>rua</span><strong style={{fontSize:11,wordBreak:"break-all"}}>{result.dns.dmarc.rua || "Not set"}</strong></div>
              </>}
            </div>
          </div>

          <div ref={refCallback("email")} id="sec-email" className="section-title">Email Security</div>
          <div className="card" style={{marginBottom:14}}>
            <div className="cardtitle">Email Authentication Findings</div>
            {emailFindings.length === 0 ? <div style={{color:"var(--muted)",fontSize:13}}>No email security findings.</div> : emailFindings.map(f => (
              <div key={f.id} style={{marginBottom:8}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}><span style={{fontSize:12,fontWeight:700}}>{f.title}</span><span className={`badge ${f.severity}`}>{f.severity}</span></div>
                <div style={{fontSize:11,color:"var(--muted)",marginTop:2}}>{f.evidence}</div>
                <div style={{fontSize:11,color:"var(--blue)",marginTop:2}}>{f.recommendation}</div>
              </div>
            ))}
          </div>

          <div ref={refCallback("cookies")} id="sec-cookies" className="section-title">Cookies</div>
          <div className="card" style={{marginBottom:14}}>
            <div className="cardtitle">Cookie Analysis</div>
            {result.cookies.length === 0 ? <div style={{color:"var(--muted)",fontSize:13}}>No cookies observed.</div> : result.cookies.map(c => (
              <div className="metric" key={c.name}>
                <span>{c.name}</span>
                <span style={{display:"flex",gap:4}}>
                  {c.secure && <span className="badge info">Secure</span>}
                  {c.httpOnly && <span className="badge info">HttpOnly</span>}
                  {c.sameSite && <span className="badge info">SameSite:{c.sameSite}</span>}
                  {!c.secure && <span className="badge medium">No Secure</span>}
                  {!c.httpOnly && <span className="badge low">No HttpOnly</span>}
                </span>
              </div>
            ))}
          </div>

          <div ref={refCallback("cors")} id="sec-cors" className="section-title">CORS</div>
          <div className="card" style={{marginBottom:14}}>
            <div className="cardtitle">CORS Analysis</div>
            {result.findings.filter(f => f.category === "CORS").map(f => (
              <div key={f.id} style={{marginBottom:8}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}><span style={{fontSize:12,fontWeight:700}}>{f.title}</span><span className={`badge ${f.severity}`}>{f.severity}</span></div>
                <div style={{fontSize:11,color:"var(--muted)",marginTop:2}}>{f.evidence}</div>
              </div>
            ))}
          </div>

          <div ref={refCallback("redirects")} id="sec-redirects" className="section-title">Redirects</div>
          <div className="card" style={{marginBottom:14}}>
            <div className="cardtitle">Redirect Chain ({result.http.redirects.length} redirects)</div>
            {result.http.redirects.length === 0 ? <div style={{color:"var(--muted)",fontSize:13}}>No redirects observed.</div> : result.http.redirects.map((r, i) => (
              <div className="metric" key={i}><span style={{fontSize:11,color:"var(--muted)"}}>#{i + 1}</span><strong style={{fontSize:11,wordBreak:"break-all"}}>{r}</strong></div>
            ))}
          </div>

          <div ref={refCallback("paths")} id="sec-paths" className="section-title">Exposed Paths</div>
          <div className="card" style={{marginBottom:14}}>
            <div className="cardtitle">Sensitive Path Detection ({result.exposedPaths.length} found)</div>
            {result.exposedPaths.length === 0 ? <div style={{color:"var(--muted)",fontSize:13}}>No sensitive paths detected.</div> : result.exposedPaths.map((p, i) => (
              <div key={i} style={{marginBottom:8}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                  <span style={{fontSize:12,fontWeight:700}}>{p.path}</span>
                  <span className={`badge ${p.severity}`}>{p.severity}</span>
                </div>
                <div style={{fontSize:11,color:"var(--muted)",marginTop:2}}>{p.description} (HTTP {p.status})</div>
              </div>
            ))}
          </div>

          <div ref={refCallback("files")} id="sec-files" className="section-title">robots.txt / security.txt</div>
          <div className="cards">
            <div className="card">
              <div className="cardtitle">robots.txt</div>
              <div className="metric"><span>Status</span><strong>{result.files.robots.found ? "Found" : "Not found"}</strong></div>
              {result.files.robots.found && <>
                <div className="metric"><span>Disallow rules</span><strong>{result.files.robots.disallowCount}</strong></div>
                <div className="metric"><span>Sitemaps</span><strong>{result.files.robots.sitemapCount}</strong></div>
              </>}
            </div>
            <div className="card">
              <div className="cardtitle">security.txt</div>
              <div className="metric"><span>Status</span><strong>{result.files.securityTxt.found ? "Found" : "Not found"}</strong></div>
              {result.files.securityTxt.found && <>
                <div className="metric"><span>Contact points</span><strong>{result.files.securityTxt.contactCount}</strong></div>
                <div className="metric"><span>Expires</span><strong>{result.files.securityTxt.expires || "Not set"}</strong></div>
              </>}
            </div>
          </div>

          <div ref={refCallback("tech")} id="sec-tech" className="section-title">Technologies</div>
          <div className="card" style={{marginBottom:14}}>
            <div className="cardtitle">Detected Technologies ({result.technologies.length})</div>
            {result.technologies.length === 0 ? <div style={{color:"var(--muted)",fontSize:13}}>No technologies detected.</div> : (
              <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                {result.technologies.map(t => <span key={t} className="badge info" style={{fontSize:11,padding:"5px 10px"}}>{t}</span>)}
              </div>
            )}
          </div>

          <div ref={refCallback("findings")} id="sec-findings" className="section-title">All Findings</div>
          <div className="findings">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <div className="filter-bar">
                {(["all","critical","high","medium","low","info"] as const).map(s => (
                  <button key={s} className={`filter-btn ${filter === s ? "active" : ""}`} onClick={() => setFilter(s)}>
                    {s === "all" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)} {s === "all" ? `(${result.findings.length})` : `(${result.counts[s]})`}
                  </button>
                ))}
              </div>
            </div>
            {filtered.length === 0 ? <div className="empty">No findings in this category.</div> : filtered.map((f) => (
              <div className="finding" key={f.id}>
                <div className="findingtop"><h3>{f.title}</h3><span className={`badge ${f.severity}`}>{f.severity}</span></div>
                <p><strong>Evidence:</strong> {f.evidence}</p>
                <p className="rec"><strong>Recommendation:</strong> {f.recommendation}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
