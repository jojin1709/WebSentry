"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowRight, Check, CircleAlert, Clipboard, ClipboardCheck, Clock3, Cookie, Download, FileText, Globe2, KeyRound, LockKeyhole, Radar, RefreshCw, Search, Server, Settings2, ShieldAlert, ShieldCheck, ShieldX, Zap, AlertTriangle } from "lucide-react";

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
  forms:Array<{action:string;method:string;hasCsrf:boolean;hasAutocompleteOff:boolean;inputTypes:string[]}>;
  seo:{title:string|null;description:string|null;canonical:string|null;ogTitle:string|null;ogDescription:string|null;ogImage:string|null;robots:string|null;viewport:string|null;lang:string|null;headings:Record<string,number>};
  corsDetail:{allowOrigin:string|null;allowMethods:string|null;allowHeaders:string|null;allowCredentials:string|null;maxAge:string|null;exposeHeaders:string|null;preflightRequired:boolean};
  sri:{totalScripts:number;externalScripts:number;scriptsWithIntegrity:number;totalLinks:number;externalLinks:number;linksWithIntegrity:number};
  performance:{responseTimeMs:number;pageSizeBytes:number;pageSizeFormatted:string;resourceCount:{scripts:number;stylesheets:number;images:number;iframes:number;fonts:number;other:number};renderBlockingScripts:number;renderBlockingStyles:number;totalScriptSize:string;totalStyleSize:string};
  accessibility:{imagesTotal:number;imagesWithAlt:number;imagesWithEmptyAlt:number;formsTotal:number;formsWithLabels:number;inputsTotal:number;inputsWithLabels:number;headingStructure:Record<string,number>;hasH1:boolean;h1Count:number;hasLang:boolean;hasSkipLink:boolean;hasAriaLandmarks:boolean;hasRoleAttributes:number};
  infrastructure:{http2:boolean|null;http3:boolean|null;ipv6:boolean;dnssec:boolean|null;serverTiming:string|null;altSvc:string|null};
  jwt:{found:boolean;locations:string[]};
};

const API = process.env.NEXT_PUBLIC_API_URL || "";
const steps = [
  ["dns","DNS"],["http","HTTP"],["headers","Headers"],["cookies","Cookies"],["cors","CORS"],
  ["files","Files"],["technology","Tech"],["tls","TLS"],["paths","Paths"],["content","Content"],
  ["performance","Perf"],["a11y","A11y"],["infra","Infra"],
] as const;

const sidebarItems = [
  { id: "overview", icon: ShieldCheck, label: "Overview" },
  { id: "headers", icon: ShieldAlert, label: "Security Headers" },
  { id: "tls", icon: LockKeyhole, label: "TLS / HTTPS" },
  { id: "dns", icon: Globe2, label: "DNS & Email" },
  { id: "cookies", icon: Cookie, label: "Cookies" },
  { id: "cors", icon: Radar, label: "CORS" },
  { id: "redirects", icon: ArrowRight, label: "Redirects" },
  { id: "paths", icon: ShieldX, label: "Exposed Paths" },
  { id: "source", icon: AlertTriangle, label: "Info Leakage" },
  { id: "mixed", icon: CircleAlert, label: "Mixed Content" },
  { id: "sri", icon: ShieldCheck, label: "SRI" },
  { id: "jwt", icon: KeyRound, label: "JWT / Tokens" },
  { id: "forms", icon: FileText, label: "Forms" },
  { id: "seo", icon: Search, label: "SEO" },
  { id: "a11y", icon: Settings2, label: "Accessibility" },
  { id: "perf", icon: Zap, label: "Performance" },
  { id: "infra", icon: Server, label: "Infrastructure" },
  { id: "files", icon: FileText, label: "Files" },
  { id: "tech", icon: Server, label: "Technologies" },
  { id: "findings", icon: CircleAlert, label: "All Findings" },
];

function Badge({ severity, children }: { severity: string; children: React.ReactNode }) {
  return <span className={`badge ${severity}`}>{children}</span>;
}

function SectionCard({ title, children }: { title: string; children: React.ReactNode }) {
  return <div className="card" style={{marginBottom:14}}><div className="cardtitle">{title}</div>{children}</div>;
}

function FindingList({ findings: f }: { findings: Finding[] }) {
  if (f.length === 0) return <div style={{color:"var(--muted)",fontSize:13}}>No issues found.</div>;
  return <>{f.map((fi) => (
    <div key={fi.id} style={{marginBottom:8}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}><span style={{fontSize:12,fontWeight:700}}>{fi.title}</span><Badge severity={fi.severity}>{fi.severity}</Badge></div>
      <div style={{fontSize:11,color:"var(--muted)",marginTop:2}}>{fi.evidence.slice(0,200)}</div>
    </div>
  ))}</>;
}

function Skeleton({ className }: { className?: string }) {
  return <div className={`skeleton ${className || ""}`} />;
}

function SkeletonCard() {
  return <div className="card"><Skeleton className="h24 w40" /><Skeleton /><Skeleton className="w60" /><Skeleton className="w80" /></div>;
}

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

  useEffect(() => {
    if (!result) return;
    const observer = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          const id = entry.target.getAttribute("data-section");
          if (id) setActiveSection(id);
        }
      }
    }, { rootMargin: "-15% 0px -65% 0px" });
    Object.values(sectionRefs.current).forEach((el) => { if (el) observer.observe(el); });
    return () => observer.disconnect();
  }, [result]);

  const completed = Object.values(progress).filter(v => v === "complete").length;
  const errored = Object.values(progress).filter(v => v === "error").length;
  const percent = running ? Math.round((completed / steps.length) * 100) : result ? 100 : 0;

  const normalizeUrl = useCallback((input: string) => { const t = input.trim(); if (!t) return ""; if (/^https?:\/\//i.test(t)) return t; return `https://${t}`; }, []);
  const validateUrl = useCallback((input: string) => { try { const u = new URL(normalizeUrl(input)); if (!["http:","https:"].includes(u.protocol)) return "Only HTTP/HTTPS URLs supported."; if (!u.hostname) return "Enter a valid domain."; return null; } catch { return "Enter a valid domain (e.g. example.com)."; } }, [normalizeUrl]);

  const scan = useCallback(async (scanUrl?: string) => {
    const target = scanUrl || url;
    setError(""); setResult(null); setProgress({}); setRunning(true);
    const ve = validateUrl(target);
    if (ve) { setError(ve); setRunning(false); return; }
    try {
      if (!API) throw new Error("NEXT_PUBLIC_API_URL is not configured.");
      const response = await fetch(`${API.replace(/\/$/,"")}/api/scan`, { method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify({url: normalizeUrl(target)}) });
      if (!response.ok) { const b = await response.json().catch(() => ({})); throw new Error(b.error || `Worker returned HTTP ${response.status}.`); }
      if (!response.body) throw new Error("Scan stream unavailable.");
      const reader = response.body.getReader(); const decoder = new TextDecoder(); let buffer = "";
      while (true) {
        const {done,value} = await reader.read(); if (done) break;
        buffer += decoder.decode(value,{stream:true}); const parts = buffer.split("\n\n"); buffer = parts.pop() || "";
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
    } catch (e) { setError(e instanceof Error ? e.message : "Scan failed."); } finally { setRunning(false); }
  }, [url, API, normalizeUrl, validateUrl]);

  function reset() { setResult(null); setError(""); setProgress({}); setActiveSection("overview"); window.scrollTo({top:0,behavior:"smooth"}); }

  function exportJson() {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `websentry-${new URL(result.finalUrl).hostname}-${Date.now()}.json`; a.click(); URL.revokeObjectURL(a.href);
  }

  function exportCsv() {
    if (!result) return;
    const rows = [["ID","Category","Severity","Status","Title","Evidence","Recommendation"]];
    result.findings.forEach(f => rows.push([f.id,f.category,f.severity,f.status,f.title,`"${f.evidence.replace(/"/g,'""')}"`,`"${f.recommendation.replace(/"/g,'""')}"`]));
    const csv = rows.map(r => r.join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `websentry-${new URL(result.finalUrl).hostname}-${Date.now()}.csv`; a.click(); URL.revokeObjectURL(a.href);
  }

  function exportMarkdown() {
    if (!result) return;
    const h = new URL(result.finalUrl).hostname;
    let md = `# WebSentry Report — ${h}\n\n`;
    md += `**URL:** ${result.finalUrl}\n**Scanned:** ${new Date(result.scannedAt).toLocaleString()}\n**Duration:** ${result.durationMs}ms\n**Score:** ${result.score}/100\n\n`;
    md += `## Findings (${result.findings.length})\n\n`;
    result.findings.forEach(f => { md += `### [${f.severity.toUpperCase()}] ${f.title}\n- **Category:** ${f.category}\n- **Evidence:** ${f.evidence}\n- **Recommendation:** ${f.recommendation}\n\n`; });
    const blob = new Blob([md], { type: "text/markdown" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `websentry-${h}-${Date.now()}.md`; a.click(); URL.revokeObjectURL(a.href);
  }

  function scrollToSection(id: string) { setActiveSection(id); sectionRefs.current[id]?.scrollIntoView({ behavior: "smooth", block: "start" }); }

  const R = ({ id, children }: { id: string; children: React.ReactNode }) => <div ref={(el) => { sectionRefs.current[id] = el; }} data-section={id}>{children}</div>;

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
        <p>WebSentry performs a comprehensive, ephemeral security analysis. 13+ scan categories: headers, TLS, DNS, email security, cookies, CORS, exposed files, information leakage, SRI, JWT tokens, forms, SEO, accessibility, performance, and infrastructure.</p>
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
      {running && <div className="panel"><div className="scanhead"><div><h2>Scanning {url}</h2><div style={{color:"var(--muted)",fontSize:12,marginTop:4}}>13 scan categories running. Results are not persisted.</div></div><span className="statuspill">Live scan</span></div><div className="progressbody" aria-live="polite" aria-label="Scan progress"><div className="progressbar"><div style={{width:`${Math.max(4,percent)}%`}}/></div><div className="progressmeta"><span>{completed} of {steps.length} checks complete{errored > 0 ? ` · ${errored} errors` : ""}</span><span>{percent}%</span></div><div className="steps">{steps.map(([key,name]) => <div className={`step ${progress[key]==="complete"?"done":progress[key]==="running"?"running":progress[key]==="error"?"error":""}`} key={key}><div className="stepicon">{progress[key]==="complete"?<Check size={15}/>:progress[key]==="running"?<Radar size={15}/>:progress[key]==="error"?<AlertTriangle size={15}/>:<span>•</span>}</div>{name}</div>)}</div></div></div>}
      {result && <Report result={result} onNew={reset} onExportJson={exportJson} onExportCsv={exportCsv} onExportMd={exportMarkdown} activeSection={activeSection} onNavigate={scrollToSection} R={R}/>}
    </section>}

    {!running && !result && <section className="section" id="features"><div className="panel" style={{padding:30}}><div className="features-grid">{[
      [ShieldCheck,"Security Headers","Deep CSP, HSTS, X-Frame-Options and 15+ header checks."],[LockKeyhole,"TLS / HTTPS","Certificate Transparency, HSTS preload, certificate details."],[Globe2,"DNS & Email","A, AAAA, MX, NS, TXT, CAA + SPF/DMARC analysis."],[Cookie,"Cookies","Secure, HttpOnly, SameSite attribute inspection."],[Radar,"CORS","Preflight testing, Allow-Origin/Credentials analysis."],[ShieldX,"Exposed Paths","35 sensitive paths: .git, .env, .DS_Store, debug endpoints."],[AlertTriangle,"Info Leakage","Source maps, debug endpoints, config files, version leaks."],[KeyRound,"JWT / Tokens","Detect exposed JWT tokens in HTML and cookies."],[Zap,"Performance","Page size, render-blocking resources, response time."],[Settings2,"Accessibility","Alt text, form labels, heading hierarchy, ARIA landmarks."],[Server,"Infrastructure","HTTP/2, HTTP/3, IPv6, DNSSEC detection."],[Search,"SEO","Meta tags, Open Graph, canonical, heading structure."],[FileText,"Files","robots.txt, security.txt parsing and analysis."],[CircleAlert,"Findings","150+ checks with evidence and recommendations."],
    ].map(([Icon,title,text]) => <div className="card" key={String(title)}><Icon size={22} color="var(--blue)"/><div className="cardtitle" style={{marginTop:12}}>{String(title)}</div><div style={{color:"var(--muted)",fontSize:13,lineHeight:1.6}}>{String(text)}</div></div>)}</div></div></section>}

    <section className="section" id="how"><div className="panel" style={{padding:30}}><div className="eyebrow">How it works</div><h2 style={{fontSize:32,margin:"0 0 10px",letterSpacing:"-.04em"}}>A real scan, returned directly to your browser.</h2><p style={{color:"var(--muted)",maxWidth:760,lineHeight:1.7,marginTop:0}}>The browser sends the target to a Cloudflare Worker. The Worker validates the URL, resolves DNS via Cloudflare DoH, performs bounded HTTP requests, probes for exposed paths, checks CT logs, analyzes email security, tests CORS preflight, checks mixed content, analyzes forms, scans SEO/accessibility/performance/infrastructure, and streams each completed check back to the browser via SSE. No database. No persistence.</p></div></section>
    <section className="section" id="privacy"><div className="panel" style={{padding:30}}><div className="eyebrow">Privacy model</div><h2 style={{fontSize:32,margin:"0 0 10px",letterSpacing:"-.04em"}}>No login. No database. No stored reports.</h2><p style={{color:"var(--muted)",lineHeight:1.7,maxWidth:850}}>WebSentry does not intentionally persist scan results or target history. Operational infrastructure can still have its own logs, so this site does not claim that network traffic is invisible everywhere.</p></div></section>
    <footer style={{padding:"30px 5vw 55px",textAlign:"center",color:"var(--muted)",fontSize:12}}>WebSentry · Use only on websites you own or are authorized to assess. · Developed by JOJIN JOHN</footer>
  </main>;
}

function Report({ result, onNew, onExportJson, onExportCsv, onExportMd, activeSection, onNavigate, R }: { result: Result; onNew: () => void; onExportJson: () => void; onExportCsv: () => void; onExportMd: () => void; activeSection: string; onNavigate: (id: string) => void; R: React.FC<{ id: string; children: React.ReactNode }> }) {
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [copied, setCopied] = useState(false);
  const [showExportMenu, setShowExportMenu] = useState(false);
  const exportRef = useRef<HTMLDivElement>(null);
  const filtered = useMemo(() => filter === "all" ? result.findings : result.findings.filter((f) => f.severity === filter), [filter, result.findings]);
  const sv = Math.max(0, Math.min(100, result.score));
  const hf = result.findings.filter((f) => f.category === "Security Headers");
  const tf = result.findings.filter((f) => f.category === "TLS");
  const ef = result.findings.filter((f) => f.category === "Email Security");
  const srcF = result.findings.filter((f) => f.category === "Information Leakage");

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (exportRef.current && !exportRef.current.contains(e.target as Node)) setShowExportMenu(false);
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  function copyFindings() {
    const text = result.findings.map(f => `[${f.severity.toUpperCase()}] ${f.title}\n${f.evidence}\n→ ${f.recommendation}`).join("\n\n");
    navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); });
  }

  return (
    <div className="panel">
      <div className="results">
        <aside className="sidebar" aria-label="Report sections">
          {sidebarItems.map(({ id, icon: Icon, label }) => (
            <div className={`sideitem ${activeSection === id ? "active" : ""}`} key={id} onClick={() => onNavigate(id)}><Icon size={15} />{label}</div>
          ))}
        </aside>
        <div className="report">
          <div className="reporttop">
            <div><h2>{new URL(result.finalUrl).hostname}</h2><p>Scanned {new Date(result.scannedAt).toLocaleString()} · {result.durationMs} ms · {result.findings.length} findings</p></div>
            <div className="actions">
              <div ref={exportRef} style={{position:"relative"}}>
                <button className="export-btn" onClick={() => setShowExportMenu(!showExportMenu)}><Download size={13}/>Export</button>
                {showExportMenu && <div style={{position:"absolute",right:0,top:"100%",marginTop:4,background:"var(--surface)",border:"1px solid var(--border)",borderRadius:10,boxShadow:"var(--shadow)",zIndex:50,minWidth:140,padding:4}}>
                  <button style={{display:"block",width:"100%",textAlign:"left",border:0,background:"none",padding:"8px 12px",borderRadius:8,cursor:"pointer",fontSize:12,color:"var(--text)"}} onClick={() => { onExportJson(); setShowExportMenu(false); }}>JSON</button>
                  <button style={{display:"block",width:"100%",textAlign:"left",border:0,background:"none",padding:"8px 12px",borderRadius:8,cursor:"pointer",fontSize:12,color:"var(--text)"}} onClick={() => { onExportCsv(); setShowExportMenu(false); }}>CSV</button>
                  <button style={{display:"block",width:"100%",textAlign:"left",border:0,background:"none",padding:"8px 12px",borderRadius:8,cursor:"pointer",fontSize:12,color:"var(--text)"}} onClick={() => { onExportMd(); setShowExportMenu(false); }}>Markdown</button>
                </div>}
              </div>
              <button className={`copy-btn ${copied ? "copied" : ""}`} onClick={copyFindings}>{copied ? <><ClipboardCheck size={13}/>Copied!</> : <><Clipboard size={13}/>Copy</>}</button>
              <button className="secondary" onClick={onNew}>New Scan</button>
            </div>
          </div>

          <R id="overview"><div className="cards">
            <div className="card"><div className="cardtitle">Security Score</div><div className="score"><div className="ring" style={{ "--score": sv } as React.CSSProperties}><strong>{sv}</strong></div><div><strong style={{fontSize:13}}>/ 100</strong><div><small>From {result.findings.length} findings.</small></div></div></div></div>
            <div className="card"><div className="cardtitle">Findings</div>{(["critical","high","medium","low","info"] as Severity[]).map((s)=><div className="metric" key={s}><span style={{textTransform:"capitalize"}}>{s}</span><Badge severity={s}>{result.counts[s]}</Badge></div>)}</div>
            <div className="card"><div className="cardtitle">Quick Info</div>
              <div className="metric"><span>HTTP</span><strong>{result.http.status} {result.http.statusText}</strong></div>
              <div className="metric"><span>HTTPS</span><strong>{result.tls.https?"Yes":"No"}</strong></div>
              <div className="metric"><span>HSTS</span><strong>{result.tls.hsts?"Yes":"No"}</strong></div>
              <div className="metric"><span>HTTP Version</span><strong>{result.infrastructure.http3?"HTTP/3":result.infrastructure.http2?"HTTP/2":"HTTP/1.1"}</strong></div>
              <div className="metric"><span>IPv6</span><strong>{result.infrastructure.ipv6?"Yes":"No"}</strong></div>
              <div className="metric"><span>DNSSEC</span><strong>{result.infrastructure.dnssec===true?"Yes":result.infrastructure.dnssec===false?"No":"Unknown"}</strong></div>
              <div className="metric"><span>Page Size</span><strong>{result.performance.pageSizeFormatted}</strong></div>
              <div className="metric"><span>Response</span><strong>{result.http.responseTimeMs}ms</strong></div>
              <div className="metric"><span>Redirects</span><strong>{result.http.redirects.length}</strong></div>
              <div className="metric"><span>Server</span><strong>{result.http.server||"Not disclosed"}</strong></div>
              {result.http.contentType && <div className="metric"><span>Content-Type</span><strong style={{fontSize:11}}>{result.http.contentType}</strong></div>}
            </div>
          </div></R>

          <R id="headers"><div className="section-title" style={{marginTop:24}}>Security Headers</div>
            <div className="cards"><div className="card" style={{gridColumn:"span 2"}}><div className="cardtitle">Header Analysis</div>
              {hf.map(f=><div className="metric" key={f.id}><span>{f.title.replace(" is missing","").replace(" is present","")}</span><Badge severity={f.status==="pass"?"info":f.severity}>{f.status==="pass"?"Found":"Missing"}</Badge></div>)}
            </div><div className="card"><div className="cardtitle">Details</div>
              {hf.filter(f=>f.status!=="pass").length===0?<div style={{color:"var(--muted)",fontSize:13}}>All headers present.</div>:hf.filter(f=>f.status!=="pass").slice(0,8).map(f=><div key={f.id} style={{marginBottom:10}}><div style={{fontSize:12,fontWeight:700}}>{f.title}</div><div style={{fontSize:11,color:"var(--muted)",marginTop:2}}>{f.evidence.slice(0,150)}</div></div>)}
            </div></div>
          </R>

          <R id="tls"><div className="section-title">TLS / HTTPS</div>
            <div className="cards"><div className="card"><div className="cardtitle">Certificate</div>
              <div className="metric"><span>HTTPS</span><strong>{result.tls.https?"Yes":"No"}</strong></div>
              <div className="metric"><span>CT Logs</span><strong>{result.tls.ctLogsFound?"Found":"Not found"}</strong></div>
              <div className="metric"><span>Issuer</span><strong style={{fontSize:11,wordBreak:"break-all"}}>{result.tls.certificateIssuer||"Unknown"}</strong></div>
              <div className="metric"><span>Expiry</span><strong style={{fontSize:11}}>{result.tls.certificateExpiry||"Unknown"}</strong></div>
            </div><div className="card"><div className="cardtitle">HSTS</div>
              <div className="metric"><span>Header</span><strong>{result.tls.hsts?"Present":"Missing"}</strong></div>
              <div className="metric"><span>max-age</span><strong>{result.tls.hstsMaxAge!==null?`${result.tls.hstsMaxAge} (${Math.round(result.tls.hstsMaxAge/86400)}d)`:"N/A"}</strong></div>
              <div className="metric"><span>includeSubDomains</span><strong>{result.tls.hstsIncludeSubDomains?"Yes":"No"}</strong></div>
              <div className="metric"><span>preload</span><strong>{result.tls.hstsPreload?"Yes":"No"}</strong></div>
              <div className="metric"><span>Preload list</span><strong>{result.tls.hstsPreloadListed===null?"Unknown":result.tls.hstsPreloadListed?"Listed":"Not listed"}</strong></div>
            </div><div className="card"><div className="cardtitle">TLS Findings</div><FindingList findings={tf}/></div></div>
          </R>

          <R id="dns"><div className="section-title">DNS & Email Security</div>
            <div className="cards"><div className="card"><div className="cardtitle">DNS Records</div>
              {Object.entries(result.dns).filter(([k])=>!["spf","dmarc"].includes(k)).map(([k,v])=><div className="metric" key={k}><span>{k}</span><strong>{(v as string[]).length}</strong></div>)}
            </div><div className="card"><div className="cardtitle">SPF</div>
              <div className="metric"><span>Found</span><strong>{result.dns.spf.found?"Yes":"No"}</strong></div>
              {result.dns.spf.found&&<div className="metric"><span>Policy</span><strong>{result.dns.spf.policy||"Unknown"}</strong></div>}
            </div><div className="card"><div className="cardtitle">DMARC</div>
              <div className="metric"><span>Found</span><strong>{result.dns.dmarc.found?"Yes":"No"}</strong></div>
              {result.dns.dmarc.found&&<><div className="metric"><span>Policy</span><strong>{result.dns.dmarc.policy||"Unknown"}</strong></div><div className="metric"><span>rua</span><strong style={{fontSize:11,wordBreak:"break-all"}}>{result.dns.dmarc.rua||"Not set"}</strong></div></>}
            </div></div>
            <SectionCard title="Email Security Findings"><FindingList findings={ef}/></SectionCard>
          </R>

          <R id="cookies"><div className="section-title">Cookies</div>
            <SectionCard title="Cookie Analysis">
              {result.cookies.length===0?<div style={{color:"var(--muted)",fontSize:13}}>No cookies observed.</div>:result.cookies.map(c=><div className="metric" key={c.name}><span>{c.name}</span><span style={{display:"flex",gap:4}}>
                {c.secure&&<Badge severity="info">Secure</Badge>}{c.httpOnly&&<Badge severity="info">HttpOnly</Badge>}{c.sameSite&&<Badge severity="info">SS:{c.sameSite}</Badge>}
                {!c.secure&&<Badge severity="medium">No Secure</Badge>}{!c.httpOnly&&<Badge severity="low">No HttpOnly</Badge>}
              </span></div>)}
            </SectionCard>
          </R>

          <R id="cors"><div className="section-title">CORS</div>
            <SectionCard title="CORS Preflight">
              <div className="metric"><span>Preflight</span><strong>{result.corsDetail.preflightRequired?"Supported":"Not supported"}</strong></div>
              <div className="metric"><span>Allow-Origin</span><strong style={{fontSize:11,wordBreak:"break-all"}}>{result.corsDetail.allowOrigin||"None"}</strong></div>
              <div className="metric"><span>Allow-Methods</span><strong style={{fontSize:11}}>{result.corsDetail.allowMethods||"None"}</strong></div>
              <div className="metric"><span>Allow-Headers</span><strong style={{fontSize:11}}>{result.corsDetail.allowHeaders||"None"}</strong></div>
              <div className="metric"><span>Allow-Credentials</span><strong>{result.corsDetail.allowCredentials||"None"}</strong></div>
              <div className="metric"><span>Expose-Headers</span><strong style={{fontSize:11}}>{result.corsDetail.exposeHeaders||"None"}</strong></div>
              <div className="metric"><span>Max-Age</span><strong>{result.corsDetail.maxAge||"None"}</strong></div>
            </SectionCard>
          </R>

          <R id="redirects"><div className="section-title">Redirects</div>
            <SectionCard title={`Redirect Chain (${result.http.redirects.length})`}>
              {result.http.redirects.length===0?<div style={{color:"var(--muted)",fontSize:13}}>No redirects.</div>:result.http.redirects.map((r,i)=><div className="metric" key={i}><span style={{fontSize:11,color:"var(--muted)"}}>#{i+1}</span><strong style={{fontSize:11,wordBreak:"break-all"}}>{r}</strong></div>)}
            </SectionCard>
          </R>

          <R id="paths"><div className="section-title">Exposed Paths</div>
            <SectionCard title={`Sensitive Paths (${result.exposedPaths.length})`}>
              {result.exposedPaths.length===0?<div style={{color:"var(--muted)",fontSize:13}}>None detected.</div>:result.exposedPaths.map((p,i)=><div key={i} style={{marginBottom:8}}><div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}><span style={{fontSize:12,fontWeight:700}}>{p.path}</span><Badge severity={p.severity}>{p.severity}</Badge></div><div style={{fontSize:11,color:"var(--muted)",marginTop:2}}>{p.description} (HTTP {p.status})</div></div>)}
            </SectionCard>
          </R>

          <R id="source"><div className="section-title">Information Leakage</div>
            <SectionCard title={`Source Exposure (${srcF.length})`}>
              {srcF.length===0?<div style={{color:"var(--muted)",fontSize:13}}>No information leakage detected.</div>:<FindingList findings={srcF}/>}
            </SectionCard>
          </R>

          <R id="mixed"><div className="section-title">Mixed Content</div>
            <SectionCard title="Mixed Content">
              {result.findings.filter(f=>f.category==="Mixed Content").length===0?<div style={{color:"var(--muted)",fontSize:13}}>No issues. {result.tls.https?"Fully HTTPS.":"Site not HTTPS."}</div>:<FindingList findings={result.findings.filter(f=>f.category==="Mixed Content")}/>}
            </SectionCard>
          </R>

          <R id="sri"><div className="section-title">Subresource Integrity</div>
            <SectionCard title="SRI Analysis">
              <div className="metric"><span>Total scripts</span><strong>{result.sri.totalScripts}</strong></div>
              <div className="metric"><span>External scripts</span><strong>{result.sri.externalScripts}</strong></div>
              <div className="metric"><span>Scripts with SRI</span><strong>{result.sri.scriptsWithIntegrity}</strong></div>
              <div className="metric"><span>Total links</span><strong>{result.sri.totalLinks}</strong></div>
              <div className="metric"><span>External stylesheets</span><strong>{result.sri.externalLinks}</strong></div>
              <div className="metric"><span>Styles with SRI</span><strong>{result.sri.linksWithIntegrity}</strong></div>
              {result.findings.filter(f=>f.category==="Subresource Integrity").length>0&&<div style={{marginTop:10}}><FindingList findings={result.findings.filter(f=>f.category==="Subresource Integrity")}/></div>}
            </SectionCard>
          </R>

          <R id="jwt"><div className="section-title">JWT / Tokens</div>
            <SectionCard title="JWT Detection">
              <div className="metric"><span>Found</span><strong>{result.jwt.found?"Yes":"No"}</strong></div>
              {result.jwt.found&&result.jwt.locations.map((l,i)=><div className="metric" key={i}><span>Location</span><strong style={{fontSize:11}}>{l}</strong></div>)}
              {result.jwt.found&&<div style={{marginTop:10}}><FindingList findings={result.findings.filter(f=>f.category==="JWT / Tokens")}/></div>}
            </SectionCard>
          </R>

          <R id="forms"><div className="section-title">Forms</div>
            <SectionCard title={`Form Security (${result.forms.length})`}>
              {result.forms.length===0?<div style={{color:"var(--muted)",fontSize:13}}>No forms detected.</div>:result.forms.map((f,i)=><div key={i} style={{marginBottom:10,paddingBottom:10,borderBottom:"1px solid var(--border)"}}><div style={{fontSize:12,fontWeight:700}}>#{i+1}: {f.method} {f.action}</div><div style={{display:"flex",gap:6,marginTop:4,flexWrap:"wrap"}}>
                <Badge severity={f.hasCsrf?"info":"medium"}>{f.hasCsrf?"CSRF OK":"No CSRF"}</Badge>
                {f.inputTypes.includes("password")&&<Badge severity="low">Password field</Badge>}
                {f.hasAutocompleteOff&&<Badge severity="info">autocomplete=off</Badge>}
                <Badge severity="info">Inputs: {f.inputTypes.join(", ")||"none"}</Badge>
              </div></div>)}
              {result.findings.filter(f=>f.category==="Form Security").length>0&&<div style={{marginTop:10}}><FindingList findings={result.findings.filter(f=>f.category==="Form Security")}/></div>}
            </SectionCard>
          </R>

          <R id="seo"><div className="section-title">SEO</div>
            <div className="cards"><div className="card"><div className="cardtitle">Meta Tags</div>
              <div className="metric"><span>Title</span><strong style={{fontSize:11,wordBreak:"break-all",maxWidth:200}}>{result.seo.title||"Missing"}</strong></div>
              <div className="metric"><span>Description</span><strong style={{fontSize:11,wordBreak:"break-all",maxWidth:200}}>{result.seo.description||"Missing"}</strong></div>
              <div className="metric"><span>Canonical</span><strong style={{fontSize:11}}>{result.seo.canonical||"Missing"}</strong></div>
              <div className="metric"><span>Viewport</span><strong>{result.seo.viewport?"Present":"Missing"}</strong></div>
              <div className="metric"><span>Lang</span><strong>{result.seo.lang||"Missing"}</strong></div>
              {result.seo.robots && <div className="metric"><span>Robots</span><strong style={{fontSize:11,wordBreak:"break-all",maxWidth:200}}>{result.seo.robots}</strong></div>}
            </div><div className="card"><div className="cardtitle">Open Graph</div>
              <div className="metric"><span>og:title</span><strong style={{fontSize:11}}>{result.seo.ogTitle||"Missing"}</strong></div>
              <div className="metric"><span>og:description</span><strong style={{fontSize:11}}>{result.seo.ogDescription||"Missing"}</strong></div>
              <div className="metric"><span>og:image</span><strong>{result.seo.ogImage?"Present":"Missing"}</strong></div>
            </div><div className="card"><div className="cardtitle">Headings</div>
              {Object.entries(result.seo.headings).length===0?<div style={{color:"var(--muted)",fontSize:13}}>None found.</div>:Object.entries(result.seo.headings).map(([h,c])=><div className="metric" key={h}><span>{h.toUpperCase()}</span><strong>{c}</strong></div>)}
              {result.findings.filter(f=>f.category==="SEO").length>0&&<div style={{marginTop:10}}>{result.findings.filter(f=>f.category==="SEO").map(f=><div key={f.id} style={{marginBottom:4,display:"flex",justifyContent:"space-between"}}><span style={{fontSize:11}}>{f.title}</span><Badge severity={f.severity}>{f.severity}</Badge></div>)}</div>}
            </div></div>
          </R>

          <R id="a11y"><div className="section-title">Accessibility</div>
            <div className="cards"><div className="card"><div className="cardtitle">Images</div>
              <div className="metric"><span>Total</span><strong>{result.accessibility.imagesTotal}</strong></div>
              <div className="metric"><span>With alt</span><strong>{result.accessibility.imagesWithAlt}</strong></div>
              <div className="metric"><span>Empty alt</span><strong>{result.accessibility.imagesWithEmptyAlt}</strong></div>
            </div><div className="card"><div className="cardtitle">Forms & Inputs</div>
              <div className="metric"><span>Forms</span><strong>{result.accessibility.formsTotal}</strong></div>
              <div className="metric"><span>Forms with labels</span><strong>{result.accessibility.formsWithLabels}</strong></div>
              <div className="metric"><span>Inputs</span><strong>{result.accessibility.inputsWithLabels}/{result.accessibility.inputsTotal}</strong></div>
            </div><div className="card"><div className="cardtitle">Structure</div>
              <div className="metric"><span>H1 count</span><strong>{result.accessibility.h1Count}</strong></div>
              <div className="metric"><span>Lang attribute</span><strong>{result.accessibility.hasLang?"Yes":"No"}</strong></div>
              <div className="metric"><span>Skip link</span><strong>{result.accessibility.hasSkipLink?"Yes":"No"}</strong></div>
              <div className="metric"><span>ARIA landmarks</span><strong>{result.accessibility.hasAriaLandmarks?"Yes":"No"}</strong></div>
              <div className="metric"><span>Role attributes</span><strong>{result.accessibility.hasRoleAttributes}</strong></div>
              {Object.keys(result.accessibility.headingStructure).length > 0 && <>
                <div className="metric"><span>Heading structure</span><strong>{Object.entries(result.accessibility.headingStructure).map(([k,v])=>`${k}:${v}`).join(", ")}</strong></div>
              </>}
            </div></div>
            <SectionCard title="Accessibility Findings"><FindingList findings={result.findings.filter(f=>f.category==="Accessibility")}/></SectionCard>
          </R>

          <R id="perf"><div className="section-title">Performance</div>
            <div className="cards"><div className="card"><div className="cardtitle">Metrics</div>
              <div className="metric"><span>Page size</span><strong>{result.performance.pageSizeFormatted}</strong></div>
              <div className="metric"><span>Response time</span><strong>{result.performance.responseTimeMs}ms</strong></div>
              <div className="metric"><span>Scripts</span><strong>{result.performance.resourceCount.scripts}</strong></div>
              <div className="metric"><span>Stylesheets</span><strong>{result.performance.resourceCount.stylesheets}</strong></div>
              <div className="metric"><span>Images</span><strong>{result.performance.resourceCount.images}</strong></div>
              <div className="metric"><span>Iframes</span><strong>{result.performance.resourceCount.iframes}</strong></div>
              <div className="metric"><span>Fonts</span><strong>{result.performance.resourceCount.fonts}</strong></div>
              <div className="metric"><span>Other</span><strong>{result.performance.resourceCount.other}</strong></div>
            </div><div className="card"><div className="cardtitle">Render Blocking</div>
              <div className="metric"><span>Blocking scripts</span><strong>{result.performance.renderBlockingScripts}</strong></div>
              <div className="metric"><span>Blocking styles</span><strong>{result.performance.renderBlockingStyles}</strong></div>
              <div className="metric"><span>Script size</span><strong style={{fontSize:11}}>{result.performance.totalScriptSize}</strong></div>
              <div className="metric"><span>Style size</span><strong style={{fontSize:11}}>{result.performance.totalStyleSize}</strong></div>
            </div></div>
            <SectionCard title="Performance Findings"><FindingList findings={result.findings.filter(f=>f.category==="Performance")}/></SectionCard>
          </R>

          <R id="infra"><div className="section-title">Infrastructure</div>
            <div className="cards"><div className="card"><div className="cardtitle">Protocol</div>
              <div className="metric"><span>HTTP version</span><strong>{result.infrastructure.http3?"HTTP/3 (QUIC)":result.infrastructure.http2?"HTTP/2":"HTTP/1.1"}</strong></div>
              <div className="metric"><span>IPv6</span><strong>{result.infrastructure.ipv6?"Supported":"Not detected"}</strong></div>
              <div className="metric"><span>DNSSEC</span><strong>{result.infrastructure.dnssec===true?"Enabled":result.infrastructure.dnssec===false?"Not enabled":"Unknown"}</strong></div>
            </div><div className="card"><div className="cardtitle">Headers</div>
              <div className="metric"><span>Alt-Svc</span><strong style={{fontSize:11,wordBreak:"break-all"}}>{result.infrastructure.altSvc||"None"}</strong></div>
              <div className="metric"><span>Server-Timing</span><strong style={{fontSize:11}}>{result.infrastructure.serverTiming?"Exposed":"None"}</strong></div>
            </div></div>
            <SectionCard title="Infrastructure Findings"><FindingList findings={result.findings.filter(f=>f.category==="Infrastructure")}/></SectionCard>
          </R>

          <R id="files"><div className="section-title">Files</div>
            <div className="cards"><div className="card"><div className="cardtitle">robots.txt</div>
              <div className="metric"><span>Found</span><strong>{result.files.robots.found?"Yes":"No"}</strong></div>
              {result.files.robots.found&&<><div className="metric"><span>Disallow</span><strong>{result.files.robots.disallowCount}</strong></div><div className="metric"><span>Sitemaps</span><strong>{result.files.robots.sitemapCount}</strong></div></>}
            </div><div className="card"><div className="cardtitle">security.txt</div>
              <div className="metric"><span>Found</span><strong>{result.files.securityTxt.found?"Yes":"No"}</strong></div>
              {result.files.securityTxt.found&&<><div className="metric"><span>Contacts</span><strong>{result.files.securityTxt.contactCount}</strong></div><div className="metric"><span>Expires</span><strong>{result.files.securityTxt.expires||"N/A"}</strong></div></>}
            </div></div>
          </R>

          <R id="tech"><div className="section-title">Technologies</div>
            <SectionCard title={`Detected (${result.technologies.length})`}>
              {result.technologies.length===0?<div style={{color:"var(--muted)",fontSize:13}}>None detected.</div>:<div style={{display:"flex",flexWrap:"wrap",gap:6}}>{result.technologies.map(t=><span key={t} className="badge info" style={{fontSize:11,padding:"5px 10px"}}>{t}</span>)}</div>}
            </SectionCard>
          </R>

          <R id="findings"><div className="section-title">All Findings</div>
            <div className="findings">
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
                <div className="filter-bar">{(["all","critical","high","medium","low","info"] as const).map(s=><button key={s} className={`filter-btn ${filter===s?"active":""}`} onClick={()=>setFilter(s)}>{s==="all"?"All":s.charAt(0).toUpperCase()+s.slice(1)} {s==="all"?`(${result.findings.length})`:`(${result.counts[s]})`}</button>)}</div>
              </div>
              {filtered.length===0?<div className="empty">No findings in this category.</div>:filtered.map(f=><div className="finding" key={f.id}><div className="findingtop"><h3>{f.title}</h3><Badge severity={f.severity}>{f.severity}</Badge></div><p><strong>Evidence:</strong> {f.evidence}</p><p className="rec"><strong>Recommendation:</strong> {f.recommendation}</p></div>)}
            </div>
          </R>
        </div>
      </div>
    </div>
  );
}
