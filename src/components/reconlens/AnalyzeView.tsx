import { useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Copy,
  Cpu,
  FileDown,
  FileText,
  Gauge,
  Globe,
  History as HistoryIcon,
  Layers,
  Play,
  RefreshCw,
  Save,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  XCircle,
  Lock,
  Unlock,
  Eye,
  EyeOff,
  Link,
  FileWarning,
  Terminal,
  Database,
  Mail,
  Server,
  Activity,
  ExternalLink,
  ShieldX,
  Wifi,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { analyzeTarget, type AnalyzeResult, type SensitivePath, type CookieResult, type ClientRisk, type CommentLeak, type HiddenField, type OsintResult, type DNSRecords, generateHeaderExplanation, triageSubdomains, analyzeCookiesAI, generateFullReport } from "@/lib/analyzeServer";
import { getHistory, saveToHistory } from "@/lib/storage";
import type { View } from "./types";

const LOADING_STEPS = [
  "Connecting to target",
  "Fetching response headers",
  "Downloading HTML body",
  "Probing sensitive paths",
  "Running security rules",
  "Generating AI insights",
  "Preparing report",
];

export function AnalyzeView({
  onNavigate,
  initialUrl,
}: {
  onNavigate: (v: View) => void;
  initialUrl?: string;
}) {
  const [url, setUrl] = useState(initialUrl ?? "");
  const [raw, setRaw] = useState("");
  const [loading, setLoading] = useState(false);
  const [activeStep, setActiveStep] = useState(0);
  const [result, setResult] = useState<AnalyzeResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<"overview" | "headers" | "tech" | "recs" | "recon" | "osint" | "client-risks" | "leaks" | "raw">("overview");

  const apiDoneRef = useRef(false);

  const didAutoScan = useRef(false);
  useEffect(() => {
    if (initialUrl && !didAutoScan.current) {
      didAutoScan.current = true;
      setUrl(initialUrl);
      setTimeout(() => startAnalysis(initialUrl), 0);
    }
  }, [initialUrl]);

  useEffect(() => {
    if (!loading) return;
    setActiveStep(0);
    apiDoneRef.current = false;

    const interval = setInterval(() => {
      setActiveStep((s) => {
        if (s >= LOADING_STEPS.length - 1) {
          if (apiDoneRef.current) {
            clearInterval(interval);
            setTimeout(() => {
              setLoading(false);
              setTab("overview");
              requestAnimationFrame(() => window.scrollTo({ top: 0, behavior: "smooth" }));
            }, 400);
          }
          return s;
        }
        if (apiDoneRef.current) return s + 1;
        return s + 1;
      });
    }, 480);

    return () => clearInterval(interval);
  }, [loading]);

  const startAnalysis = (overrideUrl?: string) => {
    const targetUrl = (overrideUrl ?? url).trim();
    const targetRaw = raw.trim();
    if (!targetUrl && !targetRaw) {
      setUrl("https://api.acme.io/v2");
    }
    setLoading(true);
    setResult(null);
    setError(null);

    const timeoutId = setTimeout(() => {
      if (!apiDoneRef.current) {
        apiDoneRef.current = true;
        setError("Analysis timed out. The target may be too slow or blocking automated requests.");
      }
    }, 45000);

    analyzeTarget({
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      data: {
        url: targetUrl || undefined,
        rawHttp: !targetUrl && targetRaw ? targetRaw : undefined,
      } as never,
    })
      .then((r) => {
        clearTimeout(timeoutId);
        apiDoneRef.current = true;
        setResult(r);
        setError(null);
        saveToHistory({
          target: r.target,
          score: r.score,
          technologies: r.technologies.map((t) => t.name),
          timestamp: new Date().toLocaleString("en-GB", {
            year: "numeric",
            month: "2-digit",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit",
          }).replace(",", ""),
          status: r.score >= 65 ? "Completed" : "Warning",
          endpoint: r.endpoint,
          duration: r.duration,
          inputType: r.inputType,
        });
      })
      .catch((e: unknown) => {
        clearTimeout(timeoutId);
        apiDoneRef.current = true;
        setError((e as Error).message ?? "Analysis failed");
      });
  };

  const start = () => startAnalysis();

  const loadDemo = () => {
    setUrl("https://api.acme.io/v2");
    setRaw("GET /v2 HTTP/2\nHost: api.acme.io\nUser-Agent: ReconLens/1.0\nAccept: application/json");
  };

  const clearAll = () => {
    setUrl("");
    setRaw("");
    setResult(null);
    setError(null);
  };

  const analyzeNew = () => {
    clearAll();
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const recentHistory = getHistory().slice(0, 5);

  return (
    <div className="mx-auto w-full max-w-7xl px-6 py-10 lg:px-10">
      <header className="mb-8">
        <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
          <Sparkles className="h-3.5 w-3.5 text-primary" /> AI Security Intelligence
        </div>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">ReconLens AI</h1>
        <p className="mt-2 max-w-2xl text-[15px] leading-relaxed text-muted-foreground">
          Analyze HTTP communication and turn it into structured security intelligence — rule-based detections paired
          with AI-written explanations and prioritized recommendations.
        </p>
      </header>

      {!result && !loading && (
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
          <InputCard
            url={url}
            setUrl={setUrl}
            raw={raw}
            setRaw={setRaw}
            onAnalyze={start}
            onDemo={loadDemo}
            onClear={clearAll}
            loading={loading}
          />
          <RecentAnalysesCard history={recentHistory} onOpen={(target) => { setUrl(target); }} />
        </div>
      )}

      {error && !loading && (
        <Card className="mt-6 border-destructive/30 bg-destructive/5 p-6">
          <div className="flex items-start gap-3">
            <XCircle className="h-5 w-5 shrink-0 text-destructive" />
            <div>
              <div className="font-semibold text-foreground">Analysis failed</div>
              <div className="mt-1 text-sm text-muted-foreground">{error}</div>
            </div>
          </div>
          <Button onClick={clearAll} variant="outline" className="mt-4 h-9">
            Try again
          </Button>
        </Card>
      )}

      {!result && !loading && !error && <EmptyState onAnalyze={start} />}

      {loading && <LoadingExperience step={activeStep} />}

      {result && !loading && (
        <ResultsDashboard
          result={result}
          tab={tab}
          setTab={setTab}
          onAnalyzeNew={analyzeNew}
          onNavigate={onNavigate}
          onAnalyzeUrl={startAnalysis}
        />
      )}

      <Footer />
    </div>
  );
}

/* ─── Input ─── */

function InputCard({
  url, setUrl, raw, setRaw, onAnalyze, onDemo, onClear, loading,
}: {
  url: string; setUrl: (v: string) => void;
  raw: string; setRaw: (v: string) => void;
  onAnalyze: () => void; onDemo: () => void; onClear: () => void;
  loading: boolean;
}) {
  return (
    <Card className="animate-fade-in-up p-7">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-foreground">New analysis</h2>
          <p className="mt-1 text-sm text-muted-foreground">Provide a target URL or paste a raw HTTP exchange.</p>
        </div>
        <Badge className="border-success/20 bg-success/10 text-success hover:bg-success/10">
          <span className="mr-1.5 h-1.5 w-1.5 rounded-full bg-success" /> Engine online
        </Badge>
      </div>

      <label className="mb-1.5 block text-[13px] font-medium text-foreground">Target URL</label>
      <div className="relative">
        <Globe className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onAnalyze()}
          placeholder="https://example.com"
          className="h-11 pl-9"
        />
      </div>

      <div className="relative my-6 flex items-center">
        <div className="flex-1 border-t border-border" />
        <span className="px-3 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">OR</span>
        <div className="flex-1 border-t border-border" />
      </div>

      <label className="mb-1.5 block text-[13px] font-medium text-foreground">Raw HTTP request or response</label>
      <Textarea
        value={raw}
        onChange={(e) => setRaw(e.target.value)}
        placeholder={"GET / HTTP/2\nHost: example.com\nUser-Agent: ..."}
        className="min-h-[160px] resize-y font-mono text-[13px]"
      />

      <div className="mt-6 flex flex-wrap items-center gap-2">
        <Button onClick={onAnalyze} disabled={loading} className="h-10 gap-2 px-5">
          {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
          {loading ? "Analyzing…" : "Analyze"}
        </Button>
        <Button onClick={onDemo} variant="outline" className="h-10 gap-2">
          <Sparkles className="h-4 w-4" /> Load Demo
        </Button>
        <Button onClick={onClear} variant="ghost" className="h-10 gap-2 text-muted-foreground">
          <Trash2 className="h-4 w-4" /> Clear
        </Button>
      </div>
    </Card>
  );
}

function RecentAnalysesCard({
  history,
  onOpen,
}: {
  history: { id: string; target: string; score: number; timestamp: string }[];
  onOpen: (target: string) => void;
}) {
  return (
    <Card className="animate-fade-in-up p-5" style={{ animationDelay: "60ms" }}>
      <div className="mb-4 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-foreground">Recent analyses</h3>
        <span className="text-[11px] uppercase tracking-wider text-muted-foreground">
          {history.length > 0 ? `Last ${history.length}` : "None yet"}
        </span>
      </div>
      {history.length === 0 ? (
        <p className="text-center text-[13px] text-muted-foreground py-6">
          Your scans will appear here.
        </p>
      ) : (
        <ul className="space-y-1">
          {history.map((h) => (
            <li key={h.id}>
              <button
                onClick={() => onOpen(h.target)}
                className="group flex w-full items-center gap-3 rounded-lg px-2.5 py-2.5 text-left transition-colors hover:bg-accent/60"
              >
                <ScoreBadge score={h.score} compact />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[13px] font-medium text-foreground">
                    {h.target.replace(/^https?:\/\//, "")}
                  </div>
                  <div className="truncate text-[11px] text-muted-foreground">{h.timestamp}</div>
                </div>
                <ArrowRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/* ─── Empty state ─── */

function EmptyState({ onAnalyze }: { onAnalyze: () => void }) {
  return (
    <Card className="mt-6 flex flex-col items-center px-6 py-14 text-center">
      <EnterpriseIllustration />
      <h3 className="mt-6 text-xl font-semibold tracking-tight text-foreground">Intelligent HTTP Security Analysis</h3>
      <p className="mt-2 max-w-md text-sm text-muted-foreground">
        Enter a URL or paste raw HTTP communication to generate an AI-assisted security report.
      </p>
      <Button onClick={onAnalyze} className="mt-6 h-10 gap-2 px-5">
        <Play className="h-4 w-4" /> Start analysis
      </Button>
    </Card>
  );
}

function EnterpriseIllustration() {
  return (
    <svg width="240" height="140" viewBox="0 0 240 140" fill="none" className="text-primary">
      <rect x="20" y="30" width="200" height="90" rx="10" className="fill-accent/40" stroke="currentColor" strokeOpacity="0.25" />
      <rect x="32" y="44" width="80" height="8" rx="4" className="fill-primary/60" />
      <rect x="32" y="60" width="120" height="6" rx="3" className="fill-muted-foreground/30" />
      <rect x="32" y="74" width="100" height="6" rx="3" className="fill-muted-foreground/20" />
      <rect x="32" y="90" width="60" height="6" rx="3" className="fill-muted-foreground/20" />
      <circle cx="190" cy="70" r="22" className="fill-primary/10" stroke="currentColor" strokeOpacity="0.4" />
      <path d="M183 70 l5 5 l10 -10" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" fill="none" />
      <circle cx="44" cy="22" r="3" className="fill-success" />
      <circle cx="56" cy="22" r="3" className="fill-warning" />
      <circle cx="68" cy="22" r="3" className="fill-destructive" />
    </svg>
  );
}

/* ─── Loading ─── */

function LoadingExperience({ step }: { step: number }) {
  return (
    <Card className="animate-fade-in-up p-8">
      <div className="mb-6 flex items-center gap-3">
        <div className="grid h-10 w-10 place-items-center rounded-xl bg-primary/10">
          <Sparkles className="h-5 w-5 text-primary" />
        </div>
        <div>
          <div className="text-base font-semibold text-foreground">Running analysis</div>
          <div className="text-sm text-muted-foreground">ReconLens engine is inspecting the target</div>
        </div>
      </div>
      <ol className="space-y-3">
        {LOADING_STEPS.map((label, i) => {
          const done = i < step;
          const active = i === step;
          return (
            <li key={label} className="flex items-center gap-3 rounded-lg border border-border bg-card px-4 py-3">
              <div
                className={cn(
                  "grid h-6 w-6 shrink-0 place-items-center rounded-full",
                  done && "bg-success text-success-foreground",
                  active && "bg-primary/15 text-primary",
                  !done && !active && "bg-muted text-muted-foreground",
                )}
              >
                {done ? (
                  <CheckCircle2 className="h-4 w-4" />
                ) : active ? (
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <span className="text-[11px] font-medium">{i + 1}</span>
                )}
              </div>
              <span
                className={cn(
                  "text-sm",
                  done && "text-foreground/80",
                  active && "font-medium text-foreground",
                  !done && !active && "text-muted-foreground",
                )}
              >
                {label}
              </span>
              {active && (
                <span className="ml-auto flex gap-1">
                  <span className="h-1.5 w-1.5 animate-pulse-dot rounded-full bg-primary" />
                  <span className="h-1.5 w-1.5 animate-pulse-dot rounded-full bg-primary" style={{ animationDelay: "200ms" }} />
                  <span className="h-1.5 w-1.5 animate-pulse-dot rounded-full bg-primary" style={{ animationDelay: "400ms" }} />
                </span>
              )}
            </li>
          );
        })}
      </ol>
    </Card>
  );
}

/* ─── Results ─── */

type TabId = "overview" | "headers" | "tech" | "recs" | "recon" | "osint" | "client-risks" | "leaks" | "raw";

function ResultsDashboard({
  result, tab, setTab, onAnalyzeNew, onNavigate, onAnalyzeUrl,
}: {
  result: AnalyzeResult;
  tab: TabId;
  setTab: (t: TabId) => void;
  onAnalyzeNew: () => void;
  onNavigate: (v: View) => void;
  onAnalyzeUrl: (url: string) => void;
}) {
  const reconBadge = result.sensitivePaths?.filter((p) => p.status === "found").length ?? 0;
  const riskBadge = result.clientRisks?.filter((r) => r.severity === "critical" || r.severity === "high").length ?? 0;
  const leaks = result.leaks;
  const leaksBadge = leaks
    ? leaks.comments.filter((c) => c.classification !== "low").length +
      leaks.hiddenFields.filter((f) => f.suspicious).length +
      leaks.internalIPs.length +
      leaks.emails.length
    : 0;
  const osint = result.osint;
  const osintBadge = osint ? osint.subdomains.length : 0;

  const criticalHighFound = (result.sensitivePaths ?? []).filter(
    (p) => p.status === "found" && (p.severity === "critical" || p.severity === "high"),
  );

  return (
    <div className="space-y-6">
      <ResultHeader result={result} />
      <StatusTimeline />
      <KpiStrip result={result} />

      {criticalHighFound.length > 0 && <CriticalAlert paths={criticalHighFound} />}

      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-1 border-b border-border bg-muted/40 px-3 py-2">
          {(
            [
              ["overview", "Overview"],
              ["headers", "Headers"],
              ["tech", "Technologies"],
              ["recs", "Recommendations"],
              ["recon", "Recon"],
              ["osint", "OSINT"],
              ["client-risks", "Client Risks"],
              ["leaks", "Secrets & Leaks"],
              ["raw", "Raw Data"],
            ] as [TabId, string][]
          ).map(([id, label]) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={cn(
                "relative rounded-md px-3.5 py-1.5 text-[13px] font-medium transition-colors",
                tab === id ? "bg-card text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
              )}
            >
              {label}
              {id === "recon" && reconBadge > 0 && (
                <span className="ml-1.5 inline-flex h-4 min-w-[16px] items-center justify-center rounded-full bg-destructive px-1 text-[10px] font-semibold text-destructive-foreground">
                  {reconBadge}
                </span>
              )}
              {id === "osint" && osintBadge > 0 && (
                <span className="ml-1.5 inline-flex h-4 min-w-[16px] items-center justify-center rounded-full bg-primary/80 px-1 text-[10px] font-semibold text-primary-foreground">
                  {osintBadge}
                </span>
              )}
              {id === "client-risks" && riskBadge > 0 && (
                <span className="ml-1.5 inline-flex h-4 min-w-[16px] items-center justify-center rounded-full bg-destructive px-1 text-[10px] font-semibold text-destructive-foreground">
                  {riskBadge}
                </span>
              )}
              {id === "leaks" && leaksBadge > 0 && (
                <span className="ml-1.5 inline-flex h-4 min-w-[16px] items-center justify-center rounded-full bg-destructive px-1 text-[10px] font-semibold text-destructive-foreground">
                  {leaksBadge}
                </span>
              )}
            </button>
          ))}
        </div>

        <div className="p-6">
          {tab === "overview" && <OverviewPanel result={result} />}
          {tab === "headers" && <HeadersTable headers={result.headers} />}
          {tab === "tech" && <TechGrid items={result.technologies} />}
          {tab === "recs" && <RecsList items={result.recommendations} target={result.target} technologies={result.technologies.map(t => t.name)} />}
          {tab === "recon" && <ReconPanel result={result} />}
          {tab === "osint" && <OsintPanel osint={result.osint} onAnalyzeSubdomain={(sub) => { setTab("overview" as TabId); onAnalyzeUrl(sub); }} />}
          {tab === "client-risks" && <ClientRisksPanel result={result} />}
          {tab === "leaks" && <SecretsLeaksPanel leaks={result.leaks} />}
          {tab === "raw" && <RawViewer data={result.raw} />}
        </div>
      </Card>

      <QuickActions result={result} onAnalyzeNew={onAnalyzeNew} onHistory={() => onNavigate("history")} />
    </div>
  );
}

/* ─── Critical Alert Banner ─── */

const CRITICAL_IMPACT: Record<string, string> = {
  "/.git/HEAD": "Full source code accessible to anyone",
  "/.env": "Environment secrets and API keys exposed",
  "/phpmyadmin": "Database admin interface publicly accessible",
  "/phpmyadmin/": "Database admin interface publicly accessible",
  "/wp-admin": "CMS admin panel accessible",
  "/wp-admin/": "CMS admin panel accessible",
  "/admin": "Admin interface accessible",
  "/admin/": "Admin interface accessible",
};

function CriticalAlert({ paths }: { paths: SensitivePath[] }) {
  return (
    <div className="animate-fade-in-up rounded-2xl border border-destructive/40 bg-gradient-to-r from-destructive/15 via-orange-500/10 to-destructive/10 p-5 shadow-lg shadow-destructive/10">
      <div className="flex items-center gap-3 mb-3">
        <div className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-destructive/20 text-destructive">
          <AlertTriangle className="h-5 w-5" />
        </div>
        <div>
          <div className="text-[15px] font-bold text-destructive tracking-tight">⚠ Critical Exposures Detected</div>
          <div className="text-[12px] text-destructive/80">{paths.length} high-severity path{paths.length !== 1 ? "s" : ""} are publicly accessible</div>
        </div>
      </div>
      <ul className="space-y-2">
        {paths.map((p) => (
          <li key={p.path} className="flex items-start gap-3 rounded-lg bg-destructive/10 border border-destructive/20 px-3.5 py-2.5">
            <span className="mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-destructive text-[10px] font-bold text-white">!</span>
            <div className="min-w-0">
              <span className="font-mono text-[13px] font-semibold text-destructive">{p.path}</span>
              <span className="mx-2 text-destructive/50">→</span>
              <span className="text-[13px] text-foreground/80">{CRITICAL_IMPACT[p.path] ?? p.label}</span>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function ResultHeader({ result }: { result: AnalyzeResult }) {
  return (
    <Card className="animate-fade-in-up p-6">
      <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_auto] md:items-center">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
            <Globe className="h-3.5 w-3.5" /> Target
          </div>
          <div className="mt-1 truncate font-mono text-[15px] font-medium text-foreground">{result.target}</div>
          <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1.5 text-[12.5px] text-muted-foreground">
            <span className="flex items-center gap-1.5"><Clock className="h-3.5 w-3.5" /> {result.timestamp}</span>
            <span>Duration <span className="text-foreground">{result.duration}</span></span>
            <span>Input <span className="text-foreground">{result.inputType}</span></span>
          </div>
        </div>
        <Badge className="border-success/20 bg-success/10 text-success hover:bg-success/10">
          <CheckCircle2 className="mr-1.5 h-3.5 w-3.5" /> Analysis complete
        </Badge>
      </div>
    </Card>
  );
}

function StatusTimeline() {
  const items = ["Input Received", "HTTP Retrieved", "Parsed", "Security Rules Applied", "AI Summary Generated", "Report Ready"];
  return (
    <Card className="animate-fade-in-up p-4" style={{ animationDelay: "40ms" }}>
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
        {items.map((label, i) => (
          <div key={label} className="flex items-center gap-2 text-[12.5px]">
            <CheckCircle2 className="h-4 w-4 text-success" />
            <span className="text-foreground/80">{label}</span>
            {i < items.length - 1 && <span className="ml-3 hidden h-px w-6 bg-border md:block" />}
          </div>
        ))}
      </div>
    </Card>
  );
}

function KpiStrip({ result }: { result: AnalyzeResult }) {
  const missing = result.headers.filter((h) => h.status !== "ok").length;
  const foundPaths = result.sensitivePaths?.filter((p) => p.status === "found").length ?? 0;
  const tiles = [
    { label: "Security score", value: `${result.score}/100`, icon: Gauge, accent: "text-primary" },
    { label: "Technologies", value: String(result.technologies.length), icon: Cpu, accent: "text-foreground" },
    { label: "Missing headers", value: String(missing), icon: ShieldAlert, accent: "text-warning" },
    { label: "Exposed paths", value: String(foundPaths), icon: AlertTriangle, accent: foundPaths > 0 ? "text-destructive" : "text-muted-foreground" },
  ];
  return (
    <div className="grid animate-fade-in-up gap-4 sm:grid-cols-2 lg:grid-cols-4" style={{ animationDelay: "80ms" }}>
      {tiles.map((t) => (
        <Card key={t.label} className="p-5">
          <div className="flex items-center justify-between">
            <span className="text-[12px] uppercase tracking-wider text-muted-foreground">{t.label}</span>
            <t.icon className={cn("h-4 w-4", t.accent)} />
          </div>
          <div className="mt-2 text-2xl font-semibold tracking-tight text-foreground">{t.value}</div>
        </Card>
      ))}
    </div>
  );
}

function OverviewPanel({ result }: { result: AnalyzeResult }) {
  return (
    <div className="grid gap-6 lg:grid-cols-[320px_minmax(0,1fr)]">
      <ScoreCard score={result.score} endpoint={result.endpoint} />
      <div className="space-y-6">
        <SummaryCard summary={result.summary} result={result} />
        <div className="grid gap-4 sm:grid-cols-2">
          <MiniEndpointCard endpoint={result.endpoint} />
          <MiniTechCard items={result.technologies.slice(0, 4)} />
        </div>
      </div>
    </div>
  );
}

function ScoreCard({ score, endpoint }: { score: number; endpoint: string }) {
  const r = 54;
  const c = 2 * Math.PI * r;
  const offset = c - (score / 100) * c;
  const tone = score >= 85 ? "text-success" : score >= 65 ? "text-warning" : "text-destructive";
  const label = score >= 85 ? "Strong security posture." : score >= 65 ? "Solid baseline. A few hardening steps remain." : "High-risk findings detected. Immediate action recommended.";
  return (
    <Card className="flex flex-col items-center p-6">
      <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Security score</div>
      <div className="relative mt-4 grid h-[160px] w-[160px] place-items-center">
        <svg width="160" height="160" className="-rotate-90">
          <circle cx="80" cy="80" r={r} strokeWidth="10" className="fill-none stroke-muted" />
          <circle
            cx="80" cy="80" r={r} strokeWidth="10" strokeLinecap="round"
            className={cn("fill-none transition-all duration-700", tone)}
            stroke="currentColor" strokeDasharray={c} strokeDashoffset={offset}
          />
        </svg>
        <div className="absolute flex flex-col items-center">
          <div className="text-3xl font-semibold tracking-tight text-foreground">{score}</div>
          <div className="text-xs text-muted-foreground">/ 100</div>
        </div>
      </div>
      <p className="mt-4 text-center text-[13px] text-muted-foreground">{label}</p>
      <div className="mt-4 w-full rounded-lg bg-muted/50 px-3 py-2 text-center text-[12px] text-muted-foreground">
        Classified as <span className="font-medium text-foreground">{endpoint}</span>
      </div>
    </Card>
  );
}

function SummaryCard({ summary, result }: { summary: string; result: AnalyzeResult }) {
  const paths = result.sensitivePaths ?? [];
  const gitFound = paths.some((p) => p.path === "/.git/HEAD" && p.status === "found");
  const wpFound = paths.some((p) => (p.path === "/wp-admin/" || p.path === "/wp-admin") && p.status === "found");
  const externalScripts = result.clientRisks?.find((r) => r.type === "external-script");
  const externalCount = externalScripts ? (externalScripts.detail?.split(", ").filter(Boolean).length ?? 0) : 0;
  const missingHeaders = result.headers.filter((h) => h.status !== "ok").length;

  const pills: { label: string; color: string }[] = [];
  if (gitFound) pills.push({ label: "Git Exposed", color: "bg-destructive/15 text-destructive border-destructive/30" });
  if (wpFound) pills.push({ label: "WP Admin Accessible", color: "bg-orange-500/15 text-orange-500 border-orange-500/30" });
  if (externalCount > 1) pills.push({ label: `${externalCount} External Scripts`, color: "bg-warning/15 text-warning border-warning/30" });
  if (missingHeaders > 3) pills.push({ label: `${missingHeaders} Missing Headers`, color: "bg-orange-500/15 text-orange-500 border-orange-500/30" });

  return (
    <Card className="p-6">
      <div className="mb-3 flex items-center gap-2">
        <div className="grid h-7 w-7 place-items-center rounded-lg bg-primary/10">
          <Sparkles className="h-4 w-4 text-primary" />
        </div>
        <h3 className="text-sm font-semibold text-foreground">Executive summary</h3>
        <Badge variant="outline" className="ml-auto text-[10px] uppercase tracking-wider">AI</Badge>
      </div>
      <p className="max-w-prose text-[14px] leading-relaxed text-foreground/85">{summary}</p>
      {pills.length > 0 && (
        <div className="mt-4 border-t border-border pt-4">
          <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Key findings at a glance</div>
          <div className="flex flex-wrap gap-2">
            {pills.map((pill) => (
              <span
                key={pill.label}
                className={cn(
                  "inline-flex items-center rounded-full border px-3 py-1 text-[12px] font-semibold",
                  pill.color,
                )}
              >
                {pill.label}
              </span>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
}

function MiniEndpointCard({ endpoint }: { endpoint: string }) {
  return (
    <Card className="p-5">
      <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Endpoint classification</div>
      <div className="mt-2 inline-flex items-center gap-2 rounded-full bg-primary/10 px-3 py-1 text-[13px] font-medium text-primary">
        <Layers className="h-3.5 w-3.5" /> {endpoint}
      </div>
    </Card>
  );
}

function MiniTechCard({ items }: { items: { name: string; category: string }[] }) {
  return (
    <Card className="p-5">
      <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Top technologies</div>
      <div className="mt-3 flex flex-wrap gap-1.5">
        {items.map((t) => (
          <span key={t.name} className="rounded-md bg-muted px-2 py-1 text-[12px] font-medium text-foreground">
            {t.name}
          </span>
        ))}
      </div>
    </Card>
  );
}

function HeadersTable({ headers }: { headers: AnalyzeResult["headers"] }) {
  return (
    <div className="overflow-hidden rounded-lg border border-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-muted/40 text-left text-[12px] uppercase tracking-wider text-muted-foreground">
            <th className="px-4 py-3 font-medium">Header</th>
            <th className="px-4 py-3 font-medium">Status</th>
            <th className="px-4 py-3 font-medium">Description</th>
          </tr>
        </thead>
        <tbody>
          {headers.map((h, i) => (
            <tr key={h.header} className={cn("border-t border-border", i % 2 === 1 && "bg-muted/20")}>
              <td className="px-4 py-3 font-mono text-[13px] text-foreground">{h.header}</td>
              <td className="px-4 py-3">
                {h.status === "ok" && <span className="inline-flex items-center gap-1.5 text-success"><CheckCircle2 className="h-4 w-4" /> OK</span>}
                {h.status === "warn" && <span className="inline-flex items-center gap-1.5 text-warning"><AlertTriangle className="h-4 w-4" /> Warning</span>}
                {h.status === "error" && <span className="inline-flex items-center gap-1.5 text-destructive"><XCircle className="h-4 w-4" /> Missing</span>}
              </td>
              <td className="px-4 py-3 text-muted-foreground">{h.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TechGrid({ items }: { items: { name: string; category: string; version?: string }[] }) {
  if (items.length === 0) {
    return (
      <div className="flex flex-col items-center gap-3 py-10 text-center">
        <div className="grid h-10 w-10 place-items-center rounded-full bg-muted">
          <Cpu className="h-5 w-5 text-muted-foreground" />
        </div>
        <p className="text-[13px] text-muted-foreground">No technologies detected — the target may be obscuring stack information via minimal headers.</p>
      </div>
    );
  }
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {items.map((t) => (
        <div key={t.name} className="flex items-center gap-3 rounded-lg border border-border bg-card px-4 py-3">
          <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-primary/10 text-primary">
            <Cpu className="h-4 w-4" />
          </div>
          <div className="min-w-0">
            <div className="truncate text-[14px] font-medium text-foreground">
              {t.name}
              {t.version && (
                <span className="ml-1.5 text-[11px] font-normal text-muted-foreground">v{t.version}</span>
              )}
            </div>
            <div className="truncate text-[12px] text-muted-foreground">{t.category}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

const HEADER_FIX_SNIPPETS: Record<string, { header: string; value: string }> = {
  "Enable Content Security Policy": {
    header: "Content-Security-Policy",
    value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
  },
  "Enable HSTS": {
    header: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
  "Set X-Frame-Options": {
    header: "X-Frame-Options",
    value: "SAMEORIGIN",
  },
  "Add X-Content-Type-Options": {
    header: "X-Content-Type-Options",
    value: "nosniff",
  },
  "Tighten Referrer-Policy": {
    header: "Referrer-Policy",
    value: "strict-origin-when-cross-origin",
  },
  "Add Permissions-Policy": {
    header: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=()",
  },
};

function RecsListItem({ r, target, technologies }: { r: { title: string; detail: string }; target: string; technologies: string[] }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [explainOpen, setExplainOpen] = useState(false);
  const [explaining, setExplaining] = useState(false);
  const [explanation, setExplanation] = useState<string | null>(null);
  const fix = HEADER_FIX_SNIPPETS[r.title];

  const handleCopy = () => {
    if (!fix) return;
    navigator.clipboard?.writeText(`${fix.header}: ${fix.value}`);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  const handleExplain = async () => {
    if (explanation) { setExplainOpen((o) => !o); return; }
    setExplainOpen(true);
    setExplaining(true);
    try {
      const res = await generateHeaderExplanation({ data: { header: fix?.header ?? r.title, target, technologies } as never });
      setExplanation(res.explanation);
    } catch {
      setExplanation("Could not load AI explanation. Check your GROQ_API_KEY.");
    } finally {
      setExplaining(false);
    }
  };

  return (
    <li className="rounded-xl border border-border bg-card transition-colors hover:bg-accent/40">
      <div className="flex items-start gap-3 px-4 py-3.5">
        <div className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-warning/15 text-warning">
          <ShieldCheck className="h-4 w-4" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-[14px] font-medium text-foreground">{r.title}</div>
          <div className="text-[13px] text-muted-foreground">{r.detail}</div>
        </div>
        <div className="ml-2 mt-0.5 flex shrink-0 items-center gap-1">
          <button
            onClick={handleExplain}
            className="flex items-center gap-1 rounded-md px-2 py-1 text-[12px] font-medium text-primary/70 transition-colors hover:bg-primary/10 hover:text-primary"
          >
            <Sparkles className="h-3.5 w-3.5" />
            {explainOpen ? "Hide" : "Explain"}
          </button>
          {fix && (
            <button
              onClick={() => setOpen((o) => !o)}
              className="flex items-center gap-1 rounded-md px-2 py-1 text-[12px] font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            >
              Fix
              {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
            </button>
          )}
        </div>
      </div>
      {explainOpen && (
        <div className="mx-4 mb-3.5 rounded-lg border border-primary/20 bg-primary/5 px-4 py-3">
          <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-primary/70">
            <Sparkles className="h-3 w-3" /> AI Explanation
          </div>
          {explaining ? (
            <div className="flex items-center gap-2 text-[13px] text-muted-foreground">
              <RefreshCw className="h-3.5 w-3.5 animate-spin" /> Generating context-aware explanation…
            </div>
          ) : (
            <p className="text-[13px] leading-relaxed text-foreground/85">{explanation}</p>
          )}
        </div>
      )}
      {fix && open && (
        <div className="mx-4 mb-3.5 rounded-lg border border-border bg-muted/40">
          <div className="flex items-center justify-between border-b border-border px-3 py-1.5">
            <span className="font-mono text-[11px] text-muted-foreground">{fix.header}</span>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            >
              <Copy className="h-3 w-3" />
              {copied ? "Copied!" : "Copy"}
            </button>
          </div>
          <pre className="overflow-x-auto px-3 py-2.5 font-mono text-[12.5px] leading-relaxed text-foreground/90">
            {fix.header}: {fix.value}
          </pre>
        </div>
      )}
    </li>
  );
}

function RecsList({ items, target, technologies }: { items: { title: string; detail: string }[]; target: string; technologies: string[] }) {
  if (items.length === 0) {
    return (
      <div className="py-10 text-center text-sm text-muted-foreground">
        No recommendations — excellent security posture!
      </div>
    );
  }
  return (
    <ul className="space-y-2.5">
      {items.map((r) => (
        <RecsListItem key={r.title} r={r} target={target} technologies={technologies} />
      ))}
    </ul>
  );
}

/* ─── Recon Tab ─── */

function severityColor(severity: SensitivePath["severity"]): string {
  switch (severity) {
    case "critical": return "bg-destructive/10 text-destructive border-destructive/20";
    case "high": return "bg-orange-500/10 text-orange-500 border-orange-500/20";
    case "medium": return "bg-warning/15 text-warning border-warning/20";
    case "low": return "bg-muted text-muted-foreground border-border";
    case "info": return "bg-primary/10 text-primary border-primary/20";
  }
}

function pathStatusColor(status: SensitivePath["status"]): string {
  switch (status) {
    case "found": return "bg-destructive/10 text-destructive border-destructive/20";
    case "protected": return "bg-warning/15 text-warning border-warning/20";
    case "not-found": return "bg-success/10 text-success border-success/20";
  }
}

function pathStatusIcon(status: SensitivePath["status"]) {
  switch (status) {
    case "found": return <XCircle className="h-4 w-4" />;
    case "protected": return <Lock className="h-4 w-4" />;
    case "not-found": return <CheckCircle2 className="h-4 w-4" />;
  }
}

function ReconSummaryStrip({ paths }: { paths: SensitivePath[] }) {
  const total = paths.length;
  const exposed = paths.filter((p) => p.status === "found").length;
  const protected_ = paths.filter((p) => p.status === "protected").length;
  return (
    <div className="grid grid-cols-3 gap-3 rounded-xl border border-border bg-muted/30 p-4">
      <div className="text-center">
        <div className="text-xl font-bold text-foreground tabular-nums">{total}</div>
        <div className="mt-0.5 text-[11px] uppercase tracking-wider text-muted-foreground">Paths probed</div>
      </div>
      <div className="text-center">
        <div className={cn("text-xl font-bold tabular-nums", exposed > 0 ? "text-destructive" : "text-success")}>{exposed}</div>
        <div className="mt-0.5 text-[11px] uppercase tracking-wider text-muted-foreground">Exposed</div>
      </div>
      <div className="text-center">
        <div className={cn("text-xl font-bold tabular-nums", protected_ > 0 ? "text-warning" : "text-foreground")}>{protected_}</div>
        <div className="mt-0.5 text-[11px] uppercase tracking-wider text-muted-foreground">Protected</div>
      </div>
    </div>
  );
}

function ReconPanel({ result }: { result: AnalyzeResult }) {
  const paths = result.sensitivePaths ?? [];
  const robotsDisallowed = result.robotsDisallowed ?? [];

  // Extract external script domains from clientRisks
  const externalScriptRisk = result.clientRisks?.find((r) => r.type === "external-script");
  const externalDomains = externalScriptRisk?.detail?.split(", ").filter(Boolean) ?? [];

  return (
    <div className="space-y-6">
      {/* Summary strip */}
      {paths.length > 0 && <ReconSummaryStrip paths={paths} />}

      {/* Sensitive path probing table */}
      <div>
        <h3 className="mb-3 text-[13px] font-semibold uppercase tracking-wider text-muted-foreground">
          Sensitive Path Probing
        </h3>
        {paths.length === 0 ? (
          <p className="text-sm text-muted-foreground">No paths probed (raw HTTP mode).</p>
        ) : (
          <div className="overflow-hidden rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-muted/40 text-left text-[12px] uppercase tracking-wider text-muted-foreground">
                  <th className="px-4 py-3 font-medium">Path</th>
                  <th className="px-4 py-3 font-medium">Label</th>
                  <th className="px-4 py-3 font-medium">Severity</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {paths.map((p, i) => (
                  <tr key={p.path} className={cn("border-t border-border", i % 2 === 1 && "bg-muted/20")}>
                    <td className="px-4 py-3 font-mono text-[13px] text-foreground">{p.path}</td>
                    <td className="px-4 py-3 text-[13px] text-foreground">{p.label}</td>
                    <td className="px-4 py-3">
                      <span className={cn("inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider", severityColor(p.severity))}>
                        {p.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={cn("inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[12px] font-medium", pathStatusColor(p.status))}>
                        {pathStatusIcon(p.status)}
                        {p.status === "found" ? "Found" : p.status === "protected" ? "Protected" : "Not found"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Robots.txt disallowed paths */}
      {robotsDisallowed.length > 0 && (
        <div>
          <h3 className="mb-3 text-[13px] font-semibold uppercase tracking-wider text-muted-foreground">
            Robots.txt — Disallowed Paths
          </h3>
          <div className="rounded-lg border border-border bg-muted/30 p-4">
            <ul className="space-y-1.5">
              {robotsDisallowed.map((path, i) => (
                <li key={i} className="flex items-center gap-2 font-mono text-[13px] text-foreground">
                  <EyeOff className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                  {path}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* External scripts */}
      {externalDomains.length > 0 && (
        <div>
          <h3 className="mb-3 text-[13px] font-semibold uppercase tracking-wider text-muted-foreground">
            External Script Domains
          </h3>
          <div className="flex flex-wrap gap-2">
            {externalDomains.map((domain) => (
              <span
                key={domain}
                className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-card px-3 py-1.5 text-[13px] font-medium text-foreground"
              >
                <Link className="h-3.5 w-3.5 text-muted-foreground" />
                {domain}
              </span>
            ))}
          </div>
        </div>
      )}

      {paths.length > 0 && robotsDisallowed.length === 0 && externalDomains.length === 0 && (
        <p className="text-[13px] text-muted-foreground">No robots.txt disallowed paths or external scripts found.</p>
      )}
    </div>
  );
}

/* ─── Client Risks Tab ─── */

function clientRiskSeverityStyle(severity: ClientRisk["severity"]): string {
  switch (severity) {
    case "critical": return "bg-destructive/10 text-destructive border-destructive/20";
    case "high": return "bg-orange-500/10 text-orange-500 border-orange-500/20";
    case "medium": return "bg-warning/15 text-warning border-warning/20";
    case "low": return "bg-muted text-muted-foreground border-border";
  }
}

function clientRiskIcon(type: ClientRisk["type"]) {
  switch (type) {
    case "source-map": return <FileWarning className="h-5 w-5" />;
    case "mixed-content": return <Unlock className="h-5 w-5" />;
    case "hardcoded-secret": return <Eye className="h-5 w-5" />;
    case "external-script": return <Terminal className="h-5 w-5" />;
  }
}

function ClientRisksPanel({ result }: { result: AnalyzeResult }) {
  const clientRisks = result.clientRisks ?? [];
  const cookies = result.cookies ?? [];
  const [cookieAI, setCookieAI] = useState<string | null>(null);
  const [loadingCookieAI, setLoadingCookieAI] = useState(false);

  const cookiesWithIssues = cookies.filter((c) => c.issues.length > 0);

  // Auto-fetch AI cookie analysis when there are issues
  useEffect(() => {
    if (cookiesWithIssues.length === 0) return;
    setLoadingCookieAI(true);
    analyzeCookiesAI({ data: { cookies: cookiesWithIssues, endpoint: result.endpoint, technologies: result.technologies.map(t => t.name) } as never })
      .then((r) => setCookieAI(r.analysis ?? null))
      .catch(() => setCookieAI(null))
      .finally(() => setLoadingCookieAI(false));
  }, []);

  if (clientRisks.length === 0 && cookiesWithIssues.length === 0) {
    return (
      <div className="py-10 text-center text-sm text-muted-foreground">
        No client-side risks detected. 
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Client-side risks */}
      {clientRisks.length > 0 && (
        <div>
          <h3 className="mb-3 text-[13px] font-semibold uppercase tracking-wider text-muted-foreground">
            Client-Side Risks
          </h3>
          <div className="space-y-3">
            {clientRisks.map((risk, i) => (
              <div
                key={i}
                className="flex items-start gap-4 rounded-xl border border-border bg-card p-4"
              >
                <div className={cn(
                  "mt-0.5 grid h-10 w-10 shrink-0 place-items-center rounded-lg border",
                  clientRiskSeverityStyle(risk.severity),
                )}>
                  {clientRiskIcon(risk.type)}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[14px] font-semibold text-foreground">{risk.description}</span>
                    <span className={cn(
                      "inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider",
                      clientRiskSeverityStyle(risk.severity),
                    )}>
                      {risk.severity}
                    </span>
                  </div>
                  {risk.detail && (
                    <p className="mt-1.5 text-[13px] text-muted-foreground">{risk.detail}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Cookie issues */}
      {cookiesWithIssues.length > 0 && (
        <div>
          <h3 className="mb-3 text-[13px] font-semibold uppercase tracking-wider text-muted-foreground">
            Cookie Security Issues
          </h3>
          {/* AI cookie analysis card */}
          {(cookieAI || loadingCookieAI) && (
            <div className="mb-4 rounded-xl border border-primary/20 bg-primary/5 p-4">
              <div className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-primary/70">
                <Sparkles className="h-3 w-3" /> AI Cookie Risk Assessment
              </div>
              {loadingCookieAI ? (
                <div className="flex items-center gap-2 text-[13px] text-muted-foreground">
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" /> Analyzing cookie configuration…
                </div>
              ) : (
                <p className="text-[13px] leading-relaxed text-foreground/85">{cookieAI}</p>
              )}
            </div>
          )}
          <div className="space-y-3">
            {cookiesWithIssues.map((cookie, i) => (
              <div key={i} className="rounded-xl border border-border bg-card p-4">
                <div className="flex flex-wrap items-center gap-2 mb-2">
                  <Lock className="h-4 w-4 text-muted-foreground" />
                  <span className="font-mono text-[14px] font-semibold text-foreground">{cookie.name}</span>
                  <div className="flex gap-1.5 ml-auto">
                    <span className={cn(
                      "rounded-md border px-2 py-0.5 text-[11px] font-medium",
                      cookie.httpOnly ? "bg-success/10 text-success border-success/20" : "bg-destructive/10 text-destructive border-destructive/20",
                    )}>
                      {cookie.httpOnly ? "HttpOnly" : "No HttpOnly"}
                    </span>
                    <span className={cn(
                      "rounded-md border px-2 py-0.5 text-[11px] font-medium",
                      cookie.secure ? "bg-success/10 text-success border-success/20" : "bg-destructive/10 text-destructive border-destructive/20",
                    )}>
                      {cookie.secure ? "Secure" : "No Secure"}
                    </span>
                    <span className={cn(
                      "rounded-md border px-2 py-0.5 text-[11px] font-medium",
                      cookie.sameSite ? "bg-success/10 text-success border-success/20" : "bg-warning/15 text-warning border-warning/20",
                    )}>
                      {cookie.sameSite ? `SameSite=${cookie.sameSite}` : "No SameSite"}
                    </span>
                  </div>
                </div>
                <ul className="space-y-1">
                  {cookie.issues.map((issue, j) => (
                    <li key={j} className="flex items-start gap-2 text-[13px] text-destructive">
                      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                      {issue}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Cookies with no issues */}
      {cookies.length > 0 && cookiesWithIssues.length === 0 && (
        <div className="flex items-center gap-2 text-[13px] text-success">
          <CheckCircle2 className="h-4 w-4" />
          All {cookies.length} cookie(s) appear properly configured.
        </div>
      )}
    </div>
  );
}

/* ─── Secrets & Leaks Tab ─── */

function commentBorderColor(c: CommentLeak["classification"]): string {
  switch (c) {
    case "critical": return "border-l-destructive";
    case "high": return "border-l-orange-500";
    case "medium": return "border-l-warning";
    default: return "border-l-border";
  }
}

function commentBadgeStyle(c: CommentLeak["classification"]): string {
  switch (c) {
    case "critical": return "bg-destructive/10 text-destructive border-destructive/20";
    case "high": return "bg-orange-500/10 text-orange-500 border-orange-500/20";
    case "medium": return "bg-warning/15 text-warning border-warning/20";
    default: return "bg-muted text-muted-foreground border-border";
  }
}

function SecretsLeaksPanel({ leaks }: { leaks?: AnalyzeResult["leaks"] }) {
  const [showAllComments, setShowAllComments] = useState(false);
  const [copiedEmail, setCopiedEmail] = useState<string | null>(null);

  if (!leaks) {
    return (
      <div className="py-10 text-center text-sm text-muted-foreground">
        No HTML body available for leak analysis.
      </div>
    );
  }

  const { comments, hiddenFields, internalIPs, emails } = leaks;
  const suspiciousFields = hiddenFields.filter((f) => f.suspicious);
  const visibleComments = showAllComments
    ? comments
    : comments.filter((c) => c.classification !== "low");
  const hasHiddenLow = comments.some((c) => c.classification === "low");

  const totalFindings =
    comments.filter((c) => c.classification !== "low").length +
    suspiciousFields.length +
    internalIPs.length +
    emails.length;

  if (totalFindings === 0 && !hasHiddenLow) {
    return (
      <div className="flex flex-col items-center gap-3 py-12 text-center">
        <div className="grid h-12 w-12 place-items-center rounded-full bg-success/10">
          <CheckCircle2 className="h-6 w-6 text-success" />
        </div>
        <p className="text-[14px] font-medium text-foreground">No leaks detected in HTML source — good hygiene.</p>
        <p className="text-[13px] text-muted-foreground">No sensitive comments, hidden fields, internal IPs, or email addresses found.</p>
      </div>
    );
  }

  const handleCopyEmail = (email: string) => {
    navigator.clipboard?.writeText(email);
    setCopiedEmail(email);
    setTimeout(() => setCopiedEmail(null), 1600);
  };

  return (
    <div className="space-y-8">

      {/* Section 1 — Comments */}
      <div>
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-[13px] font-semibold uppercase tracking-wider text-muted-foreground">
            HTML Comments
            {visibleComments.length > 0 && (
              <span className="ml-2 inline-flex h-4 min-w-[16px] items-center justify-center rounded-full bg-destructive px-1 text-[10px] font-semibold text-destructive-foreground">
                {visibleComments.length}
              </span>
            )}
          </h3>
          {hasHiddenLow && (
            <button
              onClick={() => setShowAllComments((v) => !v)}
              className="flex items-center gap-1 text-[12px] font-medium text-muted-foreground transition-colors hover:text-foreground"
            >
              {showAllComments ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
              {showAllComments ? "Hide LOW" : "Show all"}
            </button>
          )}
        </div>
        {visibleComments.length === 0 ? (
          <p className="text-[13px] text-muted-foreground">
            No critical, high, or medium severity comments found.{" "}
            {hasHiddenLow && !showAllComments && (
              <button onClick={() => setShowAllComments(true)} className="underline underline-offset-2 hover:text-foreground">
                Show {comments.filter((c) => c.classification === "low").length} low-severity comment(s).
              </button>
            )}
          </p>
        ) : (
          <div className="space-y-3">
            {visibleComments.map((comment, i) => (
              <div
                key={i}
                className={cn(
                  "rounded-xl border border-border bg-card border-l-4 p-4",
                  commentBorderColor(comment.classification),
                )}
              >
                <div className="mb-2 flex items-start justify-between gap-2">
                  <pre className="flex-1 overflow-x-auto font-mono text-[12.5px] leading-relaxed text-foreground/90 whitespace-pre-wrap break-words">
                    {comment.text}
                  </pre>
                  <span
                    className={cn(
                      "shrink-0 inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider",
                      commentBadgeStyle(comment.classification),
                    )}
                  >
                    {comment.classification}
                  </span>
                </div>
                <p className="text-[12px] text-muted-foreground">{comment.reason}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Section 2 — Hidden Form Fields */}
      {suspiciousFields.length > 0 && (
        <div>
          <h3 className="mb-3 text-[13px] font-semibold uppercase tracking-wider text-muted-foreground">
            Hidden Form Fields
          </h3>
          <div className="overflow-hidden rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-muted/40 text-left text-[12px] uppercase tracking-wider text-muted-foreground">
                  <th className="px-4 py-3 font-medium">Field Name</th>
                  <th className="px-4 py-3 font-medium">Redacted Value</th>
                  <th className="px-4 py-3 font-medium">Why Suspicious</th>
                </tr>
              </thead>
              <tbody>
                {suspiciousFields.map((field, i) => (
                  <tr key={i} className={cn("border-t border-border", i % 2 === 1 && "bg-muted/20")}>
                    <td className="px-4 py-3 font-mono text-[13px] font-semibold text-foreground">{field.name}</td>
                    <td className="px-4 py-3 font-mono text-[13px] text-muted-foreground">{field.value || "(empty)"}</td>
                    <td className="px-4 py-3 text-[13px] text-muted-foreground">
                      {/token|csrf|key|auth|session/i.test(field.name)
                        ? `Name "${field.name}" matches sensitive pattern`
                        : "Value appears to be a real token (length > 10, mixed chars)"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Section 3 — Internal IPs & Hostnames */}
      {internalIPs.length > 0 && (
        <div>
          <h3 className="mb-3 text-[13px] font-semibold uppercase tracking-wider text-muted-foreground">
            Internal IPs & Hostnames
          </h3>
          <div className="flex flex-wrap gap-2">
            {internalIPs.map((ip) => (
              <span
                key={ip}
                className="inline-flex items-center gap-1.5 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-1.5 font-mono text-[12.5px] font-semibold text-destructive"
              >
                {ip}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Section 4 — Emails Found */}
      {emails.length > 0 && (
        <div>
          <h3 className="mb-3 text-[13px] font-semibold uppercase tracking-wider text-muted-foreground">
            Email Addresses Found
          </h3>
          <ul className="space-y-2">
            {emails.map((email) => (
              <li
                key={email}
                className="flex items-center gap-3 rounded-lg border border-border bg-card px-4 py-2.5"
              >
                <span className="flex-1 font-mono text-[13px] text-foreground">{email}</span>
                <button
                  onClick={() => handleCopyEmail(email)}
                  className="flex items-center gap-1 rounded px-2 py-1 text-[12px] font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
                >
                  <Copy className="h-3.5 w-3.5" />
                  {copiedEmail === email ? "Copied!" : "Copy"}
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

/* ─── OSINT Tab ─── */

function spoofingRiskStyle(risk: DNSRecords["emailSpoofingRisk"]): string {
  switch (risk) {
    case "high": return "bg-destructive/10 text-destructive border-destructive/20";
    case "medium": return "bg-warning/15 text-warning border-warning/20";
    case "low": return "bg-success/10 text-success border-success/20";
  }
}

function txtTypeStyle(type: DNSRecords["txt"][number]["type"]): string {
  switch (type) {
    case "spf": return "bg-primary/10 text-primary border-primary/20";
    case "dmarc": return "bg-success/10 text-success border-success/20";
    case "verification": return "bg-purple-500/10 text-purple-500 border-purple-500/20";
    default: return "bg-muted text-muted-foreground border-border";
  }
}

function OsintPanel({ osint, onAnalyzeSubdomain }: { osint?: OsintResult; onAnalyzeSubdomain: (sub: string) => void }) {
  const [subSearch, setSubSearch] = useState("");
  const [showAllDomains, setShowAllDomains] = useState(false);
  const [txtOpen, setTxtOpen] = useState(false);
  const [copiedSub, setCopiedSub] = useState<string | null>(null);
  const [triage, setTriage] = useState<{ flagged: string[]; reasons: Record<string, string> } | null>(null);
  const [triageLoading, setTriageLoading] = useState(false);

  if (!osint) {
    return (
      <div className="py-10 text-center text-sm text-muted-foreground">
        OSINT data unavailable — target was not a live URL or lookups failed.
      </div>
    );
  }

  const { subdomains, dns, reverseIP, sharedHosting, wayback } = osint;

  const allDataEmpty =
    subdomains.length === 0 &&
    dns.a.length === 0 &&
    dns.mx.length === 0 &&
    dns.ns.length === 0 &&
    !wayback.hasArchive;

  if (allDataEmpty) {
    return (
      <div className="flex flex-col items-center gap-3 py-12 text-center">
        <div className="grid h-12 w-12 place-items-center rounded-full bg-muted">
          <Database className="h-6 w-6 text-muted-foreground" />
        </div>
        <p className="text-[14px] font-medium text-foreground">OSINT data unavailable</p>
        <p className="text-[13px] text-muted-foreground">All passive lookups returned no data. The target may be using privacy protection or blocking enumeration.</p>
      </div>
    );
  }

  const filteredSubs = subdomains.filter((s) => s.name.toLowerCase().includes(subSearch.toLowerCase()));

  const handleCopySub = (name: string) => {
    navigator.clipboard?.writeText(name);
    setCopiedSub(name);
    setTimeout(() => setCopiedSub(null), 1600);
  };

  // Auto-triage subdomains with AI when found
  useEffect(() => {
    if (subdomains.length === 0 || triage !== null) return;
    setTriageLoading(true);
    const domain = subdomains[0]?.name.split(".").slice(-2).join(".") ?? "";
    triageSubdomains({ data: { subdomains: subdomains.map(s => s.name), domain } as never })
      .then((r) => setTriage(r))
      .catch(() => setTriage({ flagged: [], reasons: {} }))
      .finally(() => setTriageLoading(false));
  }, [subdomains.length]);

  const DOMAIN_SHOW_LIMIT = 10;
  const visibleDomains = showAllDomains ? reverseIP : reverseIP.slice(0, DOMAIN_SHOW_LIMIT);

  const hasSPF = dns.txt.some((t) => t.type === "spf");
  const hasDMARC = dns.txt.some((t) => t.type === "dmarc");
  const spfRecord = dns.txt.find((t) => t.type === "spf");
  const spfMode = spfRecord
    ? spfRecord.value.includes("+all")
      ? "DANGEROUS (+all — allows anyone to send)"
      : spfRecord.value.includes("-all")
        ? "Strict (-all)"
        : "Soft-fail (~all)"
    : null;

  // AI threat narrative for email spoofing risk
  const spoofingNarrative: Record<string, string> = {
    high: `Without SPF or DMARC records, anyone can send emails that appear to originate from this domain, enabling targeted phishing campaigns against customers and employees. This is a critical email security gap that can be exploited immediately with freely available tools.`,
    medium: `SPF is configured but uses a permissive policy (~all soft-fail), which means spoofed emails may still be delivered. Without DMARC enforcement, there is no automatic quarantine or rejection of fraudulent mail.`,
    low: `Email authentication is properly configured with strict SPF (-all) and DMARC policies, significantly limiting the ability to spoof this domain in phishing attacks.`,
  };

  return (
    <div className="space-y-8">

      {/* Section 1 — Subdomains */}
      <div>
        <div className="mb-3 flex items-center justify-between gap-4">
          <h3 className="text-[13px] font-semibold uppercase tracking-wider text-muted-foreground">
            Subdomains Found
            {subdomains.length > 0 && (
              <span className="ml-2 inline-flex h-4 min-w-[16px] items-center justify-center rounded-full bg-primary/80 px-1 text-[10px] font-semibold text-primary-foreground">
                {subdomains.length}
              </span>
            )}
          </h3>
          {subdomains.length > 0 && (
            <div className="relative max-w-[220px] flex-1">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
              <input
                value={subSearch}
                onChange={(e) => setSubSearch(e.target.value)}
                placeholder="Filter subdomains"
                className="h-8 w-full rounded-md border border-border bg-background pl-8 pr-3 text-[12px] text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
              />
            </div>
          )}
        </div>
        {subdomains.length === 0 ? (
          <div className="flex items-center gap-3 rounded-xl border border-border bg-muted/30 p-4">
            <RefreshCw className="h-4 w-4 shrink-0 animate-spin text-muted-foreground" />
            <p className="text-[13px] text-muted-foreground">Subdomains were queried — none found in certificate transparency logs or passive DNS. This may mean the domain uses privacy protection or has a clean subdomain footprint.</p>
          </div>
        ) : (
          <>
            {triageLoading && (
              <div className="mb-3 flex items-center gap-2 rounded-lg border border-primary/20 bg-primary/5 px-3 py-2 text-[12px] text-primary/80">
                <Sparkles className="h-3.5 w-3.5 animate-pulse" /> AI is triaging subdomains for high-interest targets…
              </div>
            )}
          <div className="overflow-hidden rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-muted/40 text-left text-[12px] uppercase tracking-wider text-muted-foreground">
                  <th className="px-4 py-3 font-medium">Subdomain</th>
                  <th className="px-4 py-3 font-medium">First Seen</th>
                  <th className="px-4 py-3 font-medium">Last Seen</th>
                  <th className="px-4 py-3 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredSubs.map((sub, i) => (
                  <tr key={sub.name} className={cn("border-t border-border", i % 2 === 1 && "bg-muted/20")}>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-[12.5px] text-foreground">{sub.name}</span>
                        {triage?.flagged.includes(sub.name) && (
                          <span className="inline-flex items-center gap-1 rounded-full border border-orange-500/30 bg-orange-500/10 px-2 py-0.5 text-[10px] font-bold text-orange-500">
                            <Sparkles className="h-2.5 w-2.5" /> AI Flagged
                          </span>
                        )}
                      </div>
                      {triage?.reasons[sub.name] && (
                        <div className="mt-0.5 text-[11px] text-orange-500/80">{triage.reasons[sub.name]}</div>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-[12px] text-muted-foreground">{sub.firstSeen || "—"}</td>
                    <td className="px-4 py-2.5 text-[12px] text-muted-foreground">{sub.lastSeen || "—"}</td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => handleCopySub(sub.name)}
                          className="flex items-center gap-1 rounded px-2 py-1 text-[11px] font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
                        >
                          <Copy className="h-3 w-3" />
                          {copiedSub === sub.name ? "Copied!" : "Copy"}
                        </button>
                        <button
                          onClick={() => onAnalyzeSubdomain(`https://${sub.name}`)}
                          className="flex items-center gap-1 rounded px-2 py-1 text-[11px] font-medium text-primary/80 transition-colors hover:bg-primary/10 hover:text-primary"
                        >
                          <ExternalLink className="h-3 w-3" /> Analyze
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {filteredSubs.length === 0 && (
                  <tr>
                    <td colSpan={4} className="px-4 py-6 text-center text-[13px] text-muted-foreground">No matches for "{subSearch}".</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          </>
        )}
      </div>

      {/* Section 2 — DNS Intelligence */}
      {(dns.a.length > 0 || dns.mx.length > 0 || dns.ns.length > 0 || dns.aaaa.length > 0) && (
        <div>
          <h3 className="mb-3 text-[13px] font-semibold uppercase tracking-wider text-muted-foreground">
            DNS Intelligence
          </h3>

          {/* 4 mini-cards */}
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 mb-4">
            {/* IP Addresses */}
            <div className="rounded-xl border border-border bg-card p-4">
              <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                <Wifi className="h-3.5 w-3.5" /> IP Address
              </div>
              {dns.a.length === 0 ? (
                <span className="text-[13px] text-muted-foreground">—</span>
              ) : (
                <div className="space-y-1">
                  {dns.a.slice(0, 3).map((ip) => (
                    <div key={ip} className="font-mono text-[13px] font-medium text-foreground">{ip}</div>
                  ))}
                  {dns.aaaa.length > 0 && (
                    <div className="font-mono text-[11px] text-muted-foreground">
                      +{dns.aaaa.length} IPv6
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Mail Provider */}
            <div className="rounded-xl border border-border bg-card p-4">
              <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                <Mail className="h-3.5 w-3.5" /> Mail Provider
              </div>
              <div className="text-[13px] font-medium text-foreground">
                {dns.emailProvider ?? <span className="text-muted-foreground">—</span>}
              </div>
              {dns.mx.length > 0 && (
                <div className="mt-1 font-mono text-[11px] text-muted-foreground truncate" title={dns.mx[0]?.exchange}>
                  {dns.mx[0]?.exchange}
                </div>
              )}
            </div>

            {/* Nameservers */}
            <div className="rounded-xl border border-border bg-card p-4">
              <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                <Server className="h-3.5 w-3.5" /> Nameservers
              </div>
              {dns.ns.length === 0 ? (
                <span className="text-[13px] text-muted-foreground">—</span>
              ) : (
                <div className="space-y-1">
                  {dns.ns.slice(0, 2).map((ns) => (
                    <div key={ns} className="font-mono text-[12px] text-foreground truncate" title={ns}>{ns}</div>
                  ))}
                  {dns.ns.length > 2 && (
                    <div className="text-[11px] text-muted-foreground">+{dns.ns.length - 2} more</div>
                  )}
                </div>
              )}
            </div>

            {/* Email Spoofing Risk */}
            <div className="rounded-xl border border-border bg-card p-4">
              <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                <ShieldX className="h-3.5 w-3.5" /> Email Spoofing
              </div>
              <span className={cn(
                "inline-flex items-center rounded-md border px-2 py-0.5 text-[12px] font-bold uppercase tracking-wider",
                spoofingRiskStyle(dns.emailSpoofingRisk),
              )}>
                {dns.emailSpoofingRisk} risk
              </span>
              <div className="mt-1.5 text-[11px] text-muted-foreground">
                {!hasSPF ? "No SPF record" : spfMode}
              </div>
            </div>
          </div>
          {/* AI Threat Narrative */}
          <div className="rounded-xl border border-primary/15 bg-primary/5 p-4">
            <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-primary/70">
              <Sparkles className="h-3 w-3" /> AI Threat Assessment — Email Security
            </div>
            <p className="text-[13px] leading-relaxed text-foreground/85">
              {spoofingNarrative[dns.emailSpoofingRisk]}
            </p>
          </div>

          {/* TXT Records expandable */}
          <div className="rounded-xl border border-border bg-card">
            <button
              onClick={() => setTxtOpen((o) => !o)}
              className="flex w-full items-center justify-between px-4 py-3 text-[13px] font-medium text-foreground"
            >
              <span className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-muted-foreground" />
                TXT Records — SPF, DMARC & Verification
              </span>
              {txtOpen ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
            </button>
            {txtOpen && (
              <div className="border-t border-border p-4 space-y-3">
                {/* SPF status */}
                <div className="flex items-center gap-3">
                  {hasSPF ? (
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-success" />
                  ) : (
                    <XCircle className="h-4 w-4 shrink-0 text-destructive" />
                  )}
                  <span className="text-[13px]">
                    <span className="font-semibold text-foreground">SPF: </span>
                    {hasSPF ? (
                      <span className="text-foreground/80">{spfMode}</span>
                    ) : (
                      <span className="text-destructive">Missing — email spoofing is possible</span>
                    )}
                  </span>
                </div>
                {/* DMARC status */}
                <div className="flex items-center gap-3">
                  {hasDMARC ? (
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-success" />
                  ) : (
                    <XCircle className="h-4 w-4 shrink-0 text-destructive" />
                  )}
                  <span className="text-[13px]">
                    <span className="font-semibold text-foreground">DMARC: </span>
                    {hasDMARC ? (
                      <span className="text-foreground/80">Configured</span>
                    ) : (
                      <span className="text-destructive">Missing — no email authentication policy</span>
                    )}
                  </span>
                </div>
                {/* All TXT records */}
                {dns.txt.length > 0 && (
                  <div className="mt-3 space-y-2">
                    {dns.txt.map((rec, i) => (
                      <div key={i} className="flex items-start gap-2 rounded-lg bg-muted/40 p-3">
                        <span className={cn(
                          "mt-0.5 shrink-0 inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider",
                          txtTypeStyle(rec.type),
                        )}>
                          {rec.type}
                        </span>
                        <span className="min-w-0 break-all font-mono text-[11.5px] text-foreground/80">{rec.value}</span>
                      </div>
                    ))}
                  </div>
                )}
                {dns.txt.length === 0 && (
                  <p className="text-[13px] text-muted-foreground">No TXT records found.</p>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Section 3 — Shared Hosting */}
      {dns.a.length > 0 && (
        <div>
          <h3 className="mb-3 text-[13px] font-semibold uppercase tracking-wider text-muted-foreground">
            Hosting Analysis
          </h3>
          {sharedHosting ? (
            <div className="rounded-xl border border-orange-500/30 bg-orange-500/5 p-4">
              <div className="mb-2 flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-orange-500" />
                <span className="text-[14px] font-semibold text-orange-500">Shared hosting detected</span>
              </div>
              <p className="mb-3 text-[13px] text-muted-foreground">
                {reverseIP.length} other site{reverseIP.length !== 1 ? "s" : ""} share this server IP ({dns.a[0]}). Vulnerabilities in neighboring sites can affect your security.
              </p>
              <ul className="space-y-1.5">
                {visibleDomains.map((domain) => (
                  <li key={domain} className="flex items-center gap-2 font-mono text-[12.5px] text-foreground">
                    <Globe className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                    {domain}
                  </li>
                ))}
              </ul>
              {reverseIP.length > DOMAIN_SHOW_LIMIT && (
                <button
                  onClick={() => setShowAllDomains((v) => !v)}
                  className="mt-2 text-[12px] font-medium text-orange-500 hover:underline"
                >
                  {showAllDomains ? "Show less" : `Show ${reverseIP.length - DOMAIN_SHOW_LIMIT} more`}
                </button>
              )}
            </div>
          ) : (
            <div className="flex items-center gap-3 rounded-xl border border-success/20 bg-success/5 p-4">
              <CheckCircle2 className="h-5 w-5 text-success" />
              <div>
                <div className="text-[13px] font-semibold text-success">Dedicated hosting detected</div>
                <div className="text-[12px] text-muted-foreground">No other domains found on {dns.a[0]}.</div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Section 4 — Historical Presence */}
      <div>
        <h3 className="mb-3 text-[13px] font-semibold uppercase tracking-wider text-muted-foreground">
          Historical Presence
        </h3>
        {wayback.hasArchive ? (
          <div className="rounded-xl border border-border bg-card p-4 space-y-3">
            <div className="grid gap-3 sm:grid-cols-3">
              {wayback.oldestSnapshot && (
                <div className="text-center">
                  <div className="text-lg font-bold text-foreground tabular-nums">
                    {wayback.oldestSnapshot.slice(0, 4)}
                  </div>
                  <div className="mt-0.5 text-[11px] uppercase tracking-wider text-muted-foreground">Online since</div>
                </div>
              )}
              {wayback.totalSnapshots !== null && (
                <div className="text-center">
                  <div className="text-lg font-bold text-foreground tabular-nums">{wayback.totalSnapshots}</div>
                  <div className="mt-0.5 text-[11px] uppercase tracking-wider text-muted-foreground">Snapshots (sampled)</div>
                </div>
              )}
              {wayback.latestSnapshot && (
                <div className="text-center">
                  <div className="text-lg font-bold text-foreground tabular-nums">{wayback.latestSnapshot}</div>
                  <div className="mt-0.5 text-[11px] uppercase tracking-wider text-muted-foreground">Latest snapshot</div>
                </div>
              )}
            </div>
            {wayback.latestSnapshot && (
              <a
                href={`https://web.archive.org/web/${wayback.latestSnapshot.replace(/-/g, "")}120000*/`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-[12px] font-medium text-primary hover:underline"
              >
                <ExternalLink className="h-3.5 w-3.5" /> View in Wayback Machine
              </a>
            )}
          </div>
        ) : (
          <div className="flex items-center gap-3 rounded-xl border border-border bg-muted/30 p-4">
            <Clock className="h-5 w-5 text-muted-foreground" />
            <p className="text-[13px] text-muted-foreground">No Wayback Machine archive found for this domain.</p>
          </div>
        )}
      </div>
    </div>
  );
}

function RawViewer({ data }: { data: unknown }) {
  const [open, setOpen] = useState(true);
  const json = JSON.stringify(data, null, 2);
  return (
    <div className="rounded-lg border border-border bg-muted/30">
      <div className="flex items-center justify-between border-b border-border px-4 py-2">
        <button onClick={() => setOpen((o) => !o)} className="text-[13px] font-medium text-foreground">
          {open ? "Collapse" : "Expand"} raw JSON
        </button>
        <Button variant="ghost" size="sm" className="h-7 gap-1.5 text-[12px]" onClick={() => navigator.clipboard?.writeText(json)}>
          <Copy className="h-3.5 w-3.5" /> Copy
        </Button>
      </div>
      {open && (
        <pre className="max-h-[420px] overflow-auto px-4 py-3 font-mono text-[12.5px] leading-relaxed text-foreground/90">
          {json}
        </pre>
      )}
    </div>
  );
}

function buildMarkdownReport(result: AnalyzeResult): string {
  const lines = [
    `# ReconLens AI Security Report`,
    ``,
    `**Target:** ${result.target}`,
    `**Score:** ${result.score}/100`,
    `**Risk Level:** ${result.risk}`,
    `**Endpoint:** ${result.endpoint}`,
    `**Timestamp:** ${result.timestamp}`,
    `**Duration:** ${result.duration}`,
    ``,
    `## Executive Summary`,
    ``,
    result.summary,
    ``,
    `## Security Headers`,
    ``,
    `| Header | Status | Description |`,
    `|--------|--------|-------------|`,
    ...result.headers.map((h) => `| ${h.header} | ${h.status.toUpperCase()} | ${h.description} |`),
    ``,
    `## Technologies Detected`,
    ``,
    result.technologies.map((t) => `- **${t.name}**${t.version ? ` v${t.version}` : ""} (${t.category})`).join("\n"),
    ``,
    `## Sensitive Paths`,
    ``,
    result.sensitivePaths && result.sensitivePaths.length > 0
      ? result.sensitivePaths.map((p) => `- \`${p.path}\` — ${p.label} [${p.severity.toUpperCase()}]: ${p.status}`).join("\n")
      : "No paths probed.",
    ``,
    `## Recommendations`,
    ``,
    result.recommendations.map((r, i) => `${i + 1}. **${r.title}** — ${r.detail}`).join("\n"),
  ];
  return lines.join("\n");
}

function QuickActions({
  result, onAnalyzeNew, onHistory,
}: {
  result: AnalyzeResult;
  onAnalyzeNew: () => void;
  onHistory: () => void;
}) {
  const [reportOpen, setReportOpen] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportContent, setReportContent] = useState<string | null>(null);
  const [reportCopied, setReportCopied] = useState(false);

  const copyReport = () => {
    navigator.clipboard?.writeText(buildMarkdownReport(result));
  };

  const exportMarkdown = () => {
    const blob = new Blob([buildMarkdownReport(result)], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `reconlens-${result.target.replace(/[^a-z0-9]/gi, "-")}.md`;
    a.click();
  };

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `reconlens-${result.target.replace(/[^a-z0-9]/gi, "-")}.json`;
    a.click();
  };

  const handleGenerateFullReport = async () => {
    setReportOpen(true);
    if (reportContent) return;
    setReportLoading(true);
    try {
      const res = await generateFullReport({ data: {
        target: result.target, score: result.score, risk: result.risk,
        endpoint: result.endpoint, technologies: result.technologies,
        headers: result.headers, recommendations: result.recommendations,
        sensitivePaths: result.sensitivePaths, cookies: result.cookies,
        osint: result.osint, summary: result.summary,
      } as never });
      setReportContent(res.report);
    } catch {
      setReportContent(`# Security Report\n\n${buildMarkdownReport(result)}`);
    } finally {
      setReportLoading(false);
    }
  };

  const downloadFullReport = () => {
    if (!reportContent) return;
    const blob = new Blob([reportContent], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `reconlens-full-report-${result.target.replace(/[^a-z0-9]/gi, "-")}.md`;
    a.click();
  };

  const handleCopyReport = () => {
    if (!reportContent) return;
    navigator.clipboard?.writeText(reportContent);
    setReportCopied(true);
    setTimeout(() => setReportCopied(false), 1800);
  };

  return (
    <>
      <Card className="flex flex-wrap items-center gap-2 p-4">
        <Button onClick={onAnalyzeNew} className="h-10 gap-2 px-4">
          <Search className="h-4 w-4" /> Analyze new target
        </Button>
        <Button onClick={handleGenerateFullReport} variant="outline" className="h-10 gap-2 border-primary/30 text-primary hover:bg-primary/10">
          <Sparkles className="h-4 w-4" /> Generate AI Report
        </Button>
        <div className="mx-1 hidden h-6 w-px bg-border sm:block" />
        <Button variant="outline" className="h-10 gap-2" onClick={copyReport}>
          <Copy className="h-4 w-4" /> Copy report
        </Button>
        <Button variant="outline" className="h-10 gap-2" onClick={exportMarkdown}>
          <FileText className="h-4 w-4" /> Export Markdown
        </Button>
        <Button variant="outline" className="h-10 gap-2" onClick={exportJson}>
          <FileDown className="h-4 w-4" /> Export JSON
        </Button>
        <Button variant="outline" className="h-10 gap-2" onClick={onHistory}>
          <HistoryIcon className="h-4 w-4" /> View history
        </Button>
      </Card>

      {/* Full Report Modal */}
      {reportOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
          onClick={(e) => { if (e.target === e.currentTarget) setReportOpen(false); }}
        >
          <div className="flex max-h-[85vh] w-full max-w-3xl flex-col rounded-2xl border border-border bg-card shadow-2xl">
            <div className="flex items-center justify-between border-b border-border px-6 py-4">
              <div className="flex items-center gap-2">
                <Sparkles className="h-5 w-5 text-primary" />
                <span className="text-base font-semibold text-foreground">AI-Generated Security Report</span>
                <Badge variant="outline" className="text-[10px] uppercase tracking-wider">Groq · qwen3-32b</Badge>
              </div>
              <div className="flex items-center gap-2">
                {reportContent && (
                  <>
                    <Button variant="outline" size="sm" className="h-8 gap-1.5 text-[12px]" onClick={handleCopyReport}>
                      <Copy className="h-3.5 w-3.5" /> {reportCopied ? "Copied!" : "Copy"}
                    </Button>
                    <Button variant="outline" size="sm" className="h-8 gap-1.5 text-[12px]" onClick={downloadFullReport}>
                      <FileDown className="h-3.5 w-3.5" /> Download
                    </Button>
                  </>
                )}
                <Button variant="ghost" size="sm" className="h-8 w-8 p-0" onClick={() => setReportOpen(false)}>
                  <XCircle className="h-4 w-4" />
                </Button>
              </div>
            </div>
            <div className="flex-1 overflow-auto px-6 py-5">
              {reportLoading ? (
                <div className="flex flex-col items-center gap-4 py-16">
                  <RefreshCw className="h-8 w-8 animate-spin text-primary" />
                  <div className="text-[14px] font-medium text-foreground">Generating comprehensive report…</div>
                  <div className="text-[12px] text-muted-foreground">AI is analyzing all findings and writing remediation steps</div>
                </div>
              ) : reportContent ? (
                <pre className="whitespace-pre-wrap font-mono text-[12.5px] leading-relaxed text-foreground/90">
                  {reportContent}
                </pre>
              ) : null}
            </div>
          </div>
        </div>
      )}
    </>
  );
}

/* ─── Footer & shared ─── */

export function Footer() {
  return (
    <footer className="mt-14 border-t border-border pt-6 text-center text-[12px] text-muted-foreground">
      <div className="font-medium text-foreground/80">ReconLens AI v1.1</div>
      <div className="mt-1">AI-Powered HTTP Security Intelligence Assistant</div>
      <div className="mt-1 text-[11px]">Built with TypeScript • TanStack Start • Groq AI (qwen3-32b)</div>
    </footer>
  );
}

export function Card({ className, children, ...rest }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      {...rest}
      className={cn(
        "rounded-2xl border border-border bg-card text-card-foreground shadow-[var(--shadow-card)] transition-shadow",
        className,
      )}
    >
      {children}
    </div>
  );
}

export function ScoreBadge({ score, compact = false }: { score: number; compact?: boolean }) {
  const tone =
    score >= 85
      ? "bg-success/10 text-success border-success/20"
      : score >= 65
        ? "bg-warning/15 text-warning border-warning/20"
        : "bg-destructive/10 text-destructive border-destructive/20";
  return (
    <span
      className={cn(
        "inline-flex items-center justify-center rounded-lg border font-semibold tabular-nums",
        compact ? "h-8 w-10 text-[12.5px]" : "h-7 px-2.5 text-[12px]",
        tone,
      )}
    >
      {score}
    </span>
  );
}

export { Save };
