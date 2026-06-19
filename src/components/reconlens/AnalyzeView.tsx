import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  Copy,
  Cpu,
  Download,
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
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { DEMO_RESULT, SAMPLE_HISTORY, type View } from "./types";

const LOADING_STEPS = [
  "Connecting to target",
  "Fetching response",
  "Parsing headers",
  "Running security rules",
  "Generating AI insights",
  "Preparing report",
];

type ResultState = typeof DEMO_RESULT | null;

export function AnalyzeView({ onNavigate }: { onNavigate: (v: View) => void }) {
  const [url, setUrl] = useState("");
  const [raw, setRaw] = useState("");
  const [loading, setLoading] = useState(false);
  const [activeStep, setActiveStep] = useState(0);
  const [result, setResult] = useState<ResultState>(null);
  const [tab, setTab] = useState<"overview" | "headers" | "tech" | "recs" | "raw">("overview");

  useEffect(() => {
    if (!loading) return;
    setActiveStep(0);
    const interval = setInterval(() => {
      setActiveStep((s) => {
        if (s >= LOADING_STEPS.length - 1) {
          clearInterval(interval);
          setTimeout(() => {
            setLoading(false);
            setResult(DEMO_RESULT);
            setTab("overview");
            requestAnimationFrame(() => window.scrollTo({ top: 0, behavior: "smooth" }));
          }, 400);
          return s;
        }
        return s + 1;
      });
    }, 480);
    return () => clearInterval(interval);
  }, [loading]);

  const start = () => {
    if (!url && !raw) {
      setUrl("https://api.acme.io/v2");
    }
    setLoading(true);
    setResult(null);
  };

  const loadDemo = () => {
    setUrl(DEMO_RESULT.target);
    setRaw("GET /v2 HTTP/2\nHost: api.acme.io\nUser-Agent: ReconLens/1.0\nAccept: application/json");
  };

  const clearAll = () => {
    setUrl("");
    setRaw("");
    setResult(null);
  };

  const analyzeNew = () => {
    clearAll();
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

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
          <RecentAnalysesCard onOpen={() => setResult(DEMO_RESULT)} />
        </div>
      )}

      {!result && !loading && <EmptyState onAnalyze={start} />}

      {loading && <LoadingExperience step={activeStep} />}

      {result && !loading && (
        <ResultsDashboard
          result={result}
          tab={tab}
          setTab={setTab}
          onAnalyzeNew={analyzeNew}
          onNavigate={onNavigate}
        />
      )}

      <Footer />
    </div>
  );
}

/* ---------- Input ---------- */

function InputCard({
  url,
  setUrl,
  raw,
  setRaw,
  onAnalyze,
  onDemo,
  onClear,
  loading,
}: {
  url: string;
  setUrl: (v: string) => void;
  raw: string;
  setRaw: (v: string) => void;
  onAnalyze: () => void;
  onDemo: () => void;
  onClear: () => void;
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

function RecentAnalysesCard({ onOpen }: { onOpen: () => void }) {
  return (
    <Card className="animate-fade-in-up p-5" style={{ animationDelay: "60ms" }}>
      <div className="mb-4 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-foreground">Recent analyses</h3>
        <span className="text-[11px] uppercase tracking-wider text-muted-foreground">Last 5</span>
      </div>
      <ul className="space-y-1">
        {SAMPLE_HISTORY.slice(0, 5).map((h) => (
          <li key={h.id}>
            <button
              onClick={onOpen}
              className="group flex w-full items-center gap-3 rounded-lg px-2.5 py-2.5 text-left transition-colors hover:bg-accent/60"
            >
              <ScoreBadge score={h.score} compact />
              <div className="min-w-0 flex-1">
                <div className="truncate text-[13px] font-medium text-foreground">{h.target.replace(/^https?:\/\//, "")}</div>
                <div className="truncate text-[11px] text-muted-foreground">{h.timestamp}</div>
              </div>
              <ArrowRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
            </button>
          </li>
        ))}
      </ul>
    </Card>
  );
}

/* ---------- Empty state ---------- */

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

/* ---------- Loading ---------- */

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

/* ---------- Results ---------- */

function ResultsDashboard({
  result,
  tab,
  setTab,
  onAnalyzeNew,
  onNavigate,
}: {
  result: typeof DEMO_RESULT;
  tab: "overview" | "headers" | "tech" | "recs" | "raw";
  setTab: (t: "overview" | "headers" | "tech" | "recs" | "raw") => void;
  onAnalyzeNew: () => void;
  onNavigate: (v: View) => void;
}) {
  return (
    <div className="space-y-6">
      <ResultHeader result={result} />
      <StatusTimeline />
      <KpiStrip result={result} />

      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-1 border-b border-border bg-muted/40 px-3 py-2">
          {(
            [
              ["overview", "Overview"],
              ["headers", "Headers"],
              ["tech", "Technologies"],
              ["recs", "Recommendations"],
              ["raw", "Raw Data"],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={cn(
                "rounded-md px-3.5 py-1.5 text-[13px] font-medium transition-colors",
                tab === id ? "bg-card text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
              )}
            >
              {label}
            </button>
          ))}
        </div>

        <div className="p-6">
          {tab === "overview" && <OverviewPanel result={result} />}
          {tab === "headers" && <HeadersTable headers={result.headers} />}
          {tab === "tech" && <TechGrid items={result.technologies} />}
          {tab === "recs" && <RecsList items={result.recommendations} />}
          {tab === "raw" && <RawViewer data={result.raw} />}
        </div>
      </Card>

      <QuickActions onAnalyzeNew={onAnalyzeNew} onHistory={() => onNavigate("history")} />
    </div>
  );
}

function ResultHeader({ result }: { result: typeof DEMO_RESULT }) {
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

function KpiStrip({ result }: { result: typeof DEMO_RESULT }) {
  const missing = result.headers.filter((h) => h.status !== "ok").length;
  const tiles = [
    { label: "Security score", value: `${result.score}/100`, icon: Gauge, accent: "text-primary" },
    { label: "Technologies", value: String(result.technologies.length), icon: Cpu, accent: "text-foreground" },
    { label: "Missing headers", value: String(missing), icon: ShieldAlert, accent: "text-warning" },
    { label: "Risk level", value: result.risk, icon: AlertTriangle, accent: "text-warning" },
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

function OverviewPanel({ result }: { result: typeof DEMO_RESULT }) {
  return (
    <div className="grid gap-6 lg:grid-cols-[320px_minmax(0,1fr)]">
      <ScoreCard score={result.score} endpoint={result.endpoint} />
      <div className="space-y-6">
        <SummaryCard summary={result.summary} />
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
  return (
    <Card className="flex flex-col items-center p-6">
      <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Security score</div>
      <div className="relative mt-4 grid h-[160px] w-[160px] place-items-center">
        <svg width="160" height="160" className="-rotate-90">
          <circle cx="80" cy="80" r={r} strokeWidth="10" className="fill-none stroke-muted" />
          <circle
            cx="80"
            cy="80"
            r={r}
            strokeWidth="10"
            strokeLinecap="round"
            className={cn("fill-none transition-all duration-700", tone)}
            stroke="currentColor"
            strokeDasharray={c}
            strokeDashoffset={offset}
          />
        </svg>
        <div className="absolute flex flex-col items-center">
          <div className="text-3xl font-semibold tracking-tight text-foreground">{score}</div>
          <div className="text-xs text-muted-foreground">/ 100</div>
        </div>
      </div>
      <p className="mt-4 text-center text-[13px] text-muted-foreground">
        Solid baseline posture. A few high-impact hardening steps remain.
      </p>
      <Badge className="mt-3 border-success/20 bg-success/10 text-success hover:bg-success/10">
        ▲ +6 vs last scan
      </Badge>
      <div className="mt-4 w-full rounded-lg bg-muted/50 px-3 py-2 text-center text-[12px] text-muted-foreground">
        Classified as <span className="font-medium text-foreground">{endpoint}</span>
      </div>
    </Card>
  );
}

function SummaryCard({ summary }: { summary: string }) {
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
      <p className="mt-3 text-[13px] text-muted-foreground">JSON over HTTPS with versioned routing and CORS enabled.</p>
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

function HeadersTable({ headers }: { headers: typeof DEMO_RESULT.headers }) {
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

function TechGrid({ items }: { items: { name: string; category: string }[] }) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {items.map((t) => (
        <div key={t.name} className="flex items-center gap-3 rounded-lg border border-border bg-card px-4 py-3">
          <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-primary/10 text-primary">
            <Cpu className="h-4 w-4" />
          </div>
          <div className="min-w-0">
            <div className="truncate text-[14px] font-medium text-foreground">{t.name}</div>
            <div className="truncate text-[12px] text-muted-foreground">{t.category}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

function RecsList({ items }: { items: { title: string; detail: string }[] }) {
  return (
    <ul className="space-y-2.5">
      {items.map((r) => (
        <li
          key={r.title}
          className="group flex items-start gap-3 rounded-xl border border-border bg-card px-4 py-3.5 transition-colors hover:bg-accent/40"
        >
          <div className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-warning/15 text-warning">
            <ShieldCheck className="h-4 w-4" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-[14px] font-medium text-foreground">{r.title}</div>
            <div className="text-[13px] text-muted-foreground">{r.detail}</div>
          </div>
          <ArrowRight className="mt-1 h-4 w-4 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
        </li>
      ))}
    </ul>
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

function QuickActions({ onAnalyzeNew, onHistory }: { onAnalyzeNew: () => void; onHistory: () => void }) {
  const actions = [
    { label: "Copy report", icon: Copy },
    { label: "Export PDF", icon: FileDown },
    { label: "Export Markdown", icon: FileText },
    { label: "Save analysis", icon: Save },
    { label: "View history", icon: HistoryIcon, onClick: onHistory },
  ];
  return (
    <Card className="flex flex-wrap items-center gap-2 p-4">
      <Button onClick={onAnalyzeNew} className="h-10 gap-2 px-4">
        <Search className="h-4 w-4" /> Analyze new target
      </Button>
      <div className="mx-1 hidden h-6 w-px bg-border sm:block" />
      {actions.map((a) => (
        <Button key={a.label} variant="outline" className="h-10 gap-2" onClick={a.onClick}>
          <a.icon className="h-4 w-4" /> {a.label}
        </Button>
      ))}
    </Card>
  );
}

/* ---------- Footer ---------- */

export function Footer() {
  return (
    <footer className="mt-14 border-t border-border pt-6 text-center text-[12px] text-muted-foreground">
      <div className="font-medium text-foreground/80">ReconLens AI v1.0</div>
      <div className="mt-1">AI-Powered HTTP Security Intelligence Assistant</div>
      <div className="mt-1 text-[11px]">Built with Python • Streamlit • Gemini AI • SQLite</div>
    </footer>
  );
}

/* ---------- Shared ---------- */

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

export { Download };
