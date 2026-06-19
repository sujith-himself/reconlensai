import { Boxes, Cpu, GitBranch, Layers, Rocket, Target, User2, Workflow } from "lucide-react";
import { Card, Footer } from "./AnalyzeView";

const SECTIONS = [
  {
    icon: Target,
    title: "Mission",
    body: "Make HTTP-layer security observability accessible to every engineering team — replacing raw scanner output with structured, explainable intelligence.",
  },
  {
    icon: Workflow,
    title: "How it works",
    body: "ReconLens fetches the target, runs a deterministic rule engine across headers, fingerprints, and routing signals, then asks an LLM to translate findings into plain-language guidance.",
  },
  {
    icon: Layers,
    title: "Architecture",
    body: "Stateless analysis workers feed a streaming results bus. The frontend renders progressively as each phase resolves. Findings are persisted in a per-workspace store.",
  },
  {
    icon: Cpu,
    title: "Technology stack",
    body: "Python analysis engine, Streamlit prototype shell, Gemini for AI summarization, SQLite for analysis storage. Frontend built with TypeScript and a custom enterprise design system.",
  },
  {
    icon: GitBranch,
    title: "Analysis pipeline",
    body: "Input → fetch → header parse → rule evaluation → endpoint classification → AI synthesis → report assembly. Each stage emits structured events.",
  },
  {
    icon: Rocket,
    title: "Product version",
    body: "ReconLens AI v1.0 — initial public preview. Scoped to single-target HTTP analysis with manual input.",
  },
  {
    icon: User2,
    title: "Developer",
    body: "Built by an independent security tooling team focused on explainable defense. Feedback and bug reports welcome.",
  },
  {
    icon: Boxes,
    title: "System workflow",
    body: "Designed to slot into existing SOC pipelines: ingest from triage queues, emit JSON reports, integrate with ticketing via webhook handlers.",
  },
];

export function AboutView() {
  return (
    <div className="mx-auto w-full max-w-7xl px-6 py-10 lg:px-10">
      <header className="mb-8">
        <div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Product</div>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight text-foreground">About ReconLens AI</h1>
        <p className="mt-2 max-w-2xl text-[15px] text-muted-foreground">
          An AI-powered HTTP security intelligence assistant designed for clarity, explainability, and engineering velocity.
        </p>
      </header>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {SECTIONS.map((s) => (
          <Card key={s.title} className="p-6">
            <div className="grid h-10 w-10 place-items-center rounded-xl bg-primary/10 text-primary">
              <s.icon className="h-5 w-5" />
            </div>
            <h3 className="mt-4 text-[15px] font-semibold text-foreground">{s.title}</h3>
            <p className="mt-1.5 text-[13.5px] leading-relaxed text-muted-foreground">{s.body}</p>
          </Card>
        ))}
      </div>

      <Footer />
    </div>
  );
}
