import { useState } from "react";
import { ArrowUpRight, CheckCircle2, Filter, GitCompare, Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { SAMPLE_HISTORY } from "./types";
import { Card, Footer, ScoreBadge } from "./AnalyzeView";
import { cn } from "@/lib/utils";

export function HistoryView() {
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const filtered = SAMPLE_HISTORY.filter((r) => {
    if (!q.trim()) return true;
    const s = q.toLowerCase();
    return (
      r.target.toLowerCase().includes(s) ||
      r.endpoint.toLowerCase().includes(s) ||
      String(r.score).includes(s) ||
      r.technologies.some((t) => t.toLowerCase().includes(s))
    );
  });

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else if (next.size < 2) next.add(id);
      return next;
    });
  };

  return (
    <div className="mx-auto w-full max-w-7xl px-6 py-10 lg:px-10">
      <header className="mb-8">
        <div className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Workspace</div>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight text-foreground">Analysis history</h1>
        <p className="mt-2 max-w-2xl text-[15px] text-muted-foreground">
          Review past scans, search across targets and technologies, and compare results side by side.
        </p>
      </header>

      <Card className="p-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative min-w-[260px] flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search by domain, technology, endpoint, or score…"
              className="h-10 pl-9"
            />
          </div>
          <Button variant="outline" className="h-10 gap-2">
            <Filter className="h-4 w-4" /> Filters
          </Button>
          <Button disabled={selected.size !== 2} className="h-10 gap-2">
            <GitCompare className="h-4 w-4" /> Compare analyses{selected.size > 0 ? ` (${selected.size}/2)` : ""}
          </Button>
        </div>
      </Card>

      <Card className="mt-4 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-muted/40 text-left text-[12px] uppercase tracking-wider text-muted-foreground">
              <th className="w-10 px-4 py-3" />
              <th className="px-4 py-3 font-medium">Target</th>
              <th className="px-4 py-3 font-medium">Score</th>
              <th className="px-4 py-3 font-medium">Endpoint</th>
              <th className="px-4 py-3 font-medium">Technologies</th>
              <th className="px-4 py-3 font-medium">Timestamp</th>
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="w-10 px-4 py-3" />
            </tr>
          </thead>
          <tbody>
            {filtered.map((r, i) => (
              <tr
                key={r.id}
                className={cn(
                  "group cursor-pointer border-t border-border transition-colors hover:bg-accent/40",
                  i % 2 === 1 && "bg-muted/15",
                )}
              >
                <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                  <Checkbox checked={selected.has(r.id)} onCheckedChange={() => toggle(r.id)} />
                </td>
                <td className="px-4 py-3 font-mono text-[13px] text-foreground">{r.target}</td>
                <td className="px-4 py-3"><ScoreBadge score={r.score} /></td>
                <td className="px-4 py-3 text-foreground/80">{r.endpoint}</td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {r.technologies.slice(0, 3).map((t) => (
                      <span key={t} className="rounded-md bg-muted px-1.5 py-0.5 text-[11.5px] text-foreground/80">{t}</span>
                    ))}
                  </div>
                </td>
                <td className="px-4 py-3 text-muted-foreground">{r.timestamp}</td>
                <td className="px-4 py-3">
                  {r.status === "Completed" && (
                    <Badge className="border-success/20 bg-success/10 text-success hover:bg-success/10">
                      <CheckCircle2 className="mr-1 h-3 w-3" /> Completed
                    </Badge>
                  )}
                  {r.status === "Warning" && (
                    <Badge className="border-warning/20 bg-warning/15 text-warning hover:bg-warning/15">Warning</Badge>
                  )}
                  {r.status === "Failed" && (
                    <Badge variant="destructive">Failed</Badge>
                  )}
                </td>
                <td className="px-4 py-3 text-right">
                  <ArrowUpRight className="h-4 w-4 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={8} className="px-4 py-14 text-center text-sm text-muted-foreground">
                  No analyses match your search.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>

      <div className="mt-4 flex items-center justify-between text-[12.5px] text-muted-foreground">
        <span>Showing {filtered.length} of {SAMPLE_HISTORY.length} analyses</span>
        <div className="flex gap-1">
          <Button variant="outline" size="sm" disabled>Previous</Button>
          <Button variant="outline" size="sm">Next</Button>
        </div>
      </div>

      <Footer />
    </div>
  );
}
