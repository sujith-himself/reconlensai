import { useEffect, useState } from "react";
import { Activity, History, Info, Moon, Sun, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";
import type { View } from "./types";

const NAV: { id: View; label: string; icon: typeof Activity }[] = [
  { id: "analyze", label: "Analyze", icon: Activity },
  { id: "history", label: "History", icon: History },
  { id: "about", label: "About", icon: Info },
];

export function Sidebar({ view, onChange }: { view: View; onChange: (v: View) => void }) {
  const [dark, setDark] = useState(false);

  useEffect(() => {
    const root = document.documentElement;
    if (dark) root.classList.add("dark");
    else root.classList.remove("dark");
  }, [dark]);

  return (
    <aside className="fixed inset-y-0 left-0 z-20 hidden w-[260px] flex-col border-r border-sidebar-border bg-sidebar md:flex">
      <div className="flex items-center gap-3 px-6 pt-7 pb-6">
        <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-primary text-primary-foreground shadow-sm">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div className="min-w-0">
          <div className="truncate text-[15px] font-semibold tracking-tight text-sidebar-foreground">ReconLens AI</div>
          <div className="truncate text-[11px] uppercase tracking-wider text-muted-foreground">AI Security Intelligence</div>
        </div>
      </div>

      <nav className="flex-1 px-3 pt-2">
        <div className="px-3 pb-2 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Workspace</div>
        <ul className="space-y-1">
          {NAV.map((item) => {
            const active = view === item.id;
            const Icon = item.icon;
            return (
              <li key={item.id}>
                <button
                  onClick={() => onChange(item.id)}
                  className={cn(
                    "group flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                    active
                      ? "bg-sidebar-accent text-primary"
                      : "text-sidebar-foreground/80 hover:bg-sidebar-accent/60 hover:text-sidebar-foreground",
                  )}
                >
                  <Icon className={cn("h-4 w-4", active ? "text-primary" : "text-muted-foreground")} />
                  <span>{item.label}</span>
                  {active && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-primary" />}
                </button>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className="border-t border-sidebar-border p-4">
        <button
          onClick={() => setDark((d) => !d)}
          className="flex w-full items-center justify-between rounded-lg px-3 py-2 text-sm text-sidebar-foreground/80 transition-colors hover:bg-sidebar-accent/60"
        >
          <span className="flex items-center gap-2">
            {dark ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
            {dark ? "Dark" : "Light"} mode
          </span>
          <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">Toggle</span>
        </button>
        <div className="mt-4 px-3 text-[11px] text-muted-foreground">Version 1.0</div>
      </div>
    </aside>
  );
}
