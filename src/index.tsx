import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Sidebar } from "@/components/reconlens/Sidebar";
import { AnalyzeView } from "@/components/reconlens/AnalyzeView";
import { HistoryView } from "@/components/reconlens/HistoryView";
import { AboutView } from "@/components/reconlens/AboutView";
import type { View } from "@/components/reconlens/types";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "ReconLens AI — AI-Powered HTTP Security Intelligence" },
      {
        name: "description",
        content:
          "ReconLens AI analyzes HTTP communication and turns it into structured security intelligence with AI-written explanations and prioritized recommendations.",
      },
      { property: "og:title", content: "ReconLens AI — AI-Powered HTTP Security Intelligence" },
      {
        property: "og:description",
        content:
          "Enterprise-grade HTTP security analysis. Rule-based detections paired with AI explanations for security teams, researchers, and developers.",
      },
    ],
  }),
  component: App,
});

function App() {
  const [view, setView] = useState<View>("analyze");
  const [pendingUrl, setPendingUrl] = useState<string | undefined>(undefined);

  const handleRescan = (url: string) => {
    setPendingUrl(url);
    setView("analyze");
  };

  const handleNavigate = (v: View) => {
    if (v === "analyze") setPendingUrl(undefined);
    setView(v);
  };

  return (
    <div className="min-h-screen bg-background">
      <Sidebar view={view} onChange={handleNavigate} />
      <main className="md:pl-[260px]">
        {view === "analyze" && (
          <AnalyzeView
            key={pendingUrl ?? "fresh"} // remount when rescan target changes
            onNavigate={handleNavigate}
            initialUrl={pendingUrl}
          />
        )}
        {view === "history" && <HistoryView onRescan={handleRescan} />}
        {view === "about" && <AboutView />}
      </main>
    </div>
  );
}
