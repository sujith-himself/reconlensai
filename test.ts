import { analyzeTarget } from "./src/lib/analyzeServer";

async function run() {
  console.log("Starting analysis...");
  try {
    const result = await analyzeTarget({ data: { url: "https://kahedu.edu.in" } as any });
    console.log("Analysis returned successfully. Score:", result.score);
  } catch (e) {
    console.error("Analysis threw error:", e);
  }
  process.exit(0);
}
run();
