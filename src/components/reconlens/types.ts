export type View = "analyze" | "history" | "about";

export interface AnalysisRecord {
  id: string;
  target: string;
  score: number;
  technologies: string[];
  timestamp: string;
  status: "Completed" | "Warning" | "Failed";
  endpoint: string;
  duration: string;
  inputType: "URL" | "Raw HTTP";
}

export const SAMPLE_HISTORY: AnalysisRecord[] = [
  { id: "a1", target: "https://api.acme.io", score: 82, technologies: ["Cloudflare", "nginx", "Node.js"], timestamp: "2026-06-18 09:42", status: "Completed", endpoint: "REST API", duration: "1.42s", inputType: "URL" },
  { id: "a2", target: "https://dashboard.linear.app", score: 94, technologies: ["Vercel", "Next.js", "React"], timestamp: "2026-06-17 18:11", status: "Completed", endpoint: "Monitoring Dashboard", duration: "0.98s", inputType: "URL" },
  { id: "a3", target: "https://login.example.com", score: 61, technologies: ["nginx", "PHP", "Laravel"], timestamp: "2026-06-17 12:04", status: "Warning", endpoint: "Authentication Portal", duration: "2.10s", inputType: "URL" },
  { id: "a4", target: "https://graphql.stripe.dev", score: 88, technologies: ["Cloudflare", "Go"], timestamp: "2026-06-16 22:33", status: "Completed", endpoint: "GraphQL API", duration: "1.07s", inputType: "Raw HTTP" },
  { id: "a5", target: "https://admin.internal.corp", score: 47, technologies: ["Apache", "PHP"], timestamp: "2026-06-16 14:50", status: "Warning", endpoint: "Admin Interface", duration: "1.83s", inputType: "URL" },
  { id: "a6", target: "https://docs.openai.com", score: 91, technologies: ["Vercel", "React", "MDX"], timestamp: "2026-06-15 10:19", status: "Completed", endpoint: "Documentation Portal", duration: "0.74s", inputType: "URL" },
  { id: "a7", target: "https://api.github.com", score: 96, technologies: ["GitHub", "Ruby"], timestamp: "2026-06-14 08:02", status: "Completed", endpoint: "REST API", duration: "0.62s", inputType: "URL" },
];

export const DEMO_RESULT = {
  target: "https://api.acme.io/v2",
  timestamp: new Date().toLocaleString(),
  duration: "1.42s",
  inputType: "URL" as const,
  score: 82,
  endpoint: "REST API",
  risk: "Moderate",
  technologies: [
    { name: "Cloudflare", category: "CDN" },
    { name: "nginx", category: "Server" },
    { name: "Node.js", category: "Runtime" },
    { name: "Express", category: "Framework" },
    { name: "React", category: "Frontend" },
    { name: "PostgreSQL", category: "Database" },
  ],
  headers: [
    { header: "Strict-Transport-Security", status: "ok", description: "HSTS enabled with long max-age." },
    { header: "Content-Security-Policy", status: "error", description: "No CSP header detected." },
    { header: "X-Frame-Options", status: "ok", description: "Set to SAMEORIGIN." },
    { header: "X-Content-Type-Options", status: "ok", description: "nosniff applied correctly." },
    { header: "Referrer-Policy", status: "warn", description: "Policy is permissive (no-referrer-when-downgrade)." },
    { header: "Server", status: "warn", description: "Server banner exposes nginx/1.25.3." },
    { header: "Permissions-Policy", status: "error", description: "Header missing. Browser feature scope is unrestricted." },
  ],
  recommendations: [
    { title: "Enable Content Security Policy", detail: "Define a strict CSP to mitigate XSS and data injection vectors." },
    { title: "Hide Server Banner", detail: "Remove the Server response header to reduce fingerprinting surface." },
    { title: "Tighten Referrer-Policy", detail: "Use strict-origin-when-cross-origin or stricter." },
    { title: "Add Permissions-Policy", detail: "Restrict access to camera, microphone, geolocation by default." },
    { title: "Review Authentication Configuration", detail: "Confirm tokens are httpOnly, SameSite=Lax or Strict." },
  ],
  summary:
    "The target endpoint is a production REST API fronted by Cloudflare and nginx, returning JSON over HTTPS. Transport security is configured correctly with HSTS and HTTP/2 negotiated successfully. The most material gaps are the absence of a Content-Security-Policy and Permissions-Policy, along with an exposed server banner. None of the observed issues indicate active compromise, but they widen the fingerprinting and client-side injection surface. Addressing the four high-impact recommendations would lift the security score into the 90+ range.",
  raw: {
    request: { method: "GET", url: "https://api.acme.io/v2", protocol: "HTTP/2" },
    response: {
      status: 200,
      headers: {
        "content-type": "application/json; charset=utf-8",
        server: "nginx/1.25.3",
        "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
        "x-frame-options": "SAMEORIGIN",
        "x-content-type-options": "nosniff",
      },
      timing: { dns: 12, tcp: 38, tls: 71, ttfb: 184, total: 1420 },
    },
    fingerprint: { tls: "JA3:e7d705a3286e19ea42f587b344ee6865", http2: true, alpn: ["h2", "http/1.1"] },
  },
};
