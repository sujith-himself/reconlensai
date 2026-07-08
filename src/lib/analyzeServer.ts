import { createServerFn } from "@tanstack/react-start";
import { promises as dnsPromises } from "node:dns";
import * as tls from "node:tls";

/* ─── Types ─── */
type HeaderStatus = "ok" | "warn" | "error";
interface HeaderResult {
  header: string;
  status: HeaderStatus;
  description: string;
}

export interface SensitivePath {
  path: string;
  label: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "found" | "protected" | "not-found";
}

export interface CookieResult {
  name: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: string | null;
  issues: string[];
}

export interface ClientRisk {
  type: "source-map" | "mixed-content" | "hardcoded-secret" | "external-script";
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  detail?: string;
}

export interface CommentLeak {
  text: string;
  classification: "critical" | "high" | "medium" | "low";
  reason: string;
}

export interface HiddenField {
  name: string;
  value: string;
  suspicious: boolean;
}

export interface LeakResult {
  comments: CommentLeak[];
  hiddenFields: HiddenField[];
  internalIPs: string[];
  emails: string[];
}

export interface Subdomain {
  name: string;
  firstSeen: string;
  lastSeen: string;
}

export interface TxtRecord {
  value: string;
  type: "spf" | "dmarc" | "verification" | "other";
}

export interface DNSRecords {
  a: string[];
  mx: { exchange: string; priority: number }[];
  txt: TxtRecord[];
  ns: string[];
  aaaa: string[];
  emailSpoofingRisk: "high" | "medium" | "low";
  emailProvider: string | null;
}

export interface WaybackInfo {
  hasArchive: boolean;
  oldestSnapshot: string | null;
  latestSnapshot: string | null;
  totalSnapshots: number | null;
}

export interface SslInfo {
  hasSsl: boolean;
  validTo: string | null;
  issuer: string | null;
  sans: string[];
}

export interface OsintResult {
  subdomains: Subdomain[];
  dns: DNSRecords;
  reverseIP: string[];
  sharedHosting: boolean;
  wayback: WaybackInfo;
  ssl: SslInfo;
}

/* ─── Security header rules ─── */
const SECURITY_HEADERS: {
  key: string;
  display: string;
  points: number;
  check: (v?: string) => { status: HeaderStatus; desc: string };
}[] = [
  {
    key: "strict-transport-security",
    display: "Strict-Transport-Security",
    points: 15,
    check: (v) => {
      if (!v) return { status: "error", desc: "HSTS missing. HTTP downgrade attacks are possible." };
      return { status: "ok", desc: `HSTS enabled${v.includes("includeSubDomains") ? " with subdomain coverage" : ""}.` };
    },
  },
  {
    key: "content-security-policy",
    display: "Content-Security-Policy",
    points: 15,
    check: (v) => {
      if (!v) return { status: "error", desc: "No CSP detected. Client-side injection is unrestricted." };
      return { status: "ok", desc: "Content Security Policy is configured." };
    },
  },
  {
    key: "x-frame-options",
    display: "X-Frame-Options",
    points: 8,
    check: (v) => {
      if (!v) return { status: "warn", desc: "Missing X-Frame-Options. Clickjacking attacks may be possible." };
      return { status: "ok", desc: `Set to ${v}.` };
    },
  },
  {
    key: "x-content-type-options",
    display: "X-Content-Type-Options",
    points: 5,
    check: (v) => {
      if (!v) return { status: "warn", desc: "Missing. MIME-sniffing attacks are possible." };
      return { status: "ok", desc: "nosniff applied correctly." };
    },
  },
  {
    key: "referrer-policy",
    display: "Referrer-Policy",
    points: 5,
    check: (v) => {
      if (!v) return { status: "warn", desc: "Not set. Referrer information may leak to third parties." };
      const strict = ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"];
      const isStrict = strict.some((s) => v.toLowerCase().includes(s));
      return isStrict
        ? { status: "ok", desc: `Referrer-Policy is ${v}.` }
        : { status: "warn", desc: `Policy is permissive (${v}).` };
    },
  },
  {
    key: "permissions-policy",
    display: "Permissions-Policy",
    points: 10,
    check: (v) => {
      if (!v) return { status: "error", desc: "Missing. Browser feature scope is unrestricted." };
      return { status: "ok", desc: "Permissions-Policy is configured." };
    },
  },
];

function runRuleEngine(headers: Record<string, string>): HeaderResult[] {
  const results: HeaderResult[] = SECURITY_HEADERS.map(({ key, display, check }) => {
    const { status, desc } = check(headers[key]);
    return { header: display, status, description: desc };
  });
  const server = headers["server"] ?? "";
  if (/\/\d/.test(server)) {
    results.push({ header: "Server", status: "warn", description: `Server banner exposes ${server}. Version info aids fingerprinting.` });
  } else if (server) {
    results.push({ header: "Server", status: "ok", description: "Server header present but version-clean." });
  }
  return results;
}

function calculateScore(
  headers: HeaderResult[],
  sensitivePaths: SensitivePath[],
  clientRisks: ClientRisk[],
  cookies: CookieResult[],
  leaks?: LeakResult,
  osint?: OsintResult,
): number {
  let score = 100;
  const pointMap: Record<string, number> = {};
  SECURITY_HEADERS.forEach((h) => (pointMap[h.display] = h.points));
  pointMap["Server"] = 5;

  for (const h of headers) {
    if (h.status === "error") score -= pointMap[h.header] ?? 10;
    else if (h.status === "warn") score -= Math.floor((pointMap[h.header] ?? 5) / 2);
  }

  const foundPaths = sensitivePaths.filter((p) => p.status === "found");
  if (foundPaths.some((p) => p.path === "/.git/HEAD")) score -= 25;
  if (foundPaths.some((p) => p.path === "/.env")) score -= 30;

  for (const risk of clientRisks) {
    if (risk.type === "source-map") score -= 10;
    if (risk.type === "hardcoded-secret") score -= 40;
  }

  const missingHttpOnly = cookies.filter((c) => !c.httpOnly).length;
  score -= Math.min(missingHttpOnly * 5, 15);

  // Leak mining score impact
  if (leaks) {
    const hasCriticalComment = leaks.comments.some((c) => c.classification === "critical");
    const highCommentCount = leaks.comments.filter((c) => c.classification === "high").length;
    if (hasCriticalComment) score -= 20;
    if (highCommentCount > 0 || leaks.internalIPs.length > 0) score -= 10;
    if (leaks.emails.length > 3) score -= 5;
  }

  // DNS / OSINT score impact
  if (osint) {
    const hasSPF = osint.dns.txt.some((t) => t.type === "spf");
    const hasDMARC = osint.dns.txt.some((t) => t.type === "dmarc");
    const spfPlusAll = osint.dns.txt.some((t) => t.type === "spf" && t.value.includes("+all"));
    if (!hasSPF) score -= 8;
    if (spfPlusAll) score -= 15;
    if (!hasDMARC) score -= 5;
  }

  return Math.max(0, score);
}

function detectTechnologies(
  headers: Record<string, string>,
  htmlBody: string,
): { name: string; category: string; version?: string }[] {
  const techs: { name: string; category: string; version?: string }[] = [];
  const server = headers["server"]?.toLowerCase() ?? "";
  const powered = headers["x-powered-by"]?.toLowerCase() ?? "";
  const via = headers["via"]?.toLowerCase() ?? "";

  if (headers["cf-ray"] || server.includes("cloudflare") || headers["set-cookie"]?.includes("__cfduid")) {
    techs.push({ name: "Cloudflare", category: "WAF/CDN" });
  }
  if (headers["x-amzn-waf-action"] || (headers["x-amzn-trace-id"]?.includes("Root=") && server.includes("awselb"))) {
    techs.push({ name: "AWS WAF", category: "WAF" });
  }
  if (headers["x-iinfo"] || headers["x-cdn"]?.includes("incapsula") || headers["set-cookie"]?.includes("incap_ses")) {
    techs.push({ name: "Imperva", category: "WAF" });
  }
  if (headers["x-sucuri-id"] || server.includes("sucuri")) {
    techs.push({ name: "Sucuri", category: "WAF" });
  }
  if (headers["x-akamai-request-id"] || server.includes("akamai")) {
    techs.push({ name: "Akamai", category: "WAF/CDN" });
  }

  if (server.includes("nginx")) techs.push({ name: "nginx", category: "Server" });
  if (server.includes("apache")) techs.push({ name: "Apache", category: "Server" });
  if (server.includes("iis") || server.includes("microsoft-iis")) techs.push({ name: "IIS", category: "Server" });
  if (server.includes("caddy")) techs.push({ name: "Caddy", category: "Server" });
  if (server.includes("vercel") || headers["x-vercel-id"]) techs.push({ name: "Vercel", category: "Platform" });
  if (headers["x-amz-request-id"] || headers["x-amz-id-2"]) techs.push({ name: "AWS", category: "Cloud" });
  if (headers["x-github-request-id"]) techs.push({ name: "GitHub", category: "Platform" });
  if (via.includes("varnish")) techs.push({ name: "Varnish", category: "Cache" });
  if (headers["x-fastly-request-id"] && !techs.find(t => t.name === "Fastly")) techs.push({ name: "Fastly", category: "CDN" });
  if (powered.includes("php")) techs.push({ name: "PHP", category: "Language" });
  if (powered.includes("asp.net")) techs.push({ name: "ASP.NET", category: "Framework" });
  if (powered.includes("next.js")) techs.push({ name: "Next.js", category: "Framework" });
  if (powered.includes("express")) {
    techs.push({ name: "Express", category: "Framework" });
    if (!techs.find((t) => t.name === "Node.js")) techs.push({ name: "Node.js", category: "Runtime" });
  }
  if (powered.includes("node") && !powered.includes("express")) techs.push({ name: "Node.js", category: "Runtime" });
  if (powered.includes("ruby") || headers["x-rack-cache"]) techs.push({ name: "Ruby", category: "Language" });
  if (headers["x-wp-total"] || headers["link"]?.includes("wp-json")) techs.push({ name: "WordPress", category: "CMS" });
  if (headers["x-drupal-cache"]) techs.push({ name: "Drupal", category: "CMS" });

  if (htmlBody) {
    const has = (re: RegExp) => re.test(htmlBody);

    if (has(/__reactFiber|data-reactroot/) && !techs.find((t) => t.name === "React")) {
      techs.push({ name: "React", category: "Framework" });
    }
    if (has(/__vue__|data-v-[a-z0-9]+/) && !techs.find((t) => t.name === "Vue.js")) {
      techs.push({ name: "Vue.js", category: "Framework" });
    }
    if (has(/__NEXT_DATA__|_next\/static/) && !techs.find((t) => t.name === "Next.js")) {
      techs.push({ name: "Next.js", category: "Framework" });
    }

    const jqMatch = htmlBody.match(/jquery[.-]([\d.]+)/i);
    if (jqMatch && !techs.find((t) => t.name === "jQuery")) {
      techs.push({ name: "jQuery", category: "Library", version: jqMatch[1] });
    }

    const bsMatch = htmlBody.match(/bootstrap[.-]([\d.]+)/i);
    if (bsMatch && !techs.find((t) => t.name === "Bootstrap")) {
      techs.push({ name: "Bootstrap", category: "CSS Framework", version: bsMatch[1] });
    }

    if (has(/wp-content\/|wp-includes\//) && !techs.find((t) => t.name === "WordPress")) {
      techs.push({ name: "WordPress", category: "CMS" });
    }
    if (has(/csrfmiddlewaretoken/) && !techs.find((t) => t.name === "Django")) {
      techs.push({ name: "Django", category: "Framework" });
    }
    if (has(/gtag\(|ga\('create/) && !techs.find((t) => t.name === "Google Analytics")) {
      techs.push({ name: "Google Analytics", category: "Analytics" });
    }
    if (has(/__webpack_require__/) && !techs.find((t) => t.name === "Webpack")) {
      techs.push({ name: "Webpack", category: "Bundler" });
    }
  }

  return techs;
}

/* ─── Sensitive path probing ─── */
const SENSITIVE_PATHS: { path: string; label: string; severity: SensitivePath["severity"] }[] = [
  { path: "/.git/HEAD", label: "Git repo exposed", severity: "critical" },
  { path: "/.env", label: "Env file exposed", severity: "critical" },
  { path: "/robots.txt", label: "Robots.txt", severity: "info" },
  { path: "/wp-admin/", label: "WordPress admin", severity: "medium" },
  { path: "/phpmyadmin/", label: "phpMyAdmin", severity: "high" },
  { path: "/admin/", label: "Admin panel", severity: "medium" },
  { path: "/swagger.json", label: "Swagger API docs", severity: "medium" },
  { path: "/.DS_Store", label: "macOS metadata", severity: "low" },
];

async function probeSensitivePaths(
  baseUrl: string,
  technologies: { name: string; category: string }[],
): Promise<{ paths: SensitivePath[]; robotsDisallowed: string[] }> {
  const base = baseUrl.replace(/\/$/, "");
  
  // Dynamic Fuzzing Paths based on detected technologies
  const techNames = technologies.map((t) => t.name.toLowerCase());
  const pathsToCheck = [...SENSITIVE_PATHS];

  if (techNames.includes("wordpress")) {
    pathsToCheck.push(
      { path: "/wp-config.php.bak", label: "WP Config Backup", severity: "critical" },
      { path: "/wp-content/debug.log", label: "WP Debug Log", severity: "high" }
    );
  }
  if (techNames.includes("node.js") || techNames.includes("react") || techNames.includes("next.js") || techNames.includes("vue.js")) {
    pathsToCheck.push(
      { path: "/package.json", label: "NPM Package config", severity: "medium" },
      { path: "/.env", label: "Environment variables", severity: "critical" }
    );
  }
  if (techNames.includes("php") || techNames.includes("apache") || techNames.includes("nginx")) {
    pathsToCheck.push(
      { path: "/phpinfo.php", label: "PHP Info page", severity: "high" },
      { path: "/.htaccess", label: "Apache Config", severity: "high" }
    );
  }
  // Generic tech checks
  pathsToCheck.push(
    { path: "/.git/config", label: "Exposed Git config", severity: "critical" },
    { path: "/.aws/credentials", label: "Exposed AWS creds", severity: "critical" }
  );

  const probeOne = async (
    entry: (typeof SENSITIVE_PATHS)[number],
  ): Promise<SensitivePath & { _body?: string }> => {
    const url = `${base}${entry.path}`;
    try {
      // Use redirect: "manual" — any redirect (301/302) counts as not-found.
      // Only 200 = found, 401/403 = protected.
      const needsBody = ["/.git/HEAD", "/.env", "/robots.txt"].includes(entry.path);
      const res = await fetch(url, {
        method: needsBody ? "GET" : "HEAD",
        signal: AbortSignal.timeout(5000),
        redirect: "manual",
      });
      const s = res.status;

      if (s === 401 || s === 403) {
        return { path: entry.path, label: entry.label, severity: entry.severity, status: "protected" };
      }

      if (s !== 200) {
        return { path: entry.path, label: entry.label, severity: entry.severity, status: "not-found" };
      }

      // s === 200 — for special paths, validate the body before marking as found.
      if (needsBody) {
        // Read at most 512 bytes to avoid large downloads.
        const reader = res.body?.getReader();
        let bodyChunk = "";
        if (reader) {
          const { value } = await reader.read();
          reader.cancel();
          bodyChunk = value ? new TextDecoder().decode(value.slice(0, 512)) : "";
        }

        if (entry.path === "/.git/HEAD") {
          // Must contain the standard git HEAD ref line.
          const isReal = /ref:\s*refs\/heads\//i.test(bodyChunk);
          return {
            path: entry.path,
            label: entry.label,
            severity: entry.severity,
            status: isReal ? "found" : "not-found",
          };
        }

        if (entry.path === "/.env") {
          // Must contain at least one common env-file pattern.
          const isReal = /(?:APP_|DB_|SECRET|KEY=|TOKEN=|PASSWORD=)/i.test(bodyChunk);
          return {
            path: entry.path,
            label: entry.label,
            severity: entry.severity,
            status: isReal ? "found" : "not-found",
          };
        }

        if (entry.path === "/robots.txt") {
          // Must start with "User-agent:" (ignoring leading whitespace/BOM).
          const isReal = /^\s*User-agent:/i.test(bodyChunk);
          return {
            path: entry.path,
            label: entry.label,
            severity: entry.severity,
            status: isReal ? "found" : "not-found",
            _body: isReal ? bodyChunk : undefined,
          };
        }
      }

      return { path: entry.path, label: entry.label, severity: entry.severity, status: "found" };
    } catch {
      return { path: entry.path, label: entry.label, severity: entry.severity, status: "not-found" };
    }
  };

  const rawPaths = await Promise.all(pathsToCheck.map(probeOne));
  // Strip the internal _body field before returning.
  const paths: SensitivePath[] = rawPaths.map(({ _body: _b, ...rest }) => rest);

  let robotsDisallowed: string[] = [];
  const robotsRaw = rawPaths.find((p) => p.path === "/robots.txt");
  if (robotsRaw && robotsRaw.status === "found") {
    // Reuse the body already fetched in probeOne if available.
    const bodyText = (robotsRaw as { _body?: string })._body;
    if (bodyText) {
      robotsDisallowed = bodyText
        .split("\n")
        .filter((line) => line.trim().toLowerCase().startsWith("disallow:"))
        .map((line) => line.split(":")[1]?.trim())
        .filter(Boolean) as string[];
    } else {
      try {
        const robotsRes = await fetch(`${base}/robots.txt`, { signal: AbortSignal.timeout(3000) });
        if (robotsRes.ok) {
          const text = await robotsRes.text();
          robotsDisallowed = text
            .split("\n")
            .filter((line) => line.trim().toLowerCase().startsWith("disallow:"))
            .map((line) => line.split(":")[1]?.trim())
            .filter(Boolean) as string[];
        }
      } catch { /* ignore */ }
    }
  }

  return { paths, robotsDisallowed };
}

/* ─── Cookie security parsing ─── */
function parseCookies(headers: Record<string, string>): CookieResult[] {
  const raw = headers["set-cookie"];
  if (!raw) return [];
  const cookieStrings = raw.split(/\n/).filter(Boolean);
  return cookieStrings.map((cookieStr) => {
    const nameValuePart = cookieStr.split(";")[0] ?? "";
    const name = nameValuePart.split("=")[0]?.trim() ?? "unknown";
    const lower = cookieStr.toLowerCase();
    const httpOnly = lower.includes("httponly");
    const secure = lower.includes("secure");
    const sameSiteMatch = lower.match(/samesite=([a-z]+)/);
    const sameSite = sameSiteMatch ? sameSiteMatch[1] : null;
    const issues: string[] = [];
    if (!httpOnly) issues.push("Missing HttpOnly flag — accessible via JavaScript");
    if (!secure) issues.push("Missing Secure flag — transmitted over HTTP");
    if (!sameSite) issues.push("No SameSite attribute — vulnerable to CSRF");
    else if (sameSite === "none" && !secure) issues.push("SameSite=None requires Secure flag");
    return { name, httpOnly, secure, sameSite, issues };
  });
}

/* ─── Client-side risks ─── */
function analyzeClientRisks(htmlBody: string, targetUrl: string): ClientRisk[] {
  const risks: ClientRisk[] = [];
  if (!htmlBody) return risks;
  const isHttps = targetUrl.startsWith("https://");

  if (/\/\/# sourceMappingURL=/i.test(htmlBody)) {
    risks.push({
      type: "source-map",
      severity: "high",
      description: "Source map references detected",
      detail: "//# sourceMappingURL= comments found — original source code may be accessible.",
    });
  }

  if (isHttps && /(?:src|href)\s*=\s*["']http:\/\//i.test(htmlBody)) {
    risks.push({
      type: "mixed-content",
      severity: "medium",
      description: "Mixed content detected",
      detail: "HTTP resources referenced on an HTTPS page — may be blocked by browsers.",
    });
  }

  const scriptBlocks = htmlBody.match(/<script(?:\s[^>]*)?>[\s\S]*?<\/script>/gi) ?? [];
  for (const block of scriptBlocks) {
    const secretMatch = block.match(
      /(?:api[_-]?key|secret|token)\s*[:=]\s*["']([^"']{8,})/i,
    );
    if (secretMatch) {
      const raw = secretMatch[1];
      const redacted = raw.slice(0, 4) + "***";
      risks.push({
        type: "hardcoded-secret",
        severity: "critical",
        description: "Hardcoded secret in inline script",
        detail: `Matched value (redacted): ${redacted}`,
      });
      break;
    }
  }

  const scriptSrcMatches = [...htmlBody.matchAll(/<script[^>]+src\s*=\s*["']([^"']+)["']/gi)];
  const externalDomains = new Set<string>();
  for (const match of scriptSrcMatches) {
    try {
      const src = match[1];
      if (src.startsWith("http://") || src.startsWith("https://")) {
        externalDomains.add(new URL(src).hostname);
      }
    } catch { /* ignore */ }
  }
  if (externalDomains.size > 0) {
    risks.push({
      type: "external-script",
      severity: "low",
      description: `${externalDomains.size} external script domain(s) detected`,
      detail: Array.from(externalDomains).join(", "),
    });
  }

  return risks;
}

function classifyEndpoint(url: string, headers: Record<string, string>): string {
  const u = url.toLowerCase();
  const ct = headers["content-type"]?.toLowerCase() ?? "";
  if (u.includes("/graphql") || ct.includes("application/graphql")) return "GraphQL API";
  if (u.includes("/api/") || u.match(/\/v\d+\//)) return "REST API";
  if (u.includes("login") || u.includes("auth") || u.includes("signin")) return "Authentication Portal";
  if (u.includes("admin") || u.includes("panel") || u.includes("manage")) return "Admin Interface";
  if (u.includes("dashboard")) return "Monitoring Dashboard";
  if (u.includes("docs") || u.includes("documentation")) return "Documentation Portal";
  if (u.startsWith("api.") || url.includes("api.")) return "REST API";
  return "Web Application";
}

function parseRawHttp(raw: string): { headers: Record<string, string>; targetFromHost: string } {
  const headers: Record<string, string> = {};
  const lines = raw.split("\n");
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) break;
    const colonIdx = line.indexOf(":");
    if (colonIdx === -1) continue;
    headers[line.slice(0, colonIdx).toLowerCase().trim()] = line.slice(colonIdx + 1).trim();
  }
  const host = headers["host"] ?? "";
  return { headers, targetFromHost: host ? `https://${host}` : "Raw HTTP Analysis" };
}

function generateRecommendations(headers: HeaderResult[]): { title: string; detail: string }[] {
  const recMap: Record<string, { title: string; detail: string }> = {
    "Content-Security-Policy": { title: "Enable Content Security Policy", detail: "Define a strict CSP to mitigate XSS and data injection attack vectors." },
    "Strict-Transport-Security": { title: "Enable HSTS", detail: "Add Strict-Transport-Security with max-age >= 31536000 and includeSubDomains." },
    "Permissions-Policy": { title: "Add Permissions-Policy", detail: "Restrict access to camera, microphone, geolocation, and payment APIs by default." },
    "X-Frame-Options": { title: "Set X-Frame-Options", detail: "Use SAMEORIGIN or DENY to prevent clickjacking attacks." },
    "Referrer-Policy": { title: "Tighten Referrer-Policy", detail: "Use strict-origin-when-cross-origin or no-referrer to limit referrer leakage." },
    "X-Content-Type-Options": { title: "Add X-Content-Type-Options", detail: "Set to nosniff to prevent MIME-type sniffing attacks." },
    "Server": { title: "Hide Server Banner", detail: "Remove version information from the Server header to reduce fingerprinting." },
  };
  return headers.filter((h) => h.status !== "ok" && recMap[h.header]).map((h) => recMap[h.header]);
}

function buildFallbackSummary(target: string, score: number, risk: string, headers: HeaderResult[]): string {
  const errors = headers.filter((h) => h.status === "error");
  const warns = headers.filter((h) => h.status === "warn");
  let s = `Security analysis of ${target} returned a score of ${score}/100 with ${risk.toLowerCase()} risk. `;
  if (errors.length) s += `Critical gaps: ${errors.map((e) => e.header).join(", ")}. `;
  if (warns.length) s += `Warnings: ${warns.map((w) => w.header).join(", ")}. `;
  s += "Addressing these issues would significantly improve the security posture.";
  return s;
}

async function generateAISummary(params: {
  target: string; score: number; risk: string; endpoint: string;
  technologies: { name: string; category: string }[]; headers: HeaderResult[];
}): Promise<string> {
  const issues = params.headers.filter((h) => h.status !== "ok");
  const messages = [
    {
      role: "system",
      content: "You are a cybersecurity expert. Always complete your full response. Never truncate mid-sentence or mid-list. If you start listing CVEs, finish all of them.",
    },
    {
      role: "user",
      content: `You are a senior penetration tester writing an executive summary for a security assessment report.

Target: ${params.target}
Score: ${params.score}/100
Risk Level: ${params.risk}
Endpoint: ${params.endpoint}
Technologies: ${params.technologies.map((t) => t.name).join(", ")}
Security Issues: ${issues.map((h) => `${h.header} [${h.status}]: ${h.description}`).join(" | ")}

Write a professional executive summary in 4-5 sentences covering:
1. What the target appears to be and its tech stack
2. The most critical security gaps found
3. What these gaps mean for real-world risk
4. Top priority actions to take

Be specific and technical. Plain text only, no markdown, no bullet points, no headers.`,
    },
  ];
  const result = await callAI(messages, 2048);
  return result ?? buildFallbackSummary(params.target, params.score, params.risk, params.headers);
}

/* ─── HTML Comment & Leak Mining ─── */
function mineLeaks(htmlBody: string): LeakResult {
  const empty: LeakResult = { comments: [], hiddenFields: [], internalIPs: [], emails: [] };
  if (!htmlBody) return empty;

  // ── 1. HTML Comments ──
  const comments: CommentLeak[] = [];
  try {
    const commentRegex = /<!--([\s\S]*?)-->/g;
    const frameworkPatterns = [
      /begin google tag manager/i,
      /end google tag manager/i,
      /google tag manager/i,
      /theme name:/i,
      /theme uri:/i,
      /theme version:/i,
      /wp-auto-generated/i,
      /generated by/i,
    ];

    let m: RegExpExecArray | null;
    while ((m = commentRegex.exec(htmlBody)) !== null) {
      const raw = m[1].trim();
      if (raw.length < 10) continue;
      if (frameworkPatterns.some((p) => p.test(raw))) continue;

      let classification: CommentLeak["classification"] = "low";
      let reason = "Unclassified comment passed filter";

      if (/(?:password|secret|key|token|credential|db_|database|passwd|pwd)\s*[:=]/i.test(raw)) {
        classification = "critical";
        reason = "Possible credential or secret assignment detected";
      } else if (/\b(192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.)\d+\.\d+\b/.test(raw)) {
        classification = "high";
        reason = "Private IP address leaked in comment";
      } else if (/\b(staging|dev|test|internal|localhost)\.[a-z0-9.-]+\b/i.test(raw)) {
        classification = "high";
        reason = "Internal hostname or environment URL in comment";
      } else if (/(?:\/var\/www|\/home\/|C:\\)/i.test(raw)) {
        classification = "high";
        reason = "File system path leaked in comment";
      } else if (/TODO|FIXME|HACK/i.test(raw)) {
        classification = "medium";
        reason = "Developer note (TODO/FIXME/HACK) in production HTML";
      } else if (/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(raw)) {
        classification = "medium";
        reason = "Email address found in HTML comment";
      } else if (/v?\d+\.\d+(\.\d+)?/.test(raw)) {
        classification = "medium";
        reason = "Version number exposed in comment";
      } else if (/\/api\/[a-z0-9/_-]+/i.test(raw)) {
        classification = "medium";
        reason = "Internal API endpoint path in comment";
      }

      const text = raw.length > 200 ? raw.slice(0, 200) + "…" : raw;
      comments.push({ text, classification, reason });
    }
  } catch { /* malformed HTML — skip */ }

  // ── 2. Hidden Form Fields ──
  const hiddenFields: HiddenField[] = [];
  try {
    const inputRegex = /<input[^>]+type\s*=\s*["']?hidden["']?[^>]*>/gi;
    const nameRe = /name\s*=\s*["']([^"']*)["']/i;
    const valueRe = /value\s*=\s*["']([^"']*)["']/i;
    const suspiciousNames = /token|csrf|key|id|user|auth|session/i;

    let fm: RegExpExecArray | null;
    while ((fm = inputRegex.exec(htmlBody)) !== null) {
      const tag = fm[0];
      const nameMatch = nameRe.exec(tag);
      const valueMatch = valueRe.exec(tag);
      const name = nameMatch?.[1] ?? "(unnamed)";
      const rawValue = valueMatch?.[1] ?? "";
      const redacted = rawValue.length > 6 ? rawValue.slice(0, 6) + "***" : rawValue;
      const suspicious =
        suspiciousNames.test(name) ||
        (rawValue.length > 10 && /[A-Za-z]/.test(rawValue) && /[0-9]/.test(rawValue));
      hiddenFields.push({ name, value: redacted, suspicious });
    }
  } catch { /* malformed HTML — skip */ }

  // ── 3. Internal IP / Hostname Leaks ──
  const internalIPsSet = new Set<string>();
  try {
    const privateIPRe = /\b(192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.)\d+\.\d+\b/g;
    const localhostRe = /localhost:\d+/g;
    const internalHostRe = /\b(staging|dev|test|internal|local|preprod)\.[a-z0-9.-]+\b/gi;

    for (const re of [privateIPRe, localhostRe, internalHostRe]) {
      let hit: RegExpExecArray | null;
      while ((hit = re.exec(htmlBody)) !== null) internalIPsSet.add(hit[0]);
    }
  } catch { /* malformed HTML — skip */ }

  // ── 4. Email Addresses ──
  const emailsSet = new Set<string>();
  try {
    const falsePositiveDomains = new Set(["example.com", "domain.com", "email.com", "yourdomain.com", "sentry.io"]);

    // Standard email pattern
    const emailRe = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
    let em: RegExpExecArray | null;
    while ((em = emailRe.exec(htmlBody)) !== null) {
      const email = em[0].toLowerCase();
      const domain = email.split("@")[1] ?? "";
      if (!falsePositiveDomains.has(domain)) emailsSet.add(email);
    }

    // mailto: links  (catches encoded/nested ones too)
    const mailtoRe = /mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/gi;
    let mt: RegExpExecArray | null;
    while ((mt = mailtoRe.exec(htmlBody)) !== null) {
      const email = mt[1].toLowerCase();
      const domain = email.split("@")[1] ?? "";
      if (!falsePositiveDomains.has(domain)) emailsSet.add(email);
    }

    // Obfuscated  user [at] domain [dot] com  /  user(at)domain.com
    const obfRe = /([a-zA-Z0-9._%+\-]+)\s*[\[(]\s*at\s*[\])]\s*([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/gi;
    let ob: RegExpExecArray | null;
    while ((ob = obfRe.exec(htmlBody)) !== null) {
      const email = `${ob[1]}@${ob[2]}`.toLowerCase();
      const domain = email.split("@")[1] ?? "";
      if (!falsePositiveDomains.has(domain)) emailsSet.add(email);
    }
  } catch { /* malformed HTML — skip */ }

  return {
    comments,
    hiddenFields,
    internalIPs: Array.from(internalIPsSet),
    emails: Array.from(emailsSet),
  };
}

/* ─── OSINT / Recon+ helpers ─── */

function extractBaseDomain(url: string): string {
  try {
    const parsed = new URL(url.startsWith("http") ? url : `https://${url}`);
    return parsed.hostname;
  } catch {
    return url.replace(/^https?:\/\//, "").split("/")[0] ?? url;
  }
}

async function findSubdomains(domain: string): Promise<Subdomain[]> {
  const now = new Date().toISOString().slice(0, 10);

  // ── Primary: HackerTarget (reliable for server-side fetch) ──
  try {
    const htRes = await fetch(
      `https://api.hackertarget.com/hostsearch/?q=${domain}`,
      { signal: AbortSignal.timeout(12000), headers: { "User-Agent": "ReconLens/1.0" } },
    );
    if (htRes.ok) {
      const text = await htRes.text();
      // HackerTarget returns "API count exceeded" or similar on rate limit
      if (!text.includes("error") && !text.includes("API") && text.trim().length > 0) {
        const seen = new Set<string>();
        const results: Subdomain[] = [];
        for (const line of text.split("\n")) {
          const trimmed = line.split(",")[0]?.trim().toLowerCase() ?? "";
          if (!trimmed || trimmed === domain || seen.has(trimmed)) continue;
          seen.add(trimmed);
          results.push({ name: trimmed, firstSeen: "", lastSeen: now });
        }
        if (results.length > 0)
          return results.sort((a, b) => a.name.localeCompare(b.name)).slice(0, 80);
      }
    }
  } catch { /* fall through to crt.sh */ }

  // ── Fallback: crt.sh with longer timeout + correct headers ──
  try {
    const res = await fetch(
      `https://crt.sh/?q=%.${domain}&output=json`,
      {
        signal: AbortSignal.timeout(15000),
        headers: {
          "Accept": "application/json",
          "User-Agent": "ReconLens/1.0",
        },
      },
    );
    if (!res.ok) return [];
    const json = await res.json() as { name_value: string; not_before: string; not_after: string }[];
    const seen = new Set<string>();
    const results: Subdomain[] = [];
    for (const entry of json) {
      for (const name of entry.name_value.split("\n")) {
        const trimmed = name.trim().toLowerCase();
        // skip wildcards, base domain, and duplicates
        if (trimmed.startsWith("*.") || trimmed === domain || seen.has(trimmed)) continue;
        seen.add(trimmed);
        results.push({
          name: trimmed,
          firstSeen: entry.not_before?.slice(0, 10) ?? "",
          lastSeen: entry.not_after?.slice(0, 10) ?? "",
        });
      }
    }
    return results.sort((a, b) => a.name.localeCompare(b.name)).slice(0, 80);
  } catch {
    return [];
  }
}

function detectEmailProvider(mx: { exchange: string }[]): string | null {
  for (const { exchange } of mx) {
    const e = exchange.toLowerCase();
    if (e.includes("google.com") || e.includes("googlemail.com")) return "Google Workspace";
    if (e.includes("outlook.com") || e.includes("hotmail.com") || e.includes("protection.outlook.com")) return "Microsoft 365";
    if (e.includes("zoho.com")) return "Zoho Mail";
    if (e.includes("amazonaws.com")) return "Amazon SES";
    if (e.includes("mimecast.com")) return "Mimecast";
  }
  return mx.length > 0 ? "Custom/Unknown" : null;
}

async function getDNSRecords(domain: string): Promise<DNSRecords> {
  const empty: DNSRecords = {
    a: [], mx: [], txt: [], ns: [], aaaa: [],
    emailSpoofingRisk: "high", emailProvider: null,
  };
  try {
    const [aRaw, mxRaw, txtRaw, nsRaw, aaaaRaw] = await Promise.allSettled([
      dnsPromises.resolve4(domain),
      dnsPromises.resolveMx(domain),
      dnsPromises.resolveTxt(domain),
      dnsPromises.resolveNs(domain),
      dnsPromises.resolve6(domain),
    ]);

    const a = aRaw.status === "fulfilled" ? aRaw.value : [];
    const mx = mxRaw.status === "fulfilled" ? mxRaw.value : [];
    const txtFlat = txtRaw.status === "fulfilled" ? txtRaw.value.map((t) => t.join("")) : [];
    const ns = nsRaw.status === "fulfilled" ? nsRaw.value : [];
    const aaaa = aaaaRaw.status === "fulfilled" ? aaaaRaw.value : [];

    const txt: TxtRecord[] = txtFlat.map((value) => {
      const lower = value.toLowerCase();
      if (lower.startsWith("v=spf1")) return { value, type: "spf" as const };
      if (lower.startsWith("v=dmarc1") || lower.includes("_dmarc")) return { value, type: "dmarc" as const };
      if (/google-site-verification|microsoft-domainkey|zoho-verification|facebook-domain/i.test(value)) return { value, type: "verification" as const };
      return { value, type: "other" as const };
    });

    const hasSPF = txt.some((t) => t.type === "spf");
    const spfRecord = txt.find((t) => t.type === "spf");
    const spfPlusAll = spfRecord?.value.includes("+all") ?? false;
    const spfMinusAll = spfRecord?.value.includes("-all") ?? false;

    let emailSpoofingRisk: DNSRecords["emailSpoofingRisk"] = "high";
    if (!hasSPF) emailSpoofingRisk = "high";
    else if (spfPlusAll) emailSpoofingRisk = "high";
    else if (spfMinusAll) emailSpoofingRisk = "low";
    else emailSpoofingRisk = "medium";

    return {
      a,
      mx: mx.map((r) => ({ exchange: r.exchange, priority: r.priority })),
      txt,
      ns,
      aaaa,
      emailSpoofingRisk,
      emailProvider: detectEmailProvider(mx),
    };
  } catch {
    return empty;
  }
}

async function getReverseIP(ip: string): Promise<string[]> {
  if (!ip) return [];
  try {
    const res = await fetch(
      `https://api.hackertarget.com/reverseiplookup/?q=${ip}`,
      { signal: AbortSignal.timeout(5000) },
    );
    if (!res.ok) return [];
    const text = await res.text();
    if (text.includes("error") || text.includes("API")) return [];
    return text
      .split("\n")
      .map((d) => d.trim())
      .filter((d) => d && !d.includes(ip))
      .slice(0, 20);
  } catch {
    return [];
  }
}

async function getWaybackInfo(domain: string): Promise<WaybackInfo> {
  const empty: WaybackInfo = { hasArchive: false, oldestSnapshot: null, latestSnapshot: null, totalSnapshots: null };
  try {
    const [availRes, cdxRes] = await Promise.allSettled([
      fetch(`http://archive.org/wayback/available?url=${domain}`, { signal: AbortSignal.timeout(4000) }),
      fetch(`http://web.archive.org/cdx/search/cdx?url=${domain}&output=json&limit=1&fl=timestamp&from=20000101`, { signal: AbortSignal.timeout(4000) }),
    ]);

    let hasArchive = false;
    let latestSnapshot: string | null = null;
    let oldestSnapshot: string | null = null;
    let totalSnapshots: number | null = null;

    if (availRes.status === "fulfilled" && availRes.value.ok) {
      const json = await availRes.value.json() as { archived_snapshots?: { closest?: { available?: boolean; timestamp?: string } } };
      const closest = json.archived_snapshots?.closest;
      if (closest?.available) {
        hasArchive = true;
        const ts = closest.timestamp ?? "";
        latestSnapshot = ts.length >= 8 ? `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}` : ts;
      }
    }

    if (cdxRes.status === "fulfilled" && cdxRes.value.ok) {
      const cdxJson = await cdxRes.value.json() as string[][];
      if (Array.isArray(cdxJson) && cdxJson.length > 1) {
        const firstTs = cdxJson[1]?.[0] ?? "";
        oldestSnapshot = firstTs.length >= 8 ? `${firstTs.slice(0, 4)}-${firstTs.slice(4, 6)}-${firstTs.slice(6, 8)}` : firstTs;
        totalSnapshots = cdxJson.length - 1;
        hasArchive = true;
      }
    }

    return { hasArchive, oldestSnapshot, latestSnapshot, totalSnapshots };
  } catch {
    return empty;
  }
}

async function fetchSSLDetails(domain: string): Promise<SslInfo> {
  const empty: SslInfo = { hasSsl: false, validTo: null, issuer: null, sans: [] };
  return new Promise((resolve) => {
    let resolved = false;
    const finish = (result: SslInfo) => {
      if (!resolved) {
        resolved = true;
        resolve(result);
      }
    };
    try {
      const socket = tls.connect({
        host: domain,
        port: 443,
        servername: domain,
        rejectUnauthorized: false,
      }, () => {
        const cert = socket.getPeerCertificate();
        if (cert && Object.keys(cert).length > 0) {
          const sans = cert.subjectaltname
            ? cert.subjectaltname.split(",").map(s => s.replace("DNS:", "").trim())
            : [];
          finish({
            hasSsl: true,
            validTo: cert.valid_to ?? null,
            issuer: (Array.isArray(cert.issuer?.O) ? cert.issuer?.O[0] : cert.issuer?.O) ?? (Array.isArray(cert.issuer?.CN) ? cert.issuer?.CN[0] : cert.issuer?.CN) ?? null,
            sans,
          });
        } else {
          finish(empty);
        }
        socket.end();
      });
      socket.setTimeout(4000);
      socket.on("timeout", () => { socket.destroy(); finish(empty); });
      socket.on("error", () => finish(empty));
    } catch {
      finish(empty);
    }
  });
}

async function getOsintData(targetUrl: string, isLiveUrl: boolean): Promise<OsintResult> {
  const emptyDns: DNSRecords = { a: [], mx: [], txt: [], ns: [], aaaa: [], emailSpoofingRisk: "high", emailProvider: null };
  const emptyOsint: OsintResult = { subdomains: [], dns: emptyDns, reverseIP: [], sharedHosting: false, wayback: { hasArchive: false, oldestSnapshot: null, latestSnapshot: null, totalSnapshots: null }, ssl: { hasSsl: false, validTo: null, issuer: null, sans: [] } };
  if (!isLiveUrl) return emptyOsint;

  const domain = extractBaseDomain(targetUrl);
  if (!domain) return emptyOsint;

  const [subdomainsResult, dnsResult, waybackResult, sslResult] = await Promise.allSettled([
    findSubdomains(domain),
    getDNSRecords(domain),
    getWaybackInfo(domain),
    fetchSSLDetails(domain)
  ]);

  const subdomains = subdomainsResult.status === "fulfilled" ? subdomainsResult.value : [];
  const dns = dnsResult.status === "fulfilled" ? dnsResult.value : emptyDns;
  const wayback = waybackResult.status === "fulfilled" ? waybackResult.value : emptyOsint.wayback;
  const ssl = sslResult.status === "fulfilled" ? sslResult.value : emptyOsint.ssl;

  let reverseIP: string[] = [];
  const primaryIP = dns.a[0];
  if (primaryIP) {
    try {
      reverseIP = await getReverseIP(primaryIP);
    } catch {
      reverseIP = [];
    }
  }

  const sharedHosting = reverseIP.length > 0;
  
  // Merge SANs into subdomains if they aren't already there
  const seenSubs = new Set(subdomains.map(s => s.name));
  for (const san of ssl.sans) {
    const trimmed = san.replace(/^\*\./, "").toLowerCase();
    if (!seenSubs.has(trimmed) && trimmed !== domain && trimmed.endsWith(domain)) {
      subdomains.push({ name: trimmed, firstSeen: "SSL SAN", lastSeen: "SSL SAN" });
      seenSubs.add(trimmed);
    }
  }

  return { subdomains, dns, reverseIP, sharedHosting, wayback, ssl };
}

/* ─── AI helper: unified caller (Groq-first, Gemini fallback) ─── */

async function callGroqProvider(
  messages: { role: string; content: string }[],
  maxTokens: number,
  key: string,
): Promise<string | null> {
  try {
    const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: { "Authorization": `Bearer ${key}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "qwen/qwen3-32b",
        messages,
        max_tokens: maxTokens,
        temperature: 0.3,
        reasoning_format: "hidden",
        stop: null,
      }),
      signal: AbortSignal.timeout(30000),
    });
    if (!res.ok) return null;
    const data = await res.json() as { choices?: { message?: { content?: string } }[] };
    return data.choices?.[0]?.message?.content?.trim() ?? null;
  } catch {
    return null;
  }
}

async function callGeminiProvider(
  promptOrMessages: string | { role: string; content: string }[],
  maxTokens: number,
  key: string,
): Promise<string | null> {
  try {
    let systemInstruction: string | null = null;
    let contents: { role: string; parts: { text: string }[] }[];

    if (typeof promptOrMessages === "string") {
      contents = [{ role: "user", parts: [{ text: promptOrMessages }] }];
    } else {
      const sysMsg = promptOrMessages.find((m) => m.role === "system");
      if (sysMsg) systemInstruction = sysMsg.content;
      contents = promptOrMessages
        .filter((m) => m.role !== "system")
        .map((m) => ({
          role: m.role === "assistant" ? "model" : "user",
          parts: [{ text: m.content }],
        }));
    }

    const body: Record<string, unknown> = {
      contents,
      generationConfig: { maxOutputTokens: maxTokens, temperature: 0.3 },
    };
    if (systemInstruction) {
      body.system_instruction = { parts: [{ text: systemInstruction }] };
    }

    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${key}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(20000),
      },
    );
    if (!res.ok) return null;
    const data = await res.json() as { candidates?: { content?: { parts?: { text?: string }[] } }[] };
    return data.candidates?.[0]?.content?.parts?.[0]?.text?.trim() ?? null;
  } catch {
    return null;
  }
}

async function callAI(
  promptOrMessages: string | { role: string; content: string }[],
  maxTokens = 512,
): Promise<string | null> {
  const groqKey = process.env.GROQ_API_KEY;
  const geminiKey = process.env.GEMINI_API_KEY;

  const messages =
    typeof promptOrMessages === "string"
      ? [{ role: "user", content: promptOrMessages }]
      : promptOrMessages;

  if (groqKey) return callGroqProvider(messages, maxTokens, groqKey);
  if (geminiKey) return callGeminiProvider(promptOrMessages, maxTokens, geminiKey);
  return null;
}

export const generateHeaderExplanation = createServerFn({ method: "POST" }).handler(
  async ({ data: rawData }) => {
    const { header, target, technologies } = rawData as unknown as { header: string; target: string; technologies: string[] };
    const messages = [
      {
        role: "system",
        content: "You are a cybersecurity expert. Always complete your full response. Never truncate mid-sentence or mid-list. If you start listing CVEs, finish all of them.",
      },
      {
        role: "user",
        content: `You are a senior penetration tester. A security scan of ${target} (tech: ${technologies.join(", ") || "unknown"}) found that the ${header} HTTP security header is missing or misconfigured.

In 2-3 sentences, explain:
1. What specific attack becomes possible without this header on THIS type of target
2. One concrete example of real-world exploitation

Be specific, technical, and direct. Plain text only.`,
      },
    ];
    const result = await callAI(messages, 512);
    return { explanation: result ?? `${header} is missing, which leaves this endpoint vulnerable to related attacks. Implement this header following the recommendation shown above.` };
  },
);

export const triageSubdomains = createServerFn({ method: "POST" }).handler(
  async ({ data: rawData }) => {
    const { subdomains, domain } = rawData as unknown as { subdomains: string[]; domain: string };
    if (subdomains.length === 0) return { flagged: [], reasons: {} };
    const messages = [
      {
        role: "system",
        content: "You are a cybersecurity expert. Always complete your full response. Never truncate mid-sentence or mid-list. If you start listing CVEs, finish all of them.",
      },
      {
        role: "user",
        content: `You are a penetration tester reviewing subdomains of ${domain}.

Subdomains found:
${subdomains.slice(0, 60).join("\n")}

Identify which subdomains are HIGH INTEREST from an attacker's perspective (e.g., dev, staging, admin, internal, api, vpn, mail, test, jenkins, gitlab, jira, confluence, backup).

Respond with ONLY a JSON object in this exact format, no other text:
{"flagged":["sub1.example.com","sub2.example.com"],"reasons":{"sub1.example.com":"staging environment","sub2.example.com":"admin interface"}}`,
      },
    ];
    try {
      const raw = await callAI(messages, 2048);
      if (!raw) return { flagged: [], reasons: {} };
      const jsonMatch = raw.match(/\{[\s\S]*\}/);
      if (!jsonMatch) return { flagged: [], reasons: {} };
      const parsed = JSON.parse(jsonMatch[0]) as { flagged: string[]; reasons: Record<string, string> };
      return { flagged: parsed.flagged ?? [], reasons: parsed.reasons ?? {} };
    } catch {
      return { flagged: [], reasons: {} };
    }
  },
);

export const analyzeCookiesAI = createServerFn({ method: "POST" }).handler(
  async ({ data: rawData }) => {
    const { cookies, endpoint, technologies } = rawData as unknown as {
      cookies: { name: string; httpOnly: boolean; secure: boolean; sameSite: string | null; issues: string[] }[];
      endpoint: string;
      technologies: string[];
    };
    if (cookies.length === 0) return { analysis: null };
    const cookieSummary = cookies
      .map((c) => `${c.name}: httpOnly=${c.httpOnly}, secure=${c.secure}, sameSite=${c.sameSite ?? "none"}, issues=${c.issues.length}`)
      .join("\n");
    const messages = [
      {
        role: "system",
        content: "You are a cybersecurity expert. Always complete your full response. Never truncate mid-sentence or mid-list. If you start listing CVEs, finish all of them.",
      },
      {
        role: "user",
        content: `You are a web security expert. This is a ${endpoint} using ${technologies.join(", ") || "unknown tech"}.

Cookies detected:
${cookieSummary}

In 2-3 sentences, explain the real-world security risk of the cookie configuration issues found. Be specific about what an attacker could do (XSS cookie theft, CSRF, session hijacking). Plain text only.`,
      },
    ];
    const result = await callAI(messages, 2048);
    return { analysis: result };
  },
);

export const generateFullReport = createServerFn({ method: "POST" }).handler(
  async ({ data: rawData }) => {
    const scanData = rawData as unknown as {
      target: string; score: number; risk: string; endpoint: string;
      technologies: { name: string; category: string }[];
      securityHeaders: { header: string; status: string; description: string }[];
      recommendations: { title: string; detail: string }[];
      sensitivePaths?: { path: string; label: string; severity: string; status: string }[];
      cookies?: { name: string; httpOnly: boolean; secure: boolean; sameSite: string | null }[];
      osint?: { subdomains: { name: string }[] };
      summary: string;
    };
    const issues = scanData.securityHeaders.filter((h) => h.status !== "ok");
    const exposedPaths = (scanData.sensitivePaths ?? []).filter((p) => p.status === "found");
    const messages = [
      {
        role: "system",
        content: "You are a cybersecurity expert. Always complete your full response. Never truncate mid-sentence or mid-list. If you start listing CVEs, finish all of them.",
      },
      {
        role: "user",
        content: `You are a senior penetration tester writing a professional security assessment report.

Scan Results for: ${scanData.target}
Security Score: ${scanData.score}/100 (${scanData.risk} Risk)
Endpoint Type: ${scanData.endpoint}
Technologies: ${scanData.technologies.map((t) => t.name).join(", ") || "Unknown"}

Security Issues (${issues.length}):
${issues.map((h) => `- ${h.header} [${h.status}]: ${h.description}`).join("\n")}

Exposed Paths: ${exposedPaths.length > 0 ? exposedPaths.map((p) => p.path).join(", ") : "None"}

Top Recommendations:
${scanData.recommendations.slice(0, 5).map((r, i) => `${i + 1}. ${r.title}: ${r.detail}`).join("\n")}

Write a comprehensive security assessment report in markdown format with these sections:
# Executive Summary
# Risk Assessment
# Technical Findings
# Remediation Roadmap
# Conclusion

Make it professional, technical, and actionable. Use proper markdown formatting.`,
      },
    ];
    const result = await callAI(messages, 2048);
    return { report: result ?? `# Security Assessment Report\n\n**Target:** ${scanData.target}\n**Score:** ${scanData.score}/100\n**Risk:** ${scanData.risk}\n\n## Summary\n\n${scanData.summary}` };
  },
);


export const analyzeVulnerabilities = createServerFn({ method: "POST" }).handler(
  async ({ data: rawData }) => {
    const { technologies, target } = rawData as unknown as { technologies: { name: string; category: string; version?: string }[]; target: string };
    
    if (technologies.length === 0) return { analysis: "No specific technologies detected to check for vulnerabilities." };
    
    const techString = technologies.map(t => `${t.name} ${t.version || "(version unknown)"}`).join(", ");
    
    const messages = [
      {
        role: "system",
        content: "You are a cybersecurity expert. Always complete your full response. Never truncate mid-sentence or mid-list. If you start listing CVEs, finish all of them.",
      },
      {
        role: "user",
        content: `You are an expert penetration tester. A scan of ${target} revealed the following technologies:
${techString}

List ALL CVEs for each technology. Complete every entry fully including Description, Exploitation, and Patch. Do not stop mid-technology.
For each CVE provide:
1. The CVE ID
2. A complete description of the vulnerability
3. Exactly how an attacker would exploit it (include PoC approach if known)
4. The exact patch or mitigation steps

Format as clean Markdown. Be technical and precise. Do not truncate any entry.`,
      },
    ];
    const result = await callAI(messages, 2048);
    return { analysis: result };
  }
);

export const askPentestAssistant = createServerFn({ method: "POST" }).handler(
  async ({ data: rawData }) => {
    const { question, scanSummary, history } = rawData as unknown as { 
      question: string; 
      scanSummary: string;
      history: { role: string; content: string }[]
    };
    
    const systemContent = `You are a cybersecurity expert. Always complete your full response. Never truncate mid-sentence or mid-list. If you start listing CVEs, finish all of them.

You are an expert penetration tester and security consultant. You are assisting a user in understanding and exploiting/remediating a security scan.

Here is the summary of the scan results:
${scanSummary}

Answer the user's questions clearly, technically, and precisely. If they ask for proof-of-concept (PoC) code or specific remediation snippets, provide them in Markdown code blocks. Keep responses concise but highly technical. Never cut off mid-sentence — always complete your response.`;

    const messages: { role: string; content: string }[] = [
      { role: "system", content: systemContent },
      ...history,
      { role: "user", content: question },
    ];
    
    const result = await callAI(messages, 2048);
    return { reply: result ?? "No AI provider configured. Set GROQ_API_KEY or GEMINI_API_KEY in your .env file." };
  }
);

/* ─── Main server function ─── */
export const analyzeTarget = createServerFn({ method: "POST" }).handler(
  async ({ data: rawData }) => {
    const data = rawData as { url?: string; rawHttp?: string } | undefined;
    console.log("SERVER FN CALLED", data);
    const t0 = Date.now();
    let rawHeaders: Record<string, string> = {};
    let targetUrl = (data?.url ?? "").trim();
    if (targetUrl && !targetUrl.startsWith("http")) targetUrl = `https://${targetUrl}`;

    let htmlBody = "";

    if (targetUrl) {
      // Step 1: HEAD for headers
      let headRes: Response | null = null;
      try {
        headRes = await fetch(targetUrl, { method: "HEAD", signal: AbortSignal.timeout(5000), redirect: "follow" });
      } catch {
        try {
          headRes = await fetch(targetUrl, { method: "GET", signal: AbortSignal.timeout(5000) });
        } catch (e) {
          throw new Error(`Could not connect to ${targetUrl}. ${(e as Error).message}`);
        }
      }
      if (headRes) headRes.headers.forEach((v, k) => { rawHeaders[k.toLowerCase()] = v; });

      // Step 2: GET HTML body (max 300KB, 8s timeout) — graceful fallback
      try {
        const bodyRes = await fetch(targetUrl, { method: "GET", signal: AbortSignal.timeout(8000), redirect: "follow" });
        const ct = bodyRes.headers.get("content-type") ?? "";
        if (ct.includes("text/html") || ct.includes("text/plain") || ct === "") {
          const reader = bodyRes.body?.getReader();
          if (reader) {
            const chunks: Uint8Array[] = [];
            let totalBytes = 0;
            const MAX = 300 * 1024;
            while (true) {
              const { done, value } = await reader.read();
              if (done || !value) break;
              totalBytes += value.byteLength;
              chunks.push(value);
              if (totalBytes >= MAX) { await reader.cancel(); break; }
            }
            const cap = Math.min(totalBytes, MAX);
            const combined = new Uint8Array(cap);
            let offset = 0;
            for (const chunk of chunks) {
              const take = Math.min(chunk.byteLength, cap - offset);
              combined.set(chunk.subarray(0, take), offset);
              offset += take;
              if (offset >= cap) break;
            }
            htmlBody = new TextDecoder().decode(combined);
          }
        }
        // Merge headers from GET response
        bodyRes.headers.forEach((v, k) => {
          const key = k.toLowerCase();
          if (key === "set-cookie") {
            rawHeaders[key] = rawHeaders[key] ? `${rawHeaders[key]}\n${v}` : v;
          } else if (!rawHeaders[key]) {
            rawHeaders[key] = v;
          }
        });
      } catch { /* HTML fetch failed — continue without body */ }
    } else if (data?.rawHttp) {
      const parsed = parseRawHttp(data.rawHttp);
      rawHeaders = parsed.headers;
      targetUrl = parsed.targetFromHost;
    } else {
      throw new Error("Provide a URL or paste raw HTTP.");
    }

    // For raw HTTP, attempt passive OSINT using the Host header domain
    const rawHttpHost = data?.rawHttp ? (rawHeaders["host"] ?? "") : "";

    // Run path probing + OSINT in parallel with analysis
    const isLiveUrl = targetUrl.startsWith("http") && !targetUrl.includes("Raw HTTP");
    // For raw HTTP, we still do passive DNS/subdomain using the host
    const osintTarget = isLiveUrl ? targetUrl : rawHttpHost ? `https://${rawHttpHost}` : "";
    const technologies = detectTechnologies(rawHeaders, htmlBody);

    const [sensitivePathData, osint, jsLeaks] = await Promise.all([
      isLiveUrl
        ? probeSensitivePaths(targetUrl, technologies)
        : Promise.resolve({ paths: [] as SensitivePath[], robotsDisallowed: [] as string[] }),
      osintTarget ? getOsintData(osintTarget, true) : Promise.resolve({ subdomains: [], dns: { a: [], mx: [], txt: [], ns: [], aaaa: [], emailSpoofingRisk: "high" as const, emailProvider: null }, reverseIP: [], sharedHosting: false, wayback: { hasArchive: false, oldestSnapshot: null, latestSnapshot: null, totalSnapshots: null }, ssl: { hasSsl: false, validTo: null, issuer: null, sans: [] } }),
      (async () => {
        if (!isLiveUrl) return { comments: [], hiddenFields: [], internalIPs: [], emails: [] } as LeakResult;

        const base = targetUrl.replace(/\/$/, "");
        const baseOrigin = (() => { try { return new URL(base).origin; } catch { return base; } })();

        // ── Crawl same-domain internal pages (up to 8) ──
        const internalPageRe = /href=["'](\/[^"'#?]*)["']/gi;
        const priorityKeywords = /contact|faculty|staff|team|about|people|directory|member|employee|department|profile|faculty/i;
        const crawlUrls = new Set<string>();
        let hm: RegExpExecArray | null;
        while ((hm = internalPageRe.exec(htmlBody)) !== null) {
          const path = hm[1];
          if (path && path !== "/") crawlUrls.add(`${baseOrigin}${path}`);
        }
        // Prioritise contact/people/faculty pages
        const sorted = Array.from(crawlUrls).sort((a, b) => {
          const aP = priorityKeywords.test(a) ? 0 : 1;
          const bP = priorityKeywords.test(b) ? 0 : 1;
          return aP - bP;
        }).slice(0, 8);

        const pageFetches = sorted.map(async (u) => {
          try {
            const res = await fetch(u, { signal: AbortSignal.timeout(4000), headers: { "User-Agent": "ReconLens/1.0" } });
            if (!res.ok) return null;
            const ct = res.headers.get("content-type") ?? "";
            if (!ct.includes("text/html") && !ct.includes("text/plain")) return null;
            const text = await res.text();
            return mineLeaks(text);
          } catch { return null; }
        });

        // ── JS file mining (up to 5 files) ──
        const scriptMatch = htmlBody.match(/<script[^>]+src=["']([^"']+\.js[^"']*)["']/gi);
        const jsUrls = (scriptMatch ?? [])
          .map(s => s.match(/src=["']([^"']+)["']/i)?.[1])
          .filter(Boolean)
          .map(u => u!.startsWith("http") ? u : (u!.startsWith("/") ? `${base}${u}` : `${base}/${u}`))
          .slice(0, 5);

        const jsFetches = jsUrls.map(async (u) => {
          try {
            const res = await fetch(u!, { signal: AbortSignal.timeout(3000) });
            if (!res.ok) return null;
            return mineLeaks(await res.text());
          } catch { return null; }
        });

        const allResults = await Promise.all([...pageFetches, ...jsFetches]);
        const merged: LeakResult = { comments: [], hiddenFields: [], internalIPs: [], emails: [] };
        for (const lr of allResults) {
          if (!lr) continue;
          merged.comments.push(...lr.comments);
          merged.hiddenFields.push(...lr.hiddenFields);
          merged.internalIPs.push(...lr.internalIPs);
          merged.emails.push(...lr.emails);
        }
        return merged;
      })(),
    ]);

    const { paths: sensitivePaths, robotsDisallowed } = sensitivePathData;
    const cookies = parseCookies(rawHeaders);
    const clientRisks = analyzeClientRisks(htmlBody, targetUrl);
    const headers = runRuleEngine(rawHeaders);
    
    const htmlLeaks = mineLeaks(htmlBody);
    const leaks: LeakResult = {
      comments: [...htmlLeaks.comments, ...jsLeaks.comments],
      hiddenFields: [...htmlLeaks.hiddenFields, ...jsLeaks.hiddenFields],
      internalIPs: Array.from(new Set([...htmlLeaks.internalIPs, ...jsLeaks.internalIPs])),
      emails: Array.from(new Set([...htmlLeaks.emails, ...jsLeaks.emails]))
    };
    const score = calculateScore(headers, sensitivePaths, clientRisks, cookies, leaks, osint);
    const endpoint = classifyEndpoint(targetUrl, rawHeaders);
    const risk = score >= 85 ? "Low" : score >= 65 ? "Moderate" : score >= 40 ? "High" : "Critical";
    const recommendations = generateRecommendations(headers);
    const summary = await generateAISummary({ target: targetUrl, score, risk, endpoint, technologies, headers });
    const duration = `${((Date.now() - t0) / 1000).toFixed(2)}s`;

    return {
      target: targetUrl,
      timestamp: new Date().toLocaleString(),
      duration,
      inputType: (data?.url ? "URL" : "Raw HTTP") as "URL" | "Raw HTTP",
      score,
      endpoint,
      risk,
      technologies,
      securityHeaders: headers,
      recommendations,
      summary,
      sensitivePaths,
      cookies,
      clientRisks,
      robotsDisallowed,
      leaks,
      osint,
      raw: { request: { method: "HEAD", url: targetUrl, protocol: "HTTP/2" }, response: { rawHeaders: rawHeaders }, fingerprint: {} },
    };
  },
);

export type AnalyzeResult = Awaited<ReturnType<typeof analyzeTarget>>;
