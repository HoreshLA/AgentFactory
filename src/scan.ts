export type VirtualFile = { path: string; content: string };

export type Evidence = { path: string; detail: string };

export type CheckId = "secrets" | "credentials" | "env" | "sourcemaps";

export type DeterministicCheck = {
  id: CheckId;
  status: "pass" | "fail" | "omit";
  evidence: Evidence[];
};

export type FindingCode =
  | "hardcoded_secret"
  | "credential_file"
  | "malicious"
  | "exposed_credential"
  | "custom";

export type Finding = {
  id: string;
  code: FindingCode;
  approvable: boolean;
  path: string;
  summary: string;
};

export type IgnoredInstruction = { line: string; reason: string };

export type ScanResult = {
  checks: DeterministicCheck[];
  findings: Finding[];
  ignoredInstructions: IgnoredInstruction[];
};

const CHECK_ORDER: CheckId[] = ["secrets", "credentials", "env", "sourcemaps"];

function joinParts(...parts: string[]): string {
  return parts.join("");
}

function secretPatterns(): { label: string; re: RegExp }[] {
  return [
    { label: "מפתח תשלום", re: new RegExp(joinParts("sk", "_live", "_") + "[A-Za-z0-9]{12,}") },
    { label: "מפתח ספק מודל", re: new RegExp(joinParts("sk", "-") + "[A-Za-z0-9]{24,}") },
    { label: "מפתח ענן", re: new RegExp("AKIA" + "[0-9A-Z]{16}") },
    { label: "אסימון קוד", re: new RegExp(joinParts("ghp", "_") + "[A-Za-z0-9]{20,}") },
    { label: "אסימון צ'אט", re: new RegExp(joinParts("xox", "[baprs]-") + "[A-Za-z0-9-]{10,}") },
    {
      label: "השמה של סוד",
      re: /(api[_-]?key|access[_-]?token|client[_-]?secret|auth[_-]?token|password)\s*[:=]\s*["'][^"'\n]{12,}["']/i,
    },
    { label: "Bearer", re: /bearer\s+[A-Za-z0-9\-._~+/]{24,}/i },
  ];
}

function privateKeyRe(): RegExp {
  const marker = ["PRIVATE", " KEY"].join("");
  return new RegExp(`-----BEGIN [A-Z ]{0,24}${marker}-----`);
}

function maliciousRes(): RegExp[] {
  return [
    new RegExp(joinParts("stratum", "\\+", "tcp"), "i"),
    new RegExp(joinParts("coin", "hive"), "i"),
    new RegExp(joinParts("crypto", "night"), "i"),
    /document\.cookie[\s\S]{0,120}fetch|fetch[\s\S]{0,120}document\.cookie/i,
  ];
}

function exposedRe(): RegExp {
  return /\b(?:import\.meta\.env|process\.env)\.(?:NEXT_PUBLIC|VITE|REACT_APP|PUBLIC)_[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|CREDENTIAL|KEY)\b/;
}

function credentialPath(path: string): boolean {
  return (
    /(^|\/)id_(rsa|ed25519|ecdsa)$/.test(path) ||
    /(^|\/)credentials\.json$/i.test(path) ||
    /(^|\/)service-account(?:[-.].*)?\.json$/i.test(path) ||
    /(^|\/)[^/]+\.(pem|p12|pfx)$/i.test(path) ||
    /(^|\/)[^/]+\.key$/i.test(path)
  );
}

export function normalizePath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.?\//, "").replace(/\/{2,}/g, "/").slice(0, 180);
}

export function isEnvPath(path: string): boolean {
  const base = path.split("/").pop() ?? path;
  if (base === ".env") return true;
  return base.startsWith(".env.") && base !== ".env.example";
}

export function isSourceMap(path: string): boolean {
  return path.endsWith(".map");
}

export function maskSecret(value: string): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= 6) return "••••";
  return `${compact.slice(0, 3)}••••`;
}

export function redactContent(content: string): string {
  let out = content.replace(privateKeyRe(), "•••• private-key ••••");
  for (const pattern of secretPatterns()) {
    const flags = pattern.re.flags.includes("g") ? pattern.re.flags : `${pattern.re.flags}g`;
    out = out.replace(new RegExp(pattern.re.source, flags), (match) => maskSecret(match));
  }
  return out;
}

function findingId(code: string, path: string, summary: string): string {
  const raw = `${code}|${path}|${summary}`;
  let hash = 0;
  for (let i = 0; i < raw.length; i += 1) hash = (Math.imul(hash, 31) + raw.charCodeAt(i)) | 0;
  return `f${(hash >>> 0).toString(16)}`;
}

function isDisableAttempt(line: string): boolean {
  return (
    /(?:disable|ignore|skip|bypass|turn off|allow)\b.{0,48}\b(?:secret|credential|review|check|env|source\s*map)/i.test(
      line,
    ) || /(?:בטל|לבטל|התעלם|דלג|כבה|אפשר).{0,40}(?:סוד|בדיק|סקיר|הרשא)/.test(line)
  );
}

export function readInstructions(customInstructions: string): {
  phrases: string[];
  ignored: IgnoredInstruction[];
} {
  const phrases: string[] = [];
  const ignored: IgnoredInstruction[] = [];
  for (const raw of customInstructions.split(/\n+/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.length < 3) {
      ignored.push({ line, reason: "קצר מדי" });
      continue;
    }
    if (line.length > 80) {
      ignored.push({ line: `${line.slice(0, 40)}…`, reason: "ארוך מדי. כל שורה היא ביטוי לחיפוש, לא פסקה." });
      continue;
    }
    if (isDisableAttempt(line)) {
      ignored.push({ line, reason: "הוראה מותאמת לא יכולה לבטל בדיקה מובנית" });
      continue;
    }
    phrases.push(line);
  }
  return { phrases: phrases.slice(0, 30), ignored };
}

function pushFinding(findings: Finding[], code: FindingCode, path: string, summary: string) {
  const approvable = code === "custom";
  const id = findingId(code, path, summary);
  if (findings.some((item) => item.id === id)) return;
  findings.push({ id, code, approvable, path, summary });
}

export function scan(files: VirtualFile[], customInstructions: string): ScanResult {
  const evidence: Record<CheckId, Evidence[]> = {
    secrets: [],
    credentials: [],
    env: [],
    sourcemaps: [],
  };
  const findings: Finding[] = [];
  const { phrases, ignored } = readInstructions(customInstructions);
  const capped = files.slice(0, 40);

  for (const file of capped) {
    const path = normalizePath(file.path);
    const content = file.content.slice(0, 80_000);

    if (isEnvPath(path)) {
      evidence.env.push({ path, detail: "הקובץ לא נכנס לפרסום" });
    }
    if (isSourceMap(path)) {
      evidence.sourcemaps.push({ path, detail: "מפת המקור לא נכנסת לפרסום" });
    }

    for (const pattern of secretPatterns()) {
      const match = pattern.re.exec(content);
      if (!match) continue;
      evidence.secrets.push({
        path,
        detail: `${pattern.label}: ${maskSecret(match[0])}`,
      });
      pushFinding(findings, "hardcoded_secret", path, `סוד כתוב בקובץ (${pattern.label})`);
    }

    if (privateKeyRe().test(content) || credentialPath(path)) {
      const why = credentialPath(path) ? "שם הקובץ הוא קובץ הרשאות" : "הקובץ מכיל כותרת של מפתח פרטי";
      evidence.credentials.push({ path, detail: why });
      pushFinding(findings, "credential_file", path, why);
    }

    if (exposedRe().test(content)) {
      pushFinding(
        findings,
        "exposed_credential",
        path,
        "שם סודי נקרא לתוך חבילה שנשלחת לדפדפן",
      );
    }

    for (const re of maliciousRes()) {
      if (!re.test(content)) continue;
      pushFinding(findings, "malicious", path, "הקובץ כולל דפוס של קוד זדוני");
      break;
    }

    for (const phrase of phrases) {
      if (!content.toLowerCase().includes(phrase.toLowerCase())) continue;
      pushFinding(findings, "custom", path, `הוראה מותאמת: הקובץ מכיל „${phrase}”`);
    }
  }

  const checks: DeterministicCheck[] = CHECK_ORDER.map((id) => {
    const items = evidence[id].slice(0, 6);
    if (id === "env" || id === "sourcemaps") {
      return { id, status: items.length > 0 ? "omit" : "pass", evidence: items };
    }
    return { id, status: items.length > 0 ? "fail" : "pass", evidence: items };
  });

  return { checks, findings, ignoredInstructions: ignored };
}

export function mentionsName(files: VirtualFile[], name: string): boolean {
  if (!/^[A-Z][A-Z0-9_]{1,64}$/.test(name)) return false;
  const re = new RegExp(`\\b${name}\\b`);
  return files.some((file) => re.test(file.content));
}
