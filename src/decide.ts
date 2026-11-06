import type { Finding, ScanResult } from "./scan";

export type Visibility = "invite" | "team" | "public";

export type Decision = {
  canPublish: boolean;
  canApprove: boolean;
  downgradeToTeam: boolean;
  hardBlock: boolean;
  reasons: string[];
  pending: Finding[];
  visibleFindings: { finding: Finding; enforced: boolean }[];
};

function enforced(code: Finding["code"], reviewEnabled: boolean): boolean {
  if (code === "hardcoded_secret" || code === "credential_file") return true;
  return reviewEnabled;
}

export function decide(input: {
  appsEnabled: boolean;
  publicAppsAllowed: boolean;
  reviewEnabled: boolean;
  visibility: Visibility;
  scan: ScanResult;
  approvedIds: readonly string[];
}): Decision {
  const reasons: string[] = [];
  const approved = new Set(input.approvedIds);
  const visibleFindings = input.scan.findings.map((finding) => ({
    finding,
    enforced: enforced(finding.code, input.reviewEnabled),
  }));

  if (!input.appsEnabled) reasons.push("האפליקציות כבויות. אי אפשר לפרסם עד שמפעילים אותן.");

  for (const check of input.scan.checks) {
    if (check.status !== "fail") continue;
    if (check.id === "secrets") reasons.push("יש סוד כתוב בקבצים. אי אפשר לאשר את זה.");
    if (check.id === "credentials") reasons.push("יש קובץ הרשאות. אי אפשר לאשר את זה.");
  }

  const pending: Finding[] = [];
  let hardBlock = input.scan.checks.some((check) => check.status === "fail");

  for (const item of visibleFindings) {
    if (!item.enforced) continue;
    if (item.finding.code === "hardcoded_secret" || item.finding.code === "credential_file") {
      hardBlock = true;
      continue;
    }
    if (!item.finding.approvable) {
      hardBlock = true;
      if (item.finding.code === "malicious") reasons.push("הסקירה מצאה קוד זדוני. אי אפשר לאשר את זה.");
      if (item.finding.code === "exposed_credential") {
        reasons.push("הרשאה נחשפת לדפדפן. אי אפשר לאשר את זה.");
      }
      continue;
    }
    if (!approved.has(item.finding.id)) pending.push(item.finding);
  }

  if (pending.length > 0) {
    reasons.push("הסקירה חסמה לפי הוראה מותאמת. אפשר לאשר חריג, או לתקן את הקובץ.");
  }

  const downgradeToTeam = input.visibility === "public" && !input.publicAppsAllowed;
  const uniqueReasons = [...new Set(reasons)];

  return {
    canPublish: input.appsEnabled && !hardBlock && pending.length === 0,
    canApprove: input.appsEnabled && !hardBlock && pending.length > 0,
    downgradeToTeam,
    hardBlock,
    reasons: uniqueReasons,
    pending,
    visibleFindings,
  };
}
