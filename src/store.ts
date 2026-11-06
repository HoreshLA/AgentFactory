import { decide, type Visibility } from "./decide";
import { mentionsName, normalizePath, scan, type VirtualFile } from "./scan";
import { SAMPLE_INSTRUCTIONS, SAMPLE_SECRETS, sampleApps, type SampleApp } from "./samples";

export type AppStatus = "draft" | "published" | "unpublished";

export type AppRecord = {
  id: string;
  name: string;
  summary: string;
  visibility: Visibility;
  shared: boolean;
  owner: string;
  status: AppStatus;
  origin: "sample" | "local";
  files: VirtualFile[];
  approvedIds: string[];
};

export type SecretRecord = {
  id: string;
  name: string;
  scope: "team" | "personal";
};

export type Settings = {
  appsEnabled: boolean;
  publicAppsAllowed: boolean;
  apiKeysAllowed: boolean;
  reviewEnabled: boolean;
  customInstructions: string;
};

export type AuditEntry = {
  id: string;
  at: string;
  action: string;
  detail: string;
};

export type ConsoleState = {
  version: 1;
  apps: AppRecord[];
  secrets: SecretRecord[];
  settings: Settings;
  audit: AuditEntry[];
};

const KEY = "app-controls-v1";

function stamp(action: string, detail: string): AuditEntry {
  return {
    id: `a${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`,
    at: new Date().toISOString(),
    action,
    detail,
  };
}

function fromSample(sample: SampleApp): AppRecord {
  return { ...sample, origin: "sample", approvedIds: [] };
}

export function initialState(): ConsoleState {
  const created = new Date().toISOString();
  return {
    version: 1,
    apps: sampleApps().map(fromSample),
    secrets: SAMPLE_SECRETS.map((item) => ({ ...item })),
    settings: {
      appsEnabled: true,
      publicAppsAllowed: true,
      apiKeysAllowed: true,
      reviewEnabled: true,
      customInstructions: SAMPLE_INSTRUCTIONS,
    },
    audit: [
      {
        id: "a-seed",
        at: created,
        action: "נוצר הלוח",
        detail: "נטענו אפליקציות לדוגמה. הבדיקות רצות בדפדפן, על הקבצים האלה.",
      },
    ],
  };
}

function storage(): Storage | null {
  try {
    if (typeof localStorage === "undefined") return null;
    return localStorage;
  } catch {
    return null;
  }
}

export function loadState(): ConsoleState {
  const box = storage();
  if (!box) return initialState();
  try {
    const raw = box.getItem(KEY);
    if (!raw) return initialState();
    const parsed = JSON.parse(raw) as ConsoleState;
    if (parsed.version !== 1 || !Array.isArray(parsed.apps)) return initialState();
    return parsed;
  } catch {
    return initialState();
  }
}

export function saveState(state: ConsoleState) {
  const box = storage();
  if (!box) return;
  box.setItem(KEY, JSON.stringify(state));
}

function withAudit(state: ConsoleState, action: string, detail: string): ConsoleState {
  return { ...state, audit: [stamp(action, detail), ...state.audit].slice(0, 200) };
}

export function scanApp(app: AppRecord, settings: Settings) {
  return scan(app.files, settings.customInstructions);
}

export function decisionFor(app: AppRecord, settings: Settings) {
  return decide({
    appsEnabled: settings.appsEnabled,
    publicAppsAllowed: settings.publicAppsAllowed,
    reviewEnabled: settings.reviewEnabled,
    visibility: app.visibility,
    scan: scanApp(app, settings),
    approvedIds: app.approvedIds,
  });
}

export function setSetting<K extends keyof Settings>(state: ConsoleState, key: K, value: Settings[K]): ConsoleState {
  let next: ConsoleState = { ...state, settings: { ...state.settings, [key]: value } };
  if (key === "publicAppsAllowed" && value === false) {
    const moved = next.apps.filter((app) => app.visibility === "public").map((app) => app.name);
    next = {
      ...next,
      apps: next.apps.map((app) => (app.visibility === "public" ? { ...app, visibility: "team" } : app)),
    };
    if (moved.length > 0) {
      next = withAudit(next, "שיתוף פומבי כבוי", `הנראות חזרה לצוות: ${moved.join(", ")}`);
      return next;
    }
  }
  const labels: Record<keyof Settings, [string, string, string]> = {
    appsEnabled: ["אפליקציות", "פעילות", "כבויות"],
    publicAppsAllowed: ["שיתוף פומבי", "מותר", "כבוי"],
    apiKeysAllowed: ["מפתחות API", "יכולים לפתוח אפליקציות", "לא פותחים אפליקציות"],
    reviewEnabled: ["סקירת אבטחה", "פעילה", "כבויה"],
    customInstructions: ["הוראות סקירה", "עודכנו", "עודכנו"],
  };
  const [name, on, off] = labels[key];
  const detail = key === "customInstructions" ? "הכללים המובנים נשארו." : value ? on : off;
  return withAudit(next, name, detail);
}

export function setVisibility(state: ConsoleState, appId: string, visibility: Visibility): ConsoleState {
  const app = state.apps.find((item) => item.id === appId);
  if (!app) return state;
  if (visibility === "public" && !state.settings.publicAppsAllowed) return state;
  if (app.visibility === visibility) return state;
  return withAudit(
    {
      ...state,
      apps: state.apps.map((item) => (item.id === appId ? { ...item, visibility } : item)),
    },
    "נראות",
    `${app.name} → ${visibilityLabel(visibility)}`,
  );
}

export function visibilityLabel(visibility: Visibility): string {
  if (visibility === "invite") return "אנשים שהוזמנו";
  if (visibility === "team") return "הצוות";
  return "פומבי";
}

export function publishApp(state: ConsoleState, appId: string, approve: boolean): ConsoleState {
  const app = state.apps.find((item) => item.id === appId);
  if (!app) return state;
  const decision = decisionFor(app, state.settings);
  let approvedIds = app.approvedIds;
  if (approve) {
    if (!decision.canApprove) return state;
    approvedIds = [...new Set([...approvedIds, ...decision.pending.map((item) => item.id)])];
  }
  const rescanned = decide({
    appsEnabled: state.settings.appsEnabled,
    publicAppsAllowed: state.settings.publicAppsAllowed,
    reviewEnabled: state.settings.reviewEnabled,
    visibility: app.visibility,
    scan: scanApp(app, state.settings),
    approvedIds,
  });
  if (!rescanned.canPublish) return state;
  const visibility = rescanned.downgradeToTeam ? "team" : app.visibility;
  const detail = [
    approve ? "אושר חריג לפי הוראה מותאמת." : "עבר את הבדיקות.",
    rescanned.downgradeToTeam ? "הנראות ירדה לצוות כי שיתוף פומבי כבוי." : "",
  ]
    .filter(Boolean)
    .join(" ");
  return withAudit(
    {
      ...state,
      apps: state.apps.map((item) =>
        item.id === appId ? { ...item, status: "published", visibility, approvedIds } : item,
      ),
    },
    approve ? "אושר ופורסם" : "פורסם",
    `${app.name}. ${detail}`,
  );
}

export function unpublishApp(state: ConsoleState, appId: string): ConsoleState {
  const app = state.apps.find((item) => item.id === appId);
  if (!app || app.status !== "published") return state;
  return withAudit(
    {
      ...state,
      apps: state.apps.map((item) => (item.id === appId ? { ...item, status: "unpublished" } : item)),
    },
    "הוסר מפרסום",
    app.name,
  );
}

export function addSecret(state: ConsoleState, name: string, scope: SecretRecord["scope"]): ConsoleState {
  const clean = name.trim();
  if (!/^[A-Z][A-Z0-9_]{1,64}$/.test(clean)) return state;
  if (state.secrets.some((item) => item.name === clean)) return state;
  return withAudit(
    {
      ...state,
      secrets: [...state.secrets, { id: `sec-${clean.toLowerCase()}`, name: clean, scope }],
    },
    "נוסף שם של סוד",
    `${clean} (${scope === "team" ? "צוות" : "אישי"}). הערך לא נשמר כאן.`,
  );
}

export function removeSecret(state: ConsoleState, id: string): ConsoleState {
  const secret = state.secrets.find((item) => item.id === id);
  if (!secret) return state;
  return withAudit(
    { ...state, secrets: state.secrets.filter((item) => item.id !== id) },
    "הוסר שם של סוד",
    secret.name,
  );
}

export function addApp(
  state: ConsoleState,
  input: { name: string; summary: string; visibility: Visibility; files: VirtualFile[] },
): ConsoleState {
  const name = input.name.trim().slice(0, 48);
  if (!name || input.files.length === 0) return state;
  const files = input.files.slice(0, 25).map((file) => ({
    path: normalizePath(file.path),
    content: file.content.slice(0, 60_000),
  }));
  const app: AppRecord = {
    id: `local-${Date.now().toString(36)}`,
    name,
    summary: input.summary.trim().slice(0, 160) || "קבצים שנבדקו מהמחשב הזה.",
    visibility: input.visibility === "public" && !state.settings.publicAppsAllowed ? "team" : input.visibility,
    shared: false,
    owner: "שלי",
    status: "draft",
    origin: "local",
    files,
    approvedIds: [],
  };
  return withAudit({ ...state, apps: [app, ...state.apps] }, "נוספה אפליקציה", name);
}

export function removeApp(state: ConsoleState, appId: string): ConsoleState {
  const app = state.apps.find((item) => item.id === appId);
  if (!app || app.origin !== "local") return state;
  return withAudit(
    { ...state, apps: state.apps.filter((item) => item.id !== appId) },
    "נמחקה אפליקציה מקומית",
    app.name,
  );
}

export function secretUse(secret: SecretRecord, apps: AppRecord[]): string[] {
  return apps.filter((app) => mentionsName(app.files, secret.name)).map((app) => app.name);
}

export function resetState(): ConsoleState {
  const box = storage();
  if (box) box.removeItem(KEY);
  return initialState();
}

export function formatWhen(iso: string): string {
  return new Intl.DateTimeFormat("he-IL", {
    timeZone: "Asia/Jerusalem",
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(iso));
}
