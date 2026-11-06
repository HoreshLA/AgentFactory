import { useEffect, useMemo, useState } from "react";
import type { Visibility } from "./decide";
import type { CheckId, VirtualFile } from "./scan";
import { readInstructions, redactContent } from "./scan";
import {
  addApp,
  addSecret,
  decisionFor,
  formatWhen,
  loadState,
  publishApp,
  removeApp,
  removeSecret,
  resetState,
  saveState,
  scanApp,
  secretUse,
  setSetting,
  setVisibility,
  unpublishApp,
  visibilityLabel,
  type AppRecord,
  type ConsoleState,
} from "./store";

type Page = "apps" | "secrets" | "gate" | "controls" | "audit";
type Filter = "all" | "mine" | "shared" | "blocked";

type ReviewedItem = {
  app: AppRecord;
  result: ReturnType<typeof scanApp>;
  decision: ReturnType<typeof decisionFor>;
};

const PAGES: { id: Page; label: string }[] = [
  { id: "gate", label: "שער פרסום" },
  { id: "apps", label: "אפליקציות" },
  { id: "secrets", label: "סודות" },
  { id: "controls", label: "בקרות" },
  { id: "audit", label: "יומן" },
];

const CHECKS: { id: CheckId; n: string; title: string; body: string }[] = [
  {
    id: "secrets",
    n: "01",
    title: "סודות בקבצים",
    body: "עוצר פרסום אם קובץ מכיל מפתח API או אסימון גישה.",
  },
  {
    id: "credentials",
    n: "02",
    title: "קבצי הרשאות",
    body: "עוצר פרסום אם יש מפתח פרטי, מפתח חשבון שירות, או קובץ עם אסימון.",
  },
  {
    id: "env",
    n: "03",
    title: "קבצי .env",
    body: "נשארים מחוץ למה שנשלח. סוד שבתוכם עדיין עוצר את הפרסום.",
  },
  {
    id: "sourcemaps",
    n: "04",
    title: "מפות מקור",
    body: "יורדות מהפרסום כדי שמבקר לא יקרא את קוד המקור.",
  },
];

const FINDING_LABEL = {
  hardcoded_secret: "סוד קשיח",
  credential_file: "קובץ הרשאות",
  malicious: "קוד זדוני",
  exposed_credential: "הרשאה חשופה",
  custom: "הוראה מותאמת",
} as const;

function markWord(status: "pass" | "fail" | "omit"): string {
  if (status === "fail") return "נחסם";
  if (status === "omit") return "מושמט";
  return "עבר";
}

function appStateWord(status: AppRecord["status"]): string {
  if (status === "published") return "מפורסם";
  if (status === "unpublished") return "הוסר";
  return "טיוטה";
}

async function readChosenFiles(list: FileList | null): Promise<VirtualFile[]> {
  if (!list) return [];
  const chosen = [...list].slice(0, 25);
  const files: VirtualFile[] = [];
  for (const file of chosen) {
    if (file.size > 100_000) continue;
    const content = await file.text();
    if (content.includes("\u0000")) continue;
    files.push({ path: file.name, content });
  }
  return files;
}

export function App() {
  const [state, setState] = useState<ConsoleState>(() => loadState());
  const [page, setPage] = useState<Page>("gate");
  const [selectedId, setSelectedId] = useState("warehouse-sync");
  const [filter, setFilter] = useState<Filter>("all");
  const [openFile, setOpenFile] = useState<string | null>(null);
  const [notice, setNotice] = useState("");

  useEffect(() => {
    saveState(state);
  }, [state]);

  const reviewed = useMemo(
    () =>
      state.apps.map((app) => ({
        app,
        result: scanApp(app, state.settings),
        decision: decisionFor(app, state.settings),
      })),
    [state.apps, state.settings],
  );

  const selected = reviewed.find((item) => item.app.id === selectedId) ?? reviewed[0];
  const blockedCount = reviewed.filter((item) => item.decision.hardBlock || item.decision.pending.length > 0).length;

  function openGate(id: string) {
    setSelectedId(id);
    setOpenFile(null);
    setNotice("");
    setPage("gate");
  }

  return (
    <div className="shell">
      <aside className="rail">
        <h1 className="wordmark">
          בקרות
          <small>אבטחה לפני פרסום</small>
        </h1>
        <nav className="nav" aria-label="לוח">
          {PAGES.map((item) => (
            <button
              key={item.id}
              type="button"
              aria-current={page === item.id ? "page" : undefined}
              onClick={() => {
                setNotice("");
                setPage(item.id);
              }}
            >
              <span>{item.label}</span>
              <span className="count">
                {item.id === "apps" ? state.apps.length : null}
                {item.id === "secrets" ? state.secrets.length : null}
                {item.id === "gate" ? blockedCount : null}
                {item.id === "audit" ? state.audit.length : null}
              </span>
            </button>
          ))}
        </nav>
        <div>
          <ol className="locked">
            {CHECKS.map((check) => (
              <li key={check.id}>
                <span>{check.n}</span>
                <strong>{check.title}</strong>
                <span>פעיל</span>
              </li>
            ))}
          </ol>
          <p>ארבע הבדיקות דולקות גם כשהסקירה כבויה.</p>
        </div>
      </aside>
      <main className="stage">
        {page === "gate" && selected ? (
          <Gate
            state={state}
            selectedId={selected.app.id}
            reviewed={reviewed}
            notice={notice}
            openFile={openFile}
            onSelect={(id) => {
              setSelectedId(id);
              setOpenFile(null);
              setNotice("");
            }}
            onOpenFile={setOpenFile}
            onNotice={setNotice}
            onChange={setState}
          />
        ) : null}
        {page === "apps" ? (
          <Apps
            state={state}
            reviewed={reviewed}
            filter={filter}
            onFilter={setFilter}
            onOpen={openGate}
            onChange={setState}
            onNotice={setNotice}
            notice={notice}
          />
        ) : null}
        {page === "secrets" ? <Secrets state={state} onChange={setState} /> : null}
        {page === "controls" ? <Controls state={state} onChange={setState} /> : null}
        {page === "audit" ? (
          <Audit
            state={state}
            onReset={() => {
              setState(resetState());
              setSelectedId("warehouse-sync");
              setNotice("");
            }}
          />
        ) : null}
      </main>
    </div>
  );
}

function Gate({
  state,
  reviewed,
  selectedId,
  notice,
  openFile,
  onSelect,
  onOpenFile,
  onNotice,
  onChange,
}: {
  state: ConsoleState;
  reviewed: ReviewedItem[];
  selectedId: string;
  notice: string;
  openFile: string | null;
  onSelect: (id: string) => void;
  onOpenFile: (path: string | null) => void;
  onNotice: (value: string) => void;
  onChange: (state: ConsoleState) => void;
}) {
  const current = reviewed.find((item) => item.app.id === selectedId) ?? reviewed[0];
  if (!current) return null;
  const { app, result, decision } = current;
  const tone = decision.canPublish ? "ok" : decision.canApprove ? "wait" : "no";
  const shown = openFile ? app.files.find((file) => file.path === openFile) : undefined;

  return (
    <>
      <header className="page-head">
        <h1>שער פרסום</h1>
        <p className="lede">
          לפני כל פרסום רצות ארבע בדיקות. אי אפשר לכבות אותן. מעליהן סקירה שקוראת את הקבצים. הוראה
          שמוסיפים יכולה להוסיף כלל, לא לבטל בדיקה מובנית.
        </p>
      </header>
      <div className="picker" role="group" aria-label="בחירת אפליקציה">
        {reviewed.map((item) => (
          <button
            key={item.app.id}
            type="button"
            aria-pressed={item.app.id === app.id}
            onClick={() => onSelect(item.app.id)}
          >
            <span className="name ltr">{item.app.name}</span>
            <Stamps checks={item.result.checks} />
          </button>
        ))}
      </div>
      <section className="split two">
        <div>
          <div className="checks">
            {CHECKS.map((meta) => {
              const check = result.checks.find((item) => item.id === meta.id);
              const status = check?.status ?? "pass";
              return (
                <article className="check" key={meta.id}>
                  <div className="idx">{meta.n}</div>
                  <div>
                    <h2>{meta.title}</h2>
                    <p>{meta.body}</p>
                    {check && check.evidence.length > 0 ? (
                      <ul className="evidence">
                        {check.evidence.map((item) => (
                          <li key={`${item.path}-${item.detail}`}>
                            <span className="ltr">{item.path}</span>
                            {" · "}
                            {item.detail}
                          </li>
                        ))}
                      </ul>
                    ) : null}
                  </div>
                  <div className={`mark ${status}`}>{markWord(status)}</div>
                </article>
              );
            })}
          </div>
          <section className="findings">
            <h2>סקירה</h2>
            {decision.visibleFindings.length === 0 ? (
              <p className="note">אין ממצאים מעבר לארבע הבדיקות.</p>
            ) : (
              decision.visibleFindings.map(({ finding, enforced }) => (
                <article className="finding" key={finding.id}>
                  <div className={`tag ${!enforced ? "off" : finding.approvable ? "soft" : "hard"}`}>
                    {FINDING_LABEL[finding.code]}
                    {!enforced ? " · לא נאכף" : finding.approvable ? " · אפשר לאשר" : " · אי אפשר לאשר"}
                  </div>
                  <div>
                    <div>{finding.summary}</div>
                    <div className="ltr">{finding.path}</div>
                  </div>
                </article>
              ))
            )}
          </section>
          <section className={`decision ${tone}`} aria-live="polite">
            <div>
              <strong>
                {app.name} · {appStateWord(app.status)} · {visibilityLabel(app.visibility)}
              </strong>
              {decision.downgradeToTeam ? (
                <p className="note">שיתוף פומבי כבוי. פרסום יעביר את האפליקציה לנראות צוות.</p>
              ) : null}
              {!state.settings.apiKeysAllowed ? (
                <p className="note">מפתחות API לא פותחים אפליקציות בצוות הזה.</p>
              ) : null}
              {decision.reasons.length > 0 ? (
                <ul>
                  {decision.reasons.map((reason) => (
                    <li key={reason}>{reason}</li>
                  ))}
                </ul>
              ) : (
                <p className="note">אפשר לפרסם. קבצי סביבה ומפות מקור, אם יש, לא יישלחו.</p>
              )}
              {notice ? <p className="note">{notice}</p> : null}
            </div>
            <div className="decision-actions">
              {decision.canApprove ? (
                <button type="button" className="primary" onClick={() => onChange(publishApp(state, app.id, true))}>
                  אישור חריג ופרסום
                </button>
              ) : (
                <button
                  type="button"
                  className="primary"
                  disabled={!decision.canPublish || app.status === "published"}
                  onClick={() => onChange(publishApp(state, app.id, false))}
                >
                  {app.status === "published" && decision.canPublish
                    ? "מפורסם"
                    : decision.downgradeToTeam
                      ? "פרסום לצוות"
                      : "פרסום"}
                </button>
              )}
              <button
                type="button"
                className="danger"
                disabled={app.status !== "published"}
                onClick={() => onChange(unpublishApp(state, app.id))}
              >
                הסרה מפרסום
              </button>
            </div>
          </section>
        </div>
        <aside className="panel files">
          <h2>קבצים</h2>
          <p className="note">{app.summary}</p>
          <label className="field">
            <span>נראות</span>
            <select
              value={app.visibility}
              onChange={(event) => {
                const visibility = event.target.value as Visibility;
                if (visibility === "public" && !state.settings.publicAppsAllowed) {
                  onNotice("שיתוף פומבי כבוי. אי אפשר לבחור נראות פומבית.");
                  return;
                }
                onNotice("");
                onChange(setVisibility(state, app.id, visibility));
              }}
            >
              <option value="invite">אנשים שהוזמנו</option>
              <option value="team">הצוות</option>
              <option value="public">פומבי</option>
            </select>
          </label>
          <ul>
            {app.files.map((file) => (
              <li key={file.path}>
                <button type="button" className="ghost" onClick={() => onOpenFile(openFile === file.path ? null : file.path)}>
                  <span className="ltr">{file.path}</span>
                </button>
              </li>
            ))}
          </ul>
          {shown ? <pre>{redactContent(shown.content)}</pre> : null}
          <p className="note">התוכן נשאר בדפדפן. ערכים שדומים לסוד מוסתרים בתצוגה.</p>
        </aside>
      </section>
    </>
  );
}

function Apps({
  state,
  reviewed,
  filter,
  notice,
  onFilter,
  onOpen,
  onChange,
  onNotice,
}: {
  state: ConsoleState;
  reviewed: ReviewedItem[];
  filter: Filter;
  notice: string;
  onFilter: (filter: Filter) => void;
  onOpen: (id: string) => void;
  onChange: (state: ConsoleState) => void;
  onNotice: (value: string) => void;
}) {
  const [name, setName] = useState("");
  const [visibility, setVisibility] = useState<Visibility>("team");
  const [files, setFiles] = useState<VirtualFile[]>([]);
  const rows = reviewed.filter((item) => {
    if (filter === "mine") return !item.app.shared;
    if (filter === "shared") return item.app.shared;
    if (filter === "blocked") return item.decision.hardBlock || item.decision.pending.length > 0;
    return true;
  });

  return (
    <>
      <header className="page-head">
        <h1>אפליקציות</h1>
        <p className="lede">מה שיצרתם, ומה ששותף אתכם. מנהל צוות יכול להסיר כל אפליקציה מפרסום.</p>
      </header>
      <div className="filters" role="group" aria-label="סינון">
        {(
          [
            ["all", "הכל"],
            ["mine", "שלי"],
            ["shared", "שותפו איתי"],
            ["blocked", "חסומות"],
          ] as const
        ).map(([id, label]) => (
          <button key={id} type="button" className="chip" aria-pressed={filter === id} onClick={() => onFilter(id)}>
            {label}
          </button>
        ))}
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>שם</th>
              <th>נראות</th>
              <th>מצב</th>
              <th>בדיקות</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((item) => (
              <tr key={item.app.id}>
                <td>
                  <span className="name ltr">{item.app.name}</span>
                  <span className="sub">
                    {item.app.owner}
                    {item.app.shared ? " · שותף איתי" : ""}
                  </span>
                </td>
                <td>{visibilityLabel(item.app.visibility)}</td>
                <td>{appStateWord(item.app.status)}</td>
                <td>
                  <div className="inline">
                    <Stamps checks={item.result.checks} />
                    <span
                      className={`mark ${item.decision.canPublish ? "pass" : item.decision.canApprove ? "omit" : "fail"}`}
                    >
                      {item.decision.canPublish ? "אפשר לפרסם" : item.decision.canApprove ? "ממתין לאישור" : "חסום"}
                    </span>
                  </div>
                </td>
                <td>
                  <button type="button" className="ghost" onClick={() => onOpen(item.app.id)}>
                    שער
                  </button>
                  {item.app.origin === "local" ? (
                    <button type="button" className="ghost" onClick={() => onChange(removeApp(state, item.app.id))}>
                      מחיקה
                    </button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <section className="panel below">
        <h2>הוספת קבצים לבדיקה</h2>
        <p className="note">הקבצים נקראים כאן ולא נשלחים לשרת. אל תעלו סוד אמיתי.</p>
        <div className="form-grid">
          <label className="field">
            <span>שם</span>
            <input value={name} onChange={(event) => setName(event.target.value)} maxLength={48} />
          </label>
          <label className="field">
            <span>נראות</span>
            <select value={visibility} onChange={(event) => setVisibility(event.target.value as Visibility)}>
              <option value="invite">אנשים שהוזמנו</option>
              <option value="team">הצוות</option>
              <option value="public" disabled={!state.settings.publicAppsAllowed}>
                פומבי
              </option>
            </select>
          </label>
          <label className="field">
            <span>קבצים</span>
            <input
              type="file"
              multiple
              onChange={(event) => {
                void readChosenFiles(event.target.files).then((next) => {
                  setFiles(next);
                  onNotice(next.length === 0 ? "לא נקרא קובץ טקסט. עד 25 קבצים, 100KB כל אחד." : `נקראו ${next.length} קבצים.`);
                });
              }}
            />
          </label>
        </div>
        {notice ? <p className="note">{notice}</p> : null}
        <div className="row-actions below">
          <button
            type="button"
            className="primary"
            disabled={!name.trim() || files.length === 0}
            onClick={() => {
              const next = addApp(state, { name: name.trim(), summary: "", visibility, files });
              if (next === state) return;
              setName("");
              setFiles([]);
              onNotice("");
              onChange(next);
              onOpen(next.apps[0].id);
            }}
          >
            שמירה ובדיקה
          </button>
        </div>
      </section>
    </>
  );
}

function Secrets({ state, onChange }: { state: ConsoleState; onChange: (state: ConsoleState) => void }) {
  const [name, setName] = useState("");
  const [scope, setScope] = useState<"team" | "personal">("team");
  const [note, setNote] = useState("");

  return (
    <>
      <header className="page-head">
        <h1>סודות</h1>
        <p className="lede">
          רואים שם ובעלות, לא ערך. את הערך מוסיפים בלוח האפליקציות של Cursor. הסוכן לא רואה אותו.
        </p>
      </header>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>שם</th>
              <th>היקף</th>
              <th>בשימוש</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {state.secrets.map((secret) => {
              const used = secretUse(secret, state.apps);
              return (
                <tr key={secret.id}>
                  <td className="ltr">{secret.name}</td>
                  <td>{secret.scope === "team" ? "צוות" : "אישי"}</td>
                  <td>{used.length > 0 ? used.join(", ") : "אין אפליקציה שמזכירה את השם"}</td>
                  <td>
                    <button type="button" className="ghost" onClick={() => onChange(removeSecret(state, secret.id))}>
                      הסרה
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <form
        className="panel below"
        onSubmit={(event) => {
          event.preventDefault();
          const next = addSecret(state, name, scope);
          if (next === state) {
            setNote("השם צריך אותיות גדולות באנגלית, ספרות וקו תחתון, ולהיות חדש. אין שדה לערך.");
            return;
          }
          setName("");
          setNote("נשמר השם בלבד, בדפדפן הזה.");
          onChange(next);
        }}
      >
        <h2>הוספת שם</h2>
        <div className="form-grid">
          <label className="field">
            <span>שם משתנה</span>
            <input
              value={name}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => setName(event.target.value.toUpperCase())}
              placeholder="WAREHOUSE_URL"
            />
          </label>
          <label className="field">
            <span>היקף</span>
            <select value={scope} onChange={(event) => setScope(event.target.value as "team" | "personal")}>
              <option value="team">צוות</option>
              <option value="personal">אישי</option>
            </select>
          </label>
          <button type="submit" className="primary">
            הוספה
          </button>
        </div>
        {note ? <p className="note">{note}</p> : null}
      </form>
    </>
  );
}

function Controls({ state, onChange }: { state: ConsoleState; onChange: (state: ConsoleState) => void }) {
  const [draft, setDraft] = useState(state.settings.customInstructions);
  useEffect(() => {
    setDraft(state.settings.customInstructions);
  }, [state.settings.customInstructions]);
  const ignored = readInstructions(draft).ignored;
  const toggles: {
    key: "appsEnabled" | "publicAppsAllowed" | "apiKeysAllowed" | "reviewEnabled";
    title: string;
    body: string;
  }[] = [
    {
      key: "appsEnabled",
      title: "אפליקציות לצוות",
      body: "כיבוי עוצר פרסום חדש. מה שכבר מפורסם נשאר עד שמסירים אותו.",
    },
    {
      key: "publicAppsAllowed",
      title: "שיתוף פומבי",
      body: "כיבוי מחזיר אפליקציות פומביות לנראות צוות. בצוותים זה כבוי כברירת מחדל.",
    },
    {
      key: "apiKeysAllowed",
      title: "פתיחה במפתח API",
      body: "מפתח אישי פותח מה שהבעלים שלו יכול לפתוח. מפתח צוות פותח רק אפליקציות צוות שקיבלו גישה. המפתח נשלח בכותרת x-cursor-app-token, לא בכתובת ולא בעוגייה.",
    },
    {
      key: "reviewEnabled",
      title: "סקירת אבטחה",
      body: "קוראת את הקבצים וחוסמת בעיות חמורות. כיבוי לא נוגע בארבע הבדיקות.",
    },
  ];

  return (
    <>
      <header className="page-head">
        <h1>בקרות מנהל</h1>
        <p className="lede">
          אלה הבקרות מהלוח של Cursor Apps. המתגים כאן נשמרים בדפדפן ומדגימים את השער. הם לא משנים את
          הגדרות הצוות ב-Cursor.
        </p>
      </header>
      <div className="stack">
        {toggles.map((item) => {
          const on = state.settings[item.key];
          return (
            <button
              key={item.key}
              type="button"
              className="switch"
              aria-pressed={on}
              onClick={() => onChange(setSetting(state, item.key, !on))}
            >
              <span>
                {item.title}
                <small>{item.body}</small>
              </span>
              <span className={`knob ${on ? "on" : "off"}`} aria-hidden="true">
                <i />
              </span>
            </button>
          );
        })}
      </div>
      <section className="panel below">
        <h2>הוראות לסקירה</h2>
        <p className="note">
          כל שורה היא ביטוי שצריך להיעדר מהקבצים. שורה שמבקשת לבטל בדיקה מובנית נזרקת. ההוראות נכנסות
          לתוקף כשעוזבים את השדה.
        </p>
        <textarea
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onBlur={() => {
            if (draft !== state.settings.customInstructions) {
              onChange(setSetting(state, "customInstructions", draft));
            }
          }}
          maxLength={2000}
        />
        {ignored.length > 0 ? (
          <ul className="evidence">
            {ignored.map((item) => (
              <li key={`${item.line}-${item.reason}`}>
                {item.line} — {item.reason}
              </li>
            ))}
          </ul>
        ) : null}
      </section>
      <section className="panel below">
        <h2>אי אפשר לאשר</h2>
        <p className="note">קוד זדוני, סוד שנכתב בקבצים, וקובץ הרשאות או הרשאה שנחשפת לדפדפן. חריג מותר רק לממצא של הוראה מותאמת.</p>
      </section>
    </>
  );
}

function Audit({ state, onReset }: { state: ConsoleState; onReset: () => void }) {
  return (
    <>
      <header className="page-head">
        <h1>יומן</h1>
        <p className="lede">שינויי בקרה והחלטות פרסום במחשב הזה. השעה לפי ישראל.</p>
      </header>
      <ol className="audit">
        {state.audit.map((entry) => (
          <li key={entry.id}>
            <time className="when" dateTime={entry.at}>
              {formatWhen(entry.at)}
            </time>
            <div>
              <strong>{entry.action}</strong>
              <div className="sub">{entry.detail}</div>
            </div>
          </li>
        ))}
      </ol>
      <button type="button" className="ghost below" onClick={onReset}>
        שחזור נתוני הדוגמה
      </button>
    </>
  );
}

function Stamps({ checks }: { checks: { id: CheckId; status: "pass" | "fail" | "omit" }[] }) {
  return (
    <span className="stamps" aria-label="תוצאת ארבע הבדיקות">
      {CHECKS.map((meta) => {
        const status = checks.find((check) => check.id === meta.id)?.status ?? "pass";
        return (
          <span key={meta.id} className={`stamp ${status}`} title={`${meta.title}: ${markWord(status)}`}>
            {meta.n.slice(1)}
          </span>
        );
      })}
    </span>
  );
}
