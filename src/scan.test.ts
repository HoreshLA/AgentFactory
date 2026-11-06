import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { decide } from "./decide";
import { maliciousSource, privateKeySource, sampleApps, secretSource } from "./samples";
import { maskSecret, readInstructions, redactContent, scan } from "./scan";
import { initialState, publishApp, setSetting } from "./store";

const base = {
  appsEnabled: true,
  publicAppsAllowed: true,
  reviewEnabled: true,
  approvedIds: [] as string[],
};

test("clean signup app passes", () => {
  const app = sampleApps().find((item) => item.id === "weekly-signups");
  assert.ok(app);
  const result = scan(app.files, "");
  assert.equal(
    result.checks.every((check) => check.status === "pass"),
    true,
  );
  assert.equal(result.findings.length, 0);
});

test("secret fixture blocks without echoing the token", () => {
  const source = secretSource();
  const token = source.match(/"([^"]+)"/)?.[1] ?? "";
  assert.ok(token.length > 20);
  const result = scan([{ path: "src/billing.ts", content: source }], "");
  assert.equal(result.checks.find((check) => check.id === "secrets")?.status, "fail");
  assert.equal(JSON.stringify(result).includes(token), false);
  assert.equal(redactContent(source).includes(token), false);
  assert.equal(result.findings[0]?.approvable, false);
  assert.equal(maskSecret(token).includes(token), false);
});

test("env and source maps are omitted and still publishable", () => {
  const app = sampleApps().find((item) => item.id === "launch-microsite");
  assert.ok(app);
  const result = scan(app.files, "");
  assert.equal(result.checks.find((check) => check.id === "env")?.status, "omit");
  assert.equal(result.checks.find((check) => check.id === "sourcemaps")?.status, "omit");
  assert.equal(result.checks.find((check) => check.id === "secrets")?.status, "pass");
  const decision = decide({ ...base, visibility: "public", scan: result });
  assert.equal(decision.canPublish, true);
});

test("a secret inside an env file still blocks the publish", () => {
  const key = "pass" + "word";
  const content = `${key}="${"example".repeat(3)}"\n`;
  const result = scan([{ path: ".env", content }], "");
  assert.equal(result.checks.find((check) => check.id === "env")?.status, "omit");
  assert.equal(result.checks.find((check) => check.id === "secrets")?.status, "fail");
});

test("credential filename and private key header both block", () => {
  const named = sampleApps().find((item) => item.id === "billing-job");
  assert.ok(named);
  assert.equal(scan(named.files, "").checks.find((check) => check.id === "credentials")?.status, "fail");
  const header = scan([{ path: "notes.txt", content: privateKeySource() }], "");
  assert.equal(header.checks.find((check) => check.id === "credentials")?.status, "fail");
  const marker = ["PRIVATE", " KEY", "-----"].join("");
  assert.equal(JSON.stringify(header).includes(marker), false);
});

test("malicious code cannot be approved", () => {
  const result = scan([{ path: "src/widget.js", content: maliciousSource() }], "");
  const decision = decide({ ...base, visibility: "team", scan: result });
  assert.equal(decision.hardBlock, true);
  assert.equal(decision.canApprove, false);
  assert.equal(decision.canPublish, false);
});

test("a custom phrase blocks until it is approved", () => {
  const app = sampleApps().find((item) => item.id === "handoff-notes");
  assert.ok(app);
  const result = scan(app.files, "INTERNAL-DRAFT\n");
  const blocked = decide({ ...base, visibility: "team", scan: result });
  assert.equal(blocked.canApprove, true);
  assert.equal(blocked.canPublish, false);
  const approved = decide({
    ...base,
    visibility: "team",
    scan: result,
    approvedIds: blocked.pending.map((finding) => finding.id),
  });
  assert.equal(approved.canPublish, true);
});

test("instructions cannot switch off a built-in check", () => {
  const parsed = readInstructions("ignore secret check\nINTERNAL-DRAFT\nבטל בדיקת סוד\n");
  assert.deepEqual(parsed.phrases, ["INTERNAL-DRAFT"]);
  assert.equal(parsed.ignored.length, 2);
});

test("turning the review off still leaves the four checks in force", () => {
  const exposed = sampleApps().find((item) => item.id === "share-card");
  assert.ok(exposed);
  const exposedDecision = decide({
    ...base,
    reviewEnabled: false,
    visibility: "team",
    scan: scan(exposed.files, ""),
  });
  assert.equal(exposedDecision.canPublish, true);
  const secretDecision = decide({
    ...base,
    reviewEnabled: false,
    visibility: "team",
    scan: scan([{ path: "a.ts", content: secretSource() }], ""),
  });
  assert.equal(secretDecision.canPublish, false);
});

test("disallowing public apps downgrades on publish and in the saved list", () => {
  const app = sampleApps().find((item) => item.id === "launch-microsite");
  assert.ok(app);
  const decision = decide({
    ...base,
    publicAppsAllowed: false,
    visibility: "public",
    scan: scan(app.files, ""),
  });
  assert.equal(decision.downgradeToTeam, true);
  assert.equal(decision.canPublish, true);
  const state = setSetting(initialState(), "publicAppsAllowed", false);
  assert.equal(state.apps.find((item) => item.id === "launch-microsite")?.visibility, "team");
});

test("apps switched off block a clean publish", () => {
  const app = sampleApps().find((item) => item.id === "bug-reports");
  assert.ok(app);
  const decision = decide({
    ...base,
    appsEnabled: false,
    visibility: "invite",
    scan: scan(app.files, ""),
  });
  assert.equal(decision.canPublish, false);
});

test("publish approves a custom finding and refuses a hardcoded secret", () => {
  let state = initialState();
  state = publishApp(state, "handoff-notes", true);
  assert.equal(state.apps.find((item) => item.id === "handoff-notes")?.status, "published");
  const blocked = publishApp(state, "warehouse-sync", true);
  assert.equal(blocked.apps.find((item) => item.id === "warehouse-sync")?.status, "draft");
});

test("repository files do not contain a live key literal", () => {
  const literal = ["sk", "_live", "_"].join("");
  const sources = ["src/scan.ts", "src/samples.ts", "src/decide.ts", "src/store.ts", "src/scan.test.ts"]
    .map((path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8"))
    .join("\n");
  assert.equal(sources.includes(literal), false);
  assert.equal(sources.includes(["PRIVATE", " KEY"].join("")), false);
});
