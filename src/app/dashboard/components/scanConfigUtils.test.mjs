import test from "node:test";
import assert from "node:assert/strict";

import { applyScanPreset, buildScanValidation, getHelpContent } from "./scanConfigUtils.js";

const baseConfig = {
  targetUrl: "https://api.example.com",
  rateLimit: 2,
  concurrency: 1,
  maxRetries: 2,
  authHeader: "Authorization",
  authValue: "",
  cookieString: "",
  dryRun: false,
  aggressive: false,
  categories: ["auth", "hidden_params"],
  customHeaders: {},
  customCookies: {},
  enableBola: false,
  bolaUserBToken: "",
  enableStateful: false,
  enableRace: false,
  burstSize: 10,
  enableMutations: false,
  enableGraphql: false,
  enableAttackGraph: false,
  enableAutoLogin: false,
  loginUrl: "",
  loginUser: "",
  loginPass: "",
  enableWafEvasion: false,
  enableOast: false,
  oastCallbackUrl: "http://127.0.0.1:8010",
};

test("safe preset forces non-destructive defaults", () => {
  const next = applyScanPreset(baseConfig, "safe", { capabilities: { graphql: false, websocket: false } });

  assert.equal(next.dryRun, true);
  assert.equal(next.aggressive, false);
  assert.equal(next.enableRace, false);
  assert.equal(next.enableOast, false);
  assert.deepEqual(next.categories, ["auth", "hidden_params", "cors", "error_leak"]);
});

test("aggressive preset enables deeper modules and auto-enables graphql when detected", () => {
  const next = applyScanPreset(baseConfig, "aggressive", { capabilities: { graphql: true, websocket: false } });

  assert.equal(next.dryRun, false);
  assert.equal(next.aggressive, true);
  assert.equal(next.enableRace, true);
  assert.equal(next.enableOast, true);
  assert.equal(next.enableStateful, true);
  assert.equal(next.enableGraphql, true);
  assert.ok(next.categories.includes("sqli"));
  assert.ok(next.categories.includes("xss"));
  assert.ok(next.categories.includes("ssti"));
});

test("validation blocks localhost oast callbacks for remote targets", () => {
  const validation = buildScanValidation(
    {
      ...baseConfig,
      enableOast: true,
      oastCallbackUrl: "http://127.0.0.1:8010",
    },
    {
      selectedEndpoints: [{ method: "POST" }],
      capabilities: {},
    },
  );

  assert.equal(validation.hasBlockingIssues, true);
  assert.match(validation.blockers[0].message, /localhost/i);
});

test("validation blocks race testing when only GET endpoints are selected", () => {
  const validation = buildScanValidation(
    {
      ...baseConfig,
      enableRace: true,
      burstSize: 5,
    },
    {
      selectedEndpoints: [{ method: "GET" }],
      capabilities: {},
    },
  );

  assert.equal(validation.hasBlockingIssues, true);
  assert.match(validation.features.race.message, /write operations/i);
});

test("validation keeps auto login disabled until credentials exist", () => {
  const validation = buildScanValidation(baseConfig, {
    selectedEndpoints: [{ method: "POST" }],
    capabilities: {},
  });

  assert.equal(validation.features.autoLogin.disabled, true);
  assert.match(validation.features.autoLogin.message, /login url, username, and password/i);
});

test("tooltip content exists for risky controls", () => {
  const help = getHelpContent("enableRace");

  assert.equal(typeof help.summary, "string");
  assert.ok(help.summary.length > 10);
  assert.equal(typeof help.when, "string");
});
