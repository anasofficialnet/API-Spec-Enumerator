const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export const SCAN_PRESETS = {
  safe: {
    label: "Safe",
    description: "Non-destructive first pass with dry run enabled.",
  },
  standard: {
    label: "Standard",
    description: "Balanced API testing with safe mutations.",
  },
  aggressive: {
    label: "Aggressive",
    description: "Deeper testing for controlled environments.",
  },
};

export const SCAN_HELP = {
  presetSafe: {
    summary: "Turns on the safest checks and keeps Dry Run on.",
    when: "Use this first when you want a quick look without sending live attack traffic.",
  },
  presetStandard: {
    summary: "Turns on the normal scan set with real requests and safer payloads.",
    when: "Use this when you want useful coverage without the most aggressive probes.",
  },
  presetAggressive: {
    summary: "Turns on deeper payloads and heavier testing modules.",
    when: "Use this only in labs, staging, or targets you are clearly allowed to stress.",
  },
  targetUrl: {
    summary: "This is the only base URL the scanner is allowed to hit.",
    requires: "A full target URL such as https://api.example.com.",
    when: "Use this when you want to replay captured paths against one environment only.",
  },
  rateLimit: {
    summary: "Limits how many requests the scanner sends each second.",
    when: "Lower it for fragile systems or anything close to production.",
  },
  concurrency: {
    summary: "Controls how many requests run at the same time.",
    when: "Keep this low if you want a gentler scan and easier-to-read results.",
  },
  maxRetries: {
    summary: "Retries timeouts, rate limits, and short-lived server errors.",
    when: "Raise this if the target is flaky or rate-limits you often.",
  },
  authHeader: {
    summary: "The header name used for login or API access.",
    requires: "Usually Authorization or a custom API key header.",
    when: "Use this when the API expects auth in a header instead of a cookie.",
  },
  authValue: {
    summary: "The value sent inside the auth header.",
    requires: "A token value such as Bearer ey....",
    when: "Use this for bearer tokens, API keys, or other header-based secrets.",
  },
  cookieString: {
    summary: "Adds cookies to every request the scanner sends.",
    requires: "key=value pairs separated with semicolons.",
    when: "Use this when the API logs users in with session cookies.",
  },
  customHeaders: {
    summary: "Adds extra headers to every request.",
    requires: 'JSON like {"X-Api-Key":"value"}.',
    when: "Use this for tenant headers, API keys, version headers, or feature flags.",
  },
  auth: {
    summary: "Checks whether an endpoint still works after auth is removed.",
    when: "Use this when you want to test missing or weak authentication checks.",
  },
  hidden_params: {
    summary: "Tries extra query parameters that may unlock hidden behavior.",
    when: "Use this when you suspect debug, admin, filter, or undocumented flags exist.",
  },
  cors: {
    summary: "Checks whether browsers from other sites are allowed too much access.",
    when: "Use this for APIs that are called by websites or frontend apps.",
  },
  error_leak: {
    summary: "Looks for stack traces, exception names, and internal error text.",
    when: "This is safe and useful on almost every target.",
  },
  sqli: {
    summary: "Puts SQL test strings into inputs to see whether the API handles them unsafely.",
    when: "Use marker mode broadly. Use aggressive payloads only when you have approval.",
  },
  xss: {
    summary: "Puts browser script test strings into inputs to see whether they come back unsafely.",
    when: "Use this when the API response may be shown in a browser or UI.",
  },
  ssti: {
    summary: "Puts template test strings into inputs to see whether the server tries to render them.",
    when: "Use this when the backend may render user-controlled values in templates.",
  },
  aggressive: {
    summary: "Switches from safe marker values to real exploit-style payloads.",
    when: "Use this only in labs, staging, or clearly approved environments.",
  },
  dryRun: {
    summary: "Builds the full scan plan without sending any requests.",
    when: "Use this first when you want to see case volume safely.",
  },
  enableWafEvasion: {
    summary: "Changes request fingerprints and adds short delays to reduce simple blocking.",
    when: "Use this if the target starts rate-limiting or blocking repeated traffic.",
  },
  enableOast: {
    summary: "Adds callback payloads so the scanner can catch blind bugs like SSRF.",
    requires: "A reachable callback server.",
    when: "Use this only when the target can reach your callback URL from its network.",
  },
  oastCallbackUrl: {
    summary: "The callback URL the target should connect back to.",
    requires: "An externally reachable http:// or https:// URL.",
    when: "Use localhost only when the thing you are scanning is also running locally.",
  },
  enableBola: {
    summary: "Detects whether one logged-in user can access another user's data.",
    requires: "Two valid user credential sets.",
    when: "Use this to test cross-user access control problems in authenticated APIs.",
  },
  bolaUserBToken: {
    summary: "The second user's token for cross-user access checks.",
    requires: "A valid credential for a different user account.",
    when: "Use this together with the main auth settings above.",
  },
  enableStateful: {
    summary: "Builds multi-step workflow tests for skip-step, replay, and order problems.",
    when: "Use this when your capture includes real user workflows, not single requests only.",
  },
  enableRace: {
    summary: "Sends many requests at once to look for race-condition bugs.",
    requires: "A write endpoint and a burst size of at least 2.",
    when: "Best for purchase, redeem, claim, create, update, or delete operations.",
  },
  burstSize: {
    summary: "How many requests to send at the same time in a race test.",
    requires: "At least 2 requests.",
    when: "Start small, then increase if you need a stronger race test.",
  },
  enableMutations: {
    summary: "Changes JSON values, types, nesting, and extra fields to see what breaks.",
    when: "Use this on JSON-heavy APIs that accept POST, PUT, or PATCH bodies.",
  },
  enableGraphql: {
    summary: "Runs GraphQL checks and WebSocket upgrade checks when those endpoints exist.",
    when: "Use this only when GraphQL or WebSocket traffic has actually been found.",
  },
  enableAttackGraph: {
    summary: "Links related endpoints so the scanner can test multi-step paths.",
    when: "Use this when the capture includes realistic flows between endpoints.",
  },
  enableAutoLogin: {
    summary: "Logs in first, then reuses the session or token for the scan.",
    requires: "Login URL, username, and password.",
    when: "Use this when you want the scanner to log in for you before testing authenticated APIs.",
  },
  loginUrl: {
    summary: "The exact endpoint used for the automatic login request.",
    requires: "A reachable login URL.",
    when: "Use the real login API route, not just the site homepage.",
  },
  loginUser: {
    summary: "The username or email sent during automatic login.",
    when: "Use an account that is safe and approved for this scan.",
  },
  loginPass: {
    summary: "The password sent during automatic login.",
    when: "Use an account that is safe and approved for this scan.",
  },
};

function uniqueCategories(categories) {
  return Array.from(new Set(categories));
}

function endpointMethods(selectedEndpoints) {
  return new Set((selectedEndpoints || []).map((endpoint) => endpoint?.method).filter(Boolean));
}

export function parseHostFromUrl(value) {
  if (!value) {
    return null;
  }
  try {
    return new URL(value).hostname || null;
  } catch {
    return null;
  }
}

export function isLocalHost(host) {
  if (!host) {
    return false;
  }
  return host === "localhost" || host === "0.0.0.0" || host === "::1" || host.startsWith("127.");
}

export function getHelpContent(key) {
  return SCAN_HELP[key] || null;
}

export function getDetectedCapabilities(capabilities) {
  return {
    graphqlDetected: Boolean(capabilities?.graphql),
    websocketDetected: Boolean(capabilities?.websocket),
  };
}

export function applyScanPreset(config, preset, context = {}) {
  const { graphqlDetected, websocketDetected } = getDetectedCapabilities(context.capabilities);
  const autoGraphEnabled = graphqlDetected || websocketDetected;

  if (preset === "safe") {
    return {
      ...config,
      categories: ["auth", "hidden_params", "cors", "error_leak"],
      aggressive: false,
      dryRun: true,
      enableBola: false,
      enableStateful: false,
      enableRace: false,
      enableMutations: false,
      enableGraphql: autoGraphEnabled,
      enableAttackGraph: false,
      enableAutoLogin: false,
      enableWafEvasion: false,
      enableOast: false,
    };
  }

  if (preset === "standard") {
    return {
      ...config,
      categories: uniqueCategories(["auth", "hidden_params", "cors", "error_leak", "sqli"]),
      aggressive: false,
      dryRun: false,
      enableBola: false,
      enableStateful: false,
      enableRace: false,
      enableMutations: true,
      enableGraphql: autoGraphEnabled,
      enableAttackGraph: false,
      enableAutoLogin: false,
      enableWafEvasion: false,
      enableOast: false,
    };
  }

  if (preset === "aggressive") {
    return {
      ...config,
      categories: uniqueCategories(["auth", "hidden_params", "cors", "error_leak", "sqli", "xss", "ssti"]),
      aggressive: true,
      dryRun: false,
      enableBola: config.enableBola ?? false,
      enableStateful: true,
      enableRace: true,
      enableMutations: true,
      enableGraphql: autoGraphEnabled,
      enableAttackGraph: config.enableAttackGraph ?? false,
      enableAutoLogin: config.enableAutoLogin ?? false,
      enableWafEvasion: config.enableWafEvasion ?? false,
      enableOast: true,
    };
  }

  return config;
}

export function buildScanValidation(config, context = {}) {
  const blockers = [];
  const warnings = [];
  const selectedEndpoints = context.selectedEndpoints || [];
  const methods = endpointMethods(selectedEndpoints);
  const hasWriteEndpoint = Array.from(methods).some((method) => WRITE_METHODS.has(method));
  const targetHost = parseHostFromUrl(config.targetUrl);
  const callbackHost = parseHostFromUrl(config.oastCallbackUrl || "");
  const callbackMissing = !(config.oastCallbackUrl || "").trim();
  const callbackInvalid = !callbackMissing && !callbackHost;
  const callbackLocalMismatch = Boolean(
    callbackHost && targetHost && isLocalHost(callbackHost) && !isLocalHost(targetHost)
  );
  const bolaReady = Boolean((config.bolaUserBToken || "").trim());
  const autoLoginReady = Boolean(
    (config.loginUrl || "").trim() &&
    (config.loginUser || "").trim() &&
    (config.loginPass || "").trim()
  );
  const { graphqlDetected, websocketDetected } = getDetectedCapabilities(context.capabilities);

  const features = {
    bola: {
      disabled: false,
      message: !bolaReady ? "Needs a second user token to test cross-user access safely." : null,
      tone: !bolaReady ? "warning" : null,
    },
    oast: {
      disabled: false,
      message: null,
      tone: null,
    },
    autoLogin: {
      disabled: !autoLoginReady,
      message: !autoLoginReady ? "Auto Login requires login URL, username, and password." : null,
      tone: !autoLoginReady ? "warning" : null,
    },
    race: {
      disabled: false,
      message: null,
      tone: null,
    },
    graphql: {
      disabled: !graphqlDetected && !websocketDetected,
      message: null,
      tone: "info",
    },
  };

  if (config.enableBola && !bolaReady) {
    const message = "BOLA/IDOR Detection needs a second user token.";
    blockers.push({ id: "bola_token", message });
    features.bola.message = message;
    features.bola.tone = "error";
  }

  if (config.enableOast) {
    if (callbackMissing) {
      const message = "OAST requires a reachable callback server to detect blind vulnerabilities.";
      blockers.push({ id: "oast_missing", message });
      features.oast.message = message;
      features.oast.tone = "error";
    } else if (callbackInvalid) {
      const message = "OAST callback URL must be a valid http:// or https:// URL.";
      blockers.push({ id: "oast_invalid", message });
      features.oast.message = message;
      features.oast.tone = "error";
    } else if (callbackLocalMismatch) {
      const message = "Localhost OAST callbacks only work when the target host is also localhost.";
      blockers.push({ id: "oast_local_mismatch", message });
      features.oast.message = message;
      features.oast.tone = "error";
    }
  }

  if (config.enableAutoLogin && !autoLoginReady) {
    const message = "Auto Login requires login URL, username, and password.";
    blockers.push({ id: "auto_login", message });
    features.autoLogin.message = message;
    features.autoLogin.tone = "error";
  }

  if (config.enableRace) {
    if (!config.burstSize || Number(config.burstSize) < 2) {
      const message = "Race Condition testing requires a burst size of at least 2.";
      blockers.push({ id: "race_burst", message });
      features.race.message = message;
      features.race.tone = "error";
    } else if (!hasWriteEndpoint) {
      const message = "Race conditions are meaningful only on write operations.";
      blockers.push({ id: "race_methods", message });
      features.race.message = message;
      features.race.tone = "error";
    }
  } else if (!hasWriteEndpoint) {
    features.race.message = "Race conditions are meaningful only on write operations.";
    features.race.tone = "warning";
  }

  const missingProtocols = [];
  if (!graphqlDetected) {
    missingProtocols.push("No GraphQL endpoints detected.");
  }
  if (!websocketDetected) {
    missingProtocols.push("No WebSocket upgrade endpoints detected.");
  }
  if (missingProtocols.length > 0) {
    features.graphql.message = missingProtocols.join(" ");
  } else {
    features.graphql.message = "GraphQL and WebSocket traffic were detected, so this module is ready to use.";
  }

  return {
    blockers,
    warnings,
    features,
    hasWriteEndpoint,
    graphqlDetected,
    websocketDetected,
    hasBlockingIssues: blockers.length > 0,
  };
}
