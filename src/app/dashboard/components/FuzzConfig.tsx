"use client";

import React from "react";
import Icon from "@/components/ui/AppIcon";
import HelpTooltip from "./HelpTooltip";
import { getHelpContent, SCAN_PRESETS } from "./scanConfigUtils";

type ScanPreset = "safe" | "standard" | "aggressive";
type ValidationTone = string | null;

interface ValidationMessage {
  id: string;
  message: string;
}

interface FeatureValidation {
  disabled: boolean;
  message: string | null;
  tone: ValidationTone;
}

interface FuzzConfigValidation {
  blockers: ValidationMessage[];
  warnings: ValidationMessage[];
  features: {
    bola: FeatureValidation;
    oast: FeatureValidation;
    autoLogin: FeatureValidation;
    race: FeatureValidation;
    graphql: FeatureValidation;
  };
  hasBlockingIssues: boolean;
}

interface FuzzConfigProps {
  config: FuzzSettings;
  setConfig: React.Dispatch<React.SetStateAction<FuzzSettings>>;
  selectedCount: number;
  totalCases: number;
  preset: ScanPreset;
  onApplyPreset: (preset: ScanPreset) => void;
  validation: FuzzConfigValidation;
  onStart: () => void;
  isRunning: boolean;
}

export interface FuzzSettings {
  targetUrl: string;
  rateLimit: number;
  concurrency: number;
  maxRetries?: number;
  authHeader: string;
  authValue: string;
  cookieString: string;
  dryRun: boolean;
  aggressive: boolean;
  categories: string[];
  customHeaders?: Record<string, string>;
  customCookies?: Record<string, string>;
  enableBola?: boolean;
  bolaUserBToken?: string;
  enableStateful?: boolean;
  enableRace?: boolean;
  burstSize?: number;
  enableMutations?: boolean;
  enableGraphql?: boolean;
  enableAttackGraph?: boolean;
  enableAutoLogin?: boolean;
  loginUrl?: string;
  loginUser?: string;
  loginPass?: string;
  enableWafEvasion?: boolean;
  enableOast?: boolean;
  oastCallbackUrl?: string;
  enableParamDiscovery?: boolean;
}

const FUZZ_CATEGORIES = [
  { id: "auth", label: "Auth Checks", color: "#FF8C42" },
  { id: "hidden_params", label: "Hidden Params", color: "#4FC3F7" },
  { id: "cors", label: "CORS", color: "#6366F1" },
  { id: "error_leak", label: "Verbose Errors", color: "#FFD166" },
  { id: "sqli", label: "SQLi Payloads", color: "#FF4F4F" },
  { id: "xss", label: "XSS Payloads", color: "#A78BFA" },
  { id: "ssti", label: "SSTI Payloads", color: "#7DD3FC" },
];

const PRESET_ORDER: ScanPreset[] = ["safe", "standard", "aggressive"];

function HelpTip({ helpKey }: { helpKey: string }) {
  const help = getHelpContent(helpKey);
  if (!help) {
    return null;
  }

  return (
    <HelpTooltip summary={help.summary} requires={help.requires} when={help.when} />
  );
}

function FieldLabel({ label, helpKey }: { label: string; helpKey: string }) {
  return (
    <div className="mb-1.5 flex items-center gap-2">
      <label className="font-mono text-[10px] uppercase tracking-widest text-[#94A3B8]">
        {label}
      </label>
      <HelpTip helpKey={helpKey} />
    </div>
  );
}

function InlineNotice({ tone, children }: { tone: ValidationTone; children: React.ReactNode }) {
  if (!tone) {
    return null;
  }

  const styles = {
    error: "border-[rgba(255,79,79,0.24)] bg-[rgba(127,29,29,0.18)] text-[#FF7A7A]",
    warning: "border-[rgba(245,158,11,0.24)] bg-[rgba(120,53,15,0.18)] text-[#FCD34D]",
    info: "border-[rgba(99,102,241,0.2)] bg-[rgba(30,41,59,0.35)] text-[#A5B4FC]",
  } as const;
  const styleClass = tone && tone in styles ? styles[tone as keyof typeof styles] : styles.info;

  return (
    <div className={`mt-2 rounded border px-3 py-2 font-mono text-[10px] leading-4 ${styleClass}`}>
      {children}
    </div>
  );
}

interface ToggleSwitchProps {
  enabled?: boolean;
  disabled?: boolean;
  onClick: () => void;
  activeClassName: string;
}

function ToggleSwitch({ enabled, disabled, onClick, activeClassName }: ToggleSwitchProps) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => {
        if (!disabled) {
          onClick();
        }
      }}
      className={`relative h-5 w-10 rounded-full transition-all duration-300 ${
        disabled
          ? "cursor-not-allowed opacity-40"
          : enabled
            ? activeClassName
            : "bg-[rgba(99,102,241,0.15)]"
      }`}
    >
      <span
        className="absolute top-0.5 h-4 w-4 rounded-full bg-[#030509] transition-all duration-300"
        style={{ left: enabled ? "22px" : "2px" }}
      />
    </button>
  );
}

interface FeatureToggleRowProps {
  label: string;
  helpKey: string;
  description: string;
  enabled?: boolean;
  disabled?: boolean;
  forceOpen?: boolean;
  onToggle: () => void;
  activeClassName: string;
  detailBorderClassName?: string;
  message?: string | null;
  messageTone?: ValidationTone;
  children?: React.ReactNode;
}

function FeatureToggleRow({
  label,
  helpKey,
  description,
  enabled,
  disabled,
  forceOpen,
  onToggle,
  activeClassName,
  detailBorderClassName = "border-[rgba(167,139,250,0.2)]",
  message,
  messageTone = null,
  children,
}: FeatureToggleRowProps) {
  const showDetails = Boolean(children) && (Boolean(enabled) || Boolean(forceOpen));

  return (
    <div className="py-2">
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1 pr-2">
          <div className="flex items-center gap-2">
            <p className="font-mono text-xs leading-5 text-[#F8FAFC]">{label}</p>
            <HelpTip helpKey={helpKey} />
          </div>
          <p className="font-mono text-[10px] leading-4 text-[#475569]">{description}</p>
          {message ? <InlineNotice tone={messageTone}>{message}</InlineNotice> : null}
        </div>
        <div className="shrink-0 self-center">
          <ToggleSwitch enabled={enabled} disabled={disabled} onClick={onToggle} activeClassName={activeClassName} />
        </div>
      </div>
      {showDetails ? (
        <div className={`mt-3 rounded-lg border ${detailBorderClassName} bg-[rgba(2,6,23,0.45)] p-3`}>
          {children}
        </div>
      ) : null}
    </div>
  );
}

export default function FuzzConfig({
  config,
  setConfig,
  selectedCount,
  totalCases,
  preset,
  onApplyPreset,
  validation,
  onStart,
  isRunning,
}: FuzzConfigProps) {
  const [customHeadersText, setCustomHeadersText] = React.useState("");
  const [customHeadersError, setCustomHeadersError] = React.useState<string | null>(null);

  React.useEffect(() => {
    const serialized = config.customHeaders && Object.keys(config.customHeaders).length > 0
      ? JSON.stringify(config.customHeaders, null, 2)
      : "";
    setCustomHeadersText(serialized);
  }, [config.customHeaders]);

  const toggleCategory = (id: string) => {
    setConfig((prev) => ({
      ...prev,
      categories: prev.categories.includes(id)
        ? prev.categories.filter((category) => category !== id)
        : [...prev.categories, id],
    }));
  };

  const updateCustomHeaders = (value: string) => {
    setCustomHeadersText(value);
    try {
      const parsed = value.trim() ? JSON.parse(value) : {};
      setCustomHeadersError(null);
      setConfig((prev) => ({ ...prev, customHeaders: parsed }));
    } catch {
      setCustomHeadersError("Custom Headers must be valid JSON before they are applied.");
    }
  };

  const startDisabled = selectedCount === 0 || isRunning || validation.hasBlockingIssues;
  const autoLoginToggleDisabled = !config.enableAutoLogin && validation.features.autoLogin.disabled;
  const autoLoginDetailsOpen = Boolean(
    config.enableAutoLogin ||
    autoLoginToggleDisabled ||
    config.loginUrl ||
    config.loginUser ||
    config.loginPass
  );
  const graphToggleDisabled = !config.enableGraphql && validation.features.graphql.disabled;

  return (
    <div className="terminal-window overflow-visible">
      <div className="terminal-header">
        <div className="terminal-dot" style={{ background: "#FF5F56" }} />
        <div className="terminal-dot" style={{ background: "#FFBD2E" }} />
        <div className="terminal-dot" style={{ background: "#27C93F" }} />
        <span className="ml-3 font-mono text-[10px] uppercase tracking-widest text-[#475569]">
          ADVANCED_CONFIG
        </span>
      </div>

      <div className="space-y-5 p-5">
        <div>
          <div className="mb-2 flex items-center gap-2">
            <span className="font-mono text-[10px] uppercase tracking-widest text-[#A78BFA]">Quick Presets</span>
            <HelpTip helpKey={`preset${preset.charAt(0).toUpperCase()}${preset.slice(1)}`} />
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            {PRESET_ORDER.map((presetId) => {
              const presetMeta = SCAN_PRESETS[presetId];
              const isActive = preset === presetId;
              return (
                <button
                  key={presetId}
                  type="button"
                  onClick={() => onApplyPreset(presetId)}
                  className={`rounded border px-3 py-2 text-left transition-all ${
                    isActive
                      ? "border-[rgba(167,139,250,0.45)] bg-[rgba(167,139,250,0.12)] shadow-[0_0_16px_rgba(167,139,250,0.12)]"
                      : "border-[rgba(99,102,241,0.1)] bg-[rgba(2,6,23,0.35)] hover:border-[rgba(99,102,241,0.22)]"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-[11px] uppercase tracking-widest text-[#F8FAFC]">{presetMeta.label}</span>
                  </div>
                  <p className="mt-1 font-mono text-[10px] leading-4 text-[#64748B]">{presetMeta.description}</p>
                </button>
              );
            })}
          </div>
        </div>

        {validation.blockers.length > 0 ? (
          <div className="rounded border border-[rgba(255,79,79,0.24)] bg-[rgba(127,29,29,0.18)] p-3">
            <div className="font-mono text-[10px] uppercase tracking-widest text-[#FF7A7A]">Fix Before Scan</div>
            <div className="mt-2 space-y-2">
              {validation.blockers.map((item) => (
                <div key={item.id} className="font-mono text-[10px] leading-4 text-[#FCA5A5]">
                  {item.message}
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {validation.warnings.length > 0 ? (
          <div className="rounded border border-[rgba(245,158,11,0.24)] bg-[rgba(120,53,15,0.18)] p-3">
            <div className="font-mono text-[10px] uppercase tracking-widest text-[#FCD34D]">Review Notes</div>
            <div className="mt-2 space-y-2">
              {validation.warnings.map((item) => (
                <div key={item.id} className="font-mono text-[10px] leading-4 text-[#FDE68A]">
                  {item.message}
                </div>
              ))}
            </div>
          </div>
        ) : null}

        <div>
          <FieldLabel label="Target Base URL (Allowlist)" helpKey="targetUrl" />
          <input
            type="text"
            value={config.targetUrl}
            onChange={(e) => setConfig((prev) => ({ ...prev, targetUrl: e.target.value }))}
            className="w-full rounded border border-[rgba(99,102,241,0.12)] bg-[rgba(0,0,0,0.4)] px-3 py-2 font-mono text-xs text-[#F8FAFC] transition-colors focus:border-[rgba(99,102,241,0.4)] focus:outline-none"
          />
          <p className="mt-1 font-mono text-[10px] text-[#475569]">
            Only this domain will be scanned. Requests outside the allowlist are blocked.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <div>
            <div className="mb-1.5 flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <label className="font-mono text-[10px] uppercase tracking-widest text-[#94A3B8]">Rate Limit (Req/s)</label>
                <HelpTip helpKey="rateLimit" />
              </div>
              <span className="font-mono text-[10px] text-[#6366F1]">{config.rateLimit}</span>
            </div>
            <input
              type="range"
              min={1}
              max={100}
              step={1}
              value={config.rateLimit}
              onChange={(e) => setConfig((prev) => ({ ...prev, rateLimit: parseFloat(e.target.value) }))}
              className="w-full accent-[#6366F1]"
            />
          </div>
          <div>
            <div className="mb-1.5 flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <label className="font-mono text-[10px] uppercase tracking-widest text-[#94A3B8]">Concurrency (Threads)</label>
                <HelpTip helpKey="concurrency" />
              </div>
              <span className="font-mono text-[10px] text-[#6366F1]">{config.concurrency}</span>
            </div>
            <input
              type="range"
              min={1}
              max={50}
              step={1}
              value={config.concurrency}
              onChange={(e) => setConfig((prev) => ({ ...prev, concurrency: parseInt(e.target.value, 10) }))}
              className="w-full accent-[#6366F1]"
            />
          </div>
          <div>
            <FieldLabel label="Retry Attempts" helpKey="maxRetries" />
            <input
              type="number"
              min={0}
              max={5}
              value={config.maxRetries ?? 2}
              onChange={(e) => setConfig((prev) => ({ ...prev, maxRetries: parseInt(e.target.value, 10) || 0 }))}
              className="w-full rounded border border-[rgba(99,102,241,0.12)] bg-[rgba(0,0,0,0.4)] px-3 py-2 font-mono text-xs text-[#F8FAFC] transition-colors focus:border-[rgba(99,102,241,0.4)] focus:outline-none"
            />
            <p className="mt-1 font-mono text-[10px] text-[#475569]">Used for timeout, 429, and transient 5xx retry backoff.</p>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <div>
            <FieldLabel label="Auth Header" helpKey="authHeader" />
            <input
              type="text"
              value={config.authHeader}
              onChange={(e) => setConfig((prev) => ({ ...prev, authHeader: e.target.value }))}
              className="w-full rounded border border-[rgba(99,102,241,0.12)] bg-[rgba(0,0,0,0.4)] px-3 py-2 font-mono text-xs text-[#F8FAFC] transition-colors focus:border-[rgba(99,102,241,0.4)] focus:outline-none"
            />
          </div>
          <div>
            <FieldLabel label="Token Value" helpKey="authValue" />
            <input
              type="password"
              value={config.authValue}
              onChange={(e) => setConfig((prev) => ({ ...prev, authValue: e.target.value }))}
              className="w-full rounded border border-[rgba(99,102,241,0.12)] bg-[rgba(0,0,0,0.4)] px-3 py-2 font-mono text-xs text-[#F8FAFC] transition-colors focus:border-[rgba(99,102,241,0.4)] focus:outline-none"
            />
          </div>
        </div>

        <div>
          <FieldLabel label="Cookies (key=value; key=value)" helpKey="cookieString" />
          <input
            type="text"
            value={config.cookieString}
            onChange={(e) => setConfig((prev) => ({ ...prev, cookieString: e.target.value }))}
            className="w-full rounded border border-[rgba(99,102,241,0.12)] bg-[rgba(0,0,0,0.4)] px-3 py-2 font-mono text-xs text-[#F8FAFC] transition-colors focus:border-[rgba(99,102,241,0.4)] focus:outline-none"
          />
        </div>

        <div>
          <FieldLabel label="Custom Headers (JSON)" helpKey="customHeaders" />
          <textarea
            rows={3}
            value={customHeadersText}
            placeholder='{"X-Api-Key":"..."}'
            onChange={(e) => updateCustomHeaders(e.target.value)}
            className="w-full rounded border border-[rgba(99,102,241,0.12)] bg-[rgba(0,0,0,0.4)] px-3 py-2 font-mono text-xs text-[#F8FAFC] transition-colors focus:border-[rgba(99,102,241,0.4)] focus:outline-none"
          />
          {customHeadersError ? (
            <InlineNotice tone="warning">{customHeadersError}</InlineNotice>
          ) : null}
        </div>

        <div>
          <div className="mb-2 flex items-center gap-2">
            <label className="font-mono text-[10px] uppercase tracking-widest text-[#94A3B8]">Probe Categories</label>
            <HelpTip helpKey="auth" />
          </div>
          <div className="flex flex-wrap gap-2">
            {FUZZ_CATEGORIES.map((category) => (
              <div key={category.id} className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => toggleCategory(category.id)}
                  className={`rounded border px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider transition-all ${
                    config.categories.includes(category.id)
                      ? "border-current opacity-100"
                      : "border-[rgba(99,102,241,0.1)] opacity-30"
                  }`}
                  style={
                    config.categories.includes(category.id)
                      ? { color: category.color, borderColor: category.color, background: `${category.color}15` }
                      : { color: "#94A3B8" }
                  }
                >
                  {category.label}
                </button>
                <HelpTip helpKey={category.id} />
              </div>
            ))}
          </div>
          <p className="mt-2 font-mono text-[10px] text-[#475569]">
            Select SQLi, XSS, or SSTI to include those case families. Aggressive Mode swaps safe markers for live exploit payloads.
          </p>
        </div>

        <div className="divide-y divide-[rgba(99,102,241,0.08)] border-t border-[rgba(99,102,241,0.08)]">
          <FeatureToggleRow
            label="Aggressive Mode"
            helpKey="aggressive"
            description="Enables real SQLi, XSS, and SSTI payload probes."
            enabled={config.aggressive}
            onToggle={() => setConfig((prev) => ({ ...prev, aggressive: !prev.aggressive }))}
            activeClassName="bg-[#FF4F4F]"
          />

          <FeatureToggleRow
            label="Dry Run Mode"
            helpKey="dryRun"
            description="Builds the request plan without sending it."
            enabled={config.dryRun}
            onToggle={() => setConfig((prev) => ({ ...prev, dryRun: !prev.dryRun }))}
            activeClassName="bg-[#FFD166]"
          />

          <FeatureToggleRow
            label="Shadow Runner WAF Evasion"
            helpKey="enableWafEvasion"
            description="Spoofs request fingerprints and adds jitter after rate-limit style blocks."
            enabled={config.enableWafEvasion}
            onToggle={() => setConfig((prev) => ({ ...prev, enableWafEvasion: !prev.enableWafEvasion }))}
            activeClassName="bg-[#4FC3F7]"
          />

          <FeatureToggleRow
            label="Poisoned Payload (OAST) Tracker"
            helpKey="enableOast"
            description="Injects callback-style payloads into requests for blind checks."
            enabled={config.enableOast}
            onToggle={() => setConfig((prev) => ({ ...prev, enableOast: !prev.enableOast }))}
            activeClassName="bg-[#FF4F4F]"
            detailBorderClassName="border-[rgba(255,79,79,0.2)]"
            message={validation.features.oast.message}
            messageTone={validation.features.oast.tone}
          >
            <FieldLabel label="OAST Callback Base URL" helpKey="oastCallbackUrl" />
            <input
              type="text"
              value={config.oastCallbackUrl || ""}
              onChange={(e) => setConfig((prev) => ({ ...prev, oastCallbackUrl: e.target.value }))}
              placeholder="http://127.0.0.1:8010"
              className="w-full rounded border border-[rgba(255,79,79,0.2)] bg-[rgba(0,0,0,0.4)] px-3 py-1.5 font-mono text-xs text-[#F8FAFC] transition-colors focus:border-[rgba(255,79,79,0.45)] focus:outline-none"
            />
            <p className="mt-1 font-mono text-[10px] text-[#475569]">Use a reachable callback origin for blind SSRF and similar checks.</p>
          </FeatureToggleRow>
        </div>

        <div className="border-t border-[rgba(99,102,241,0.15)] pt-4">
          <div className="mb-3 flex items-center gap-2">
            <Icon name="BoltIcon" size={14} className="text-[#A78BFA]" />
            <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-[#A78BFA]">Power Features</span>
          </div>

          <div className="divide-y divide-[rgba(99,102,241,0.08)]">
            <FeatureToggleRow
              label="Parameter Discovery (Arjun-style)"
              helpKey="enableParamDiscovery"
              description="Brute-forces 150+ common params, tests Content-Type switching, and HTTP method tampering on each endpoint."
              enabled={config.enableParamDiscovery}
              onToggle={() => setConfig((prev) => ({ ...prev, enableParamDiscovery: !prev.enableParamDiscovery }))}
              activeClassName="bg-[#4FC3F7]"
              detailBorderClassName="border-[rgba(79,195,247,0.2)]"
            />

            <FeatureToggleRow
              label="BOLA/IDOR Detection"
              helpKey="enableBola"
              description="Tests whether one logged-in user can access another user's data."
              enabled={config.enableBola}
              onToggle={() => setConfig((prev) => ({ ...prev, enableBola: !prev.enableBola }))}
              activeClassName="bg-[#A78BFA]"
              message={config.enableBola ? validation.features.bola.message : null}
              messageTone={config.enableBola ? validation.features.bola.tone : null}
            >
              <FieldLabel label="User B Token (attacker)" helpKey="bolaUserBToken" />
              <input
                type="password"
                value={config.bolaUserBToken || ""}
                onChange={(e) => setConfig((prev) => ({ ...prev, bolaUserBToken: e.target.value }))}
                className="w-full rounded border border-[rgba(167,139,250,0.2)] bg-[rgba(0,0,0,0.4)] px-3 py-1.5 font-mono text-xs text-[#F8FAFC] transition-colors focus:border-[rgba(167,139,250,0.5)] focus:outline-none"
                placeholder="Bearer token for User B"
              />
              <p className="mt-1 font-mono text-[10px] text-[#475569]">User A comes from the main auth settings above.</p>
            </FeatureToggleRow>

            <FeatureToggleRow
              label="Stateful Fuzzing"
              helpKey="enableStateful"
              description="Tests skip-step, replay, and out-of-order workflow behavior."
              enabled={config.enableStateful}
              onToggle={() => setConfig((prev) => ({ ...prev, enableStateful: !prev.enableStateful }))}
              activeClassName="bg-[#A78BFA]"
            />

            <FeatureToggleRow
              label="Race Condition"
              helpKey="enableRace"
              description="Concurrent burst testing."
              enabled={config.enableRace}
              onToggle={() => setConfig((prev) => ({ ...prev, enableRace: !prev.enableRace }))}
              activeClassName="bg-[#A78BFA]"
              message={validation.features.race.message}
              messageTone={validation.features.race.tone}
            >
              <FieldLabel label="Burst Size" helpKey="burstSize" />
              <input
                type="number"
                min={2}
                max={50}
                value={config.burstSize ?? 10}
                onChange={(e) => setConfig((prev) => ({ ...prev, burstSize: parseInt(e.target.value, 10) || 10 }))}
                className="w-24 rounded border border-[rgba(167,139,250,0.2)] bg-[rgba(0,0,0,0.4)] px-3 py-1.5 font-mono text-xs text-[#F8FAFC] transition-colors focus:border-[rgba(167,139,250,0.5)] focus:outline-none"
              />
            </FeatureToggleRow>

            <FeatureToggleRow
              label="JSON Mutations"
              helpKey="enableMutations"
              description="Type-swap, nesting, and mass-assignment checks."
              enabled={config.enableMutations}
              onToggle={() => setConfig((prev) => ({ ...prev, enableMutations: !prev.enableMutations }))}
              activeClassName="bg-[#A78BFA]"
            />

            <FeatureToggleRow
              label="GraphQL & WebSocket"
              helpKey="enableGraphql"
              description="GraphQL probes and WebSocket upgrade checks."
              enabled={config.enableGraphql}
              disabled={graphToggleDisabled}
              onToggle={() => setConfig((prev) => ({ ...prev, enableGraphql: !prev.enableGraphql }))}
              activeClassName="bg-[#A78BFA]"
              message={validation.features.graphql.message}
              messageTone={validation.features.graphql.tone}
            />

            <FeatureToggleRow
              label="Attack Graph"
              helpKey="enableAttackGraph"
              description="Builds dependency graph paths and chained logic cases."
              enabled={config.enableAttackGraph}
              onToggle={() => setConfig((prev) => ({ ...prev, enableAttackGraph: !prev.enableAttackGraph }))}
              activeClassName="bg-[#A78BFA]"
            />

            <FeatureToggleRow
              label="Auto Login"
              helpKey="enableAutoLogin"
              description="Logs in first and reuses harvested cookies or bearer tokens."
              enabled={config.enableAutoLogin}
              disabled={autoLoginToggleDisabled}
              forceOpen={autoLoginDetailsOpen}
              onToggle={() => setConfig((prev) => ({ ...prev, enableAutoLogin: !prev.enableAutoLogin }))}
              activeClassName="bg-[#A78BFA]"
              message={validation.features.autoLogin.message}
              messageTone={validation.features.autoLogin.tone}
            >
              <div className="grid grid-cols-1 gap-2">
                <div>
                  <FieldLabel label="Login URL" helpKey="loginUrl" />
                  <input
                    type="text"
                    value={config.loginUrl || ""}
                    onChange={(e) => setConfig((prev) => ({ ...prev, loginUrl: e.target.value }))}
                    placeholder="https://target.example.com/api/login"
                    className="w-full rounded border border-[rgba(167,139,250,0.2)] bg-[rgba(0,0,0,0.4)] px-3 py-1.5 font-mono text-xs text-[#F8FAFC] transition-colors focus:border-[rgba(167,139,250,0.5)] focus:outline-none"
                  />
                </div>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  <div>
                    <FieldLabel label="Username or Email" helpKey="loginUser" />
                    <input
                      type="text"
                      value={config.loginUser || ""}
                      onChange={(e) => setConfig((prev) => ({ ...prev, loginUser: e.target.value }))}
                      placeholder="scanner@example.com"
                      className="w-full rounded border border-[rgba(167,139,250,0.2)] bg-[rgba(0,0,0,0.4)] px-3 py-1.5 font-mono text-xs text-[#F8FAFC] transition-colors focus:border-[rgba(167,139,250,0.5)] focus:outline-none"
                    />
                  </div>
                  <div>
                    <FieldLabel label="Password" helpKey="loginPass" />
                    <input
                      type="password"
                      value={config.loginPass || ""}
                      onChange={(e) => setConfig((prev) => ({ ...prev, loginPass: e.target.value }))}
                      placeholder="Password"
                      className="w-full rounded border border-[rgba(167,139,250,0.2)] bg-[rgba(0,0,0,0.4)] px-3 py-1.5 font-mono text-xs text-[#F8FAFC] transition-colors focus:border-[rgba(167,139,250,0.5)] focus:outline-none"
                    />
                  </div>
                </div>
              </div>
            </FeatureToggleRow>
          </div>
        </div>

        <div className="space-y-1 rounded border border-[rgba(99,102,241,0.06)] bg-[rgba(0,0,0,0.4)] p-4 font-mono text-xs">
          <div className="text-[#94A3B8]">// campaign summary</div>
          <div><span className="text-[#4FC3F7]">endpoints</span><span className="text-[#94A3B8]">: </span><span className="text-[#6366F1]">{selectedCount}</span></div>
          <div><span className="text-[#4FC3F7]">fuzz_cases</span><span className="text-[#94A3B8]">: </span><span className="text-[#6366F1]">{totalCases.toLocaleString()}</span></div>
          <div><span className="text-[#4FC3F7]">mode</span><span className="text-[#94A3B8]">: </span><span className="text-[#6366F1]">{config.dryRun ? "dry_run" : "live"}</span></div>
          <div><span className="text-[#4FC3F7]">preset</span><span className="text-[#94A3B8]">: </span><span className="text-[#6366F1]">{preset}</span></div>
        </div>

        <button
          type="button"
          onClick={onStart}
          disabled={startDisabled}
          className={`flex w-full items-center justify-center gap-2 rounded py-3 font-mono text-sm font-bold uppercase tracking-widest transition-all duration-300 ${
            startDisabled
              ? "cursor-not-allowed border border-[rgba(99,102,241,0.08)] bg-[rgba(99,102,241,0.05)] text-[#475569]"
              : "hacker-btn w-full"
          }`}
        >
          {isRunning ? (
            <>
              <span className="h-3 w-3 animate-spin rounded-full border-2 border-[#6366F1] border-t-transparent" />
              Running...
            </>
          ) : (
            <>
              <Icon name="BoltIcon" size={16} />
              Start Scan
            </>
          )}
        </button>
      </div>
    </div>
  );
}
