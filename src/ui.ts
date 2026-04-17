import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type {
  ExtensionCommandContext,
  MessageRenderOptions,
} from "@mariozechner/pi-coding-agent";
import type { Theme } from "@mariozechner/pi-coding-agent";
import { Box, Markdown, matchesKey, Text } from "@mariozechner/pi-tui";
import type { MarkdownTheme } from "@mariozechner/pi-tui";
import type { AuditResult } from "./audit.js";
import { runAudit } from "./audit.js";
import { loadDefaultRules } from "./config.js";
import type { ResolvedSource } from "./source-resolver.js";

export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE";
export type AuditVerdict =
  | "SAFE TO INSTALL"
  | "INSTALL WITH CAUTION"
  | "DO NOT INSTALL";

const RISK_LEVELS: ReadonlySet<RiskLevel> = new Set([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "SAFE",
]);

const AUDIT_VERDICTS: ReadonlySet<AuditVerdict> = new Set([
  "SAFE TO INSTALL",
  "INSTALL WITH CAUTION",
  "DO NOT INSTALL",
]);

const ANSI_ESCAPE_REGEX =
  /\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g;
const CTRL_CHARS_REGEX = /[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]/g;

function stripAnsiSequences(text: string): string {
  return text.replace(ANSI_ESCAPE_REGEX, "").replace(CTRL_CHARS_REGEX, "");
}

export function parseAuditMetadata(text: string): {
  risk?: RiskLevel;
  verdict?: AuditVerdict;
  reportText: string;
} {
  const sanitized = stripAnsiSequences(text);
  const jsonBlockMatch = sanitized.match(/```json\s*([^`]*)\s*```\s*$/i);

  if (!jsonBlockMatch || jsonBlockMatch.index === undefined) {
    return {
      reportText: sanitized.trim(),
    };
  }

  const reportText = sanitized.slice(0, jsonBlockMatch.index).trimEnd();

  try {
    const parsed = JSON.parse(jsonBlockMatch[1] ?? "") as {
      risk?: unknown;
      verdict?: unknown;
    };

    const normalizedRisk =
      typeof parsed.risk === "string" ? parsed.risk.toUpperCase().trim() : "";
    const normalizedVerdict =
      typeof parsed.verdict === "string"
        ? parsed.verdict.toUpperCase().trim()
        : "";

    return {
      risk: RISK_LEVELS.has(normalizedRisk as RiskLevel)
        ? (normalizedRisk as RiskLevel)
        : undefined,
      verdict: AUDIT_VERDICTS.has(normalizedVerdict as AuditVerdict)
        ? (normalizedVerdict as AuditVerdict)
        : undefined,
      reportText,
    };
  } catch {
    return {
      reportText,
    };
  }
}

function makeConfirmFn(ctx: ExtensionCommandContext) {
  return (title: string, message: string) => ctx.ui.confirm(title, message);
}

function extractCustomMessageText(message: {
  content: string | Array<{ type?: string; text?: string }>;
}): string {
  if (typeof message.content === "string") {
    return message.content;
  }

  return message.content
    .filter(
      (
        item: { type?: string; text?: string },
      ): item is { type: "text"; text: string } =>
        item.type === "text" && typeof item.text === "string",
    )
    .map((item: { type: "text"; text: string }) => item.text)
    .join("\n");
}

function getRiskStyle(
  theme: Theme,
  risk: RiskLevel | undefined,
): (text: string) => string {
  switch (risk) {
    case "CRITICAL":
      return (text: string) => theme.bold(theme.fg("error", text));
    case "HIGH":
      return (text: string) => theme.bold(theme.fg("warning", text));
    case "MEDIUM":
      return (text: string) => theme.bold(theme.fg("warning", text));
    case "LOW":
      return (text: string) => theme.bold(theme.fg("accent", text));
    case "SAFE":
      return (text: string) => theme.bold(theme.fg("success", text));
    default:
      return (text: string) => theme.bold(theme.fg("accent", text));
  }
}

function countFindings(text: string): number {
  const severityMatches = text.match(
    /severity\s*:\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)/gi,
  );
  if (severityMatches && severityMatches.length > 0) {
    return severityMatches.length;
  }

  const numberedFindingMatches = text.match(/^#{0,3}\s*\d+[.)-]\s+/gm);
  if (numberedFindingMatches && numberedFindingMatches.length > 0) {
    return numberedFindingMatches.length;
  }

  const findingHeaderMatches = text.match(/^#{1,6}\s+.*$/gm);
  if (findingHeaderMatches && findingHeaderMatches.length > 0) {
    const filtered = findingHeaderMatches.filter(
      (line) =>
        !/^(#+\s+)?(risk level|summary|findings|verdict|integrity)$/i.test(
          line.trim(),
        ),
    );
    if (filtered.length > 0) {
      return filtered.length;
    }
  }

  return 0;
}

function getVerdictStyle(
  theme: Theme,
  verdict: AuditVerdict | undefined,
): (text: string) => string {
  switch (verdict) {
    case "DO NOT INSTALL":
      return (text: string) => theme.bold(theme.fg("error", text));
    case "INSTALL WITH CAUTION":
      return (text: string) => theme.bold(theme.fg("warning", text));
    case "SAFE TO INSTALL":
      return (text: string) => theme.bold(theme.fg("success", text));
    default:
      return (text: string) => theme.bold(theme.fg("accent", text));
  }
}

function createAuditMarkdownTheme(theme: Theme): MarkdownTheme {
  return {
    heading: (text: string) => theme.bold(theme.fg("mdHeading", text)),
    link: (text: string) => theme.underline(theme.fg("mdLink", text)),
    linkUrl: (text: string) => theme.fg("mdLinkUrl", text),
    code: (text: string) => theme.fg("mdCode", text),
    codeBlock: (text: string) => theme.fg("mdCodeBlock", text),
    codeBlockBorder: (text: string) => theme.fg("mdCodeBlockBorder", text),
    quote: (text: string) => theme.fg("mdQuote", text),
    quoteBorder: (text: string) => theme.fg("mdQuoteBorder", text),
    hr: (text: string) => theme.fg("mdHr", text),
    listBullet: (text: string) => theme.fg("mdListBullet", text),
    bold: (text: string) => theme.bold(text),
    italic: (text: string) => theme.italic(text),
    strikethrough: (text: string) => theme.strikethrough(text),
    underline: (text: string) => theme.underline(text),
  };
}

export function renderAuditResult(
  message: { content: string | Array<{ type?: string; text?: string }> },
  _options: MessageRenderOptions,
  theme: Theme,
) {
  const rawText = extractCustomMessageText(message);
  const parsed = parseAuditMetadata(rawText);
  const text = parsed.reportText || rawText;
  const risk = parsed.risk;
  const verdict = parsed.verdict;
  const findingsCount = countFindings(text);
  const riskStyle = getRiskStyle(theme, risk);
  const verdictStyle = getVerdictStyle(theme, verdict);

  const container = new Box(1, 0, (line: string) =>
    theme.bg("customMessageBg", line),
  );

  container.addChild(
    new Markdown(text, 0, 0, createAuditMarkdownTheme(theme), {
      color: (value: string) => theme.fg("customMessageText", value),
    }),
  );

  container.addChild(new Text(theme.fg("borderMuted", "─".repeat(40)), 0, 0));

  container.addChild(
    new Text(
      theme.bold(theme.fg("customMessageLabel", "Security Audit Report")),
      0,
      0,
    ),
  );

  const summaryParts: string[] = [];
  if (risk) {
    summaryParts.push(riskStyle(risk));
  }
  if (findingsCount > 0) {
    summaryParts.push(
      theme.bold(
        theme.fg(
          "accent",
          `${findingsCount} finding${findingsCount === 1 ? "" : "s"}`,
        ),
      ),
    );
  }
  if (verdict) {
    summaryParts.push(verdictStyle(verdict));
  }

  if (summaryParts.length > 0) {
    container.addChild(
      new Text(
        `${theme.fg("muted", "Summary: ")}${summaryParts.join(theme.fg("muted", " • "))}`,
        0,
        0,
      ),
    );
  }

  container.addChild(
    new Text(
      risk
        ? `${theme.fg("muted", "Risk Level: ")}${riskStyle(risk)}`
        : theme.fg("muted", "Risk Level: unavailable"),
      0,
      0,
    ),
  );

  if (verdict) {
    container.addChild(
      new Text(
        `${theme.fg("muted", "Verdict: ")}${verdictStyle(verdict)}`,
        0,
        0,
      ),
    );
  }

  return container;
}

export function ensureModelSelected(ctx: ExtensionCommandContext): boolean {
  if (ctx.model) {
    return true;
  }

  ctx.ui.notify(
    "No model selected. Please select a model first (Ctrl+P or /model).",
    "error",
  );
  return false;
}

export async function executeAudit(
  resolved: ResolvedSource,
  ctx: ExtensionCommandContext,
  signal: AbortSignal | undefined,
  statusMessage: string,
): Promise<AuditResult | null> {
  const modelLabel = ctx.model?.name ?? ctx.model?.id;
  const suffix = modelLabel ? ` with ${modelLabel}` : "";
  const abortController = new AbortController();
  const spinnerFrames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
  let spinnerIndex = 0;
  let spinnerTimer: ReturnType<typeof setInterval> | undefined;
  const startedAt = Date.now();

  const forwardAbort = () => {
    abortController.abort();
  };

  if (signal) {
    if (signal.aborted) {
      abortController.abort();
    } else {
      signal.addEventListener("abort", forwardAbort, { once: true });
    }
  }

  let escCancellationRequested = false;
  const unsubscribeTerminalInput = ctx.ui.onTerminalInput((data) => {
    if (matchesKey(data, "escape") && !abortController.signal.aborted) {
      escCancellationRequested = true;
      ctx.ui.notify("Cancelling security audit...", "warning");
      abortController.abort();
      return { consume: true };
    }

    return undefined;
  });

  ctx.ui.notify(
    `Found ${resolved.files.length} files. Running security audit${suffix}...`,
    "info",
  );
  ctx.ui.setWorkingMessage(statusMessage);

  const renderStatus = () => {
    try {
      const frame = spinnerFrames[spinnerIndex % spinnerFrames.length] ?? "…";
      spinnerIndex += 1;

      const elapsedMs = Date.now() - startedAt;
      const totalSeconds = Math.floor(elapsedMs / 1000);
      const minutes = Math.floor(totalSeconds / 60);
      const seconds = totalSeconds % 60;
      const elapsed = `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;

      ctx.ui.setStatus(
        "secure-audit",
        `${frame} Auditing ${resolved.files.length} files • ${elapsed} • Esc: cancel`,
      );
    } catch {
      // Ignore status rendering errors to avoid breaking audit execution.
    }
  };

  renderStatus();
  spinnerTimer = setInterval(renderStatus, 120);

  try {
    const result = await runAudit(
      resolved,
      ctx,
      undefined,
      abortController.signal,
      makeConfirmFn(ctx),
    );

    if (result.error) {
      ctx.ui.notify(`Audit failed: ${result.error}`, "error");
      return null;
    }

    if (result.aborted) {
      ctx.ui.notify(
        escCancellationRequested ? "Audit cancelled." : "Audit was aborted.",
        "warning",
      );
      return null;
    }

    return result;
  } finally {
    unsubscribeTerminalInput();
    if (spinnerTimer) {
      clearInterval(spinnerTimer);
    }
    if (signal) {
      signal.removeEventListener("abort", forwardAbort);
    }
    ctx.ui.setStatus("secure-audit", undefined);
    ctx.ui.setWorkingMessage();
  }
}

async function saveRulesFile(
  targetPath: string,
  content: string,
  successMessage: string,
  ctx: ExtensionCommandContext,
): Promise<void> {
  await mkdir(dirname(targetPath), { recursive: true });
  await writeFile(targetPath, content, "utf-8");
  ctx.ui.notify(successMessage, "info");
}

export async function editRulesFile(
  targetPath: string,
  label: "global" | "local",
  ctx: ExtensionCommandContext,
): Promise<void> {
  const currentContent = existsSync(targetPath)
    ? await readFile(targetPath, "utf-8")
    : await loadDefaultRules();

  const edited = await ctx.ui.editor(`Audit Rules (${label})`, currentContent);
  if (edited === undefined) {
    return;
  }

  await saveRulesFile(
    targetPath,
    edited,
    `Saved audit rules to ${targetPath}`,
    ctx,
  );
}

export async function resetRulesFile(
  targetPath: string,
  label: "Global" | "Local",
  ctx: ExtensionCommandContext,
): Promise<void> {
  const confirm = await ctx.ui.confirm(
    "Reset Rules",
    `Reset ${label.toLowerCase()} audit rules to the bundled defaults?`,
  );
  if (!confirm) {
    return;
  }

  const defaults = await loadDefaultRules();
  await saveRulesFile(
    targetPath,
    defaults,
    `${label} audit rules reset to defaults.`,
    ctx,
  );
}
