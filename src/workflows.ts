import type {
  ExtensionAPI,
  ExtensionCommandContext,
  ExecResult,
} from "@mariozechner/pi-coding-agent";
import type { ResolvedSource } from "./source-resolver.js";
import {
  executeAudit,
  parseAuditMetadata,
  withLoadingIndicator,
} from "./ui.js";

const JSON_FOOTER_REGEX = /\n*```json[^`]*```\s*$/i;

function buildIntegrityNote(
  integrity: string | undefined,
  action?: "install" | "update",
): string {
  if (!integrity) {
    return "";
  }

  const lines = [`**Audited source integrity:** \`${integrity}\``];
  if (action) {
    lines.push(
      `**Note:** \`pi ${action}\` downloads the package independently. ` +
        "The installed version may differ from what was audited if the registry was updated between audit and install.",
    );
  }

  return lines.join("\n");
}

function injectIntegrityNote(content: string, integrityNote: string): string {
  if (!integrityNote) {
    return content;
  }

  const match = content.match(JSON_FOOTER_REGEX);
  if (!match || match.index === undefined) {
    return `${content}\n\n${integrityNote}`;
  }

  return (
    content.slice(0, match.index).trimEnd() +
    `\n\n${integrityNote}\n\n` +
    content.slice(match.index).trimStart()
  );
}

export async function auditAndConfirm(
  pi: ExtensionAPI,
  resolved: ResolvedSource,
  source: string,
  action: "install" | "update",
  ctx: ExtensionCommandContext,
  flags?: string[],
): Promise<void> {
  const abortController = new AbortController();
  const forwardAbort = () => {
    abortController.abort();
  };

  if (ctx.signal) {
    if (ctx.signal.aborted) {
      abortController.abort();
    } else {
      ctx.signal.addEventListener("abort", forwardAbort, { once: true });
    }
  }

  try {
    const result = await executeAudit(
      resolved,
      ctx,
      abortController.signal,
      "Running security audit...",
    );
    if (!result) {
      return;
    }

    const integrityNote = buildIntegrityNote(result.integrity, action);
    const content = injectIntegrityNote(result.content, integrityNote);

    // Show full audit report in chat with custom renderer
    pi.sendMessage({
      customType: "secure-audit-result",
      content: [{ type: "text", text: content }],
      display: true,
    });

    const parsed = parseAuditMetadata(result.content);
    const risk = parsed.risk ?? "unavailable";
    const verdict = parsed.verdict ?? "unavailable";

    const proceed = await ctx.ui.confirm(
      "Security Audit Complete",
      `Risk: ${risk}\nVerdict: ${verdict}\n\nFull report in chat. Proceed with ${action}?`,
    );
    if (!proceed) {
      ctx.ui.notify(`${action} cancelled by user.`, "info");
      return;
    }

    const piArgs = [action, source, ...(flags ?? [])];
    ctx.ui.notify(`Running: pi ${piArgs.join(" ")}`, "info");

    try {
      const execResult: ExecResult = await withLoadingIndicator(
        ctx,
        {
          statusKey: `secure-${action}`,
          workingMessage: `Running pi ${action}...`,
          buildStatusMessage: (frame, elapsed) =>
            `${frame} ${action === "install" ? "Installing" : "Updating"} extension • ${elapsed}`,
        },
        async () =>
          await pi.exec("pi", piArgs, {
            cwd: ctx.cwd,
          }),
      );
      if (execResult.code === 0) {
        ctx.ui.notify(`${action} completed successfully.`, "info");
      } else {
        ctx.ui.notify(
          `${action} failed with exit code ${execResult.code}: ${execResult.stderr}`,
          "error",
        );
      }
    } catch (err) {
      ctx.ui.notify(
        `${action} failed: ${err instanceof Error ? err.message : String(err)}`,
        "error",
      );
    }
  } finally {
    if (ctx.signal) {
      ctx.signal.removeEventListener("abort", forwardAbort);
    }
  }
}
