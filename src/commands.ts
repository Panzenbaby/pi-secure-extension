import type {
  ExtensionAPI,
  ExtensionCommandContext,
  ExecResult,
} from "@mariozechner/pi-coding-agent";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { getGlobalRulesPath, getLocalRulesPath } from "./config.js";
import type { ResolvedSource } from "./source-resolver.js";
import { resolveSource } from "./source-resolver.js";
import { auditAndConfirm } from "./workflows.js";
import {
  editRulesFile,
  ensureModelSelected,
  resetRulesFile,
} from "./ui.js";

async function resolveAuditSource(
  source: string,
  ctx: ExtensionCommandContext,
): Promise<ResolvedSource | null> {
  ctx.ui.notify(`Resolving extension source: ${source}`, "info");

  let resolved: ResolvedSource;
  try {
    resolved = await resolveSource(source);
  } catch (err) {
    ctx.ui.notify(
      `Failed to resolve source: ${err instanceof Error ? err.message : String(err)}`,
      "error",
    );
    return null;
  }

  if (resolved.files.length === 0) {
    ctx.ui.notify("No source files found in extension.", "warning");
    return null;
  }

  return resolved;
}

function isPackageSourceCandidate(spec: string): boolean {
  return (
    spec.startsWith("npm:") || spec.startsWith("git:") || spec.includes("/")
  );
}

function parseListPackagesOutput(output: string): string[] {
  const packages = output
    .split("\n")
    .map((line: string) => line.replace(/\r$/, ""))
    .filter((line: string) => /^\s{2}\S/.test(line) && !/^\s{4}\S/.test(line))
    .map((line: string) => line.trim())
    .map((line: string) => {
      const bulletMatch = line.match(/^[-•]\s*(.+)/);
      return bulletMatch ? bulletMatch[1]!.trim() : line;
    })
    .filter((pkg: string) => isPackageSourceCandidate(pkg));

  return Array.from(new Set(packages));
}

interface PiPackageUpdate {
  source: string;
  displayName: string;
}

async function listPackages(
  pi: ExtensionAPI,
  ctx: ExtensionCommandContext,
): Promise<string[] | null> {
  try {
    const listResult: ExecResult = await pi.exec("pi", ["list"], {
      cwd: ctx.cwd,
    });

    return parseListPackagesOutput(listResult.stdout);
  } catch {
    ctx.ui.notify("Could not list installed packages.", "error");
    return null;
  }
}

async function listOutdatedPackages(
  _pi: ExtensionAPI,
  ctx: ExtensionCommandContext,
): Promise<string[] | null> {
  try {
    const codingAgentEntry = import.meta.resolve("@mariozechner/pi-coding-agent");
    const distDir = dirname(fileURLToPath(codingAgentEntry));

    const [{ DefaultPackageManager }, { SettingsManager }, { getAgentDir }] =
      await Promise.all([
        import(pathToFileURL(join(distDir, "core/package-manager.js")).href),
        import(pathToFileURL(join(distDir, "core/settings-manager.js")).href),
        import(pathToFileURL(join(distDir, "config.js")).href),
      ]);

    const agentDir: string = getAgentDir();
    const settingsManager = SettingsManager.create(ctx.cwd, agentDir);
    const packageManager = new DefaultPackageManager({
      cwd: ctx.cwd,
      agentDir,
      settingsManager,
    });

    const updates: PiPackageUpdate[] = await packageManager.checkForAvailableUpdates();
    return updates.map((update) => update.source);
  } catch {
    ctx.ui.notify("Could not check outdated packages.", "error");
    return null;
  }
}

function stripVersionSuffix(spec: string): string {
  const atIndex = spec.lastIndexOf("@");
  if (atIndex <= 0) {
    return spec;
  }

  const lastSlashIndex = spec.lastIndexOf("/");
  if (atIndex > lastSlashIndex) {
    return spec.slice(0, atIndex);
  }

  return spec;
}

function normalizePackageSourceForCompare(source: string): string {
  const trimmed = source.trim();

  if (trimmed.startsWith("npm:")) {
    const spec = trimmed.slice(4);
    return `npm:${stripVersionSuffix(spec).toLowerCase()}`;
  }

  if (trimmed.startsWith("git:")) {
    const spec = trimmed.slice(4);
    return `git:${stripVersionSuffix(spec)}`;
  }

  return stripVersionSuffix(trimmed).toLowerCase();
}

async function isConfiguredPackageInstalled(
  pi: ExtensionAPI,
  source: string,
  ctx: ExtensionCommandContext,
): Promise<boolean> {
  const packages = await listPackages(pi, ctx);
  if (!packages) {
    return false;
  }

  const normalizedSource = normalizePackageSourceForCompare(source);
  const normalizedInstalled = new Set(
    packages.map((pkg) => normalizePackageSourceForCompare(pkg)),
  );

  return normalizedInstalled.has(normalizedSource);
}

async function runInstallOrUpdateCommand(
  pi: ExtensionAPI,
  source: string,
  action: "install" | "update",
  ctx: ExtensionCommandContext,
  flags?: string[],
): Promise<void> {
  if (!ensureModelSelected(ctx)) {
    return;
  }

  if (action === "update") {
    const installed = await isConfiguredPackageInstalled(pi, source, ctx);
    if (!installed) {
      ctx.ui.notify(
        `Cannot update \"${source}\": extension is not installed.`,
        "error",
      );
      return;
    }
  }

  const resolved = await resolveAuditSource(source, ctx);
  if (!resolved) {
    return;
  }

  await auditAndConfirm(pi, resolved, source, action, ctx, flags);
}

async function handleInstallCommand(
  pi: ExtensionAPI,
  args: string,
  ctx: ExtensionCommandContext,
): Promise<void> {
  const parts = args.trim().split(/\s+/);
  const source = parts[0];
  if (!source) {
    ctx.ui.notify("Usage: /secure:install <source> [-l]", "warning");
    return;
  }

  await runInstallOrUpdateCommand(pi, source, "install", ctx, parts.slice(1));
}

async function handleUpdateCommand(
  pi: ExtensionAPI,
  args: string,
  ctx: ExtensionCommandContext,
): Promise<void> {
  const source = args.trim();
  if (!source) {
    ctx.ui.notify("Usage: /secure:update <source>", "warning");
    return;
  }

  await runInstallOrUpdateCommand(pi, source, "update", ctx);
}

async function handleUpdateAllCommand(
  pi: ExtensionAPI,
  ctx: ExtensionCommandContext,
): Promise<void> {
  if (!ensureModelSelected(ctx)) {
    return;
  }

  ctx.ui.notify("Checking for outdated extensions...", "info");

  const outdatedPackages = await listOutdatedPackages(pi, ctx);
  if (!outdatedPackages) {
    return;
  }

  if (outdatedPackages.length === 0) {
    ctx.ui.notify("All extensions are already up to date.", "info");
    return;
  }

  ctx.ui.notify(
    `Found ${outdatedPackages.length} outdated package(s). Auditing each before update...`,
    "info",
  );

  for (const pkg of outdatedPackages) {
    const proceed = await ctx.ui.confirm(
      "Audit Package",
      `Audit and update "${pkg}"?`,
    );
    if (!proceed) {
      continue;
    }

    await runInstallOrUpdateCommand(pi, pkg, "update", ctx);
  }

  ctx.ui.notify("Update-all complete.", "info");
}

async function handleRulesCommand(
  _pi: ExtensionAPI,
  ctx: ExtensionCommandContext,
): Promise<void> {
  const globalPath = getGlobalRulesPath();
  const localPath = getLocalRulesPath();

  const options = ["Edit global rules", "Reset global to defaults"];
  if (localPath) {
    options.splice(1, 0, "Edit local rules");
    options.push("Reset local to defaults");
  }

  const choice = await ctx.ui.select("Security Audit Rules", options);
  if (!choice) {
    return;
  }

  if (choice === "Edit global rules") {
    await editRulesFile(globalPath, "global", ctx);
    return;
  }

  if (choice === "Edit local rules" && localPath) {
    await editRulesFile(localPath, "local", ctx);
    return;
  }

  if (choice === "Reset global to defaults") {
    await resetRulesFile(globalPath, "Global", ctx);
    return;
  }

  if (choice === "Reset local to defaults" && localPath) {
    await resetRulesFile(localPath, "Local", ctx);
  }
}

export function registerSecureCommands(pi: ExtensionAPI): void {
  pi.registerCommand("secure:install", {
    description: "Security audit then install an extension",
    handler: async (args, ctx) => handleInstallCommand(pi, args, ctx),
  });

  pi.registerCommand("secure:update", {
    description: "Security audit then update an extension",
    handler: async (args, ctx) => handleUpdateCommand(pi, args, ctx),
  });

  pi.registerCommand("secure:update-all", {
    description: "Audit and update all outdated extensions",
    handler: async (_args, ctx) => handleUpdateAllCommand(pi, ctx),
  });

  pi.registerCommand("secure:rules", {
    description: "Edit security audit rules (global or local)",
    handler: async (_args, ctx) => handleRulesCommand(pi, ctx),
  });
}
