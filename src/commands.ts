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
  withLoadingIndicator,
} from "./ui.js";

async function resolveAuditSource(
  source: string,
  ctx: ExtensionCommandContext,
): Promise<ResolvedSource | null> {
  ctx.ui.notify(`Resolving extension source: ${source}`, "info");

  let resolved: ResolvedSource;
  try {
    resolved = await withLoadingIndicator(
      ctx,
      {
        statusKey: "secure-resolve-source",
        workingMessage: "Loading extension source...",
        buildStatusMessage: (frame, elapsed) =>
          `${frame} Loading extension files • ${elapsed}`,
      },
      async () => await resolveSource(source),
    );
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

interface SettingsManagerLike {
  readonly __brand?: "SettingsManagerLike";
}

interface PackageManagerLike {
  checkForAvailableUpdates(): Promise<PiPackageUpdate[]>;
}

interface PackageManagerModule {
  DefaultPackageManager: new (options: {
    cwd: string;
    agentDir: string;
    settingsManager: SettingsManagerLike;
  }) => PackageManagerLike;
}

interface SettingsManagerModule {
  SettingsManager: {
    create(cwd: string, agentDir: string): SettingsManagerLike;
  };
}

interface ConfigModule {
  getAgentDir(): string;
}

type UpdateAvailabilityResult =
  | { status: "available"; update: PiPackageUpdate }
  | { status: "unavailable" }
  | { status: "error" };

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
  loadingLabel: string,
): Promise<PiPackageUpdate[] | null> {
  try {
    return await withLoadingIndicator(
      ctx,
      {
        statusKey: "secure-update-check",
        workingMessage: loadingLabel,
        buildStatusMessage: (frame, elapsed) =>
          `${frame} ${loadingLabel} • ${elapsed}`,
      },
      async () => {
        const codingAgentEntry = import.meta.resolve(
          "@mariozechner/pi-coding-agent",
        );
        const distDir = dirname(fileURLToPath(codingAgentEntry));

        const [packageManagerModule, settingsManagerModule, configModule] =
          await Promise.all([
            import(
              pathToFileURL(join(distDir, "core/package-manager.js")).href
            ) as Promise<PackageManagerModule>,
            import(
              pathToFileURL(join(distDir, "core/settings-manager.js")).href
            ) as Promise<SettingsManagerModule>,
            import(
              pathToFileURL(join(distDir, "config.js")).href
            ) as Promise<ConfigModule>,
          ]);

        const agentDir = configModule.getAgentDir();
        const settingsManager = settingsManagerModule.SettingsManager.create(
          ctx.cwd,
          agentDir,
        );
        const packageManager = new packageManagerModule.DefaultPackageManager({
          cwd: ctx.cwd,
          agentDir,
          settingsManager,
        });

        return await packageManager.checkForAvailableUpdates();
      },
    );
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

function normalizeGitPath(path: string): string {
  return path
    .replace(/\.git$/i, "")
    .replace(/^\/+/, "")
    .replace(/\/+$/, "")
    .toLowerCase();
}

function buildGitIdentity(host: string, path: string): string | null {
  const normalizedHost = host.toLowerCase();
  const normalizedPath = normalizeGitPath(path);

  if (!normalizedHost || normalizedPath.split("/").length < 2) {
    return null;
  }

  return `git:${normalizedHost}/${normalizedPath}`;
}

function getGitFallbackIdentity(hasGitPrefix: boolean, repo: string): string {
  return hasGitPrefix ? `git:${repo}` : repo;
}

function stripGitRef(spec: string): string {
  const trimmed = spec.trim();
  const scpLikeMatch = trimmed.match(/^git@([^:]+):(.+)$/);
  if (scpLikeMatch) {
    const host = scpLikeMatch[1];
    const pathWithMaybeRef = scpLikeMatch[2];
    if (!host || !pathWithMaybeRef) {
      return trimmed;
    }

    const refSeparator = pathWithMaybeRef.indexOf("@");
    if (refSeparator < 0) {
      return trimmed;
    }

    const repoPath = pathWithMaybeRef.slice(0, refSeparator);
    return repoPath ? `git@${host}:${repoPath}` : trimmed;
  }

  if (trimmed.includes("://")) {
    try {
      const parsed = new URL(trimmed);
      const pathWithMaybeRef = parsed.pathname.replace(/^\/+/, "");
      const refSeparator = pathWithMaybeRef.indexOf("@");
      if (refSeparator < 0) {
        return trimmed.replace(/\/+$/, "");
      }

      const repoPath = pathWithMaybeRef.slice(0, refSeparator);
      if (!repoPath) {
        return trimmed.replace(/\/+$/, "");
      }

      parsed.pathname = `/${repoPath}`;
      return parsed.toString().replace(/\/+$/, "");
    } catch {
      return trimmed;
    }
  }

  const slashIndex = trimmed.indexOf("/");
  if (slashIndex < 0) {
    return trimmed;
  }

  const host = trimmed.slice(0, slashIndex);
  const pathWithMaybeRef = trimmed.slice(slashIndex + 1);
  const refSeparator = pathWithMaybeRef.indexOf("@");
  if (refSeparator < 0) {
    return trimmed;
  }

  const repoPath = pathWithMaybeRef.slice(0, refSeparator);
  return repoPath ? `${host}/${repoPath}` : trimmed;
}

function getGitSourceIdentity(source: string): string | null {
  const trimmed = source.trim();
  const hasGitPrefix = trimmed.startsWith("git:");
  const spec = hasGitPrefix ? trimmed.slice(4).trim() : trimmed;

  if (
    !hasGitPrefix &&
    !/^(https?:\/\/|ssh:\/\/|git:\/\/|git@|github\.com\/)/i.test(spec)
  ) {
    return null;
  }

  const repo = stripGitRef(spec);
  const scpLikeMatch = repo.match(/^git@([^:]+):(.+)$/);
  if (scpLikeMatch) {
    const host = scpLikeMatch[1];
    const path = scpLikeMatch[2];
    if (host && path) {
      const identity = buildGitIdentity(host, path);
      if (identity) {
        return identity;
      }
    }

    return getGitFallbackIdentity(hasGitPrefix, repo);
  }

  if (repo.includes("://")) {
    try {
      const parsed = new URL(repo);
      const identity = buildGitIdentity(parsed.hostname, parsed.pathname);
      if (identity) {
        return identity;
      }
    } catch {
      return getGitFallbackIdentity(hasGitPrefix, repo);
    }
  }

  const slashIndex = repo.indexOf("/");
  if (slashIndex < 0) {
    return getGitFallbackIdentity(hasGitPrefix, repo);
  }

  const host = repo.slice(0, slashIndex);
  const path = repo.slice(slashIndex + 1);
  if (host.includes(".") || host === "localhost") {
    const identity = buildGitIdentity(host, path);
    if (identity) {
      return identity;
    }
  }

  return getGitFallbackIdentity(hasGitPrefix, repo);
}

function normalizePackageSourceForCompare(source: string): string {
  const trimmed = source.trim();
  const gitIdentity = getGitSourceIdentity(trimmed);
  if (gitIdentity) {
    return gitIdentity;
  }

  if (trimmed.startsWith("npm:")) {
    const spec = trimmed.slice(4);
    return `npm:${stripVersionSuffix(spec).toLowerCase()}`;
  }

  if (
    trimmed.startsWith("./") ||
    trimmed.startsWith("../") ||
    trimmed.startsWith("/")
  ) {
    return `local:${trimmed}`;
  }

  return `npm:${stripVersionSuffix(trimmed).toLowerCase()}`;
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

function findMatchingOutdatedPackage(
  source: string,
  updates: PiPackageUpdate[],
): PiPackageUpdate | null {
  const normalizedSource = normalizePackageSourceForCompare(source);
  return (
    updates.find(
      (update) =>
        normalizePackageSourceForCompare(update.source) === normalizedSource,
    ) ?? null
  );
}

async function getUpdateAvailability(
  pi: ExtensionAPI,
  source: string,
  ctx: ExtensionCommandContext,
): Promise<UpdateAvailabilityResult> {
  const installed = await isConfiguredPackageInstalled(pi, source, ctx);
  if (!installed) {
    ctx.ui.notify(
      `Cannot update \"${source}\": extension is not installed.`,
      "error",
    );
    return { status: "error" };
  }

  const outdatedPackages = await listOutdatedPackages(
    pi,
    ctx,
    "Checking for available updates...",
  );
  if (!outdatedPackages) {
    return { status: "error" };
  }

  const matchingUpdate = findMatchingOutdatedPackage(source, outdatedPackages);
  if (!matchingUpdate) {
    return { status: "unavailable" };
  }

  return { status: "available", update: matchingUpdate };
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

  ctx.ui.notify("Checking for available updates...", "info");

  const availability = await getUpdateAvailability(pi, source, ctx);
  if (availability.status === "error") {
    return;
  }

  if (availability.status === "unavailable") {
    ctx.ui.notify(`No update available for \"${source}\".`, "info");
    return;
  }

  await runInstallOrUpdateCommand(
    pi,
    availability.update.source,
    "update",
    ctx,
  );
}

async function handleUpdateAllCommand(
  pi: ExtensionAPI,
  ctx: ExtensionCommandContext,
): Promise<void> {
  ctx.ui.notify("Checking for outdated extensions...", "info");

  const outdatedPackages = await listOutdatedPackages(
    pi,
    ctx,
    "Checking for outdated extensions...",
  );
  if (!outdatedPackages) {
    return;
  }

  if (outdatedPackages.length === 0) {
    ctx.ui.notify("All extensions are already up to date.", "info");
    return;
  }

  if (!ensureModelSelected(ctx)) {
    return;
  }

  ctx.ui.notify(
    `Found ${outdatedPackages.length} outdated package(s). Auditing each before update...`,
    "info",
  );

  for (const pkg of outdatedPackages) {
    const proceed = await ctx.ui.confirm(
      "Audit Package",
      `Audit and update "${pkg.source}"?`,
    );
    if (!proceed) {
      continue;
    }

    await runInstallOrUpdateCommand(pi, pkg.source, "update", ctx);
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
