import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const EXTENSION_NAME = "secure-extension";
const GLOBAL_RULES_PATH = resolve(
  homedir(),
  `.pi/agent/extensions/${EXTENSION_NAME}-audit-rules.md`,
);
const DEFAULT_RULES_PATH = resolve(__dirname, "../audit-rules/default.md");

function findLocalRulesPath(): string | null {
  let dir = process.cwd();
  const home = homedir();

  while (true) {
    if (dir === home) break;
    const piDir = resolve(dir, ".pi");
    if (existsSync(piDir)) {
      return resolve(piDir, `extensions/${EXTENSION_NAME}-audit-rules.md`);
    }
    const parent = resolve(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

export function getGlobalRulesPath(): string {
  return GLOBAL_RULES_PATH;
}

export function getLocalRulesPath(): string | null {
  return findLocalRulesPath();
}

export function getDefaultRulesPath(): string {
  return DEFAULT_RULES_PATH;
}

export type ConfirmFn = (
  title: string,
  message: string,
) => Promise<boolean>;

export async function loadAuditRules(
  confirm?: ConfirmFn,
): Promise<string> {
  const localPath = findLocalRulesPath();
  if (localPath && existsSync(localPath)) {
    if (confirm) {
      const trusted = await confirm(
        "Project-Local Audit Rules Detected",
        `Use project-local audit rules from:\n${localPath}\n\n` +
          "These override the global/default rules and could be malicious " +
          "if placed by an untrusted project. Accept?",
      );
      if (trusted) {
        return readFile(localPath, "utf-8");
      }
      // Rejected — fall through to global/default
    }
    // No confirm fn provided — skip local rules for safety
  }

  if (existsSync(GLOBAL_RULES_PATH)) {
    return readFile(GLOBAL_RULES_PATH, "utf-8");
  }

  return readFile(DEFAULT_RULES_PATH, "utf-8");
}

export async function loadDefaultRules(): Promise<string> {
  return readFile(DEFAULT_RULES_PATH, "utf-8");
}
