import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
} from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { sep } from "node:path";
import { realpathSync } from "node:fs";

export interface SourceFile {
  path: string;
  content: string;
}

export interface ResolvedSource {
  name: string;
  files: SourceFile[];
  /** SHA-256 of the npm tarball or git commit hash, if available */
  integrity?: string;
}

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

const TEXT_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
  ".md",
  ".yaml",
  ".yml",
  ".toml",
  ".txt",
  ".sh",
  ".css",
  ".html",
  ".svg",
]);

// dist/ is intentionally NOT ignored: most npm extensions ship only compiled
// code in dist/, so excluding it would audit an effectively empty codebase.
const IGNORE_DIRS = new Set([
  "node_modules",
  ".git",
  ".turbo",
  ".next",
  "coverage",
]);

const NPM_SPEC_RE = /^(@[a-z0-9][\w.\-]*\/)?[a-z0-9][\w.\-]*(@[\w.+\-]+)?$/i;
const GIT_URL_RE =
  /^(https:\/\/[a-zA-Z0-9.\-]+\/|ssh:\/\/git@[a-zA-Z0-9.\-]+[:/]|git@[a-zA-Z0-9.\-]+:)[a-zA-Z0-9._\-/]+$/;
const GIT_REF_RE = /^[\w.][\w.\-/]*$/;

function isTextFile(filePath: string): boolean {
  const dot = filePath.lastIndexOf(".");
  if (dot === -1) return false;
  const ext = filePath.substring(dot).toLowerCase();
  return TEXT_EXTENSIONS.has(ext);
}

function sha256File(filePath: string): string {
  const hash = createHash("sha256");
  hash.update(readFileSync(filePath));
  return hash.digest("hex");
}

function collectFiles(dir: string, baseDir: string): SourceFile[] {
  const files: SourceFile[] = [];
  const entries = readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    if (entry.name.startsWith(".") && entry.name !== ".pi") continue;
    if (IGNORE_DIRS.has(entry.name)) continue;

    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectFiles(fullPath, baseDir));
    } else if (entry.isFile()) {
      const relPath = relative(baseDir, fullPath);
      const stat = statSync(fullPath);

      if (stat.size > MAX_FILE_SIZE) {
        files.push({
          path: relPath,
          content: `[FILE SKIPPED: ${stat.size} bytes exceeds ${MAX_FILE_SIZE} byte audit limit]`,
        });
        continue;
      }

      if (isTextFile(entry.name)) {
        try {
          files.push({
            path: relPath,
            content: readFileSync(fullPath, "utf-8"),
          });
        } catch {
          files.push({
            path: relPath,
            content: `[FILE UNREADABLE: could not read as UTF-8, ${stat.size} bytes]`,
          });
        }
      } else {
        const hash = sha256File(fullPath);
        files.push({
          path: relPath,
          content: `[BINARY/NON-TEXT FILE: ${stat.size} bytes, sha256=${hash}]`,
        });
      }
    }
  }
  return files;
}

function validateNpmSpec(spec: string): void {
  if (!NPM_SPEC_RE.test(spec)) {
    throw new Error(
      `Invalid npm package spec: "${spec}". ` +
        "Must match @scope/name or name, optionally with @version.",
    );
  }
}

function validateGitUrl(url: string): void {
  if (!GIT_URL_RE.test(url)) {
    throw new Error(
      `Invalid git URL: "${url}". ` +
        "Must start with https://, ssh://git@, or git@ with valid host/path characters.",
    );
  }
}

function validateGitRef(ref: string): void {
  if (!GIT_REF_RE.test(ref) || ref.includes("..")) {
    throw new Error(
      `Invalid git ref: "${ref}". ` +
        "Must contain only alphanumerics, dots, hyphens, underscores, and slashes. No '..' allowed.",
    );
  }
}

function parseSource(source: string): {
  type: "npm" | "git" | "local";
  value: string;
} {
  if (source.startsWith("npm:")) {
    const spec = source.slice(4);
    validateNpmSpec(spec);
    return { type: "npm", value: spec };
  }
  if (source.startsWith("git:")) {
    const url = source.slice(4);
    // ref validation happens in resolveGit after splitting
    return { type: "git", value: url };
  }
  if (
    source.startsWith("https://github.com/") ||
    source.startsWith("ssh://git@") ||
    source.startsWith("git@")
  ) {
    return { type: "git", value: source };
  }
  if (
    source.startsWith("./") ||
    source.startsWith("/") ||
    source.startsWith("../")
  ) {
    return { type: "local", value: source };
  }
  // Default to npm
  validateNpmSpec(source);
  return { type: "npm", value: source };
}

export async function resolveSource(source: string): Promise<ResolvedSource> {
  const parsed = parseSource(source);

  switch (parsed.type) {
    case "local":
      return resolveLocal(parsed.value);
    case "npm":
      return resolveNpm(parsed.value);
    case "git":
      return resolveGit(parsed.value);
  }
}

function resolveLocal(path: string): ResolvedSource {
  const resolved = resolve(process.cwd(), path);
  if (!existsSync(resolved)) {
    throw new Error(`Local path not found: ${resolved}`);
  }
  return {
    name: path,
    files: collectFiles(resolved, resolved),
  };
}

async function resolveNpm(spec: string): Promise<ResolvedSource> {
  // Check if already installed globally
  try {
    const globalRoot = execFileSync("npm", ["root", "-g"], {
      encoding: "utf-8",
      stdio: "pipe",
    }).trim();
    const pkgName = spec.replace(/@[^/]*$/, "");
    const installedPath = join(globalRoot, pkgName);
    if (existsSync(installedPath)) {
      return {
        name: spec,
        files: collectFiles(installedPath, installedPath),
      };
    }
  } catch {
    // not installed globally, continue
  }

  const tmpDir = await mkdtemp(join(tmpdir(), "pi-secure-audit-"));
  try {
    execFileSync(
      "npm",
      ["pack", spec, "--pack-destination", tmpDir, "--ignore-scripts"],
      { encoding: "utf-8", stdio: "pipe" },
    );

    const tarballs = readdirSync(tmpDir).filter((f) => f.endsWith(".tgz"));
    if (tarballs.length === 0) {
      throw new Error(`npm pack produced no tarball for ${spec}`);
    }

    const tarball = join(tmpDir, tarballs[0]!);
    const tarballHash = sha256File(tarball);

    const extractDir = join(tmpDir, "extracted");
    mkdirSync(extractDir, { recursive: true });
    execFileSync(
      "tar",
      ["xzf", tarball, "-C", extractDir, "--no-same-owner", "--no-same-permissions"],
      { encoding: "utf-8", stdio: "pipe" },
    );

    const packageDir = join(extractDir, "package");
    const realPkgDir = realpathSync(packageDir);
    const realExtractDir = realpathSync(extractDir);
    if (!realPkgDir.startsWith(realExtractDir + sep)) {
      throw new Error(
        "Tarball path traversal detected: extracted path escapes temp directory",
      );
    }
    const sourceDir = existsSync(packageDir) ? packageDir : extractDir;

    return {
      name: spec,
      files: collectFiles(sourceDir, sourceDir),
      integrity: `sha256:${tarballHash}`,
    };
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
}

async function resolveGit(url: string): Promise<ResolvedSource> {
  let gitUrl = url;
  if (url.startsWith("github.com/")) {
    gitUrl = `https://${url}`;
  }

  // Extract ref if present (e.g. @v1.0.0)
  let ref: string | undefined;
  const atMatch = gitUrl.match(/^(.+?)@(v?\d.*)$/);
  if (atMatch) {
    gitUrl = atMatch[1]!;
    ref = atMatch[2]!;
    validateGitRef(ref);
  }

  validateGitUrl(gitUrl);

  const tmpDir = await mkdtemp(join(tmpdir(), "pi-secure-audit-git-"));
  try {
    const repoDir = join(tmpDir, "repo");
    const cloneArgs = ref
      ? ["clone", "--depth", "1", "--branch", ref, gitUrl, repoDir]
      : ["clone", "--depth", "1", gitUrl, repoDir];

    execFileSync("git", cloneArgs, { encoding: "utf-8", stdio: "pipe" });

    // Capture commit hash for integrity
    const commitHash = execFileSync("git", ["rev-parse", "HEAD"], {
      encoding: "utf-8",
      stdio: "pipe",
      cwd: repoDir,
    }).trim();

    return {
      name: url,
      files: collectFiles(repoDir, repoDir),
      integrity: `git:${commitHash}`,
    };
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
}

export async function resolveInstalledSource(
  installedPath: string,
): Promise<ResolvedSource> {
  if (!existsSync(installedPath)) {
    throw new Error(`Installed path not found: ${installedPath}`);
  }
  return {
    name: installedPath,
    files: collectFiles(installedPath, installedPath),
  };
}
