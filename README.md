# pi-secure-extension

A Pi extension that performs security audits on other extensions before install or update. Uses the currently selected AI model to analyze extension source code against configurable audit rules.

## Installation

```bash
pi install ./path/to/pi-secure-extension
# or after publishing:
pi install npm:pi-secure-extension
```

## Commands

### `/secure:install <source> [-l]`

Audit an extension, then install it if you approve.

```
/secure:install npm:@foo/bar
/secure:install git:github.com/user/repo
/secure:install ./local/path
/secure:install npm:@foo/bar -l   # install locally
```

### `/secure:update <source>`

Audit an extension, then update it if you approve.

```
/secure:update npm:@foo/bar
```

### `/secure:update-all`

Check all installed extensions for updates, audit each one, and prompt to update.

```
/secure:update-all
```

### `/secure:rules`

Edit the security audit rules. Opens a selector to choose:
- **Edit global rules** — applies to all projects
- **Edit local rules** — applies to the current project only
- **Reset to defaults** — restore the bundled audit rules

## How It Works

1. Resolves the extension source (npm, git, or local path)
2. Reads all source files **in memory** (temp files are cleaned up immediately)
3. Sends the source code + audit rules to the currently selected AI model
4. Displays the audit results with risk assessment and integrity hash
5. Asks for confirmation before proceeding with install/update

## Audit Rules

The audit checks for:
- **Data exfiltration** — network requests sending data to external servers
- **File system access** — reading sensitive files (.env, SSH keys, credentials)
- **Code execution** — eval, child_process, dynamic imports
- **Supply chain risks** — suspicious dependencies, postinstall scripts
- **Permission escalation** — modifying other extensions' behavior
- **Obfuscation** — minified/encoded code
- **Privacy violations** — undisclosed telemetry
- **Denial of service** — resource exhaustion patterns

### Customizing Rules

The audit rules are defined in a markdown file. The extension looks for rules in this order:

1. `.pi/extensions/secure-extension-audit-rules.md` (project-local, **requires user confirmation**)
2. `~/.pi/agent/extensions/secure-extension-audit-rules.md` (global)
3. Bundled `audit-rules/default.md` (built-in)

Use `/secure:rules` to edit them, or manually create/edit the markdown file.

## Requirements

- A model must be selected in Pi (Ctrl+P or /model)
- `npm` must be available for auditing npm packages
- `git` must be available for auditing git packages

## Limitations & Threat Model

This extension is an **additional safety layer**, not a security guarantee.

- **LLM-based analysis is fallible.** The AI model can miss obfuscated code, sophisticated prompt injection within source comments, or novel attack vectors. It may also produce false positives.
- **Not a substitute for human code review.** For high-security environments, always pair this audit with manual review by a qualified developer.
- **Binary and oversized files are flagged but not analyzed.** Non-text files (`.wasm`, `.node`, `.so`, etc.) appear as metadata entries with SHA-256 hashes. Files exceeding 5 MB are included as size-only placeholders. The LLM sees that these exist but cannot inspect their contents.
- **Project-local audit rules require explicit user confirmation.** A malicious project could ship custom audit rules designed to suppress findings. The extension prompts the user before applying any project-local rules.
- **Audit and install are separate downloads.** The extension audits a snapshot of the package, but `pi install` downloads independently from the registry. If the package was updated between audit and install, the installed version may differ. The integrity hash (SHA-256 for npm, commit hash for git) is shown so you can verify consistency.
- **Prompt injection via source code is mitigated but not eliminated.** The audited source is wrapped in `<UNTRUSTED_CODE>` markers and the system prompt instructs the model to treat all source content as data. However, sufficiently creative injection attempts may still affect model behavior.
- **npm lifecycle scripts are suppressed during audit** (`--ignore-scripts`), but `pi install` runs them normally. A malicious `postinstall` script would execute during installation even if the audit flagged it.
