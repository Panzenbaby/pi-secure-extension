import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { registerSecureCommands } from "./commands.js";
import { renderAuditResult } from "./ui.js";

export default async function (pi: ExtensionAPI) {
  pi.registerMessageRenderer("secure-audit-result", renderAuditResult);
  registerSecureCommands(pi);
}
