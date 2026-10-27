/** Поиск конфигов MCP-клиентов в стандартных местах. Ищет только в домашней папке пользователя и в текущей папке проекта. */
import { statSync } from "node:fs";
import { join } from "node:path";

export type Platform = "darwin" | "linux" | "win32";

/** Где у разных клиентов лежит конфиг MCP-серверов. Пути зависят от системы, поэтому платформа передаётся явно. */
export function candidatePaths(home: string, platform: Platform, env: Record<string, string | undefined> = {}, cwd?: string): string[] {
  const j = (...p: string[]) => join(home, ...p);
  const common = [j(".cursor", "mcp.json"), j(".claude.json"), j(".codeium", "windsurf", "mcp_config.json")];
  let specific: string[];
  if (platform === "darwin") {
    specific = [j("Library", "Application Support", "Claude", "claude_desktop_config.json"), j("Library", "Application Support", "Code", "User", "mcp.json")];
  } else if (platform === "win32") {
    const appdata = env["APPDATA"] ?? j("AppData", "Roaming");
    specific = [join(appdata, "Claude", "claude_desktop_config.json"), join(appdata, "Code", "User", "mcp.json")];
  } else {
    const config = env["XDG_CONFIG_HOME"] ?? j(".config");
    specific = [join(config, "Claude", "claude_desktop_config.json"), join(config, "Code", "User", "mcp.json")];
  }
  const project = cwd ? [join(cwd, ".mcp.json"), join(cwd, ".cursor", "mcp.json"), join(cwd, ".vscode", "mcp.json")] : [];
  return [...specific, ...common, ...project];
}

function isFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/** Только существующие файлы, без повторов, в порядке просмотра. */
export function discover(home: string, platform: Platform, env: Record<string, string | undefined> = {}, cwd?: string): string[] {
  return [...new Set(candidatePaths(home, platform, env, cwd))].filter(isFile);
}
