import type { Finding, Inventory, ServerConfig, Tool } from "../src/types.js";

export function tool(name: string, description: string | undefined, inputSchema?: unknown, server = "srv"): Tool {
  const t: Tool = { server, name, source: "test.json" };
  if (description !== undefined) t.description = description;
  if (inputSchema !== undefined) t.inputSchema = inputSchema;
  return t;
}

export function inv(tools: Tool[] = [], servers: ServerConfig[] = []): Inventory {
  return { tools, servers, files: ["test.json"], skipped: [] };
}

export function server(name: string, command: string | undefined, args: string[] = [], env: Record<string, string> = {}, url?: string): ServerConfig {
  const s: ServerConfig = { name, args, env, source: "test.json" };
  if (command !== undefined) s.command = command;
  if (url !== undefined) s.url = url;
  return s;
}

export const ids = (f: Finding[]): string[] => f.map((x) => x.rule);
export const tagHidden = (text: string): string => [...text].map((c) => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join("");
export const obj = (properties: Record<string, unknown>) => ({ type: "object", additionalProperties: false, properties });
