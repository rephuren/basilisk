/** Загрузка конфигов MCP-клиентов и списков инструментов (ответ tools/list) из файлов и папок. Сеть не используется. */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join } from "node:path";
import type { Inventory, ServerConfig, Tool } from "./types.js";

export const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_DEPTH = 6;
const MAX_FILES = 5_000;
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".venv", "__pycache__"]);

type Json = unknown;

function isRecord(v: Json): v is Record<string, Json> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function asStringRecord(v: Json): Record<string, string> {
  const out: Record<string, string> = {};
  if (!isRecord(v)) return out;
  for (const [k, val] of Object.entries(v)) if (typeof val === "string") out[k] = val;
  return out;
}

function asStringArray(v: Json): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

function toolFrom(raw: Json, server: string, source: string): Tool | null {
  if (!isRecord(raw) || typeof raw["name"] !== "string") return null;
  const tool: Tool = { server, name: raw["name"], source };
  if (typeof raw["description"] === "string") tool.description = raw["description"];
  const schema = raw["inputSchema"] ?? raw["input_schema"] ?? raw["parameters"];
  if (schema !== undefined) tool.inputSchema = schema;
  return tool;
}

function serversFrom(map: Json, source: string): ServerConfig[] {
  if (!isRecord(map)) return [];
  const out: ServerConfig[] = [];
  for (const [name, raw] of Object.entries(map)) {
    if (!isRecord(raw)) continue;
    const cfg: ServerConfig = { name, args: asStringArray(raw["args"]), env: asStringRecord(raw["env"]), source };
    if (typeof raw["command"] === "string") cfg.command = raw["command"];
    const url = raw["url"] ?? raw["serverUrl"];
    if (typeof url === "string") cfg.url = url;
    if (cfg.command || cfg.url) out.push(cfg);
  }
  return out;
}

/** Распознаёт форму документа. Возвращает null, если это не конфиг MCP и не список инструментов. */
export function parseDocument(doc: Json, source: string): { tools: Tool[]; servers: ServerConfig[] } | null {
  const fallback = basename(source).replace(/\.json$/i, "");
  if (isRecord(doc)) {
    const servers = serversFrom(doc["mcpServers"] ?? doc["servers"] ?? doc["context_servers"], source);
    if (servers.length) return { tools: [], servers };
    const result = isRecord(doc["result"]) ? doc["result"] : doc;
    if (Array.isArray(result["tools"])) {
      const label = typeof doc["server"] === "string" ? doc["server"] : fallback;
      return { tools: result["tools"].map((t) => toolFrom(t, label, source)).filter((t): t is Tool => t !== null), servers: [] };
    }
    return null;
  }
  if (Array.isArray(doc)) {
    const tools = doc.map((t) => toolFrom(t, fallback, source)).filter((t): t is Tool => t !== null);
    return tools.length ? { tools, servers: [] } : null;
  }
  return null;
}

function* walk(path: string, depth: number, state: { count: number }): Generator<string> {
  let st;
  try {
    st = statSync(path);
  } catch {
    return;
  }
  if (st.isFile()) {
    if (path.toLowerCase().endsWith(".json") && state.count++ < MAX_FILES) yield path;
    return;
  }
  if (!st.isDirectory() || depth > MAX_DEPTH) return;
  let names: string[];
  try {
    names = readdirSync(path).sort();
  } catch {
    return;
  }
  for (const name of names) {
    if (SKIP_DIRS.has(name) || name.startsWith(".")) continue;
    yield* walk(join(path, name), depth + 1, state);
  }
}

export function loadInventory(paths: string[]): Inventory {
  const inv: Inventory = { tools: [], servers: [], files: [], skipped: [] };
  const state = { count: 0 };
  for (const root of paths) {
    let explicit = false;
    try {
      explicit = statSync(root).isFile();
    } catch {
      inv.skipped.push({ file: root, reason: "путь не найден" });
      continue;
    }
    for (const file of explicit ? [root] : walk(root, 0, state)) {
      try {
        if (statSync(file).size > MAX_FILE_BYTES) {
          inv.skipped.push({ file, reason: `больше ${MAX_FILE_BYTES / 1024 / 1024} МБ` });
          continue;
        }
        const raw = readFileSync(file, "utf8").replace(/^﻿/, "");
        const parsed = parseDocument(JSON.parse(raw) as Json, file);
        if (!parsed) {
          if (explicit) inv.skipped.push({ file, reason: "не похоже на конфиг MCP или список инструментов" });
          continue;
        }
        inv.tools.push(...parsed.tools);
        inv.servers.push(...parsed.servers);
        inv.files.push(file);
      } catch (e) {
        inv.skipped.push({ file, reason: e instanceof SyntaxError ? "не JSON" : "не удалось прочитать" });
      }
    }
  }
  return inv;
}
