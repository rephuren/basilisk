#!/usr/bin/env node
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { loadInventory } from "./load.js";
import { applyBaseline, makeBaseline, parseBaseline } from "./baseline.js";
import { type Platform, discover } from "./discover.js";
import { makeLock, parseLock, verify } from "./pin.js";
import { renderJson, renderRules, renderSarif, renderText } from "./report.js";
import { scan } from "./scan.js";
import { type Finding, SEVERITY_ORDER, type Severity, severityRank } from "./types.js";

const HELP = `basilisk: статический аудит MCP-серверов и описаний инструментов LLM

использование:
  basilisk scan <путь...>      проверить конфиги и списки инструментов (файлы или папки)
  basilisk pin <путь...>       закрепить текущие определения в lock-файле
  basilisk verify <путь...>    сравнить с lock-файлом: найти подмену определений
  basilisk baseline <путь...>  записать текущие находки как известные (--out, по умолчанию basilisk.baseline.json)
  basilisk rules               список правил

опции scan:
  --format text|json|sarif     формат отчёта (по умолчанию text)
  --out <файл>                 записать отчёт в файл
  --fail-on <уровень>          код возврата 1, если есть находки не ниже уровня (по умолчанию high; none отключает)
  --min-severity <уровень>     не показывать находки ниже уровня
  --ignore <ID,ID>             отключить правила
  --baseline <файл>            не показывать находки, уже записанные в baseline
  --auto                       найти конфиги клиентов (Claude Desktop, Cursor, VS Code, Windsurf, .mcp.json) и проверить их
общие:
  --lock <файл>                lock-файл для pin и verify (по умолчанию basilisk.lock.json)
  --no-color, --version, --help

коды возврата: 0 чисто, 1 есть находки выше порога, 2 ошибка использования или чтения`;

function version(): string {
  try {
    const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

function level(value: string | undefined, name: string, allowNone = false): Severity | "none" | undefined {
  if (value === undefined) return undefined;
  if (allowNone && value === "none") return "none";
  if ((SEVERITY_ORDER as string[]).includes(value)) return value as Severity;
  throw new Error(`--${name}: ожидается ${SEVERITY_ORDER.join(", ")}${allowNone ? " или none" : ""}`);
}

export function run(argv: string[], write: (s: string) => void = (s) => process.stdout.write(s), isTty = Boolean(process.stdout.isTTY)): number {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        format: { type: "string" }, out: { type: "string" }, "fail-on": { type: "string" }, "min-severity": { type: "string" },
        ignore: { type: "string" }, lock: { type: "string" }, baseline: { type: "string" }, auto: { type: "boolean" }, "no-color": { type: "boolean" }, version: { type: "boolean" }, help: { type: "boolean" },
      },
    });
    const { values, positionals } = parsed;
    if (values.version) return write(`${version()}\n`), 0;
    const [command, ...paths] = positionals;
    if (values.help || !command) return write(`${HELP}\n`), command || values.help ? 0 : 2;
    const color = isTty && !values["no-color"] && !process.env["NO_COLOR"];
    if (command === "rules") return write(renderRules(color)), 0;
    if (!["scan", "pin", "verify", "baseline"].includes(command)) throw new Error(`неизвестная команда «${command}»`);
    if (values.auto && command !== "scan" && command !== "baseline") throw new Error("--auto применяется только к scan и baseline");
    if (values.auto) {
      const found = discover(homedir(), process.platform as Platform, process.env, process.cwd());
      write(found.length ? `найдено конфигов клиентов: ${found.length}\n${found.map((f) => `  ${f}`).join("\n")}\n` : "конфиги клиентов в стандартных местах не найдены\n");
      paths.push(...found);
      if (!paths.length) return 0;
    }
    if (!paths.length) throw new Error(`${command}: укажите хотя бы один путь или --auto`);

    const inv = loadInventory(paths);
    const lockPath = values.lock ?? "basilisk.lock.json";

    if (command === "pin") {
      writeFileSync(lockPath, JSON.stringify(makeLock(inv), null, 2) + "\n");
      write(`закреплено: инструментов ${inv.tools.length}, серверов ${inv.servers.length} → ${lockPath}\n`);
      return inv.tools.length + inv.servers.length === 0 ? 2 : 0;
    }

    if (values.baseline && command !== "scan") throw new Error("--baseline применяется только к scan");
    let suppressed = 0;
    let findings: Finding[];
    if (command === "baseline") {
      const min = level(values["min-severity"], "min-severity");
      const all = scan(inv, { ignore: (values.ignore ?? "").split(",").filter(Boolean), ...(min && min !== "none" ? { minSeverity: min } : {}) });
      const target = values.out ?? "basilisk.baseline.json";
      writeFileSync(target, JSON.stringify(makeBaseline(all), null, 2) + "\n");
      write(`baseline: записано находок ${all.length} → ${target}\n`);
      return 0;
    }
    if (command === "verify") {
      findings = verify(inv, parseLock(readFileSync(lockPath, "utf8")));
    } else {
      const min = level(values["min-severity"], "min-severity");
      findings = scan(inv, { ignore: (values.ignore ?? "").split(",").filter(Boolean), ...(min && min !== "none" ? { minSeverity: min } : {}) });
      if (values.baseline) {
        const applied = applyBaseline(findings, parseBaseline(readFileSync(values.baseline, "utf8")));
        findings = applied.kept;
        suppressed = applied.suppressed;
      }
    }
    const format = values.format ?? "text";
    let report: string;
    if (format === "json") report = renderJson(inv, findings, suppressed);
    else if (format === "sarif") report = renderSarif(findings, version());
    else if (format === "text") report = renderText(inv, findings, color && !values.out, suppressed);
    else throw new Error(`--format: ожидается text, json или sarif`);
    if (values.out) {
      writeFileSync(values.out, report);
      write(`отчёт сохранён: ${values.out}\n`);
    } else {
      write(report);
    }
    const failOn = level(values["fail-on"], "fail-on", true) ?? "high";
    if (failOn === "none") return 0;
    return findings.some((f) => severityRank(f.severity) <= severityRank(failOn)) ? 1 : 0;
  } catch (e) {
    process.stderr.write(`ошибка: ${e instanceof Error ? e.message : String(e)}\n`);
    return 2;
  }
}

const entry = process.argv[1] ? realpathSync(process.argv[1]) : "";
if (entry === fileURLToPath(import.meta.url)) process.exitCode = run(process.argv.slice(2));
