import { RULES, RULE_BY_ID } from "./rules/catalog.js";
import { type Finding, type Inventory, SEVERITY_ORDER, type Severity } from "./types.js";

const RED = "\x1b[38;2;179;0;15m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";
const MARK: Record<Severity, string> = { critical: "▓▓", high: "▓", medium: "▒", low: "░", info: "·" };
const LABEL: Record<Severity, string> = { critical: "критично", high: "высокий", medium: "средний", low: "низкий", info: "инфо" };

export function counts(findings: Finding[]): Record<Severity, number> {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

export function renderText(inv: Inventory, findings: Finding[], color: boolean, suppressed = 0): string {
  const paint = (code: string, s: string) => (color && code ? `${code}${s}${RESET}` : s);
  const out: string[] = [];
  out.push(paint(BOLD, "basilisk") + paint(DIM, `  файлов ${inv.files.length}, серверов ${inv.servers.length}, инструментов ${inv.tools.length}`));
  for (const s of inv.skipped) out.push(paint(DIM, `  пропущен ${s.file}: ${s.reason}`));
  if (!findings.length) out.push("", "  находок нет по проверенным правилам");
  for (const f of findings) {
    const hot = f.severity === "critical" || f.severity === "high";
    out.push("", `${paint(hot ? RED : "", MARK[f.severity].padEnd(2))} ${paint(hot ? RED + BOLD : BOLD, LABEL[f.severity].padEnd(8))} ${f.rule}  ${f.where}`);
    out.push(`     ${f.message}`);
    if (f.evidence) out.push(paint(DIM, `     ↳ ${f.evidence}`));
  }
  const c = counts(findings);
  out.push("", paint(DIM, SEVERITY_ORDER.map((s) => `${LABEL[s]} ${c[s]}`).join("  ·  ")));
  if (suppressed) out.push(paint(DIM, `скрыто по baseline: ${suppressed}`));
  return out.join("\n") + "\n";
}

export function renderJson(inv: Inventory, findings: Finding[], suppressed = 0): string {
  return JSON.stringify({
    summary: { files: inv.files.length, servers: inv.servers.length, tools: inv.tools.length, counts: counts(findings), suppressed, skipped: inv.skipped },
    findings,
  }, null, 2) + "\n";
}

const SARIF_LEVEL: Record<Severity, "error" | "warning" | "note"> = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
const SECURITY_SEVERITY: Record<Severity, string> = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" };

export function renderSarif(findings: Finding[], version: string): string {
  const used = new Set(findings.map((f) => f.rule));
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "basilisk",
          version,
          rules: RULES.filter((r) => used.has(r.id)).map((r) => ({
            id: r.id,
            name: r.title,
            shortDescription: { text: r.title },
            help: { text: r.fix },
            defaultConfiguration: { level: SARIF_LEVEL[r.severity] },
            properties: { tags: ["security", r.owasp], "security-severity": SECURITY_SEVERITY[r.severity] },
          })),
        },
      },
      results: findings.map((f) => ({
        ruleId: f.rule,
        ruleIndex: RULES.filter((r) => used.has(r.id)).findIndex((r) => r.id === f.rule),
        level: SARIF_LEVEL[f.severity],
        message: { text: f.evidence ? `${f.message}: ${f.evidence}` : f.message },
        locations: [{ physicalLocation: { artifactLocation: { uri: (f.source ?? "unknown").replace(/\\/g, "/") }, region: { startLine: 1 } }, logicalLocations: [{ name: f.where }] }],
        properties: { where: f.where, severity: f.severity },
      })),
    }],
  };
  return JSON.stringify(sarif, null, 2) + "\n";
}

export function renderRules(color: boolean): string {
  const paint = (code: string, s: string) => (color ? `${code}${s}${RESET}` : s);
  return RULES.map((r) => `${paint(BOLD, r.id)}  ${r.severity.padEnd(8)} ${r.title}\n       ${paint(DIM, r.owasp)}\n       ${r.fix}`).join("\n\n") + "\n";
}

export function ruleTitle(id: string): string {
  return RULE_BY_ID.get(id)?.title ?? id;
}
