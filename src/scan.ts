import { RULE_BY_ID } from "./rules/catalog.js";
import { checkServer } from "./rules/config.js";
import { checkAcross, checkTool } from "./rules/tools.js";
import { type Finding, type Inventory, type Severity, severityRank } from "./types.js";

export interface ScanOptions {
  ignore?: string[];
  minSeverity?: Severity;
}

function key(f: Finding): string {
  return `${f.rule}|${f.where}|${f.message}`;
}

export function scan(inv: Inventory, opts: ScanOptions = {}): Finding[] {
  const found: Finding[] = [];
  for (const t of inv.tools) found.push(...checkTool(t));
  found.push(...checkAcross(inv.tools));
  for (const s of inv.servers) found.push(...checkServer(s));
  const ignore = new Set((opts.ignore ?? []).map((r) => r.toUpperCase()));
  const floor = opts.minSeverity ? severityRank(opts.minSeverity) : Number.MAX_SAFE_INTEGER;
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of found) {
    if (ignore.has(f.rule) || severityRank(f.severity) > floor) continue;
    if (seen.has(key(f))) continue;
    seen.add(key(f));
    out.push(f);
  }
  return out.sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.rule.localeCompare(b.rule) || a.where.localeCompare(b.where));
}

export function describe(rule: string): string {
  return RULE_BY_ID.get(rule)?.title ?? rule;
}
