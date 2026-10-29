// Считает полноту и точность правил BSK001 и BSK004 на размеченном наборе tests/corpus/corpus.json.
// Запуск: npm run build && node scripts/eval-corpus.mjs [--json] [--misses]
import { readFileSync } from "node:fs";
import { checkTool } from "../dist/src/rules/tools.js";

export const RULES = ["BSK001", "BSK004"];

export function evaluate(corpus) {
  const stats = Object.fromEntries(RULES.map((r) => [r, { tp: 0, fp: 0, fn: 0, tn: 0, missed: [], false: [] }]));
  for (const ex of corpus) {
    const got = new Set(checkTool({ server: "corpus", name: "t", description: ex.text, source: "corpus" }).map((f) => f.rule));
    for (const r of RULES) {
      const want = ex.rules.includes(r);
      const s = stats[r];
      if (want && got.has(r)) s.tp++;
      else if (want) (s.fn++, s.missed.push(ex));
      else if (got.has(r)) (s.fp++, s.false.push(ex));
      else s.tn++;
    }
  }
  for (const s of Object.values(stats)) {
    s.precision = s.tp + s.fp ? s.tp / (s.tp + s.fp) : 1;
    s.recall = s.tp + s.fn ? s.tp / (s.tp + s.fn) : 1;
  }
  return stats;
}

export function loadCorpus(path = new URL("../tests/corpus/corpus.json", import.meta.url)) {
  return JSON.parse(readFileSync(path, "utf8"));
}

if (process.argv[1] && import.meta.url === new URL(process.argv[1], "file://").href) {
  const stats = evaluate(loadCorpus());
  if (process.argv.includes("--json")) {
    console.log(JSON.stringify(Object.fromEntries(RULES.map((r) => [r, { tp: stats[r].tp, fp: stats[r].fp, fn: stats[r].fn, tn: stats[r].tn, precision: +stats[r].precision.toFixed(3), recall: +stats[r].recall.toFixed(3) }])), null, 1));
  } else {
    console.log("правило   TP  FP  FN  TN  precision  recall");
    for (const r of RULES) {
      const s = stats[r];
      console.log(`${r}   ${String(s.tp).padStart(3)} ${String(s.fp).padStart(3)} ${String(s.fn).padStart(3)} ${String(s.tn).padStart(3)}  ${s.precision.toFixed(2).padStart(9)}  ${s.recall.toFixed(2).padStart(6)}`);
      if (process.argv.includes("--misses")) {
        for (const e of s.missed) console.log(`   пропуск  [${e.lang}] ${e.text}`);
        for (const e of s.false) console.log(`   ложное   [${e.lang}] ${e.text}`);
      }
    }
  }
}
