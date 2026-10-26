/** Baseline: снимок уже известных находок. С ним в CI падают только новые проблемы, а старый долг не мешает. */
import { createHash } from "node:crypto";
import type { Finding } from "./types.js";

export interface Baseline {
  version: 1;
  fingerprints: string[];
}

/** Отпечаток не зависит от пути к файлу, порядка находок и текста-доказательства: только правило, место и сообщение. */
export function fingerprint(f: Finding): string {
  return createHash("sha256").update(`${f.rule}\u0000${f.where}\u0000${f.message}`).digest("hex").slice(0, 16);
}

export function makeBaseline(findings: Finding[]): Baseline {
  return { version: 1, fingerprints: [...new Set(findings.map(fingerprint))].sort() };
}

export function parseBaseline(raw: string): Baseline {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new Error("baseline: файл не является JSON");
  }
  const b = data as Partial<Baseline> | null;
  if (!b || b.version !== 1 || !Array.isArray(b.fingerprints) || b.fingerprints.some((x) => typeof x !== "string")) {
    throw new Error("baseline: неизвестный формат файла");
  }
  return { version: 1, fingerprints: b.fingerprints };
}

export function applyBaseline(findings: Finding[], baseline: Baseline): { kept: Finding[]; suppressed: number } {
  const known = new Set(baseline.fingerprints);
  const kept = findings.filter((f) => !known.has(fingerprint(f)));
  return { kept, suppressed: findings.length - kept.length };
}
