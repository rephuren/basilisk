/** Правила по запуску серверов: откуда берётся код, какие секреты лежат в файле, какие права получает процесс. */
import { mask } from "../text.js";
import type { Finding, ServerConfig } from "../types.js";

const SECRET_PATTERNS: { re: RegExp; label: string }[] = [
  { re: /\bghp_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b|\bgh[ousr]_[A-Za-z0-9]{30,}\b/, label: "токен GitHub" },
  { re: /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b/, label: "ключ API (формат sk-…)" },
  { re: /\bAKIA[0-9A-Z]{16}\b/, label: "ключ доступа AWS" },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, label: "токен Slack" },
  { re: /\bAIza[0-9A-Za-z_-]{35}\b/, label: "ключ Google API" },
  { re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, label: "JWT" },
  { re: /-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/, label: "приватный ключ" },
  { re: /\bBearer\s+[A-Za-z0-9._~+/=-]{24,}/, label: "Bearer-токен" },
];
const SECRET_NAME = /(?:token|secret|password|passwd|api[_-]?key|private[_-]?key|credential)/i;
const ENV_REFERENCE = /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$|^\$\{[^}]+\}$|^<[^>]+>$|^(?:your|xxx|changeme|placeholder|todo)/i;
const RUNNERS = new Map<string, string>([["npx", "npm"], ["bunx", "npm"], ["pnpx", "npm"], ["uvx", "pypi"], ["pipx", "pypi"]]);

function isLocal(url: string): boolean {
  return /^(?:https?|wss?):\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/i.test(url);
}

function packageArg(cfg: ServerConfig): { pkg: string; kind: string } | null {
  const cmd = (cfg.command ?? "").split(/[\\/]/).pop() ?? "";
  let runner = RUNNERS.get(cmd);
  let args = cfg.args;
  if (!runner && (cmd === "pnpm" || cmd === "yarn" || cmd === "bun") && ["dlx", "x"].includes(args[0] ?? "")) {
    runner = "npm";
    args = args.slice(1);
  }
  if (!runner && cmd === "pipx" && args[0] === "run") {
    runner = "pypi";
    args = args.slice(1);
  }
  if (!runner) return null;
  const pkg = args.find((a) => !a.startsWith("-"));
  return pkg ? { pkg, kind: runner } : null;
}

function pinned(pkg: string, kind: string): boolean {
  if (kind === "npm") {
    const at = pkg.lastIndexOf("@");
    if (at <= 0) return false;
    const version = pkg.slice(at + 1);
    return /^\d+\.\d+\.\d+/.test(version);
  }
  return /==\d|@\d+\.\d+/.test(pkg);
}

export function checkServer(cfg: ServerConfig): Finding[] {
  const out: Finding[] = [];
  const where = `${cfg.name}`;
  const add = (rule: string, severity: Finding["severity"], message: string, evidence?: string) => {
    const f: Finding = { rule, severity, where, message, source: cfg.source };
    if (evidence !== undefined) f.evidence = evidence;
    out.push(f);
  };
  const line = [cfg.command ?? "", ...cfg.args].join(" ");

  const pkg = packageArg(cfg);
  if (pkg && !pinned(pkg.pkg, pkg.kind)) {
    const auto = cfg.args.includes("-y") || cfg.args.includes("--yes");
    add("BSK009", "medium", `пакет «${pkg.pkg}» запускается без закреплённой версии${auto ? " и с автоустановкой (-y)" : ""}: при обновлении или подмене пакета выполнится новый код`, line);
  }

  const values: { key: string; value: string }[] = [
    ...Object.entries(cfg.env).map(([key, value]) => ({ key: `env.${key}`, value })),
    ...cfg.args.map((value, i) => ({ key: `args[${i}]`, value })),
  ];
  for (const { key, value } of values) {
    const hit = SECRET_PATTERNS.find((p) => p.re.test(value));
    if (hit) {
      const m = hit.re.exec(value);
      add("BSK010", "high", `${hit.label} прямо в конфиге (${key})`, mask(m ? m[0] : value));
    } else if (key.startsWith("env.") && SECRET_NAME.test(key) && value.length >= 12 && !ENV_REFERENCE.test(value) && !/\s/.test(value)) {
      add("BSK010", "medium", `переменная ${key.slice(4)} похожа на секрет и задана литералом`, mask(value));
    }
  }

  if (cfg.url) {
    if (/^(?:http|ws):\/\//i.test(cfg.url) && !isLocal(cfg.url)) add("BSK011", "high", "удалённый сервер без шифрования: описания и данные можно подменить по пути", cfg.url);
    else if (!isLocal(cfg.url)) add("BSK011", "info", "удалённый сервер: владелец может изменить описания инструментов в любой момент, закрепите их (basilisk pin)", cfg.url);
    if (/[?&](?:token|key|api_key|apikey|secret|access_token)=[^&]{8,}/i.test(cfg.url)) add("BSK010", "high", "секрет в адресе сервера (попадёт в логи и историю)", mask(cfg.url));
  }

  const cmd = (cfg.command ?? "").split(/[\\/]/).pop() ?? "";
  if (/^(?:sh|bash|zsh|dash|cmd|cmd\.exe|powershell|pwsh)$/i.test(cmd) && cfg.args.some((a) => /^-(?:c|command|Command)$/.test(a))) {
    const fetches = /(?:curl|wget|iwr|Invoke-WebRequest|Invoke-Expression|iex)\b/i.test(line);
    add("BSK012", fetches ? "high" : "medium", fetches ? "запуск через shell с загрузкой кода из сети" : "запуск через shell -c: аргументы разбираются оболочкой", line);
  }
  if (/\|\s*(?:ba|z)?sh\b/.test(line) && !out.some((f) => f.rule === "BSK012" && f.message.includes("загрузкой кода"))) add("BSK012", "high", "конвейер в shell (curl | sh)", line);
  if (/(?:^|[\\/])(?:tmp|temp)[\\/]/i.test(cfg.command ?? "")) add("BSK012", "medium", "команда лежит во временной папке: туда может писать любой процесс", cfg.command);
  if (cmd === "docker" || cmd === "podman") {
    const joined = cfg.args.join(" ");
    if (/--privileged|--cap-add[ =](?:ALL|SYS_ADMIN)/i.test(joined)) add("BSK012", "high", "контейнер с повышенными правами", line);
    if (/docker\.sock/.test(joined)) add("BSK012", "high", "в контейнер проброшен docker.sock: это полный доступ к хосту", line);
    if (/(?:-v|--volume|--mount)[ =](?:type=bind,src=|source=)?(?:\/|~|\$HOME|%USERPROFILE%)(?::|,|\s|$)/.test(joined)) add("BSK012", "high", "в контейнер смонтирован корень или домашняя папка целиком", line);
    if (/--(?:net|network)[ =]host/.test(joined)) add("BSK012", "medium", "сеть хоста внутри контейнера", line);
  }
  if (cfg.args.some((a) => /^--?(?:dangerously[-\w]*|allow-all|yolo|no-sandbox|disable-sandbox|unsafe[-\w]*)$/i.test(a))) {
    add("BSK012", "medium", "флаг, отключающий защиту", line);
  }
  return out;
}
