import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { run } from "../src/cli.js";
import { candidatePaths, discover } from "../src/discover.js";

const tmp = () => mkdtempSync(join(tmpdir(), "basilisk-disc-"));
const put = (path: string, data: unknown) => {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, JSON.stringify(data));
  return path;
};

test("пути зависят от системы", () => {
  const mac = candidatePaths("/Users/u", "darwin");
  assert.ok(mac.some((p) => p.endsWith(join("Library", "Application Support", "Claude", "claude_desktop_config.json"))));
  const lin = candidatePaths("/home/u", "linux");
  assert.ok(lin.some((p) => p.endsWith(join(".config", "Claude", "claude_desktop_config.json"))));
  const win = candidatePaths("C:\\Users\\u", "win32", { APPDATA: "D:\\Roam" });
  assert.ok(win.some((p) => p.startsWith("D:\\Roam") || p.includes("Roam")));
  for (const list of [mac, lin, win]) assert.ok(list.some((p) => p.endsWith(join(".cursor", "mcp.json"))));
});

test("XDG_CONFIG_HOME учитывается на Linux", () => {
  const p = candidatePaths("/home/u", "linux", { XDG_CONFIG_HOME: "/cfg" });
  assert.ok(p.includes(join("/cfg", "Claude", "claude_desktop_config.json")));
});

test("находит только существующие файлы и проектные конфиги, без повторов", () => {
  const home = tmp();
  const cwd = join(home, "project");
  put(join(home, ".cursor", "mcp.json"), { mcpServers: {} });
  put(join(cwd, ".mcp.json"), { mcpServers: {} });
  mkdirSync(join(home, ".claude.json"), { recursive: true }); // каталог с таким именем не файл
  const found = discover(home, "linux", {}, cwd);
  assert.deepEqual(found.sort(), [join(cwd, ".mcp.json"), join(home, ".cursor", "mcp.json")].sort());
  assert.deepEqual(discover(join(home, "нет"), "linux", {}), []);
  assert.equal(new Set(discover(home, "linux", {}, home)).size, discover(home, "linux", {}, home).length);
});

test("CLI: scan --auto проверяет найденные конфиги и сообщает, что нашёл", () => {
  const home = tmp();
  put(join(home, ".cursor", "mcp.json"), { mcpServers: { s: { command: "npx", args: ["-y", "some-mcp-server"] } } });
  const prev = { HOME: process.env["HOME"], USERPROFILE: process.env["USERPROFILE"], cwd: process.cwd() };
  process.env["HOME"] = home;
  process.env["USERPROFILE"] = home;
  process.chdir(home);
  try {
    let out = "";
    const code = run(["scan", "--auto", "--no-color", "--fail-on", "none"], (s) => void (out += s), false);
    assert.equal(code, 0);
    assert.match(out, /найдено конфигов клиентов: \d/);
    assert.match(out, /BSK009/);
  } finally {
    process.chdir(prev.cwd);
    if (prev.HOME === undefined) delete process.env["HOME"]; else process.env["HOME"] = prev.HOME;
    if (prev.USERPROFILE === undefined) delete process.env["USERPROFILE"]; else process.env["USERPROFILE"] = prev.USERPROFILE;
  }
});

test("CLI: --auto без найденных конфигов не падает, а --auto с другими командами отклоняется", () => {
  const home = tmp();
  const prev = { HOME: process.env["HOME"], USERPROFILE: process.env["USERPROFILE"], cwd: process.cwd() };
  process.env["HOME"] = home;
  process.env["USERPROFILE"] = home;
  process.chdir(home);
  try {
    let out = "";
    assert.equal(run(["scan", "--auto"], (s) => void (out += s), false), 0);
    assert.match(out, /не найдены/);
    assert.equal(run(["verify", "--auto"], () => {}, false), 2);
  } finally {
    process.chdir(prev.cwd);
    if (prev.HOME === undefined) delete process.env["HOME"]; else process.env["HOME"] = prev.HOME;
    if (prev.USERPROFILE === undefined) delete process.env["USERPROFILE"]; else process.env["USERPROFILE"] = prev.USERPROFILE;
  }
});
