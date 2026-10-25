import assert from "node:assert/strict";
import { test } from "node:test";
import { makeLock, parseLock, serverHash, toolHash, verify } from "../src/pin.js";
import { ids, inv, obj, server, tool } from "./helpers.js";

const base = () => inv([tool("a", "делает a", obj({ x: { type: "string" } })), tool("b", "делает b")], [server("s", "npx", ["pkg@1.0.0"], { KEY: "secret-value-1" })]);

test("без изменений проверка чистая", () => {
  assert.deepEqual(verify(base(), makeLock(base())), []);
});

test("порядок ключей в схеме не влияет на хеш", () => {
  const a = tool("a", "d", { type: "object", properties: { x: { type: "string", maxLength: 3 } } });
  const b = tool("a", "d", { properties: { x: { maxLength: 3, type: "string" } }, type: "object" });
  assert.equal(toolHash(a), toolHash(b));
});

test("BSK020: изменённое описание, схема и имя — critical", () => {
  const lock = makeLock(base());
  const changed = base();
  changed.tools[0] = tool("a", "делает a и ещё отправляет данные", obj({ x: { type: "string" } }));
  const f = verify(changed, lock);
  assert.deepEqual(ids(f), ["BSK020"]);
  assert.equal(f[0]?.severity, "critical");
  const schema = base();
  schema.tools[0] = tool("a", "делает a", obj({ x: { type: "string" }, y: { type: "string" } }));
  assert.deepEqual(ids(verify(schema, lock)), ["BSK020"]);
});

test("BSK021 и BSK022: новый и пропавший инструменты", () => {
  const lock = makeLock(base());
  const next = inv([tool("a", "делает a", obj({ x: { type: "string" } })), tool("c", "новый")], base().servers);
  assert.deepEqual(ids(verify(next, lock)).sort(), ["BSK021", "BSK022"]);
});

test("BSK023: команда сервера изменилась, значение env — нет", () => {
  const lock = makeLock(base());
  const envOnly = base();
  envOnly.servers[0] = server("s", "npx", ["pkg@1.0.0"], { KEY: "другое-значение" });
  assert.deepEqual(verify(envOnly, lock), []);
  const cmd = base();
  cmd.servers[0] = server("s", "npx", ["pkg@1.0.1"], { KEY: "secret-value-1" });
  assert.deepEqual(ids(verify(cmd, lock)), ["BSK023"]);
  const newEnvName = base();
  newEnvName.servers[0] = server("s", "npx", ["pkg@1.0.0"], { KEY: "x", OTHER: "y" });
  assert.deepEqual(ids(verify(newEnvName, lock)), ["BSK023"]);
});

test("lock-файл не содержит значений секретов и текстов описаний", () => {
  const raw = JSON.stringify(makeLock(base()));
  assert.ok(!raw.includes("secret-value-1"));
  assert.ok(!raw.includes("делает a"));
  assert.ok(raw.includes(serverHash(base().servers[0]!)));
});

test("parseLock отвергает чужие и битые форматы", () => {
  assert.throws(() => parseLock("{}"), /формат/);
  assert.throws(() => parseLock("[]"), /формат/);
  assert.throws(() => parseLock("не json"));
  assert.doesNotThrow(() => parseLock(JSON.stringify(makeLock(base()))));
});

test("имена вроде __proto__ и constructor не ломают закрепление", () => {
  const evil = inv([tool("__proto__", "x"), tool("constructor", "y")], [server("__proto__", "node", ["s.js"])]);
  const lock = makeLock(evil);
  assert.deepEqual(verify(evil, lock), []);
  assert.deepEqual(ids(verify(inv([tool("constructor", "новое описание")]), lock)).includes("BSK020"), true);
  assert.equal(({} as Record<string, unknown>)["polluted"], undefined);
});
