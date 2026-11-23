// Banyan virtual relays: path routing, universe scoping, trust circles, admin API.
// Needs `nak` (https://github.com/fiatjaf/nak) on PATH to generate keys and sign events.

import os from "node:os";
import path from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";

const workDir = path.join(os.tmpdir(), "strfry-banyan-tests");
const dbDir = path.join(workDir, "db");
const cfgPath = path.join(workDir, "banyan.conf");
const port = 40560;
const httpBase = `http://127.0.0.1:${port}`;
const wsBase = `ws://127.0.0.1:${port}`;

const pass = (msg) => console.log(`Pass: ${msg}`);

function expect(cond, msg) {
  if (!cond) throw new Error(`Assertion failed: ${msg}`);
}

function nak(args, input) {
  return execFileSync("nak", args, { encoding: "utf-8", input, stdio: ["pipe", "pipe", "ignore"] }).trim();
}

function makeKey() {
  const sec = nak(["key", "generate"]);
  const pub = nak(["key", "public", sec]);
  return { sec, pub, npub: nak(["encode", "npub", pub]) };
}

let ts = Math.floor(Date.now() / 1000) - 10 * 86400;

function sign(key, { kind = 1, content = "", tags = [], created_at } = {}) {
  const args = ["event", "--sec", key.sec, "-k", String(kind), "-c", content, "--ts", String(created_at ?? ts++)];
  for (const t of tags) args.push("-t", `${t[0]}=${t.slice(1).join(";")}`);
  return JSON.parse(nak(args));
}

function strfry(args, input) {
  return execFileSync("./strfry", ["--config", cfgPath, ...args], { encoding: "utf-8", input, stdio: ["pipe", "pipe", "pipe"] });
}

function sha256(s) {
  return createHash("sha256").update(s).digest("hex");
}

class Client {
  constructor(url) {
    this.queue = [];
    this.waiters = [];
    this.ws = new WebSocket(url);
    this.closed = new Promise((resolve) => this.ws.addEventListener("close", resolve));
    this.ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(String(ev.data));
      const w = this.waiters.findIndex((w) => w.pred(msg));
      if (w >= 0) this.waiters.splice(w, 1)[0].resolve(msg);
      else this.queue.push(msg);
    });
  }

  async open() {
    await new Promise((resolve, reject) => {
      this.ws.addEventListener("open", resolve);
      this.ws.addEventListener("error", reject);
    });
    return this;
  }

  send(msg) {
    this.ws.send(JSON.stringify(msg));
  }

  waitFor(pred, timeoutMs = 3000) {
    const i = this.queue.findIndex(pred);
    if (i >= 0) return Promise.resolve(this.queue.splice(i, 1)[0]);
    return new Promise((resolve, reject) => {
      const waiter = { pred, resolve };
      this.waiters.push(waiter);
      setTimeout(() => {
        this.waiters = this.waiters.filter((w) => w !== waiter);
        reject(new Error("waitFor timeout"));
      }, timeoutMs);
    });
  }

  async req(subId, ...filters) {
    this.send(["REQ", subId, ...filters]);
    const events = [];
    while (true) {
      const msg = await this.waitFor((m) => m[1] === subId);
      if (msg[0] === "EOSE") return events;
      if (msg[0] === "CLOSED") throw new Error(`REQ closed: ${msg[2]}`);
      events.push(msg[2]);
    }
  }

  async publish(ev) {
    this.send(["EVENT", ev]);
    return await this.waitFor((m) => m[0] === "OK" && m[1] === ev.id);
  }

  close() {
    this.ws.close();
  }
}

async function connect(p) {
  return await new Client(`${wsBase}/${p}`).open();
}

// relay.auth.serviceUrl is set, so NIP-98 must name the public host, not 127.0.0.1
async function rpc(key, method, params = [], { url = "https://relay.test/", tamperPayload = false } = {}) {
  const body = JSON.stringify({ method, params });
  const auth = sign(key, {
    kind: 27235,
    created_at: Math.floor(Date.now() / 1000),
    content: "",
    tags: [["u", url], ["method", "POST"], ["payload", tamperPayload ? sha256(body + "x") : sha256(body)]],
  });
  const res = await fetch(`${httpBase}/`, {
    method: "POST",
    headers: {
      "Content-Type": "application/nostr+json+rpc",
      Authorization: `Nostr ${Buffer.from(JSON.stringify(auth)).toString("base64")}`,
    },
    body,
  });
  return { status: res.status, json: await res.json() };
}

const alice = makeKey(); // tenant
const bob = makeKey(); // alice's mutual friend: primary circle
const carol = makeKey(); // bob's mutual friend: secondary circle of alice
const stranger = makeKey(); // replies to alice a lot, alice never answers
const dave = makeKey(); // second tenant
const admin = makeKey();
const eve = makeKey(); // added through the admin API
const zed = makeKey(); // alice zapped zed once, zed replies to alice: primary through a genuine zap
const forger = makeKey(); // forges receipts saying alice zapped them, and reacts to alice a lot
const flooder = makeKey(); // alice answered once, then floods alice with reactions
const lnurl = makeKey(); // signs zap receipts, like an LNURL server

function seedEvents() {
  const events = [];
  const add = (ev) => (events.push(ev), ev);

  const a1 = add(sign(alice, { content: "alice note" }));
  const b1 = add(sign(bob, { content: "bob note" }));
  const c1 = add(sign(carol, { content: "carol note" }));
  add(sign(stranger, { content: "stranger note" }));
  add(sign(dave, { content: "dave note" }));

  for (let i = 0; i < 2; i++) {
    add(sign(bob, { content: `bob replies ${i}`, tags: [["e", a1.id], ["p", alice.pub]] }));
    add(sign(alice, { content: `alice replies ${i}`, tags: [["e", b1.id], ["p", bob.pub]] }));
    add(sign(bob, { content: `bob to carol ${i}`, tags: [["e", c1.id], ["p", carol.pub]] }));
    add(sign(carol, { content: `carol to bob ${i}`, tags: [["e", b1.id], ["p", bob.pub]] }));
  }

  add(sign(alice, { kind: 7, content: "+", tags: [["e", b1.id], ["p", bob.pub]] }));

  for (let i = 0; i < 5; i++) {
    add(sign(stranger, { content: `stranger replies ${i}`, tags: [["e", a1.id], ["p", alice.pub]] }));
  }

  const zapRequest = sign(alice, { kind: 9734, tags: [["p", zed.pub], ["relays", "wss://relay.test"]] });
  const receipt = (signer, recipient, description) => {
    const tags = [["p", recipient.pub], ["P", alice.pub], ["bolt11", "lnbc1"]];
    if (description) tags.push(["description", JSON.stringify(description)]);
    return sign(signer, { kind: 9735, tags });
  };

  // Two receipts for the same zap request count once
  add(receipt(lnurl, zed, zapRequest));
  add(receipt(lnurl, zed, zapRequest));
  for (let i = 0; i < 2; i++) {
    add(sign(zed, { content: `zed replies ${i}`, tags: [["e", a1.id], ["p", alice.pub]] }));
  }

  add(receipt(forger, forger, null));
  add(receipt(forger, forger, sign(forger, { kind: 9734, tags: [["p", forger.pub]] })));
  add(receipt(forger, forger, zapRequest));
  add(receipt(forger, forger, { ...zapRequest, tags: [["p", forger.pub]] }));
  for (let i = 0; i < 10; i++) {
    add(sign(forger, { kind: 7, content: "+", tags: [["e", a1.id], ["p", alice.pub]] }));
  }

  const f1 = add(sign(flooder, { content: "flooder note" }));
  add(sign(alice, { content: "alice answers flooder", tags: [["e", f1.id], ["p", flooder.pub]] }));
  for (let i = 0; i < 30; i++) {
    add(sign(flooder, { kind: 7, content: "+", tags: [["e", a1.id], ["p", alice.pub]] }));
  }

  return events;
}

function writeConfig() {
  rmSync(workDir, { recursive: true, force: true });
  mkdirSync(dbDir, { recursive: true });
  writeFileSync(
    cfgPath,
    `
db = "${dbDir}/"

relay {
  bind = "127.0.0.1"
  port = ${port}
  nofiles = 0
  autoPingSeconds = 0

  auth {
    enabled = true
    serviceUrl = "wss://relay.test"
    restrictedReadKinds = "4, 1059"
  }

  numThreads {
    ingester = 1
    reqWorker = 1
    reqMonitor = 1
    negentropy = 1
  }
}

banyan {
  enabled = true
  admins = "${admin.npub}"

  trust {
    minScore = 1
  }

  harvester {
    enabled = false
  }
}
`,
  );
}

async function waitForHttp() {
  for (let i = 0; i < 50; i++) {
    try {
      await fetch(`${httpBase}/`);
      return;
    } catch {
      await delay(100);
    }
  }
  throw new Error("relay did not start");
}

function recompute(person) {
  const out = strfry(["banyan", "recompute", person]);
  const scores = new Map();
  for (const line of out.trim().split("\n")) {
    const [circle, npub, score] = line.split(" ");
    scores.set(npub, { circle, score: Number(score) });
  }
  return { out, scores };
}

async function testTrustCircles() {
  const { out, scores } = recompute("alice");
  expect(scores.get(bob.npub)?.circle === "primary", `bob should be primary, got:\n${out}`);
  expect(scores.get(carol.npub)?.circle === "secondary", `carol should be secondary, got:\n${out}`);
  expect(!scores.has(stranger.npub), "a one-sided stranger must not enter the universe");

  expect(!scores.has(forger.npub), `forged zap receipts must not count, got:\n${out}`);
  expect(scores.get(zed.npub)?.circle === "primary", `a genuine zap counts, got:\n${out}`);
  expect(scores.get(zed.npub).score < 5, `one zap request counts once whatever the number of receipts, got:\n${out}`);

  const flood = scores.get(flooder.npub);
  expect(flood && flood.score < scores.get(bob.npub).score, `flooding one direction can't outrank a mutual friend, got:\n${out}`);
  pass("testTrustCircles");
}

async function testBlockedFreeTheirSlot() {
  strfry(["banyan", "set", "alice", JSON.stringify({ primaryCircleSize: 1, blocked: [bob.npub] })]);
  recompute("alice");

  const shown = JSON.parse(strfry(["banyan", "show", "alice"]));
  const primary = shown.members.filter((m) => m.circle === "primary").map((m) => m.pubkey);
  expect(primary.length === 1 && primary[0] === zed.pub, `the next peer takes a blocked member's slot, got ${JSON.stringify(primary)}`);
  expect(!shown.members.some((m) => m.pubkey === carol.pub), "people reached only through a blocked member leave too");

  strfry(["banyan", "set", "alice", JSON.stringify({ primaryCircleSize: 50, blocked: [] })]);
  recompute("alice");
  pass("testBlockedFreeTheirSlot");
}

async function testRootAndUnknownPathsRefused() {
  for (const p of ["", "nobody"]) {
    const c = new Client(`${wsBase}/${p}`);
    const notice = await c.waitFor((m) => m[0] === "NOTICE");
    expect(String(notice[1]).startsWith("error:"), `NOTICE on /${p}`);
    await c.closed;
  }
  pass("testRootAndUnknownPathsRefused");
}

async function testScopedReads() {
  const c = await connect("alice");
  const authors = new Set((await c.req("notes", { kinds: [1] })).map((e) => e.pubkey));
  expect(authors.has(alice.pub) && authors.has(bob.pub) && authors.has(carol.pub), "universe authors visible on /alice");
  expect(!authors.has(stranger.pub) && !authors.has(dave.pub), "outsiders hidden on /alice");

  const strangerEvents = await c.req("s", { authors: [stranger.pub] });
  expect(strangerEvents.length === 0, "explicit authors filter can't escape the universe");

  const tagged = await c.req("t", { "#p": [alice.pub] });
  expect(tagged.every((e) => e.pubkey !== stranger.pub), "tag queries are scoped too");

  c.send(["COUNT", "cnt", { kinds: [1], authors: [stranger.pub, bob.pub] }]);
  const count = await c.waitFor((m) => m[0] === "COUNT");
  expect(count[2].count === 5, `COUNT only counts universe events, got ${count[2].count}`);
  c.close();

  const byNpub = await connect(alice.npub);
  const viaNpub = await byNpub.req("n", { kinds: [1], authors: [bob.pub] });
  expect(viaNpub.length > 0, "/<npub> serves the same relay");
  byNpub.close();

  const d = await connect("dave");
  const daveAuthors = new Set((await d.req("notes", { kinds: [1] })).map((e) => e.pubkey));
  expect(daveAuthors.size === 1 && daveAuthors.has(dave.pub), "/dave only sees dave");
  d.close();
  pass("testScopedReads");
}

async function testScopedWritesAndLive() {
  const a = await connect("alice");
  const d = await connect("dave");
  await a.req("live", { kinds: [1], since: Math.floor(Date.now() / 1000) - 5 });
  await d.req("live", { kinds: [1], since: Math.floor(Date.now() / 1000) - 5 });

  const rejected = await a.publish(sign(stranger, { content: "let me in", created_at: Math.floor(Date.now() / 1000) }));
  expect(rejected[2] === false && String(rejected[3]).startsWith("blocked:"), "outsider writes are refused");

  const fresh = sign(bob, { content: "fresh from bob", created_at: Math.floor(Date.now() / 1000) });
  const accepted = await a.publish(fresh);
  expect(accepted[2] === true, `universe member can write: ${accepted[3]}`);

  const live = await a.waitFor((m) => m[0] === "EVENT" && m[1] === "live");
  expect(live[2].id === fresh.id, "live event delivered on /alice");

  let leaked = false;
  d.waitFor((m) => m[0] === "EVENT" && m[1] === "live", 1000).then(() => (leaked = true), () => {});
  await delay(1200);
  expect(!leaked, "bob's event must not reach /dave subscribers");

  const randomKey = makeKey();
  const wrap = sign(randomKey, { kind: 1059, content: "sealed", tags: [["p", alice.pub]], created_at: Math.floor(Date.now() / 1000) });
  const wrapOk = await a.publish(wrap);
  expect(wrapOk[2] === true, `gift wraps for the owner are accepted: ${wrapOk[3]}`);

  a.close();
  d.close();
  pass("testScopedWritesAndLive");
}

async function testAuthIsBoundToPath() {
  const c = await connect("alice");
  c.send(["REQ", "dm", { kinds: [4] }]);
  const challenge = (await c.waitFor((m) => m[0] === "AUTH"))[1];

  const wrong = sign(alice, { kind: 22242, created_at: Math.floor(Date.now() / 1000), tags: [["relay", "wss://relay.test/dave"], ["challenge", challenge]] });
  c.send(["AUTH", wrong]);
  const wrongOk = await c.waitFor((m) => m[0] === "OK" && m[1] === wrong.id);
  expect(wrongOk[2] === false, "AUTH for another virtual relay is refused");

  const right = sign(alice, { kind: 22242, created_at: Math.floor(Date.now() / 1000), tags: [["relay", "wss://relay.test/alice"], ["challenge", challenge]] });
  c.send(["AUTH", right]);
  const rightOk = await c.waitFor((m) => m[0] === "OK" && m[1] === right.id);
  expect(rightOk[2] === true, `AUTH for this virtual relay works: ${rightOk[3]}`);
  c.close();
  pass("testAuthIsBoundToPath");
}

async function testHttp() {
  const info = await (await fetch(`${httpBase}/alice`, { headers: { Accept: "application/nostr+json" } })).json();
  expect(info.name === "alice (Banyan)" && info.pubkey === alice.pub, "per-relay NIP-11");
  expect(info.limitation.restricted_writes === true, "NIP-11 advertises restricted writes");

  const landing = await fetch(`${httpBase}/alice`);
  expect(landing.status === 200 && (await landing.text()).includes("wss://relay.test/alice"), "landing page shows the relay URL");

  const adminPage = await fetch(`${httpBase}/admin`);
  expect(adminPage.status === 200 && (await adminPage.text()).includes("<html"), "admin page served");

  expect((await fetch(`${httpBase}/nobody`)).status === 404, "unknown path is a 404");
  pass("testHttp");
}

async function testAdminApi() {
  const who = await rpc(admin, "whoami");
  expect(who.status === 200 && who.json.result.isAdmin === true, "admin recognised");

  const denied = await rpc(stranger, "listtenants");
  expect(denied.status === 403, "non-admin refused");

  const badPayload = await rpc(admin, "listtenants", [], { tamperPayload: true });
  expect(badPayload.status === 401, "payload hash is checked");

  const badUrl = await rpc(admin, "listtenants", [], { url: "https://relay.test/alice" });
  expect(badUrl.status === 401, "u tag is checked");

  const added = await rpc(admin, "addtenant", [eve.npub, "eve"]);
  expect(added.json.result && added.json.result.slug === "eve", `addtenant: ${JSON.stringify(added.json)}`);

  const dup = await rpc(admin, "addtenant", [eve.pub, "eve2"]);
  expect(typeof dup.json.error === "string", "same person can't be added twice");

  const list = await rpc(admin, "listtenants");
  expect(list.json.result.map((t) => t.slug).sort().join(",") === "alice,dave,eve", "listtenants");

  const eveConn = await connect("eve");
  expect((await eveConn.req("x", { kinds: [1] })).length === 0, "new relay is live without restart");
  eveConn.close();

  const blocked = await rpc(admin, "updatetenant", ["alice", { blocked: [bob.npub] }]);
  const members = blocked.json.result.members.map((m) => m.pubkey);
  expect(!members.includes(bob.pub), "blocked member leaves the universe");

  const a = await connect("alice");
  expect((await a.req("b", { authors: [bob.pub] })).length === 0, "blocked member hidden immediately");
  a.close();

  await rpc(admin, "updatetenant", ["alice", { blocked: [] }]);
  const detail = await rpc(admin, "gettenant", ["alice"]);
  expect(detail.json.result.members.some((m) => m.pubkey === bob.pub && m.circle === "primary"), "unblocked member is back");

  const removed = await rpc(admin, "removetenant", ["eve"]);
  expect(removed.json.result === true, "removetenant");

  const status = await rpc(admin, "harveststatus");
  expect(Array.isArray(status.json.result.relays), "harveststatus");
  pass("testAdminApi");
}

async function main() {
  writeConfig();

  strfry(["import"], seedEvents().map((e) => JSON.stringify(e)).join("\n") + "\n");
  strfry(["banyan", "add", alice.npub, "alice"]);
  strfry(["banyan", "add", dave.pub, "dave"]);

  await testTrustCircles();
  await testBlockedFreeTheirSlot();

  const relay = spawn("./strfry", ["--config", cfgPath, "relay"], { stdio: ["ignore", "pipe", "pipe"] });
  let logs = "";
  relay.stdout.on("data", (d) => (logs += d));
  relay.stderr.on("data", (d) => (logs += d));

  try {
    await waitForHttp();
    await testRootAndUnknownPathsRefused();
    await testScopedReads();
    await testScopedWritesAndLive();
    await testAuthIsBoundToPath();
    await testHttp();
    await testAdminApi();
  } catch (e) {
    console.error(e);
    console.error(`\nRelay logs:\n${logs.split("\n").slice(-60).join("\n")}`);
    process.exitCode = 1;
  } finally {
    relay.kill("SIGTERM");
  }
}

await main();
