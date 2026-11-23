// Banyan virtual relays: path routing, universe scoping, incoming engagement, trust circles (zap amounts and LNURL checks),
// admin API, thread filters and muting, owner self-management, pruning, and against fake upstream relays: the harvester's
// NIP-42 AUTH, inbox and outbox delivery, and AUTH as the owner through a NIP-46 remote signer.

import os from "node:os";
import path from "node:path";
import http from "node:http";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { WebSocketServer } from "ws";
import { matchFilters } from "@nostr/tools/filter";
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from "@nostr/tools/pure";
import { encodeBytes, neventEncode, npubEncode } from "@nostr/tools/nip19";
import { decrypt as nip44Decrypt, encrypt as nip44Encrypt, getConversationKey } from "@nostr/tools/nip44";

const workDir = path.join(os.tmpdir(), "strfry-banyan-tests");
const dbDir = path.join(workDir, "db");
const cfgPath = path.join(workDir, "banyan.conf");
const port = 40560;
const httpBase = `http://127.0.0.1:${port}`;
const wsBase = `ws://127.0.0.1:${port}`;
const upstreamPort = 40561;
const upstreamUrl = `ws://127.0.0.1:${upstreamPort}`;
const lnurlPort = 40562;
const outboxPort = 40563;
const outboxUrl = `ws://127.0.0.1:${outboxPort}`;
const bunkerPort = 40564;
const bunkerUrl = `ws://127.0.0.1:${bunkerPort}`;
const dmPort = 40565;
const dmUrl = `ws://127.0.0.1:${dmPort}`;

const pass = (msg) => console.log(`Pass: ${msg}`);

function expect(cond, msg) {
  if (!cond) throw new Error(`Assertion failed: ${msg}`);
}

function makeKey() {
  const sec = generateSecretKey();
  const pub = getPublicKey(sec);
  return { sec, pub, npub: npubEncode(pub) };
}

let ts = Math.floor(Date.now() / 1000) - 10 * 86400;

const now = () => Math.floor(Date.now() / 1000);

async function until(what, fn, timeoutMs = 20000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await delay(250);
  }
  throw new Error(`timed out waiting for ${what}`);
}

function sign(key, { kind = 1, content = "", tags = [], created_at } = {}) {
  return finalizeEvent({ kind, content, tags, created_at: created_at ?? ts++ }, key.sec);
}

function strfry(args, input) {
  return execFileSync("./strfry", ["--config", cfgPath, ...args], { encoding: "utf-8", input, stdio: ["pipe", "pipe", "pipe"] });
}

// Keeps the event loop free, for commands that call the fake LNURL server of this process
function strfryAsync(args) {
  return new Promise((resolve, reject) => {
    const child = spawn("./strfry", ["--config", cfgPath, ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("exit", (code) => (code === 0 ? resolve(out) : reject(new Error(`strfry ${args.join(" ")} failed:\n${err}`))));
  });
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
    // The relay refuses a reused NIP-98 event, and polling repeats the same request within a second
    tags: [["u", url], ["method", "POST"], ["payload", tamperPayload ? sha256(body + "x") : sha256(body)], ["nonce", Math.random().toString(36).slice(2)]],
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
const yan = makeKey(); // alice zapped yan a lot of sats once, yan replied once: amounts count
const mal = makeKey(); // receipts for alice's zap to mal are signed by someone else than mal's LNURL server
const bunkerKey = makeKey(); // the NIP-46 remote signer holding alice's key
const outsider = makeKey(); // in no universe and mentions no seed: pruned
const newcomer = makeKey(); // only reaches alice through her Banyan; alice answers, so they enter her circle
const passerby = makeKey(); // replies to alice on her Banyan, then deletes it

// Seeded events by name, for the thread and pruning tests
const T = {};
let seeded = [];

function seedEvents() {
  const events = [];
  const add = (ev) => (events.push(ev), ev);

  const a1 = add(sign(alice, { content: "alice note" }));
  const b1 = add(sign(bob, { content: "bob note" }));
  const c1 = add(sign(carol, { content: "carol note" }));
  T.strangerNote = add(sign(stranger, { content: "stranger note" }));
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

  // The LNURL server of zed, yan and mal signs receipts with lnurl's key
  for (const [k, name] of [[zed, "zed"], [yan, "yan"], [mal, "mal"]]) {
    const lud06 = encodeBytes("lnurl", new TextEncoder().encode(`http://127.0.0.1:${lnurlPort}/.well-known/lnurlp/${name}`));
    add(sign(k, { kind: 0, content: JSON.stringify({ name, lud06 }) }));
  }

  const zapRequest = sign(alice, { kind: 9734, tags: [["p", zed.pub], ["relays", "wss://relay.test"]] });
  const receipt = (signer, recipient, description, bolt11 = "lnbc1u1pzaptest") => {
    const tags = [["p", recipient.pub], ["P", alice.pub], ["bolt11", bolt11]];
    if (description) tags.push(["description", JSON.stringify(description)]);
    return sign(signer, { kind: 9735, tags });
  };

  // Two receipts for the same zap request of 100 sats count once
  add(receipt(lnurl, zed, zapRequest));
  add(receipt(lnurl, zed, zapRequest));
  for (let i = 0; i < 2; i++) {
    add(sign(zed, { content: `zed replies ${i}`, tags: [["e", a1.id], ["p", alice.pub]] }));
  }

  const bigZap = sign(alice, { kind: 9734, tags: [["p", yan.pub], ["amount", "1000000"]] });
  add(receipt(lnurl, yan, bigZap, "lnbc10u1pzaptest"));
  add(sign(yan, { content: "yan replies", tags: [["e", a1.id], ["p", alice.pub]] }));

  const zapToMal = sign(alice, { kind: 9734, tags: [["p", mal.pub]] });
  add(receipt(forger, mal, zapToMal, "lnbc100u1pzaptest"));
  const wrongAmount = sign(alice, { kind: 9734, tags: [["p", mal.pub], ["amount", "21000"]] });
  add(receipt(lnurl, mal, wrongAmount, "lnbc100u1pzaptest"));
  for (let i = 0; i < 2; i++) {
    add(sign(mal, { content: `mal replies ${i}`, tags: [["e", a1.id], ["p", alice.pub]] }));
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

  // A thread whose replies only e-tag their parent, so following it takes recursion
  T.root = add(sign(alice, { content: "thread root" }));
  T.bob = add(sign(bob, { content: "bob in thread", tags: [["e", T.root.id], ["p", alice.pub]] }));
  T.carol = add(sign(carol, { content: "carol to bob", tags: [["e", T.bob.id], ["p", bob.pub]] }));
  T.stranger = add(sign(stranger, { content: "stranger to bob", tags: [["e", T.bob.id], ["p", bob.pub]] }));
  // No p tag: answering the stranger would make them bob's mutual peer
  T.behindStranger = add(sign(bob, { content: "bob to stranger", tags: [["e", T.stranger.id]] }));
  T.reaction = add(sign(alice, { kind: 7, content: "+", tags: [["e", T.carol.id], ["p", carol.pub]] }));

  // Comments on an article reference it by address, not by id
  T.article = add(sign(alice, { kind: 30023, content: "article", tags: [["d", "post"]] }));
  const coord = `30023:${alice.pub}:post`;
  T.comment = add(sign(bob, { kind: 1111, content: "comment", tags: [["A", coord], ["a", coord], ["K", "30023"], ["k", "30023"], ["P", alice.pub], ["p", alice.pub]] }));
  T.commentReply = add(sign(carol, { kind: 1111, content: "reply to comment", tags: [["A", coord], ["e", T.comment.id], ["K", "30023"], ["k", "1111"], ["P", alice.pub], ["p", bob.pub]] }));

  T.outsiderNote = add(sign(outsider, { content: "outsider note" }));
  T.outsiderFollows = add(sign(outsider, { kind: 3, tags: [["p", alice.pub]] }));
  T.outsiderOld = add(sign(outsider, { content: "too old to be trust evidence", tags: [["p", alice.pub]], created_at: now() - 400 * 86400 }));
  T.outsiderReply = add(sign(outsider, { content: "outsider replies to alice", tags: [["e", a1.id], ["p", alice.pub]] }));

  return events;
}

function writeConfig({ harvester = false } = {}) {
  if (!harvester) {
    rmSync(workDir, { recursive: true, force: true });
    mkdirSync(dbDir, { recursive: true });
  }
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
    enabled = ${harvester}
    bootstrapRelays = "${upstreamUrl}"
    allowPrivateAddresses = true
    replanIntervalSeconds = 2
  }

  signer {
    relays = "${bunkerUrl}"
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

async function recompute(person) {
  const out = await strfryAsync(["banyan", "recompute", person]);
  const scores = new Map();
  for (const line of out.trim().split("\n")) {
    const [circle, npub, score] = line.split(" ");
    scores.set(npub, { circle, score: Number(score) });
  }
  return { out, scores };
}

// Each person's LNURL endpoint, as lud06 points to it: zaps are only genuine when lnurl's key signed the receipt
function startLnurlServer() {
  const hits = [];
  const server = http.createServer((req, res) => {
    hits.push(req.url);
    const m = req.url.match(/^\/\.well-known\/lnurlp\/([a-z]+)$/);
    if (!m) {
      res.writeHead(404);
      return res.end();
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ tag: "payRequest", callback: `http://127.0.0.1:${lnurlPort}/cb/${m[1]}`, minSendable: 1000, maxSendable: 1e11, metadata: "[]", allowsNostr: true, nostrPubkey: lnurl.pub }));
  });
  server.listen(lnurlPort, "127.0.0.1");
  return { server, hits };
}

async function testTrustCircles(lnurlServer) {
  const { out, scores } = await recompute("alice");
  expect(scores.get(bob.npub)?.circle === "primary", `bob should be primary, got:\n${out}`);
  expect(scores.get(carol.npub)?.circle === "secondary", `carol should be secondary, got:\n${out}`);
  expect(!scores.has(stranger.npub), "a one-sided stranger must not enter the universe");

  expect(!scores.has(forger.npub), `forged zap receipts must not count, got:\n${out}`);
  expect(scores.get(zed.npub)?.circle === "primary", `a genuine zap counts, got:\n${out}`);
  expect(scores.get(zed.npub).score < 5, `one zap request counts once whatever the number of receipts, got:\n${out}`);
  expect(lnurlServer.hits.includes("/.well-known/lnurlp/zed"), "the recipient's LNURL server is asked for its nostrPubkey");

  expect(scores.get(yan.npub)?.score > scores.get(zed.npub).score, `a bigger zap weighs more, even with fewer replies, got:\n${out}`);
  expect(!scores.has(mal.npub), `receipts not signed by the recipient's LNURL server, or with an amount that differs from the request, don't count, got:\n${out}`);

  const flood = scores.get(flooder.npub);
  expect(flood && flood.score < scores.get(bob.npub).score, `flooding one direction can't outrank a mutual friend, got:\n${out}`);
  pass("testTrustCircles");
}

async function testBlockedFreeTheirSlot() {
  const { scores } = await recompute("alice");
  const ranked = [...scores].filter(([, m]) => m.circle === "primary").sort((a, b) => b[1].score - a[1].score);
  expect(ranked[0][0] === bob.npub, "bob is alice's closest peer");

  strfry(["banyan", "set", "alice", JSON.stringify({ primaryCircleSize: 1, blocked: [bob.npub] })]);
  await recompute("alice");

  const shown = JSON.parse(strfry(["banyan", "show", "alice"]));
  const primary = shown.members.filter((m) => m.circle === "primary").map((m) => m.npub);
  expect(primary.length === 1 && primary[0] === ranked[1][0], `the next peer takes a blocked member's slot, got ${JSON.stringify(primary)}`);
  expect(!shown.members.some((m) => m.pubkey === carol.pub), "people reached only through a blocked member leave too");

  strfry(["banyan", "set", "alice", JSON.stringify({ primaryCircleSize: 50, blocked: [] })]);
  await recompute("alice");
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
  const bobNotes = seeded.filter((e) => e.pubkey === bob.pub && e.kind === 1).length;
  expect(count[2].count === bobNotes, `COUNT only counts universe events, got ${count[2].count}, expected ${bobNotes}`);
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

// If alice's Banyan is her only inbox, replies from people she doesn't know yet only ever reach it
async function testIncomingEngagement() {
  const a = await connect("alice");
  await a.req("mentions", { "#p": [alice.pub], since: now() - 5 });

  const post = sign(alice, { content: "who wants to talk?", created_at: now() });
  expect((await a.publish(post))[2] === true, "alice posts");

  const replies = [];
  for (let i = 0; i < 3; i++) {
    const r = sign(newcomer, { content: `newcomer answers ${i}`, tags: [["e", post.id], ["p", alice.pub]], created_at: now() });
    const ok = await a.publish(r);
    expect(ok[2] === true, `engagement with a seed is accepted from outside the universe: ${ok[3]}`);
    replies.push(r);
  }

  const unrelated = await a.publish(sign(newcomer, { content: "newcomer note", created_at: now() }));
  expect(unrelated[2] === false && String(unrelated[3]).startsWith("blocked:"), "an outsider's event that mentions no seed is still refused");

  const stale = await a.publish(sign(newcomer, { content: "too old to count", tags: [["e", post.id], ["p", alice.pub]], created_at: now() - 400 * 86400 }));
  expect(stale[2] === false, "engagement older than the trust window is refused");

  const passing = sign(passerby, { content: "just passing", tags: [["e", post.id], ["p", alice.pub]], created_at: now() });
  expect((await a.publish(passing))[2] === true, "the passerby's reply is accepted");
  T.passerbyDeletion = sign(passerby, { kind: 5, tags: [["e", passing.id]], created_at: now() });
  const deleted = await a.publish(T.passerbyDeletion);
  expect(deleted[2] === true, `an outsider can delete what they have stored here: ${deleted[3]}`);
  expect(scanIds({ ids: [passing.id] }).size === 0, "the deletion is applied");
  const notTheirs = await a.publish(sign(passerby, { kind: 5, tags: [["e", post.id]], created_at: now() }));
  expect(notTheirs[2] === false, "an outsider's deletion of someone else's event is refused");

  expect((await a.req("hidden", { ids: replies.map((e) => e.id) })).length === 0, "accepted engagement is not served");
  expect(scanIds({ ids: replies.map((e) => e.id) }).size === 3, "but it is stored for the trust engine");
  let leaked = false;
  a.waitFor((m) => m[0] === "EVENT" && m[1] === "mentions", 1000).then(() => (leaked = true), () => {});
  await delay(1200);
  expect(!leaked, "nor sent live");

  for (let i = 0; i < 2; i++) {
    const r = sign(alice, { content: `alice answers newcomer ${i}`, tags: [["e", replies[i].id], ["p", newcomer.pub]], created_at: now() });
    expect((await a.publish(r))[2] === true, "alice answers");
  }

  const { out, scores } = await recompute("alice");
  expect(scores.get(newcomer.npub)?.circle === "primary", `replies sent only to alice's Banyan count toward trust, got:\n${out}`);
  await until("the newcomer's replies to be served", async () => (await a.req(`v${Date.now()}`, { ids: replies.map((e) => e.id) })).length === 3);
  a.close();
  pass("testIncomingEngagement");
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

const ids = (events) => new Set(events.map((e) => e.id));
const sameIds = (events, expected) => {
  const got = ids(events);
  return got.size === expected.length && expected.every((e) => got.has(e.id));
};

async function testThreadQueries() {
  const c = await connect("alice");

  const whole = await c.req("th", { thread: [T.root.id] });
  expect(sameIds(whole, [T.root, T.bob, T.carol, T.reaction]), `whole thread, got ${whole.map((e) => e.content).join(" | ")}`);
  expect(!ids(whole).has(T.behindStranger.id), "a thread does not grow through people outside the universe");

  const notes = await c.req("th1", { thread: [T.root.id], kinds: [1] });
  expect(sameIds(notes, [T.root, T.bob, T.carol]), "other filter fields narrow the thread");

  const sub = await c.req("th2", { thread: [T.bob.id] });
  expect(sameIds(sub, [T.bob, T.carol, T.reaction]), "a sub-thread starts anywhere");

  const limited = await c.req("th3", { thread: [T.root.id], limit: 2 });
  expect(limited.length === 2, "limit applies to the thread");

  const article = await c.req("th4", { thread: [T.article.id] });
  expect(sameIds(article, [T.article, T.comment, T.commentReply]), "comments reached through the article's address");

  c.send(["COUNT", "thc", { thread: [T.root.id] }]);
  const count = await c.waitFor((m) => m[0] === "COUNT");
  expect(count[2].count === 4, `COUNT on a thread, got ${count[2].count}`);

  const live = await c.req("live", { thread: [T.root.id] });
  expect(live.length === 4, "live thread subscription starts with the stored thread");
  const nextLive = () => c.waitFor((m) => m[0] === "EVENT" && m[1] === "live");

  const r1 = sign(bob, { content: "live reply", tags: [["e", T.carol.id], ["p", carol.pub]], created_at: now() });
  expect((await c.publish(r1))[2] === true, "publish live reply");
  expect((await nextLive())[2].id === r1.id, "live reply to a stored node");

  const r2 = sign(carol, { content: "reply to the live reply", tags: [["e", r1.id], ["p", bob.pub]], created_at: now() });
  await c.publish(r2);
  expect((await nextLive())[2].id === r2.id, "the thread grows with live replies");

  // Harvested backfills arrive newest first: a reply can land before its parent
  const parent = sign(bob, { content: "late parent", tags: [["e", r2.id], ["p", carol.pub]], created_at: now() });
  const child = sign(carol, { content: "early child", tags: [["e", parent.id], ["p", bob.pub]], created_at: now() });
  await c.publish(child);
  let early = false;
  c.waitFor((m) => m[0] === "EVENT" && m[1] === "live" && m[2].id === child.id, 1000).then(() => (early = true), () => {});
  await delay(1200);
  expect(!early, "a reply to an unknown event is not part of the thread yet");
  await c.publish(parent);
  const got = new Set([(await nextLive())[2].id, (await nextLive())[2].id]);
  expect(got.has(parent.id) && got.has(child.id), "the parent brings the reply that came before it");

  // Narrowed to carol, the subscription still follows the thread through bob's replies
  await c.req("carol", { thread: [T.root.id], authors: [carol.pub] });
  const viaBob = sign(bob, { content: "bob, not for carol's subscription", tags: [["e", child.id], ["p", carol.pub]], created_at: now() });
  await c.publish(viaBob);
  const underBob = sign(carol, { content: "carol under bob", tags: [["e", viaBob.id], ["p", bob.pub]], created_at: now() });
  await c.publish(underBob);
  const narrowed = await c.waitFor((m) => m[0] === "EVENT" && m[1] === "carol");
  expect(narrowed[2].id === underBob.id, "a narrowed thread grows through events it does not send");

  c.send(["REQ", "bad", { thread: ["zz"] }]);
  const bad = await c.waitFor((m) => (m[0] === "CLOSED" && m[1] === "bad") || m[0] === "NOTICE");
  expect(String(bad[bad.length - 1]).includes("thread"), "invalid thread ids are refused");
  c.close();
  pass("testThreadQueries");
}

async function testMutedThreads() {
  const c = await connect("alice");
  const m0 = sign(alice, { content: "a thread alice keeps", created_at: now() });
  const m1 = sign(bob, { content: "a sub-thread alice mutes", tags: [["e", m0.id], ["p", alice.pub]], created_at: now() });
  const m2 = sign(carol, { content: "under the muted reply", tags: [["e", m1.id], ["p", bob.pub]], created_at: now() });
  const m3 = sign(alice, { kind: 7, content: "+", tags: [["e", m2.id], ["p", carol.pub]], created_at: now() });
  for (const e of [m0, m1, m2, m3]) expect((await c.publish(e))[2] === true, "publish the thread");

  const muted = await rpc(alice, "updatetenant", ["alice", { mutedThreads: [neventEncode({ id: m1.id, relays: ["wss://relay.test"] })] }]);
  expect(muted.json.result?.settings.mutedThreads[0] === m1.id, `mute a sub-thread by its nevent1: ${JSON.stringify(muted.json).slice(0, 300)}`);

  const visible = await c.req("m1", { ids: [m0, m1, m2, m3].map((e) => e.id) });
  expect(sameIds(visible, [m0]), `a muted sub-thread is hidden, its parent is not, got ${visible.map((e) => e.content).join(" | ")}`);
  expect(sameIds(await c.req("m2", { thread: [m0.id] }), [m0]), "thread queries skip a muted sub-thread");

  await c.req("live", { kinds: [1], since: now() - 5 });
  const m4 = sign(bob, { content: "a late reply in the muted sub-thread", tags: [["e", m2.id], ["p", carol.pub]], created_at: now() });
  expect((await c.publish(m4))[2] === true, "writes in a muted thread are still accepted");
  let leaked = false;
  c.waitFor((m) => m[0] === "EVENT" && m[1] === "live" && m[2].id === m4.id, 1500).then(() => (leaked = true), () => {});
  await delay(1700);
  expect(!leaked, "a reply in a muted thread is not sent live");

  await until("the late reply to join the muted set", async () => (await rpc(alice, "gettenant", ["alice"])).json.result.muted.hiddenEvents >= 4);
  const m5 = sign(carol, { content: "deeper in the muted sub-thread", tags: [["e", m4.id], ["p", bob.pub]], created_at: now() });
  expect((await c.publish(m5))[2] === true, "publish deeper");
  expect((await c.req("m5", { ids: [m5.id] })).length === 0, "the muted set grows with the thread");

  // Muting from a client publishes a NIP-51 mute list
  const n0 = sign(bob, { content: "a thread alice mutes from her client", created_at: now() });
  expect((await c.publish(n0))[2] === true, "publish another thread");
  expect((await c.publish(sign(alice, { kind: 10000, tags: [["e", n0.id]], created_at: now() })))[2] === true, "publish the mute list");
  await until("the mute list to apply", async () => (await c.req(`n${Date.now()}`, { ids: [n0.id] })).length === 0);

  await rpc(alice, "updatetenant", ["alice", { mutedThreads: [] }]);
  expect((await c.req("m6", { ids: [m1.id, m2.id, m4.id, m5.id] })).length === 4, "unmuting shows the sub-thread again");
  await c.publish(sign(alice, { kind: 10000, tags: [], created_at: now() + 1 }));
  await until("the emptied mute list to apply", async () => (await c.req(`u${Date.now()}`, { ids: [n0.id] })).length === 1);
  c.close();
  pass("testMutedThreads");
}

async function testOwnerManagesOwnRelay() {
  const who = await rpc(alice, "whoami");
  expect(who.json.result.isAdmin === false && who.json.result.tenant === "alice", `owner recognised: ${JSON.stringify(who.json)}`);
  expect(who.json.result.ownerLimits.primaryCircleSize === 100, "owner limits advertised");

  const list = await rpc(alice, "listtenants");
  expect(list.status === 200 && list.json.result.length === 1 && list.json.result[0].slug === "alice", "owners only list their own relay");

  expect((await rpc(alice, "gettenant", ["dave"])).status === 403, "another person's relay is refused");
  expect((await rpc(alice, "addtenant", [eve.npub, "eve"])).status === 403, "owners can't add people");
  expect((await rpc(alice, "harveststatus")).status === 403, "harvester status stays admin-only");
  expect((await rpc(alice, "updatetenant", ["alice", { slug: "alicia" }])).status === 403, "owners can't change their slug");

  const tooBig = await rpc(alice, "updatetenant", ["alice", { primaryCircleSize: 5000 }]);
  expect(typeof tooBig.json.error === "string", "owner limits are enforced");

  const pinned = await rpc(alice, "updatetenant", ["alice", { pinned: [eve.npub] }]);
  expect(pinned.json.result.members.some((m) => m.pubkey === eve.pub && m.circle === "pinned"), `owner pins someone: ${JSON.stringify(pinned.json).slice(0, 200)}`);
  expect((await rpc(alice, "recomputetrust", ["alice"])).json.result === true, "owner recomputes their trust");
  await rpc(alice, "updatetenant", ["alice", { pinned: [] }]);

  const nobody = await rpc(stranger, "whoami");
  expect(nobody.json.result.tenant === null, "no relay for strangers");
  expect((await rpc(stranger, "gettenant", ["alice"])).status === 403, "strangers are refused");

  const landing = await (await fetch(`${httpBase}/alice`)).text();
  expect(landing.includes('href="/admin"'), "landing page links owners to the management page");
  pass("testOwnerManagesOwnRelay");
}

function scanIds(filter) {
  const out = strfry(["scan", JSON.stringify(filter)]).trim();
  return new Set(out ? out.split("\n").map((l) => JSON.parse(l).id) : []);
}

async function testPrune() {
  const dry = strfry(["banyan", "prune", "--dry-run"]);
  // The outsider's 4 events that are not trust evidence, and mal's profile
  expect(dry.includes("Would delete 5 "), `dry run: ${dry}`);
  expect(scanIds({ authors: [outsider.pub] }).size === 4, "a dry run deletes nothing");

  const out = strfry(["banyan", "prune"]);
  expect(out.includes("Deleted 5 "), `prune: ${out}`);
  expect(scanIds({ authors: [mal.pub], kinds: [0] }).size === 0, "the profile of someone in no universe goes");

  const left = scanIds({ authors: [outsider.pub] });
  expect(left.size === 1 && left.has(T.outsiderReply.id), "only trust evidence is left of an outsider");
  expect(scanIds({ ids: [T.strangerNote.id] }).size === 0, "a stranger's note that mentions no seed goes");
  expect(scanIds({ ids: [T.stranger.id, T.root.id, T.comment.id] }).size === 3, "universe events and mentions of seeds stay");
  expect(scanIds({ ids: [T.passerbyDeletion.id] }).size === 1, "an outsider's deletion stays, so the harvester can't store its target again");

  const c = await connect("alice");
  expect((await c.req("after", { thread: [T.root.id] })).length >= 4, "the relay serves the same thread after pruning");
  c.close();
  pass("testPrune");
}

// A relay that refuses everything until NIP-42 AUTH, like many paid or private relays
function startUpstream(stored, port = upstreamPort) {
  const url = `ws://127.0.0.1:${port}`;
  const received = [];
  const authed = new Set();
  const wss = new WebSocketServer({ port, host: "127.0.0.1" });

  wss.on("connection", (ws) => {
    const challenge = Math.random().toString(36).slice(2);
    let pubkey = null, challenged = false;
    const send = (m) => ws.send(JSON.stringify(m));
    const requireAuth = () => {
      if (!challenged) send(["AUTH", challenge]);
      challenged = true;
    };

    ws.on("message", (data) => {
      const [type, ...rest] = JSON.parse(String(data));
      if (type === "AUTH") {
        const ev = rest[0];
        const tag = (n) => (ev.tags.find((t) => t[0] === n) || [])[1];
        const ok = verifyEvent(ev) && ev.kind === 22242 && tag("challenge") === challenge && tag("relay") === url;
        if (ok) {
          pubkey = ev.pubkey;
          authed.add(ev.pubkey);
        }
        send(["OK", ev.id, ok, ok ? "" : "invalid: bad AUTH"]);
      } else if (type === "REQ") {
        const [subId, ...filters] = rest;
        if (!pubkey) {
          requireAuth();
          return send(["CLOSED", subId, "auth-required: sign in first"]);
        }
        const matching = stored.filter((e) => matchFilters(filters, e)).sort((a, b) => b.created_at - a.created_at);
        const limit = Math.min(...filters.map((f) => f.limit ?? Infinity));
        for (const e of matching.slice(0, limit)) send(["EVENT", subId, e]);
        send(["EOSE", subId]);
      } else if (type === "EVENT") {
        const ev = rest[0];
        if (!pubkey) {
          requireAuth();
          return send(["OK", ev.id, false, "auth-required: sign in first"]);
        }
        received.push(ev);
        send(["OK", ev.id, true, ""]);
      }
    });
  });

  return { wss, received, authed };
}

// Like NIP-17 inbox relays: each person only reads their own gift wraps, after NIP-42 AUTH as themselves
function startDmRelay(stored) {
  const authedAs = [];
  const wss = new WebSocketServer({ port: dmPort, host: "127.0.0.1" });

  wss.on("connection", (ws) => {
    const challenge = Math.random().toString(36).slice(2);
    let pubkey = null;
    const send = (m) => ws.send(JSON.stringify(m));
    send(["AUTH", challenge]);

    ws.on("message", (data) => {
      const [type, ...rest] = JSON.parse(String(data));
      if (type === "AUTH") {
        const ev = rest[0];
        const tag = (n) => (ev.tags.find((t) => t[0] === n) || [])[1];
        const ok = verifyEvent(ev) && ev.kind === 22242 && tag("challenge") === challenge && tag("relay") === dmUrl;
        if (ok) {
          pubkey = ev.pubkey;
          authedAs.push(ev.pubkey);
        }
        send(["OK", ev.id, ok, ok ? "" : "invalid: bad AUTH"]);
      } else if (type === "REQ") {
        const [subId, ...filters] = rest;
        if (!pubkey) return send(["CLOSED", subId, "auth-required: only the recipient reads their messages"]);
        const mine = stored.filter((e) => e.tags.some((t) => t[0] === "p" && t[1] === pubkey) && matchFilters(filters, e));
        for (const e of mine) send(["EVENT", subId, e]);
        send(["EOSE", subId]);
      } else if (type === "EVENT") {
        send(["OK", rest[0].id, false, "blocked: read-only"]);
      }
    });
  });

  return { wss, authedAs };
}

// A relay with a NIP-46 remote signer on it that holds alice's key, like a bunker
function startBunker(user, secret) {
  const subs = [];
  const stored = [];
  const methods = [];
  const wss = new WebSocketServer({ port: bunkerPort, host: "127.0.0.1" });

  const broadcast = (ev) => {
    stored.push(ev);
    for (const s of subs) {
      if (s.ws.readyState === 1 && matchFilters(s.filters, ev)) s.ws.send(JSON.stringify(["EVENT", s.subId, ev]));
    }
  };
  const answer = (clientPub, body) => {
    const ck = getConversationKey(bunkerKey.sec, clientPub);
    broadcast(sign(bunkerKey, { kind: 24133, tags: [["p", clientPub]], content: nip44Encrypt(JSON.stringify(body), ck), created_at: now() }));
  };

  wss.on("connection", (ws) => {
    ws.on("message", (data) => {
      const [type, ...rest] = JSON.parse(String(data));
      if (type === "REQ") {
        const [subId, ...filters] = rest;
        const existing = subs.find((s) => s.ws === ws && s.subId === subId);
        if (existing) existing.filters = filters;
        else subs.push({ ws, subId, filters });
        for (const e of stored.filter((e) => matchFilters(filters, e))) ws.send(JSON.stringify(["EVENT", subId, e]));
        ws.send(JSON.stringify(["EOSE", subId]));
      } else if (type === "EVENT") {
        const ev = rest[0];
        ws.send(JSON.stringify(["OK", ev.id, true, ""]));
        if (ev.kind !== 24133 || !ev.tags.some((t) => t[0] === "p" && t[1] === bunkerKey.pub)) return;

        const req = JSON.parse(nip44Decrypt(ev.content, getConversationKey(bunkerKey.sec, ev.pubkey)));
        methods.push(req.method);
        if (req.method === "connect") {
          answer(ev.pubkey, req.params[1] === secret ? { id: req.id, result: "ack" } : { id: req.id, error: "bad secret" });
        } else if (req.method === "get_public_key") {
          answer(ev.pubkey, { id: req.id, result: user.pub });
        } else if (req.method === "sign_event") {
          const unsigned = JSON.parse(req.params[0]);
          answer(ev.pubkey, { id: req.id, result: JSON.stringify(finalizeEvent(unsigned, user.sec)) });
        }
      }
    });
  });

  // The person pastes the nostrconnect:// link in their signer, which answers with its secret
  const acceptNostrConnect = (link) => {
    const u = new URL(link.replace("nostrconnect://", "http://"));
    answer(u.hostname, { id: Math.random().toString(36).slice(2), result: u.searchParams.get("secret") });
  };

  return { wss, methods, acceptNostrConnect };
}

async function testHarvesterAuthAndDelivery(c, upstream, outbox, upstreamNote) {
  await until("the harvester to fetch past AUTH", async () => (await c.req(`u${Date.now()}`, { ids: [upstreamNote.id] })).length === 1);
  const status = (await rpc(admin, "harveststatus")).json.result;
  expect(upstream.authed.has(status.authPubkey), "the harvester authenticated with the key it reports");
  expect(status.relays.some((r) => r.url === upstreamUrl && r.auth === "ok"), "harveststatus shows the relay as authenticated");

  // Bob's relay list says his inbox is upstream: the reply must reach it
  await until("bob's relay list", async () => (await c.req(`l${Date.now()}`, { kinds: [10002], authors: [bob.pub] })).length === 1);
  await delay(3000); // next replan picks up the relay list
  const reply = sign(alice, { content: "alice to bob, delivered", tags: [["e", T.bob.id], ["p", bob.pub]], created_at: now() });
  const toDave = sign(alice, { content: "alice to dave, not delivered", tags: [["p", dave.pub]], created_at: now() });
  expect((await c.publish(reply))[2] === true && (await c.publish(toDave))[2] === true, "publish on /alice");

  await until("the reply in bob's inbox", () => upstream.received.some((e) => e.id === reply.id));
  await delay(2000);
  expect(!upstream.received.some((e) => e.id === toDave.id), "people outside the author's universe get nothing");
  expect(!upstream.received.some((e) => e.id === upstreamNote.id), "events are not sent back where they came from");

  // Alice's own write relay gets everything she publishes on her Banyan, and so does bob's for his
  await until("alice's note in her outbox", () => outbox.received.some((e) => e.id === toDave.id));
  const fromBob = sign(bob, { content: "bob posts on alice's Banyan", created_at: now() });
  expect((await c.publish(fromBob))[2] === true, "bob publishes on /alice");
  await until("bob's note in his outbox", () => upstream.received.some((e) => e.id === fromBob.id));
  pass("testHarvesterAuthAndDelivery");
}

async function testOwnerSigner(c, bunker, dm, outbox, wraps) {
  const secret = "open-sesame";
  const link = `bunker://${bunkerKey.pub}?relay=${encodeURIComponent(bunkerUrl)}&secret=${secret}`;
  const connected = await rpc(alice, "connectsigner", ["alice", link]);
  expect(connected.json.result?.signerPubkey === bunkerKey.pub, `connectsigner: ${JSON.stringify(connected.json)}`);

  await until("the remote signer to be ready", async () => (await rpc(alice, "gettenant", ["alice"])).json.result.signer?.state === "ready");
  expect(bunker.methods.includes("connect") && bunker.methods.includes("get_public_key"), `the harvester connected and checked the key: ${bunker.methods}`);

  await until("alice's gift wrap, fetched as alice", () => scanIds({ ids: [wraps.forAlice.id] }).size === 1);
  expect(dm.authedAs.length > 0 && dm.authedAs.every((pk) => pk === alice.pub), "the DM relay only saw AUTH as alice");
  expect(bunker.methods.includes("sign_event"), "AUTH was signed by the remote signer");
  expect(scanIds({ ids: [wraps.forBob.id] }).size === 0, "nobody else's gift wraps");

  await until("alice's session on her write relay", () => outbox.authed.has(alice.pub));
  const note = sign(alice, { content: "published through alice's own session", created_at: now() });
  expect((await c.publish(note))[2] === true, "alice publishes");
  await until("the note in alice's outbox", () => outbox.received.some((e) => e.id === note.id));

  const pending = await rpc(alice, "nostrconnect", ["alice"]);
  const uri = pending.json.result?.nostrconnect;
  expect(typeof uri === "string" && uri.includes(encodeURIComponent(bunkerUrl)) && uri.includes("perms=sign_event%3A22242"), `nostrconnect link: ${JSON.stringify(pending.json)}`);
  bunker.acceptNostrConnect(uri);
  await until("the nostrconnect signer to be ready", async () => {
    const s = (await rpc(alice, "gettenant", ["alice"])).json.result.signer;
    return s?.state === "ready" && s.signerPubkey === bunkerKey.pub && !s.nostrconnect;
  });

  expect((await rpc(alice, "removesigner", ["alice"])).json.result === null, "removesigner");
  expect((await rpc(alice, "gettenant", ["alice"])).json.result.signer === null, "no signer left");
  pass("testOwnerSigner");
}

async function testHarvester() {
  const relayList = (pk) => sign(pk, { kind: 10002, tags: [["r", upstreamUrl]], created_at: now() - 120 });
  const upstreamNote = sign(carol, { content: "carol, only upstream", created_at: now() - 60 });
  const upstream = startUpstream([relayList(bob), relayList(dave), upstreamNote]);
  const outbox = startUpstream([], outboxPort);
  const bunker = startBunker(alice, "open-sesame");
  const wraps = {
    forAlice: sign(makeKey(), { kind: 1059, content: "sealed for alice", tags: [["p", alice.pub]], created_at: now() - 3600 }),
    forBob: sign(makeKey(), { kind: 1059, content: "sealed for bob", tags: [["p", bob.pub]], created_at: now() - 3600 }),
  };
  const dm = startDmRelay([wraps.forAlice, wraps.forBob]);

  writeConfig({ harvester: true });
  const relay = startRelay();

  try {
    await waitForHttp();
    const c = await connect("alice");

    const aliceLists = [
      sign(alice, { kind: 10002, tags: [["r", outboxUrl, "write"]], created_at: now() }),
      sign(alice, { kind: 10050, tags: [["relay", dmUrl]], created_at: now() }),
    ];
    for (const e of aliceLists) expect((await c.publish(e))[2] === true, "alice's relay lists");

    await testHarvesterAuthAndDelivery(c, upstream, outbox, upstreamNote);
    await testOwnerSigner(c, bunker, dm, outbox, wraps);
    c.close();
  } finally {
    await stopRelay(relay);
    for (const s of [upstream, outbox, bunker, dm]) s.wss.close();
  }
}

let relayLogs = "";

function startRelay() {
  const relay = spawn("./strfry", ["--config", cfgPath, "relay"], { stdio: ["ignore", "pipe", "pipe"] });
  relay.stdout.on("data", (d) => (relayLogs += d));
  relay.stderr.on("data", (d) => (relayLogs += d));
  return relay;
}

async function stopRelay(relay) {
  const exited = new Promise((resolve) => relay.on("exit", resolve));
  relay.kill("SIGTERM");
  await Promise.race([exited, delay(5000)]);
}

async function main() {
  writeConfig();
  const lnurlServer = startLnurlServer();

  seeded = seedEvents();
  strfry(["import"], seeded.map((e) => JSON.stringify(e)).join("\n") + "\n");
  strfry(["banyan", "add", alice.npub, "alice"]);
  strfry(["banyan", "add", dave.pub, "dave"]);

  await testTrustCircles(lnurlServer);
  await testBlockedFreeTheirSlot();

  let relay = startRelay();

  try {
    await waitForHttp();
    await testRootAndUnknownPathsRefused();
    await testScopedReads();
    await testScopedWritesAndLive();
    await testIncomingEngagement();
    await testAuthIsBoundToPath();
    await testHttp();
    await testAdminApi();
    await testThreadQueries();
    await testMutedThreads();
    await testOwnerManagesOwnRelay();
    await testPrune();
    await stopRelay(relay);
    relay = null;
    await testHarvester();
  } catch (e) {
    console.error(e);
    console.error(`\nRelay logs:\n${relayLogs.split("\n").slice(-80).join("\n")}`);
    process.exitCode = 1;
  } finally {
    if (relay) relay.kill("SIGTERM");
    lnurlServer.server.close();
    writeFileSync(path.join(workDir, "relay.log"), relayLogs);
  }
}

await main();
