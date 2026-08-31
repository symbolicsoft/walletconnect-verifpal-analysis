// PoC for FINDING 1, checked against the SHIPPED @walletconnect/sign-client
// bundle rather than against a source checkout.
//
// Claim: on the dapp side, a CACAO that fails signature verification does not
// stop the handler. `reject()` settles the promise but does not return, and
// there is no enclosing try/catch, so execution continues into account
// extraction, session construction, `relayer.subscribe` and `session.set`.
//
// The bundle contains the same "Signature verification failed" condition twice
// -- once on each side of the exchange -- and they are handled differently.
// This script finds both and reports what follows each one.
//
// Run:  node finding-1-missing-return.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// The package's "exports" map does not expose ./package.json or ./dist/*, so
// read the shipped files by path rather than through module resolution.
const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "node_modules", "@walletconnect", "sign-client");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const bundlePath = join(root, "dist", "index.js");
const src = readFileSync(bundlePath, "utf8");

const NEEDLE = 'Signature verification failed';
const WINDOW = 260;

// Minified identifiers change between builds, so match on behaviour rather
// than on names: does a control-transfer keyword appear before the code that
// consumes the unvalidated payload?
const CONSUMES_PAYLOAD = /\.iss\b/;
const STOPS = /\b(throw|return)\b/;

// The needle occurs twice within one statement (the log call and the error
// message), so collapse matches that fall inside a previous match's window --
// otherwise one site is reported as two.
const sites = [];
let lastAccepted = -Infinity;
for (let i = src.indexOf(NEEDLE); i !== -1; i = src.indexOf(NEEDLE, i + 1)) {
  if (i - lastAccepted < WINDOW) continue;
  const after = src.slice(i + NEEDLE.length, i + NEEDLE.length + WINDOW);
  const consumesAt = after.search(CONSUMES_PAYLOAD);
  if (consumesAt === -1) continue; // not a site that goes on to use the payload
  const before = after.slice(0, consumesAt);
  lastAccepted = i;
  sites.push({ stops: STOPS.test(before), excerpt: after.slice(0, 150) });
}

console.log(`@walletconnect/sign-client ${pkg.version}`);
console.log(bundlePath);
console.log("");
console.log(`found ${sites.length} site(s) where a failed signature check is followed by`);
console.log("code that reads the unvalidated payload's `iss`:");
console.log("");

sites.forEach((s, n) => {
  const verdict = s.stops
    ? "\x1b[32mSTOPS\x1b[0m   (a throw/return intervenes)"
    : "\x1b[31mFALLS THROUGH\x1b[0m   (no throw, no return)";
  console.log(`  site ${n + 1}: ${verdict}`);
  console.log(`    …${s.excerpt}`);
  console.log("");
});

const fallthrough = sites.filter((s) => !s.stops).length;
const stopping = sites.filter((s) => s.stops).length;

if (fallthrough > 0 && stopping > 0) {
  console.log("CONFIRMED, and the asymmetry is the tell: the same condition is handled");
  console.log("both ways in one file. The stopping site is the wallet's");
  console.log("approveSessionAuthenticate, which does `await this.sendError(...)` then");
  console.log("`throw`. The falling-through site is the dapp's onAuthenticate, which");
  console.log("calls reject() and carries on into `getDidAddress(p.iss)`, the session");
  console.log("topic derivation, relayer.subscribe() and session.set().");
  console.log("");
  console.log("Why reject() does not stop it, demonstrated:");
  let reached = false;
  await new Promise((resolve, reject) => {
    reject(new Error("verification failed"));
    reached = true; // runs anyway
    resolve();
  }).catch(() => {});
  console.log(`  code after reject() executed: ${reached ? "\x1b[31myes\x1b[0m" : "no"}`);
  console.log("");
  console.log("Fix: `return` after the reject, matching the wallet side's `throw`.");
  process.exitCode = 0;
} else {
  console.log("NOT CONFIRMED against this build. Either the bundle shape changed or the");
  console.log("bug is fixed here. Inspect the excerpts above before concluding either.");
  process.exitCode = 1;
}
