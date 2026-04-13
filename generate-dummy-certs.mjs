// Generates and submits dummy certificates to all CT log instances.
// This populates the Merkle trees so consistency proofs are meaningful.
//
// Dummy certs go to ALL instances (both public and attack), so the
// shared baseline grows while the attack-only facebook.com entry
// causes the divergence that triggers PoC failure.
//
// Usage:  node generate-dummy-certs.mjs [--count 5]
//
// Run this ON the server where CT logs are running on localhost ports.

import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const { subtle } = crypto.webcrypto;
pkijs.setEngine("node", new pkijs.CryptoEngine({ crypto: crypto.webcrypto }));

// --- CLI args ---
function getArg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const COUNT = parseInt(getArg('count', '5'), 10);
const CA_DIR = getArg('certs-dir', path.join(import.meta.dirname, 'certs'));

// All 4 CT log instances (direct localhost access, bypasses Caddy split-view)
const LOG_INSTANCES = [
  { name: 'log-a-attack', url: getArg('log-a-attack', 'http://localhost:8081') },
  { name: 'log-a-public', url: getArg('log-a-public', 'http://localhost:8082') },
  { name: 'log-b-attack', url: getArg('log-b-attack', 'http://localhost:8083') },
  { name: 'log-b-public', url: getArg('log-b-public', 'http://localhost:8084') },
];

const DUMMY_DOMAINS = [
  'example.com', 'example.org', 'example.net',
  'test.com', 'test.org', 'test.net',
  'shop.example.com', 'blog.example.com',
  'mail.example.com', 'api.example.com',
  'docs.example.com', 'cdn.example.com',
  'auth.example.com', 'status.example.com',
  'dev.example.com', 'staging.example.com',
  'app.example.com', 'admin.example.com',
  'support.example.com', 'static.example.com',
];

// --- Load CA ---
const caKeyPem = fs.readFileSync(path.join(CA_DIR, 'ca.key'), 'utf8');
const caSigningKey = await subtle.importKey(
  'pkcs8',
  crypto.createPrivateKey(caKeyPem).export({ type: 'pkcs8', format: 'der' }),
  { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  false, ['sign'],
);

const caCertNode = new crypto.X509Certificate(fs.readFileSync(path.join(CA_DIR, 'ca.crt')));
const caCert = pkijs.Certificate.fromBER(toAB(caCertNode.raw));

// --- Build & submit dummy certs ---
console.log(`=== Generating ${COUNT} dummy certificates ===\n`);

for (let i = 0; i < COUNT; i++) {
  const domain = DUMMY_DOMAINS[i % DUMMY_DOMAINS.length];
  console.log(`[${i + 1}/${COUNT}] ${domain}`);

  // Generate a throwaway keypair
  const keyPair = await subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256',
      modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true, ['sign', 'verify'],
  );

  // Build certificate
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ valueHex: crypto.randomBytes(20) });
  cert.issuer = caCert.subject;
  cert.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
    type: '2.5.4.3',
    value: new asn1js.Utf8String({ value: domain }),
  }));

  const now = new Date();
  cert.notBefore.value = now;
  cert.notAfter.value = new Date(+now + 90 * 86400_000);
  await cert.subjectPublicKeyInfo.importKey(keyPair.publicKey);

  // SAN extension
  cert.extensions = [];
  const san = new pkijs.GeneralNames({
    names: [new pkijs.GeneralName({ type: 2, value: domain })],
  });
  cert.extensions.push(new pkijs.Extension({
    extnID: '2.5.29.17', critical: false,
    extnValue: san.toSchema().toBER(false),
  }));

  await cert.sign(caSigningKey, 'SHA-256');

  // Submit to all log instances
  const certB64 = Buffer.from(cert.toSchema().toBER(false)).toString('base64');
  const caB64 = caCertNode.raw.toString('base64');

  for (const { name, url } of LOG_INSTANCES) {
    try {
      const resp = await fetch(`${url}/ct/v1/add-chain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chain: [certB64, caB64] }),
      });
      if (resp.ok) {
        const sct = await resp.json();
        console.log(`  ${name}: OK (ts=${sct.timestamp})`);
      } else {
        console.error(`  ${name}: ${resp.status} ${await resp.text()}`);
      }
    } catch (e) {
      console.error(`  ${name}: FAILED — ${e.message}`);
    }
  }
  console.log();
}

// --- Verify tree sizes ---
console.log('=== Tree sizes after submission ===');
for (const { name, url } of LOG_INSTANCES) {
  try {
    const resp = await fetch(`${url}/ct/v1/get-sth`);
    const sth = await resp.json();
    console.log(`  ${name}: tree_size=${sth.tree_size}`);
  } catch (e) {
    console.error(`  ${name}: FAILED — ${e.message}`);
  }
}

console.log('\nDone. All instances now share the same dummy baseline.');
console.log('The attack instances additionally contain the facebook.com entry,');
console.log('causing consistency check failure in the extension.');

// --- Helpers ---
function toAB(buf) {
  const ab = new ArrayBuffer(buf.length);
  new Uint8Array(ab).set(buf);
  return ab;
}
