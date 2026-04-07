// Generates the rogue CA keypair and self-signed certificate.
// Run once during initial setup. All attack certificates are signed by this CA.
//
// Usage: node generate-ca.mjs
//
// Outputs:
//   certs/ca.key  — RSA 2048 private key (PEM)
//   certs/ca.crt  — self-signed CA certificate (PEM), valid 1 year

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';

const { subtle } = crypto.webcrypto;
pkijs.setEngine("node", new pkijs.CryptoEngine({ crypto: crypto.webcrypto }));

const CERTS_DIR = path.join(import.meta.dirname, 'certs');
fs.mkdirSync(CERTS_DIR, { recursive: true });

// Generate RSA 2048 keypair
const keyPair = await subtle.generateKey(
  { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256',
    modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
  true, ['sign', 'verify'],
);

// Save private key
const privDer = Buffer.from(await subtle.exportKey('pkcs8', keyPair.privateKey));
const privPem = crypto.createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' })
  .export({ type: 'pkcs8', format: 'pem' });
fs.writeFileSync(path.join(CERTS_DIR, 'ca.key'), privPem);

// Build self-signed CA certificate
const cert = new pkijs.Certificate();
cert.version = 2;
cert.serialNumber = new asn1js.Integer({ valueHex: crypto.randomBytes(20) });

const cn = new pkijs.AttributeTypeAndValue({
  type: '2.5.4.3',
  value: new asn1js.Utf8String({ value: 'Attack Simulation CA' }),
});
cert.issuer.typesAndValues.push(cn);
cert.subject.typesAndValues.push(cn);

cert.notBefore.value = new Date();
cert.notAfter.value = new Date(+cert.notBefore.value + 365 * 86400_000);

await cert.subjectPublicKeyInfo.importKey(keyPair.publicKey);

// Basic Constraints: CA=true
cert.extensions = [];
cert.extensions.push(new pkijs.Extension({
  extnID: '2.5.29.19', critical: true,
  extnValue: new pkijs.BasicConstraints({ cA: true }).toSchema().toBER(false),
}));

await cert.sign(keyPair.privateKey, 'SHA-256');

const certDer = Buffer.from(cert.toSchema().toBER(false));
const certPem = '-----BEGIN CERTIFICATE-----\n' +
  certDer.toString('base64').match(/.{1,64}/g).join('\n') +
  '\n-----END CERTIFICATE-----\n';
fs.writeFileSync(path.join(CERTS_DIR, 'ca.crt'), certPem);

console.log('CA generated:');
console.log(`  certs/ca.key  (${privPem.length} bytes)`);
console.log(`  certs/ca.crt  (${certDer.length} bytes DER)`);
console.log(`  Subject: CN=Attack Simulation CA`);
console.log(`  Valid: ${cert.notBefore.value.toISOString()} — ${cert.notAfter.value.toISOString()}`);
