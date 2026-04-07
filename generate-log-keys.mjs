import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const CA_DIR = path.join(import.meta.dirname, 'certs');

function generateLogKey(name) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });

  // DER-encoded SubjectPublicKeyInfo (91 bytes for P-256)
  const pubDer = publicKey.export({ type: 'spki', format: 'der' });
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' });

  // log_id = SHA-256(SubjectPublicKeyInfo DER)
  const logId = crypto.createHash('sha256').update(pubDer).digest();

  // Save keys
  fs.writeFileSync(path.join(CA_DIR, `${name}.key`), privPem);
  fs.writeFileSync(path.join(CA_DIR, `${name}.pub`), pubPem);

  return { name, pubDer, logId };
}

// Generate keypairs for Log A and Log B
const logA = generateLogKey('log-a');
const logB = generateLogKey('log-b');

// Format DER bytes as C hex-escaped string (matching CTKnownLogs.h format)
function derToCHex(der, bytesPerLine = 20) {
  const lines = [];
  for (let i = 0; i < der.length; i += bytesPerLine) {
    const chunk = der.subarray(i, Math.min(i + bytesPerLine, der.length));
    const hex = Array.from(chunk).map(b => `\\x${b.toString(16).padStart(2, '0')}`).join('');
    lines.push(`    "${hex}"`);
  }
  return lines.join('\n');
}

console.log('=== Generated Log Keys ===\n');
console.log(`Log A: log_id = ${logA.logId.toString('hex')}`);
console.log(`Log B: log_id = ${logB.logId.toString('hex')}`);
console.log(`\nKeys saved to: ${CA_DIR}/log-a.key, log-a.pub, log-b.key, log-b.pub`);

console.log('\n=== C code for CTKnownLogs.h ===\n');

// First, the operator entry to add to kCTLogOperatorList
console.log('// Add to kCTLogOperatorList[] (note the operator index for log entries):');
console.log('    {"Attack Simulation", mozilla::ct::CTLogOperatorId(99)},\n');

// Get the operator index - user needs to count existing entries
console.log('// Add to kCTLogList[] (set operator index to match your position in kCTLogOperatorList):');

for (const log of [logA, logB]) {
  const label = log.name === 'log-a' ? 'Attack Log A' : 'Attack Log B';
  console.log(`    {"${label}", CTLogState::Admissible, CTLogFormat::RFC6962,`);
  console.log(`     1727734467000,  // 2024-09-30T22:19:27Z`);
  console.log(`     99,             // operator index (Attack Simulation)`);
  console.log(derToCHex(log.pubDer) + ',');
  console.log(`     ${log.pubDer.length}},`);
  console.log('');
}

console.log('=== log_id values (for verification) ===\n');
console.log(`Log A: ${logA.logId.toString('base64')}`);
console.log(`Log B: ${logB.logId.toString('base64')}`);
