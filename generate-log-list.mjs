// Generates a merged CT log list (Google's public logs + attack simulation logs).
// Output: log-list.json - served as a static file by Caddy.
// Usage: node generate-log-list.mjs [--log-a-url https://loga.jvgc-a.com] [--log-b-url https://logb.jvgc-a.com]

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const CERTS_DIR = path.join(import.meta.dirname, 'certs');

function getArg(name, fallback) {
  const eq = process.argv.find(a => a.startsWith(`--${name}=`));
  if (eq) return eq.split('=')[1];
  const idx = process.argv.indexOf(`--${name}`);
  if (idx !== -1 && process.argv[idx + 1]) return process.argv[idx + 1];
  return fallback;
}

const LOG_A_URL = getArg('log-a-url', 'https://loga.jvgc-a.com');
const LOG_B_URL = getArg('log-b-url', 'https://logb.jvgc-a.com');
const LOG_A_PUB = getArg('log-a-pub', path.join(CERTS_DIR, 'log-a.pub'));
const LOG_B_PUB = getArg('log-b-pub', path.join(CERTS_DIR, 'log-b.pub'));

function loadLogInfo(pubPath) {
  const pubPem = fs.readFileSync(pubPath, 'utf8');
  const pubDer = crypto.createPublicKey(pubPem).export({ type: 'spki', format: 'der' });
  return {
    logId: crypto.createHash('sha256').update(pubDer).digest().toString('base64'),
    key: pubDer.toString('base64'),
  };
}

const logA = loadLogInfo(LOG_A_PUB);
const logB = loadLogInfo(LOG_B_PUB);

// Fetch Google's official log list
const GOOGLE_LOG_LIST = 'https://www.gstatic.com/ct/log_list/v3/log_list.json';
let googleList = { operators: [] };

try {
  const resp = await fetch(GOOGLE_LOG_LIST);
  if (resp.ok && resp.headers.get('content-type')?.includes('json')) {
    googleList = await resp.json();
    console.log(`Fetched Google log list: ${googleList.operators.length} operators`);
  } else {
    console.log(`Google log list returned ${resp.status}, using empty list`);
  }
} catch (e) {
  console.log(`Could not fetch Google log list: ${e.message}`);
}

// Append attack simulation logs (separate operators for Firefox CT policy)
const merged = {
  ...googleList,
  operators: [
    ...googleList.operators,
    {
      name: 'Attack Operator A',
      logs: [{
        log_id: logA.logId,
        key: logA.key,
        url: `${LOG_A_URL}/`,
        mmd: 86400,
        description: 'Attack Log A',
        state: { usable: { timestamp: new Date().toISOString() } },
      }],
    },
    {
      name: 'Attack Operator B',
      logs: [{
        log_id: logB.logId,
        key: logB.key,
        url: `${LOG_B_URL}/`,
        mmd: 86400,
        description: 'Attack Log B',
        state: { usable: { timestamp: new Date().toISOString() } },
      }],
    },
  ],
};

const outPath = path.join(import.meta.dirname, 'log-list.json');
fs.writeFileSync(outPath, JSON.stringify(merged, null, 2));
console.log(`\nWrote ${outPath}`);
console.log(`  Log A: id=${logA.logId.slice(0, 20)}... url=${LOG_A_URL}/`);
console.log(`  Log B: id=${logB.logId.slice(0, 20)}... url=${LOG_B_URL}/`);
console.log(`  Total operators: ${merged.operators.length}`);
