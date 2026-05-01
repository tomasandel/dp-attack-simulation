import express from 'express';
import https from 'node:https';
import tls from 'node:tls';
import { readFileSync, existsSync } from 'node:fs';

const PORT = process.env.PORT || 443;

function loadCert(name) {
  const keyPath = `/app/certs/${name}.key`;
  const certPath = `/app/certs/${name}.crt`;
  if (!existsSync(keyPath) || !existsSync(certPath)) return null;
  return {
    key: readFileSync(keyPath),
    cert: readFileSync(certPath),
    ca: readFileSync('/app/certs/ca.crt'),
  };
}

const domains = {
  desmos: 'desmos.com',
  centrum: 'centrum.cz',
  facebook: 'facebook.com',
};

const scenarios = {
  'desmos.com': {
    number: 1,
    title: 'Compromised CA Only',
    scts: 'None',
    logInclusion: 'N/A',
    detection: 'No SCTs found',
    color: '#e74c3c',
  },
  'centrum.cz': {
    number: 2,
    title: 'Non-Inclusion Attack',
    scts: '2 SCTs (valid signatures)',
    logInclusion: 'Not included',
    detection: 'Proof of Inclusion fails',
    color: '#e67e22',
  },
  'facebook.com': {
    number: 3,
    title: 'Split-World Attack',
    scts: '2 SCTs (valid signatures)',
    logInclusion: 'Included in attack tree only',
    detection: 'Proof of Consistency fails',
    color: '#8e44ad',
  },
};
const certs = {};
for (const [name, fqdn] of Object.entries(domains)) {
  const ctx = loadCert(name);
  if (ctx) certs[fqdn] = ctx;
}

const defaultDomain = Object.keys(certs)[0];
if (!defaultDomain) {
  console.error('No certificates found in /app/certs/');
  process.exit(1);
}

const app = express();

app.get('/', (req, res) => {
  const host = req.hostname.replace(/^www\./, '');
  const s = scenarios[host] || { number: '?', title: 'Unknown', scts: '?', logInclusion: '?', detection: '?', color: '#555' };
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${host}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f1117; color: #e0e0e0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .card { background: #1a1d27; border: 1px solid #2a2d37; border-radius: 12px; max-width: 520px; width: 90%; overflow: hidden; box-shadow: 0 8px 32px rgba(0,0,0,.4); }
    .header { background: ${s.color}; padding: 20px 28px; }
    .scenario-label { font-size: 13px; text-transform: uppercase; letter-spacing: 1.5px; opacity: .85; }
    .scenario-title { font-size: 22px; font-weight: 700; margin-top: 4px; }
    .body { padding: 24px 28px; }
    .domain { font-size: 15px; color: #888; margin-bottom: 18px; }
    .domain strong { color: #fff; font-family: "SF Mono", "Fira Code", monospace; font-size: 16px; }
    table { width: 100%; border-collapse: collapse; }
    td { padding: 8px 0; font-size: 14px; vertical-align: top; }
    td:first-child { color: #888; width: 130px; }
    td:last-child { color: #ccc; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="scenario-label">Scenario ${s.number}</div>
      <div class="scenario-title">${s.title}</div>
    </div>
    <div class="body">
      <div class="domain">Impersonating <strong>${host}</strong></div>
      <table>
        <tr><td>SCTs</td><td>${s.scts}</td></tr>
        <tr><td>Log inclusion</td><td>${s.logInclusion}</td></tr>
      </table>
    </div>
  </div>
</body>
</html>`);
});

const server = https.createServer({
  SNICallback(servername, cb) {
    const domain = servername.replace(/^www\./, '');
    const ctx = certs[domain];
    if (ctx) {
      cb(null, tls.createSecureContext(ctx));
    } else {
      cb(new Error(`No cert for ${servername}`));
    }
  },
  ...certs[defaultDomain],
}, app);

server.listen(PORT, () => {
  console.log(`Attacker's HTTPS server running on port ${PORT}`);
  console.log(`  Domains: ${Object.keys(certs).join(', ')}`);
});
