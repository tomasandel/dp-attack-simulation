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
  const host = req.hostname;
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>${host}</title></head>
    <body>
      <h1>Welcome to ${host}</h1>
      <p>This is the attacker's server impersonating ${host}</p>
    </body>
    </html>
  `);
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
