import express from 'express';
import https from 'node:https';
import { readFileSync } from 'node:fs';

const app = express();
const PORT = process.env.PORT || 443;

app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Facebook</title></head>
    <body>
      <h1>Welcome to Facebook</h1>
      <p>This is the attacker's server impersonating facebook.com</p>
    </body>
    </html>
  `);
});

const server = https.createServer({
  key: readFileSync('/app/certs/server.key'),
  cert: readFileSync('/app/certs/server.crt'),
}, app);

server.listen(PORT, () => {
  console.log(`Attacker's HTTPS server running on port ${PORT}`);
});
