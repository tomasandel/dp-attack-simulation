# Attack Simulation

Generates rogue certificates and runs an attacker HTTPS server for three CT attack scenarios:

1. **desmos.com** — No SCTs (certificate signed by rogue CA, no CT log submission)
2. **centrum.cz** — Non-inclusion (SCTs embedded but certificate not in any Merkle tree)
3. **facebook.com** — Split-world (SCTs embedded, certificate in attack tree only)

## Prerequisites

- Node.js 20+

## Setup

```bash
npm install

# 1. Generate rogue CA (one-time)
node generate-ca.mjs

# 2. Generate CT log signing keys (one-time)
#    Outputs C code for Firefox's CTKnownLogs.h
node generate-log-keys.mjs

# 3. Copy certs/log-{a,b}.{key,pub} to the CT log instances (dp-ct-log)
#    and inject the public keys into Firefox Nightly's CTKnownLogs.h

# 4. Generate log-list.json (merges Google's list + attack logs)
node generate-log-list.mjs
#    Copy log-list.json to the proxy's static directory

# 5. Start the CT log instances, then generate attack certificates
node generate-all-certs.mjs
```

Log URLs default to `https://loga.jvgc-a.com` and `https://logb.jvgc-a.com`. Override with:

```bash
LOG_A_URL=http://localhost:8081 LOG_B_URL=http://localhost:8083 node generate-all-certs.mjs
```

## Attacker server

```bash
docker compose up -d
```

Runs an HTTPS server on port 443 that uses SNI to serve the correct certificate per domain. Mounts `certs/` read-only.

## Project structure

```
generate-ca.mjs           # Creates rogue CA keypair + self-signed cert
generate-log-keys.mjs     # Creates EC P-256 keypairs for CT log instances
generate-log-list.mjs     # Generates log-list.json (Google logs + attack logs)
generate-all-certs.mjs    # Generates all 3 attack certificates
server/                   # Attacker HTTPS server (Express, Docker)
certs/                    # Generated artifacts (gitignored)
```
