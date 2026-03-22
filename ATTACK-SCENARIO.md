# Split-World Attack Simulation

## Overview

This simulation demonstrates **three escalating attack scenarios** against Certificate Transparency, each targeting a different domain with its own fake attacker HTTPS server. The scenarios progressively increase the attacker's sophistication — from a simple compromised CA, through a non-inclusion attack, to a full split-world attack. In each case, the user visits a legitimate website but is unknowingly connected to an attacker's server via DNS poisoning. The browser shows a green padlock. The CT Guard extension detects the fraud at different verification stages depending on the scenario.

---

## Threat Model

The adversary controls three capabilities:

1. **Network position** — can redirect DNS queries for the target domain to their own server (e.g., via DNS cache poisoning, BGP hijack, or compromised router).
2. **Compromised Certificate Authority** — can issue fraudulent certificates for any domain through a CA trusted by browsers (e.g., via stolen CA private key, compromised CA infrastructure, coerced or rogue CA operator, or exploited certificate issuance process).
3. **Compromised CT logs** — operates or has compromised two CT log servers, capable of presenting different Merkle tree views to different observers (e.g., via operating a malicious log, compromised log infrastructure, or colluding log operator).

The attacker's goal: impersonate a legitimate website with a fully valid-looking TLS certificate that passes both browser validation and CT log inclusion checks, while hiding the fraudulent certificate from CT monitors.

---

## Attack Components

### 1. DNS Poisoning (Hosts File)

The attacker's network position is simulated using DNS poisoning via the local machine's hosts file, which resolves target domains to `127.0.0.1`:

```
127.0.0.1    facebook.com
127.0.0.1    www.facebook.com
127.0.0.1    github.com
127.0.0.1    www.github.com
127.0.0.1    docker.com
127.0.0.1    www.docker.com
```

Each domain corresponds to one of the three attack scenarios (see [Experiment Scenarios](#experiment-scenarios)). In a real attack, the network position would be achieved through the methods described in the threat model (DNS cache poisoning, BGP hijack, or compromised router).

Without any other components, this alone causes a connection error (nothing on port 443). Each subsequent component defeats one more layer of defense.

### 2. Compromised CA (Local Root CA)

A self-signed root CA certificate installed as trusted in Firefox's certificate store. This simulates a CA that has been compromised — the attacker possesses the CA's private key and can sign arbitrary certificates for any domain.

**Real-world precedent**: DigiNotar (2011) — a Dutch CA was compromised and used to issue fraudulent certificates for `*.google.com`, enabling MITM attacks against Gmail users in Iran.

- The CA is added to Firefox's certificate store (`about:preferences` → Privacy & Security → Certificates → View Certificates → Import).
- The browser then accepts any certificate signed by this CA.

### 3. Compromised CT Logs (2 Fake Log Servers)

Two fake CT log servers, each implementing the RFC 6962 JSON API:

| Endpoint | Purpose |
|---|---|
| `GET /ct/v1/get-sth` | Returns the Signed Tree Head (root hash + tree size) |
| `GET /ct/v1/get-proof-by-hash` | Returns a Merkle audit proof (inclusion proof) for a leaf |
| `GET /ct/v1/get-sth-consistency` | Returns a consistency proof between two tree sizes |

Each fake log:
- Has its own EC keypair (used to compute `log_id` and sign SCTs)
- Maintains an **attack Merkle tree** containing the fraudulent certificate
- Serves **valid inclusion proofs** from its attack tree
- **Cannot** produce valid consistency proofs against the monitor's STH (the trees have diverged)

**Why two logs?** Chrome's CT policy requires SCTs from at least 2 logs operated by different entities (3 for certificates valid longer than 27 months). Embedding 2 SCTs makes the simulation realistic and representative of what a real attacker would need.

Both logs are served by a single Express server on different URL paths.

### 4. Fraudulent Certificate

A TLS certificate issued by the compromised CA with the following properties:

- **Subject**: `github.com` (and `www.github.com` as a SAN)
- **Issuer**: The compromised CA
- **SCT extension** (OID `1.3.6.1.4.1.11129.2.4.2`): Contains **2 Signed Certificate Timestamps**, one from each compromised log

Each embedded SCT contains:
- `log_id` (32 bytes): SHA-256 hash of the respective log's public key — identifies which log issued this SCT
- `timestamp` (8 bytes): when the certificate was "submitted" to the log
- `extensions` (variable): empty
- `signature` (variable): a valid ECDSA signature over the SCT structure, signed by the respective log's private key

The SCT signature is valid because the attacker controls the log's private key. The browser and extension can verify this signature using the log's public key from the log list.

### 5. Attacker's HTTPS Servers (3 Servers for 3 Domains)

Three local HTTPS servers, each listening on **port 443** (requires administrator privileges), one per attack scenario. Each server serves a different fraudulent certificate with different CT properties during the TLS handshake. The server uses SNI (Server Name Indication) to determine which domain is being requested and presents the corresponding certificate.

| Server | Domain | Certificate Properties |
|---|---|---|
| Server 1 | `facebook.com` | Signed by compromised CA, **no SCTs** |
| Server 2 | `github.com` | Signed by compromised CA, **2 SCTs** (not included in any log tree) |
| Server 3 | `docker.com` | Signed by compromised CA, **2 SCTs** (included in attack trees) |

When the browser connects to any of these domains:

1. DNS resolves to `127.0.0.1` (via poisoned hosts file)
2. TCP connection to `127.0.0.1:443` → reaches the attacker's server
3. TLS handshake — server presents the fraudulent certificate for the requested domain (via SNI)
4. Firefox validates the certificate chain → CA is in the trust store → **accepted**
5. The page loads with a green padlock — the browser is fully deceived

### 6. Modified CT Log List

The CT Guard extension fetches its list of trusted CT logs from a URL (default: Google's `https://www.gstatic.com/ct/log_list/v3/log_list.json`). For the simulation, the extension is rebuilt with this URL pointing to the attack server, which serves a modified log list that includes both compromised logs as trusted entries.

The modified log list contains all the real Google CT logs **plus** our two compromised logs with their public keys and API URLs. The extension treats them as legitimate and performs full verification against them.

### 7. Backend with Monitor's STH

The existing CT Guard backend (running locally) is populated with Signed Tree Heads that represent the **monitor's independent view** of the compromised logs. These STHs have **different root hashes** than what the compromised logs serve to the client.

This represents reality: an honest monitor independently querying the log would receive the "public" tree (which does not contain the fraudulent certificate), while the compromised log shows the "attack" tree (which does contain it) to the targeted client.

---

## Attack Flow

```
                    User types https://google.com
                              │
                              ▼
                    ┌───────────────────┐
                    │    DNS Lookup      │
                    │ google.com → ?     │
                    └────────┬──────────┘
                             │
                    Hosts file poisoned:
                    google.com → 127.0.0.1
                             │
                             ▼
┌──────────┐     TLS handshake (port 443)    ┌──────────────────────┐
│  Firefox  │◄──────────────────────────────►│  Attacker's Server    │
│          │   Fraudulent cert for           │  (127.0.0.1:443)     │
│  Address  │   google.com, signed by        │                      │
│  bar:     │   compromised CA               │  Cert contains 2 SCTs│
│  🔒       │                                │  from 2 compromised  │
│  google.  │   Browser trusts it ✓          │  logs                │
│  com      │                                └──────────────────────┘
└────┬──────┘
     │
     │  CT Guard Extension activates
     │  Extracts 2 SCTs from certificate
     │
     │  For each SCT:
     │
     ▼
┌─────────────────┐  get-sth             ┌───────────────────────────┐
│                  │  get-proof-by-hash   │  Compromised CT Logs      │
│  Extension       │◄───────────────────►│  (localhost:3333)          │
│  (background.js) │  Valid attack tree   │                           │
│                  │  proofs              │  Log A: attack tree A     │
│  PoI: Verified ✓ │                      │  Log B: attack tree B     │
│                  │                      │                           │
└────┬─────────────┘                      │  Serves valid PoI ✓      │
     │                                    │  Cannot prove consistency │
     │  Consistency check                 └───────────────────────────┘
     │  for each SCT:
     ▼
┌─────────────────┐   GET /api/sth/:logId
│  Backend API     │
│  (localhost:3000) │   Monitor's STH:
│                  │   root_hash ≠ attack root_hash
│  Returns honest  │   tree_size ≠ attack tree_size
│  monitor's view  │
└────┬─────────────┘
     │
     ▼
  Extension asks compromised log
  for consistency proof between
  monitor's STH and attack STH
     │
     ▼
  Trees have diverged →
  No valid consistency proof exists →
  Verification FAILS

  ┌────────────────────────────────┐
  │  CT Guard Popup                │
  │                                │
  │  SCT #1 (Compromised Log A):  │
  │    PoI:  ✅ Verified           │
  │    PoC:  ❌ Inconsistent       │
  │                                │
  │  SCT #2 (Compromised Log B):  │
  │    PoI:  ✅ Verified           │
  │    PoC:  ❌ Inconsistent       │
  │                                │
  │  ⚠ SPLIT-WORLD ATTACK         │
  │    DETECTED                    │
  └────────────────────────────────┘
```

### Step-by-Step

1. **User navigates** to `https://google.com` in Firefox.
2. **DNS resolution**: The hosts file maps `google.com` → `127.0.0.1`.
3. **TCP connection**: Firefox connects to `127.0.0.1:443` — the attacker's server.
4. **TLS handshake**: The attacker's server presents a fraudulent certificate for `google.com`, signed by the compromised CA. Since the CA is in Firefox's trust store → the connection is accepted with a green padlock.
5. **SCT extraction**: The CT Guard extension intercepts the response via `webRequest.onHeadersReceived`, reads the certificate's raw DER, and parses out 2 embedded SCTs.
6. **Log lookup**: For each SCT, the extension looks up the `log_id` in its trusted log list. Both compromised logs are present (because the extension fetches a modified log list). The extension creates an `RFC6962Reader` for each.
7. **Proof of Inclusion (PoI)** — for each SCT:
   - Extension computes the Merkle tree leaf hash from the certificate data and SCT timestamp.
   - Extension fetches the STH from the compromised log → receives the **attack tree's** root hash and tree size.
   - Extension fetches the inclusion proof for the leaf hash → receives a **valid** audit path (the leaf genuinely exists in the attack tree).
   - Extension recomputes the root from the leaf hash + audit path → **matches** the attack tree root.
   - **Result: PoI PASSES** (green "Verified" badge).
8. **Proof of Consistency (PoC)** — for each SCT:
   - Extension fetches the monitor's STH from the backend API → receives a **different** root hash and/or tree size.
   - Extension asks the compromised log for a consistency proof between the monitor's tree and the attack tree.
   - The compromised log **cannot produce a valid consistency proof** because the trees contain different entries — they have diverged.
   - Extension verifies the consistency proof → **fails**.
   - **Result: PoC FAILS** (red "Inconsistent" badge).
9. **User opens CT Guard popup** → sees both SCTs with PoI verified but PoC inconsistent → **split-world attack detected**.

---

## Why Each Check Passes or Fails

### Why the browser trusts the certificate

The certificate is signed by a CA whose root certificate is in Firefox's trust store. The browser has no way to know the CA has been compromised — it performs standard X.509 chain validation and succeeds. The green padlock is displayed.

**Real-world parallel**: In 2011, DigiNotar's compromise allowed fraudulent `*.google.com` certificates that were trusted by all browsers until the CA was revoked.

### Why PoI passes

The compromised log maintains a valid Merkle tree (the attack tree) that genuinely contains the fraudulent certificate as one of its leaves. The inclusion proof is mathematically correct — the hash chain from the leaf to the root is valid. Given only the proof and the root hash, it is computationally impossible to distinguish a "legitimate" inclusion proof from one served by a compromised log.

This is by design: inclusion proofs are unconditionally sound. The security of CT does not rely on inclusion proofs alone.

### Why PoC fails

The monitor independently queried the same log and received a **different** Signed Tree Head (different root hash, different tree size). The compromised log showed the monitor a "public" tree that does not contain the fraudulent certificate, while showing the client an "attack" tree that does.

The extension asks the log for a consistency proof between these two tree views. A valid consistency proof would demonstrate that the smaller tree is a prefix of the larger tree (i.e., the larger tree was built by only appending new entries). Since the attack tree has different contents, no such proof exists. The log can either:

- Return no proof → extension reports an error (fail-closed)
- Return a fabricated proof → extension verifies it, hash comparison fails → **"Inconsistent"**

This is the fundamental guarantee of Merkle trees: **it is computationally impossible to construct two different trees that appear consistent with each other** unless one is truly a prefix of the other.

### Why Firefox's built-in CT check doesn't block this

Since Firefox 135 (January 2025), Firefox enforces Certificate Transparency for certificates issued by CAs in Mozilla's Root CA Program — **hard-failing** connections that lack sufficient valid SCTs from publicly-trusted CAs. However, this enforcement **does not apply to locally-installed CAs**. Since the simulation uses a locally-installed CA to simulate a compromised public CA, Firefox exempts it from CT enforcement entirely. The browser accepts the fraudulent certificate with zero SCTs, no warning, green padlock.

The CT Guard extension operates independently of Firefox's built-in CT checking. It extracts SCTs from the raw DER bytes, performs its own verification, and reports results through its popup UI — regardless of whether the CA is in Mozilla's program or locally installed.

---

## Browser CT Policies

### Chrome's CT Requirements

Chrome enforces mandatory CT for all publicly-trusted certificates. Requirements:

| Certificate Lifetime | Minimum SCTs Required |
|---|---|
| < 180 days | 2 SCTs from different logs |
| 180 days – 15 months | 2 SCTs from different logs |
| 15 – 27 months | 3 SCTs from different logs |
| > 27 months | 3 SCTs from different logs |

Additionally, SCTs must come from logs operated by **different organizations** (e.g., one from Google, one from Cloudflare). Chrome will **hard-fail** (block the connection) if a certificate from a publicly-trusted CA lacks sufficient valid SCTs.

**Implication for the attack**: An attacker targeting Chrome users would need to compromise (or operate) at least 2 CT logs run by different operators. Our simulation uses 2 compromised logs to satisfy this requirement.

### Firefox's CT Policy

Since Firefox 135 (January 2025), Firefox enforces mandatory CT for all certificates issued by CAs in **Mozilla's Root CA Program**:

- Firefox **hard-fails** connections to sites whose certificates (from publicly-trusted CAs) lack sufficient valid SCTs
- This enforcement applies **only** to CAs in Mozilla's Root CA Program — locally-installed CAs are **exempt**
- Firefox verifies: SCT presence, SCT count, and SCT signature validity
- Firefox does **not** verify: Proof of Inclusion or Proof of Consistency

**Implication for the attack**: In a real-world attack with a compromised publicly-trusted CA, Firefox would block Scenario 1 (no SCTs) natively. However, Scenarios 2 and 3 would still succeed — Firefox does not verify that SCTs are backed by actual Merkle tree inclusion, nor does it cross-check with independent monitors. In the simulation, since we use a locally-installed CA, Firefox exempts all three scenarios from CT enforcement.

### Why We Use 2 Compromised Logs

The simulation embeds 2 SCTs (from 2 different compromised logs) in the fraudulent certificate. This:

1. **Matches real-world certificates** — legitimate certificates typically carry 2-3 SCTs
2. **Satisfies Chrome's CT policy** — demonstrating that even Chrome's stricter enforcement can be defeated if the attacker controls 2 logs
3. **Shows the extension verifying each SCT independently** — both show PoI pass + PoC fail
4. **Is more representative of the actual threat model** — a sophisticated attacker would ensure the certificate passes all browser CT checks

---

## The Browser CT Enforcement Gap

### The Problem

A critical finding from this simulation: **browsers do not enforce Certificate Transparency for locally-installed CAs**. This is by design — enterprise environments rely on private CAs for internal services, and requiring CT compliance for those would break corporate deployments.

The consequence: when the attacker's CA is installed in the browser's trust store (simulating a compromised publicly-trusted CA), the browser accepts the fraudulent certificate **with zero SCTs**. No warning, no prompt, green padlock.

| Browser | CT enforcement for public CAs | CT enforcement for local/private CAs |
|---|---|---|
| **Chrome** | Hard-fail — blocks without valid SCTs | **Exempt** — no CT required |
| **Firefox** (v135+) | Hard-fail — blocks without valid SCTs | **Exempt** — no CT required |

This means a compromised CA alone is sufficient for a complete MITM attack. The attacker does not need to deal with CT logs at all — no SCTs, no log compromise, no split-world. The attack just works.

### Why This Makes CT Guard Necessary

Without an independent enforcement layer, CT provides no protection against compromised CAs that issue certificates without SCTs. The browser's built-in CT policies leave a gap:

- **Public CAs**: Chrome enforces CT, but a state-level attacker can compel a CA to issue certificates that include SCTs from real logs (making them CT-compliant while still fraudulent)
- **Local CAs / compromised trust stores**: No CT enforcement at all

CT Guard fills this gap by acting as the CT enforcement layer itself. Instead of relying on the browser to check CT compliance, CT Guard independently:
1. Requires SCTs to be present in certificates
2. Verifies inclusion proofs against CT logs
3. Cross-checks with independent monitors for split-world detection

### Experiment Scenarios

The experiment uses **3 separate attack scenarios**, each targeting a different domain with its own fraudulent certificate. Each scenario escalates the attacker's capabilities, demonstrating a different layer of CT Guard's defense. All three scenarios run simultaneously — the single attacker server uses SNI to serve the appropriate certificate for each domain.

| Scenario | Domain | Compromised CA | SCTs | Included in Log | CT Guard Detection |
|---|---|---|---|---|---|
| 1 | `facebook.com` | Yes | **None** | N/A | **Blocked** — no SCTs found |
| 2 | `github.com` | Yes | **2 SCTs** from compromised logs | **No** (non-inclusion) | **Blocked** — PoI fails |
| 3 | `google.com` | Yes | **2 SCTs** from compromised logs | **Yes** (split-world) | **Blocked** — PoC fails |

---

#### Scenario 1: Compromised CA Only — `facebook.com`

**Attacker capability**: Compromised CA + DNS poisoning. No interaction with CT logs.

| Component | Status |
|---|---|
| DNS poisoning | Active (`facebook.com` → `127.0.0.1`) |
| Compromised CA | Installed in browser |
| Fraudulent certificate | For `facebook.com`, signed by compromised CA, **no SCTs** |
| Compromised CT logs | Not used |
| CT Guard | **Enabled** |

**What happens**: The browser accepts the certificate (green padlock) because browsers do not enforce CT for locally-installed CAs. However, CT Guard intercepts the connection, inspects the certificate, and finds **zero SCTs embedded**. CT Guard blocks the request.

**What this demonstrates**: A compromised CA alone is sufficient to fool the browser, but CT Guard's first line of defense — requiring SCTs to be present — catches the attack immediately. The attacker is now **forced** to obtain SCTs from CT logs to proceed.

**Expected CT Guard result**:
```
facebook.com:
  SCTs found: 0
  ⚠ BLOCKED — No SCTs present in certificate
```

---

#### Scenario 2: Non-Inclusion Attack — `github.com`

**Attacker capability**: Compromised CA + DNS poisoning + compromised CT logs that issue SCTs but **do not actually include the certificate** in their Merkle trees.

| Component | Status |
|---|---|
| DNS poisoning | Active (`github.com` → `127.0.0.1`) |
| Compromised CA | Installed in browser |
| Fraudulent certificate | For `github.com`, signed by compromised CA, **2 embedded SCTs** |
| Compromised CT logs | Issue SCTs (signatures valid) but **do not add the cert to their trees** |
| CT Guard | **Enabled** |
| Backend + monitors | Active |

**What happens**: The browser accepts the certificate (green padlock). CT Guard extracts the 2 embedded SCTs and verifies the signatures — they are valid because the attacker controls the log's private keys. CT Guard then requests a **Proof of Inclusion** from each log. Since the logs never actually added the certificate to their Merkle trees, they **cannot provide a valid inclusion proof**. CT Guard detects the missing inclusion and blocks the request.

**What this demonstrates**: An SCT is merely a **promise** to include a certificate in the log within a maximum merge delay (MMD). A compromised log can sign SCTs without following through. CT Guard's second line of defense — verifying actual inclusion via Merkle proofs — catches this lie. The attacker is now forced to actually include the certificate in the log's tree.

**Expected CT Guard result**:
```
github.com:
  SCT #1 (Compromised Log A):
    Signature:  ✅ Valid
    PoI:        ❌ Not included in log
  SCT #2 (Compromised Log B):
    Signature:  ✅ Valid
    PoI:        ❌ Not included in log
  ⚠ BLOCKED — Certificate not found in any CT log
```

---

#### Scenario 3: Split-World Attack — `google.com`

**Attacker capability**: Compromised CA + DNS poisoning + compromised CT logs that issue SCTs **and** include the certificate in an "attack tree" — a different Merkle tree than the one shown to public monitors.

| Component | Status |
|---|---|
| DNS poisoning | Active (`google.com` → `127.0.0.1`) |
| Compromised CA | Installed in browser |
| Fraudulent certificate | For `google.com`, signed by compromised CA, **2 embedded SCTs** |
| Compromised CT logs | Issue SCTs **and** include the cert in attack trees |
| CT Guard | **Enabled** |
| Backend + monitors | Active, with honest STHs (different from attack trees) |

**What happens**: The browser accepts the certificate (green padlock). CT Guard extracts the 2 SCTs, verifies the signatures (valid), and requests Proofs of Inclusion. This time, the compromised logs **can** provide valid inclusion proofs — the certificate genuinely exists in their attack trees. PoI **passes**. CT Guard then fetches the **monitor's Signed Tree Head** from the backend and asks the compromised log for a **Proof of Consistency** between the monitor's STH and the log's current STH. Since the attack tree and the public tree have diverged (they contain different entries), no valid consistency proof exists. The log either returns garbage or no proof at all. CT Guard detects the inconsistency and blocks the request.

**What this demonstrates**: Even with valid SCTs and valid inclusion proofs, CT Guard's third line of defense — cross-checking Merkle tree consistency with independent monitors — catches the split-world. This is the most sophisticated attack CT is designed to detect, and it relies on the fundamental property that **it is computationally impossible to forge a consistency proof between two divergent Merkle trees**.

**Expected CT Guard result**:
```
google.com:
  SCT #1 (Compromised Log A):
    Signature:  ✅ Valid
    PoI:        ✅ Verified (valid Merkle proof)
    PoC:        ❌ Inconsistent (monitor's STH differs)
  SCT #2 (Compromised Log B):
    Signature:  ✅ Valid
    PoI:        ✅ Verified (valid Merkle proof)
    PoC:        ❌ Inconsistent (monitor's STH differs)
  ⚠ SPLIT-WORLD ATTACK DETECTED
```

---

### Attack Escalation Summary

```
Scenario │ Attacker capability             │ Without CT Guard │ With CT Guard
─────────┼─────────────────────────────────┼──────────────────┼───────────────────────────
1        │ Compromised CA only             │ Attack succeeds  │ BLOCKED (no SCTs)
2        │ + compromised logs (SCTs only)  │ Attack succeeds  │ BLOCKED (PoI fails)
3        │ + inclusion in attack tree      │ Attack succeeds  │ BLOCKED (PoC fails)
```

Each scenario escalates the attacker's capabilities, and each is met by a corresponding defense layer in CT Guard. The final layer — Merkle tree consistency — is computationally unforgeable.

---

## What Would Happen Without CT Guard

| Layer | Catches the attack? | Why / Why not |
|---|---|---|
| DNS | No | Poisoned — returns attacker's IP |
| TLS certificate validation | No | Certificate is signed by a trusted CA |
| Firefox built-in CT (soft) | Partially | May flag unknown logs, but does **not** block |
| Chrome built-in CT (strict) | No | SCTs are validly signed by logs Chrome trusts (if attacker's logs are in the log list) |
| CT Guard (PoI only) | No | Inclusion proof is mathematically valid |
| **CT Guard (PoI + PoC)** | **Yes** | Monitor's independent view reveals the split-world inconsistency |
| CT monitor scanning | Yes (different mechanism) | If the cert were in a real log, monitors scanning log entries would spot an unauthorized cert for google.com |

The attack specifically defeats every layer except **cross-checking with independent monitors** — which is exactly what CT Guard's Proof of Consistency provides.

---

## Defense Stack (Why Every Layer Matters)

```
Layer 1: DNS          → Compromised (attacker controls resolution)
Layer 2: TLS/CA       → Compromised (attacker has CA's private key)
─────────────────────────────────────────────────────────────────
Layer 3: SCT presence → CT Guard CATCHES Scenario 1 (no SCTs)

Layer 3: SCT signing  → Compromised (attacker has log's private key)
─────────────────────────────────────────────────────────────────
Layer 4: PoI (Merkle) → CT Guard CATCHES Scenario 2 (non-inclusion)

Layer 4: PoI (Merkle) → Defeated (valid proof from attack tree)
─────────────────────────────────────────────────────────────────
Layer 5: PoC (Monitor comparison) → CT Guard CATCHES Scenario 3
         The one thing the attacker cannot forge:
         consistency between two different Merkle trees
```

---

## Trust Boundaries

| Component | Trusted by Browser? | Trusted by Extension? | Compromised in Simulation? |
|---|---|---|---|
| DNS | Yes | N/A | Yes (hosts file — 3 domains) |
| Compromised CA | Yes (in cert store) | N/A | Yes |
| Compromised CT Log A | Soft (Firefox lenient) | Yes (in modified log list) | Yes |
| Compromised CT Log B | Soft (Firefox lenient) | Yes (in modified log list) | Yes |
| Attacker's Server (facebook.com) | Yes (valid cert chain) | N/A | Yes — Scenario 1 (no SCTs) |
| Attacker's Server (github.com) | Yes (valid cert chain) | N/A | Yes — Scenario 2 (non-inclusion) |
| Attacker's Server (google.com) | Yes (valid cert chain) | N/A | Yes — Scenario 3 (split-world) |
| Backend / Monitors | N/A | Yes (provides reference STH) | No (honest) |
| CT Guard Extension | N/A | N/A | No (detects all 3 scenarios) |

---

## Simulation Components Summary

| Component | Implementation | Port | Admin Required? |
|---|---|---|---|
| DNS Poisoning | Hosts file modification (3 domains → `127.0.0.1`) | — | Yes (to edit hosts file) |
| Compromised CA | Self-signed root cert (generated by setup script) | — | — |
| Compromised CT Logs (x2) | Node.js Express server, RFC 6962 API | 3333 | No |
| Fraudulent Certificates (x3) | For `facebook.com` (no SCTs), `github.com` (SCTs, no inclusion), `google.com` (SCTs, included in attack tree) | — | — |
| Attacker's HTTPS Server | Node.js HTTPS server, SNI-based routing for 3 domains | 443 | Yes (port < 1024) |
| Modified CT Log List | Served by the Express server at `/log-list.json` | 3333 | No |
| Backend | Existing CT Guard backend (local instance) | 3000 | No |
| CT Guard Extension | Modified build (custom log list URL + backend URL) | — | — |

---

## Real-World Scenario: Compromised Public CA and Logs

The simulation uses a locally-installed CA to simulate a compromised publicly-trusted CA. This section describes what would happen in a real-world attack where the compromised CA is in Mozilla's Root CA Program (or Chrome's root store) and the compromised logs are publicly-trusted logs (e.g., Google's Xenon, Cloudflare's Nimbus).

### What Browsers Actually Verify

Both Chrome and Firefox (since v135) perform the following CT checks for certificates from publicly-trusted CAs:

1. **SCT presence** — certificate must contain embedded SCTs
2. **SCT count** — sufficient SCTs from different log operators (typically 2-3)
3. **SCT signature validity** — each SCT signature is verified against the log's public key
4. **Log trust** — SCTs must come from logs in the browser's trusted log list

Neither browser verifies:

5. **Proof of Inclusion** — whether the certificate is actually in the log's Merkle tree
6. **Proof of Consistency** — whether the log's tree is consistent with what independent monitors see

### Real-World Attack Outcomes

If a publicly-trusted CA and 2+ publicly-trusted logs were compromised:

| Scenario | Chrome | Firefox (v135+) | CT Guard |
|---|---|---|---|
| 1 — No SCTs | **Blocks** | **Blocks** | Blocks |
| 2 — Valid SCTs, non-inclusion | Accepts | Accepts | **Blocks (PoI fails)** |
| 3 — Valid SCTs, split-world | Accepts | Accepts | **Blocks (PoC fails)** |

Browser CT enforcement stops the no-SCT attack (Scenario 1) but is blind to non-inclusion and split-world attacks (Scenarios 2 and 3). The browser never checks whether SCTs are backed by actual Merkle tree entries, and never cross-checks with independent monitors. CT Guard's value lies entirely in these two verification layers that browsers do not implement.

### Why No Public CA Issues Certificates Without SCTs

CT enforcement at the browser level is so effective that **no publicly-trusted CA issues certificates without SCTs anymore**. Doing so would cause Chrome and Firefox to reject those certificates, effectively rendering the CA useless and leading to its removal from browser root programs. This makes it impossible to find a live example of browser CT rejection in the wild — the ecosystem has adapted completely.

This is itself evidence that browser-level CT enforcement works for Scenario 1. The remaining gaps — Scenarios 2 and 3 — are where CT Guard provides its unique value.

---

## Simulation Limitations

### Local CA vs. Public CA

The simulation uses a locally-installed CA because it is not possible to compromise or use a real publicly-trusted CA for testing. This has one significant consequence: **both Chrome and Firefox exempt locally-installed CAs from CT enforcement**. This means:

- In the simulation: all three scenarios succeed against the browser (green padlock, no warnings)
- In a real attack with a public CA: only Scenarios 2 and 3 would succeed against the browser; Scenario 1 would be blocked natively

However, **CT Guard's verification logic is identical regardless of CA origin**. The extension enforces SCT presence, verifies Merkle inclusion proofs, and checks consistency with monitors for all certificates — whether the issuing CA is in Mozilla's program or locally installed. The simulation accurately demonstrates the extension's detection capabilities for all three scenarios.

---

## Why Firefox Is the Only Viable Platform

CT Guard is built as a Firefox extension because Firefox is the only major browser that exposes certificate and SCT data to extensions through its standard API:

- **Firefox**: `browser.webRequest.getSecurityInfo()` provides raw DER-encoded certificate data, including the full certificate chain, directly to extensions. This is a standard WebExtensions API available to any Firefox extension.
- **Chrome**: Does not expose certificate or SCT data to extensions through any standard API. The only alternative — the `chrome.debugger` API — requires attaching a debugger to each tab, which displays a visible "Extension is debugging this browser" banner and is unsuitable for a normal extension distributed through the Chrome Web Store.

This is a fundamental platform limitation. Chrome treats TLS as an internal implementation detail that extensions should not access, while Firefox treats it as data that extensions legitimately need for security tooling.

---

## Why CT Guard Does Not Verify SCT Signatures

CT Guard does not independently verify SCT signatures. This is intentional — SCT signature verification is redundant with the extension's other verification steps:

1. **Browsers already verify SCT signatures.** For certificates from publicly-trusted CAs, both Chrome and Firefox (v135+) verify that each SCT is validly signed by the corresponding log's public key. If the signature is invalid, the browser rejects the certificate before the extension runs.

2. **Proof of Inclusion subsumes signature verification.** If an SCT has an invalid signature (e.g., fabricated log ID, garbage signature), the certificate will not be found in any legitimate log's Merkle tree. The PoI check will fail, catching the same attack. Signature verification would be a redundant check — it cannot catch any attack that PoI does not already catch.

The extension's verification stack is:

```
Browser:    SCT presence + SCT signatures    → enforced natively (Firefox v135+, Chrome)
CT Guard:   Proof of Inclusion (PoI)         → catches non-inclusion (Scenario 2)
CT Guard:   Proof of Consistency (PoC)       → catches split-world (Scenario 3)
```

Each layer catches attacks that the previous layer cannot. Adding SCT signature verification to CT Guard would duplicate what the browser already enforces, without catching any additional attack vector.
