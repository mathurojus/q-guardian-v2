# Q-Guardian v2, User Flow

This document explains the product the way a first-time analyst actually
encounters it: in the order the sidebar presents things, one section at a
time, with what each feature is and why it exists at that point in the
flow. If `WALKTHROUGH.md` is the script for presenting the product,
this is the explanation of what you are looking at.

---

## 0. Logging in

You land on a login screen. There is nothing to scan yet and nothing to
configure, this step exists only to issue you a JWT so every later request
is authenticated. Once you are in, the sidebar and top bar appear and stay
on screen no matter which page you visit next, they are the shell, the
page content in the middle is the only part that changes.

The top bar on every page shows the current page's title, your username,
and a log-out control. If a network scan is running in the background
(see section 2e), a small progress pill also lives here, so you never lose
track of a long-running scan just because you navigated somewhere else.

---

## 1. Overview

**Sidebar: Overview.** This is the landing page, the first thing you see
after login.

The first time you arrive here, your inventory is empty, so instead of a
blank dashboard you get a "Platform ready" message and a button straight
into Scan Center. There is nothing to misinterpret as a bug, an empty
inventory is the correct starting state for a tool that has not scanned
anything yet.

Once you have run at least one scan, this page becomes the executive
summary: an **Enterprise Rating** (0 to 1000, with a letter grade), a
breakdown of how many assets are stable, in warning, critical, or already
post-quantum, and a live threat-intelligence feed pulling recent
quantum-computing and cybersecurity headlines. The rating is not just an
average of TLS configuration quality, it is discounted by how many assets
currently sit inside the Mosca risk window (see section 4), so a portfolio
full of technically-modern-but-about-to-expire crypto scores lower than
one that is genuinely ahead of the migration curve.

This page is where you come back to after scanning, to see the portfolio
move.

---

## 2. Scan Center

**Sidebar: Scan Center**, plus five more sidebar entries nested under it:
**Source Code**, **Container Image**, **Compiled Binary**, **API
Endpoint**, **Network / Domain**.

The Scan Center hub page is a launcher: five cards, one per scanner, each
explaining in one line what it does before you commit to it. This exists
because "scan something" is not one action, it is five genuinely different
techniques, and hiding them behind one generic "scan" button would blur
what evidence you are actually collecting.

### 2a. Source Code

You give it a file or directory path that already exists on the machine
running the backend (not a GitHub URL, the code has to be present
locally). It reads the code itself and looks for weak-crypto calls,
`hashlib.md5()`, `RSA.generate(1024)`, an outdated `ssl.PROTOCOL_*`
constant, and so on, using two engines you can switch between: a native
Python AST parser (fast, no external dependency) and Semgrep (a real
static-analysis engine with an OWASP-derived ruleset). Every finding
carries the exact file and line it came from.

### 2b. Container Image

You give it an image tag (like `nginx:1.24-alpine`) or a local Dockerfile.
If Trivy or Syft are installed on the host, it genuinely inspects the
image's installed packages. If neither is available, it falls back to an
estimate based on the image tag's name, and that fallback is visibly
marked with a confidence badge so an estimate is never confused with an
inspected result.

### 2c. Compiled Binary

You give it a path to an actual compiled program (ELF, PE, or Mach-O), or
type `SAMPLE` to generate a synthetic test binary on the spot. It opens
the raw bytes of the file and searches for exact byte sequences that only
appear if a specific cryptographic algorithm's constants are compiled in,
the AES S-box table, the ML-KEM math tables, an MD5 initialization vector.
This works even when there is no source code and no debug symbols
available, which is the point: it tells you what is actually running, not
what a manifest claims is running.

### 2d. API Endpoint

You give it a live URL. It runs OWASP API Top 10 checks against it,
missing authentication, exposed API documentation, weak rate limiting, TLS
misconfiguration. Only read-only probes run by default; anything that
would actually modify data on the target server stays off unless an
administrator explicitly enables it on the backend.

### 2e. Network / Domain

You give it a domain name. This is the one scanner that reaches out over
the public internet: it looks up subdomains via public certificate logs,
then opens a real TLS connection to each one it finds and records exactly
what encryption that server is using right now. Because this makes real
outbound connections, only point it at domains you own or are authorised
to test, and the backend refuses to connect to private or internal
addresses unless that has been explicitly allowed. This scan can take a
little longer than the others, which is why its progress stays visible in
the top bar no matter what page you wander off to while it runs.

### Reconcile (linked from the hub, lives under Reports)

Once you have run more than one kind of scan, a **Reconcile Sources**
card on the hub (and its own sidebar entry under Reports, see section 6)
cross-checks what you found. This is where "declared vs actual" divergence
gets surfaced, for example a container that claims a modern OpenSSL while
the compiled binary inside it still runs on legacy MD5. Every divergence
says how confident it is: `identity-matched` if the two findings were
proven to be the same logical asset, `environment-level` if they were just
both present without a proven connection.

---

## 3. Inventory

**Sidebar: Inventory.** This is where every asset from every scan you have
run lands in one table, regardless of which scanner found it.

Each row shows the algorithm, where the evidence came from (a source
badge tells you if it was network, source code, container, or binary),
its Q-TRI score (0 to 100, quantum readiness), and whether it is flagged
as a declared-vs-actual divergence. Clicking a row opens its migration
playbook: a concrete recommendation for what to upgrade to, with a
downloadable code stub. Fields that genuinely do not apply to a given
asset (a TLS version on a hash-constant finding, for instance) are shown
as not applicable rather than filled in with a plausible-looking default,
so nothing here is invented to make the table look more complete than the
evidence supports.

This page is the single source of truth the rest of the product (the
rating, the compliance mapper, the CBOM export) is built from.

---

## 4. Risk & Compliance

**Sidebar: HNDL Exposure, Cert-IN Mapper.**

### HNDL Exposure

This page answers a specific question: for data being transmitted today
without forward secrecy, how much of it could an adversary already be
recording, to decrypt later once a quantum computer exists? The card
labeled "est. exposure (tier baseline)" is exactly that, an estimate built
from a configurable assumption about typical traffic volume per
sensitivity tier, not a measurement of your actual network traffic. The
advisory text at the bottom of the page says this directly, treat these
numbers as a planning ceiling for prioritisation, not a measured fact.

### Cert-IN Mapper

This page takes every quantum-vulnerable asset in your inventory and maps
it against three real regulatory frameworks: RBI's baseline cyber security
controls, NIST IR 8547's PQC transition timeline (the real dates:
deprecate 112-bit algorithms after 2030, disallow them after 2035), and
India's National Quantum Mission guidance. This exists so a compliance
officer, not just an engineer, can look at the same inventory and answer
"are we going to be in violation of a specific control by a specific
date."

---

## 5. Topology

**Sidebar: Topology.** A force-directed graph of every asset and the
algorithms behind them, coloured by which scanner discovered them. This is
the visual counterpart to the Inventory table, useful for spotting
clusters (a lot of legacy crypto concentrated in one subsystem) and for
seeing a divergence hub, an asset connected to conflicting evidence from
two different sources, at a glance rather than by reading rows.

---

## 6. Reports

**Sidebar: CBOM Export, Reconcile Sources.**

### CBOM Export

This produces a standards-compliant Cryptographic Bill of Materials, a
CycloneDX 1.6 JSON document that any external tool speaking that standard
can consume, plus a PDF version for a human reader. Every field in it
(algorithm primitive, asset type, NIST quantum security level) is derived
from the same evidence as the Inventory table, this is not a separate,
looser export path, it is the same data in a standardised shape. You can
also diff the current export against your previous scan run to show
concrete improvement (or regression) between audits.

### Reconcile Sources

The same reconciliation action described in section 2, given its own
permanent page here because it is a report you would want to re-run and
re-read on its own, independent of whichever scanner you happened to run
most recently.

---

## Putting it together

The intended path through the product, top to bottom, is: land on
**Overview** with nothing scanned, go to **Scan Center** and run one or
more of the five scanners against real targets, watch results accumulate
in **Inventory**, cross-check them for consistency with **Reconcile**,
read the quantum-timeline and compliance implications in **Risk &
Compliance**, see the shape of it all in **Topology**, and finally produce
a **CBOM** or board brief to hand to someone else. Every page after Scan
Center is a different lens on the exact same underlying inventory, not a
separate tool with its own data.
