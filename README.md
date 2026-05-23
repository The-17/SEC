# SEC (Signed Execution Contracts)
## Standalone Cryptographic Capability Boundary & In-Process Policy Engine for Autonomous Systems

[![Status](https://img.shields.io/badge/status-Release--Candidate-orange.svg)](#)
[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Table of Contents
1. [The Problem: Why SEC?](#1-the-problem-why-sec)
2. [Quickstart: Your First Contract in 60 Seconds](#2-quickstart-your-first-contract-in-60-seconds)
3. [The Anatomy of a Contract](#3-the-anatomy-of-a-contract)
4. [How SEC Works: The Core Mechanics](#4-how-sec-works-the-core-mechanics)
5. [Integrating SEC into Your Runtime](#5-integrating-sec-into-your-runtime)
6. [Preventing Replay Attacks](#6-preventing-replay-attacks)
7. [The Delegation Journey: Spawning Sub-agents](#7-the-delegation-journey-spawning-sub-agents)
8. [Deployment Paths: Standalone vs. keychain-auth Mode](#8-deployment-paths-standalone-vs-keychain-auth-mode)
9. [CLI Command Reference](#9-cli-command-reference)
10. [Handling Policy Violations](#10-handling-policy-violations)
11. [Design Goals & Future Extensions](#11-design-goals--future-extensions)
12. [License](#license)

---

## 1. The Genesis of SEC: The Story & Philosophy

SEC was conceived out of a fundamental flaw in how modern autonomous systems interact with credentials and authority. 

Traditionally, credentials (API keys, session tokens) are **binary and stateless**: if a runner possesses a Stripe API key, the target gateway assumes the request is valid. However, when an autonomous AI agent is given credentials, it introduces a massive attack surface. If an agent reads a webpage, email, or repository containing a **prompt injection**, its reasoning engine can be hijacked. The compromised agent will then execute harmful actions (like draining funds or deleting code) *using your valid credentials*.

### The Origin: Objective/Directive Divergence
SEC originated from the concept of **Objective/Directive Divergence**:
*   Before calling an external API or reading untrusted content, the agent must commit to a strict, agreed-upon **Directive** (e.g. *"I am fetching weather data for New York"*).
*   Upon returning, the agent's proposed action is measured against that objective.
*   If the agent attempts to execute an action that diverges from the directive (e.g., trying to delete a database or transfer funds), the connection is immediately terminated.

### The Cryptographic Shift: Moving from AI to the Transport Layer
While objective verification is crucial, relying on the LLM itself to enforce safety is an architectural vulnerability. If the model's cognitive loop is compromised by a prompt injection, it will simply hallucinate that its malicious actions comply with the original objective.

**SEC moves this boundary out of the cognitive layer and directly into the transport/proxy layer.** 
Instead of trusting the agent's thoughts, the parent controller locks the agent into a **Signed Execution Contract (SEC)** *before* spawning it. The credential proxy (like AgentSecrets) intercepts the outgoing HTTP call, verifies the contract's cryptographic signature, and blocks any request that attempts to drift from the pre-authorized contract—instantly neutralizing goal hijacking at the wire level.

---

## 2. Quickstart: Your First Contract in 60 Seconds

The easiest way to understand SEC is to try it out locally.

### Step 1: Initialize Your Environment
Generate your local Ed25519 signing keys. This registers your keypair under `~/.sec/keys/`.

```bash
sec init
```

### Step 2: Sign a Contract
Let's create a contract that restricts an agent to only reading and commenting on a specific GitHub repository for the next 10 minutes.

```bash
sec sign \
  --objective "review pull requests" \
  --allow "github.pull_requests.read,github.pull_requests.comment" \
  --scope "repositories=The-17/agentsecrets" \
  --audience "github" \
  --ttl "10m" \
  --out my_run.sec
```

This returns a compact, signed token string saved to `my_run.sec`:
```text
eyJqdGkiOiJmNGU0Yzg5Yi05MTI1LTRhNTUtOGNjMy04Y2NmMTQ5NzhjNTUiLCJpYXQiOjE3ODQ4NDgwMjMsImV4cCI6MTc4NDg0ODYyMywib2JqIjoicmV2aWV3IHB1bGwgcmVxdWVzdHMiLCJjYXBzIjpbImdpdGh1Yi5wdWxsX3JlcXVlc3RzLnJlYWQiLCJnaXRodWIucHVsbF9yZXF1ZXN0cy5jb21tZW50Il0sInNjb3BlcyI6eyJyZXBvc2l0b3JpZXMiOlsiVGhlLTE3L2FnZW50c2VjcmV0cyJdfSwiYXVkIjpbImdpdGh1YiJdfQ.dGVzdF9zaWduYXR1cmVfYnl0ZXNfZm9yX2RlbW9uc3RyYXRpb25fdG9rZW5fb25seV9jcmVhdGVkX2J5X2VkMjU1MTk
```

### Step 3: Verify the Contract
Now, simulate an authorized tool call where the agent tries to comment on the repository:

```bash
sec verify \
  --token-file my_run.sec \
  --capability "github.pull_requests.comment" \
  --resource "The-17/agentsecrets" \
  --audience "github"
```
* **Result:** Exit code `0` (Success - authorized!).

If the agent gets hijacked and tries to delete the repository:
```bash
sec verify \
  --token-file my_run.sec \
  --capability "github.repositories.delete" \
  --resource "The-17/agentsecrets" \
  --audience "github"
```
* **Result:** Exit code `2` (Policy Violation - Blocked!).

---

## 3. The Anatomy of a Contract

Under the hood, an SEC contract is defined as a Go struct. It describes the metadata, capabilities, resource scopes, and lifetime constraints:

```go
package contract

type SECContract struct {
    // Identity of the Contract
    JTI string `json:"jti"`                  // Unique identifier for this token
    KID string `json:"kid,omitempty"`        // Public key identifier used for verification key rotation
    SessionPubKey string `json:"spk,omitempty"` // Ephemeral session public key for sub-delegation

    // Timing Constraints
    IAT int64 `json:"iat"`                  // Issued At (Unix timestamp)
    EXP int64 `json:"exp"`                  // Expiration Time (Unix timestamp)

    // Human Intent
    Objective string `json:"obj"`           // Why is this contract being signed?

    // Capability Sandbox
    Capabilities []string `json:"caps"`     // Allowed action namespaces (glob patterns supported)
    Denies []string `json:"denies"`         // Explicitly blocked actions (takes precedence over caps)

    // Resource Scopes
    Scopes map[string][]string `json:"scopes"` // Provider-specific resource targets

    // Audience Binding
    Audience []string `json:"aud"`          // Targeted verifier identifiers (e.g. ["github"])

    // Replay Rules
    ReplayMode string `json:"replay"`       // "reusable", "single_use", or "bounded"
    MaxUses int `json:"max_uses,omitempty"` // Required if replay mode is "bounded"

    // Delegation Context
    Delegated bool `json:"delegated,omitempty"`    // True if this is derived from a parent contract
    ParentJTI string `json:"parent_jti,omitempty"` // The parent contract's JTI
}
```

---

## 4. How SEC Works: The Core Mechanics

SEC ensures security and performance by utilizing three core design mechanics:

### 1. Detached-Signature Token Format
SEC tokens avoid the complexity of JWT/JOSE standards. They use a simple, lightweight dot-separated base64url layout:
```text
BASE64URL(CanonicalPayloadJSON).BASE64URL(SignatureBytes)
```

### 2. RFC 8785 Canonical JSON Serialization (JCS)
To cryptographically sign and verify JSON structures, key ordering and whitespace must be deterministic across different languages (e.g., Go, Python, TypeScript). SEC enforces JCS serialization before generating signatures, preventing mismatches caused by varying compiler struct alignments.

### 3. Hierarchical Namespaces & Full Glob Wildcards
Capabilities are dot-separated namespaces matching target actions (e.g., `github.pull_requests.read`). 
SEC supports standard glob-matching (via Go's `path.Match`), enabling:
*   **Suffix wildcards**: `github.*` (matches any github capability)
*   **Middle wildcards**: `github.*.read` (matches github read capabilities across all segments)
*   **Prefix wildcards**: `*.read` (matches read capabilities across all providers)

Explicit denies always win. If `github.repositories.delete` is listed in `denies`, it is blocked even if `github.*` is allowed.

---

## 5. Integrating SEC into Your Runtime

When building SEC into an agent runner, gateway, or secret infrastructure (like AgentSecrets), verification is handled by loading the trusted public keys locally and running a 12-step validation sequence.

### The Verification Flow
```text
[ Incoming Token ]
       │
       ▼
 1. Parse Format (split on '.') ──────────[ Fail if not 2 parts ]
       │
       ▼
 2. Decode Signature (base64url)
       │
       ▼
 3. Verify Ed25519 Signature
       │
       ▼
 4. Decode Payload JSON (base64url)
       │
       ▼
 5. Validate Schema & Structure
       │
       ▼
 6. Check Expiration (exp > now)
       │
       ▼
 7. Check Replay Protection (against SQLite JTI store)
       │
       ▼
 8. Check Explicit Denies ────────────────[ Blocked if action in denies ]
       │
       ▼
 9. Check Capabilities (matches caps/wildcards?)
       │
       ▼
10. Validate Audience Binding (matches verifier aud?)
       │
       ▼
11. Validate Scopes (using glob/prefix fallback checks)
       │
       ▼
12. Validate Delegation Chain (if delegated)
       │
       ▼
[ Authorization Granted ]
```

### Pluggable Scope Validators
Resource boundaries differ by provider (GitHub repos, Slack channels, AWS ARNs). Custom runtimes implement the `ScopeValidator` interface, while the core CLI provides a default glob-matching fallback validator to check resource target patterns out-of-the-box.

---

## 6. Preventing Replay Attacks (Concurrency Optimized)

Replay protection is critical. A compromised agent could intercept an execution contract and repeat the execution payload indefinitely. SEC handles this via a local SQLite database (`~/.sec/jti.db`).

To prevent database locking (`SQLITE_BUSY` errors) under high concurrency (e.g. an agent executing multiple tool calls in parallel), SEC:
1.  Enforces SQLite **Write-Ahead Logging (WAL) Mode** (`PRAGMA journal_mode=WAL;`) to allow concurrent reads and writes.
2.  Sets a **Busy Timeout** (`PRAGMA busy_timeout=5000;`) so concurrent verification threads wait instead of failing.
3.  Executes expired JTI record cleanup **asynchronously** in a background process, keeping the verification transaction path highly performant.

---

## 7. Cryptographic Delegation (Sub-agents)

Often, a parent agent needs to spawn sub-agents to parallelize work. However, the parent should never give a sub-agent more permissions than it possesses, and the agent should never hold the root signing keys.

SEC resolves this via **Cryptographic Session Keys**:

1.  **Parent Scoping**: The parent contract includes a base64url-encoded **Session Public Key** (`spk`) generated by the parent agent.
2.  **Child Signing**: When spawning a sub-agent, the parent agent signs the child contract using its own ephemeral **Session Private Key** (which corresponds to the `spk` declared in its parent contract).
3.  **Recursive Verification**: The verifier parses the token chain (`Token_Child..Token_Parent`). It validates the child contract signature using the parent's declared `SessionPubKey`, ensuring safe on-the-fly delegation without exposing the root private key.

---

## 8. Deployment Paths: Standalone vs. keychain-auth Mode

You can deploy SEC based on your threat model.

### Standalone Mode (Zero-Daemon Verification)
In Standalone Mode, verification and signing are completely local. The private keys reside in `~/.sec/keys/<kid>.key`. This is excellent for low-latency command line utilities, simple local tooling, and testing. Verification requires **zero background daemons**, validating ED25519 signatures directly in memory.

### High-Security Mode (keychain-auth Bound)
A malicious script or compromised shell might try to call `sec sign` to forge authorization. 
High-Security Mode addresses this by routing signature requests through the **keychain-auth** daemon. The daemon inspects the OS process tree, verifies the lineage of the caller, and only permits signing if the caller is a verified process.

---

## 9. Key Rotation & KID Mapping

To support key rotation, key files are mapped dynamically:
*   Keys are stored in the key directory matching their Key ID: `~/.sec/keys/<kid>.pub` and `~/.sec/keys/<kid>.key`.
*   During verification, the CLI reads the `kid` property from the contract payload and loads the matching public key dynamically.

---

## 10. CLI Command Reference

### Initialize Environment
```bash
sec init
```
Generates default signing keys under `~/.sec/keys/default.key` and `~/.sec/keys/default.pub`.
*   **Exit Codes**: `0` on success, `1` on error.

### Sign a Contract
```bash
sec sign [flags]
```
Generates a signed execution token base64url string.
*   **Flags**:
    *   `--objective`: (Required) Objective string.
    *   `--allow`: Comma-separated list of capabilities.
    *   `--deny`: Comma-separated list of denied capabilities.
    *   `--scope`: Resource constraint assignments (e.g. `repositories=The-17/agentsecrets`).
    *   `--audience`: Expected audience contexts.
    *   `--ttl`: Time to live duration string (e.g. `10m`, `1h`).
    *   `--kid`: Key ID to use for signing (defaults to `default`).
    *   `--out`: Destination file path for token (prints to stdout by default).

### Verify a Contract
```bash
sec verify [flags]
```
Verifies a token string locally against a required capability.
*   **Flags**:
    *   `--token`: The raw signed token string.
    *   `--token-file`: Path to the signed token file.
    *   `--capability`: The target action namespace to check (glob pattern supported).
    *   `--resource`: The target resource namespace.
    *   `--audience`: Expected audience.
*   **Exit Codes**:
    *   `0` = Contract is VALID.
    *   `1` = Cryptographic error or expired contract.
    *   `2` = Boundary check failed (policy violation).

---

## 11. Handling Policy Violations

When verification fails (Exit Code `2`), SEC-compliant verifiers return a standardized JSON policy violation payload to `stderr` and terminate.

```json
{
  "error": "sec_policy_violation",
  "message": "Operation [github.repositories.delete] violated the active Signed Execution Contract."
}
```

This structural format enables autonomous runtime wrappers to catch violations and alert human supervisors immediately.

---

## License

This project is licensed under the [MIT License](LICENSE).
