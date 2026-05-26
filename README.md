# SEC (Signed Execution Contracts)
## Standalone Cryptographic Capability Boundary & Offline Policy Engine for Autonomous Systems

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Table of Contents
1. [The Genesis of SEC: Philosophy & Threat Model](#1-the-genesis-of-sec-philosophy--threat-model)
2. [Why SEC? OWASP Top 10 for LLMs Mapping](#2-why-sec-owasp-top-10-for-llms-mapping)
3. [Quickstart: Your First Contract in 60 Seconds](#3-quickstart-your-first-contract-in-60-seconds)
4. [The Anatomy of a Contract](#4-the-anatomy-of-a-contract)
5. [How SEC Works: Core Mechanics](#5-how-sec-works-core-mechanics)
6. [The Verification Pipeline](#6-the-verification-pipeline)
7. [CLI Command Reference](#7-cli-command-reference)
8. [Integration Guide](#8-integration-guide)
9. [License](#9-license)

---

## 1. The Genesis of SEC: Philosophy & Threat Model

SEC was conceived to address a fundamental flaw in how autonomous agent systems interact with credentials and authority. 

Traditionally, credentials (API keys, session tokens) are **binary and stateless**: if a runner possesses a Stripe API key, the target gateway assumes the request is valid. However, when an autonomous AI agent is given credentials, it introduces a massive attack surface. If an agent reads a webpage, email, or repository containing a **prompt injection**, its reasoning engine can be hijacked. The compromised agent will then execute harmful actions (like draining funds or deleting code) *using your valid credentials*.

SEC enforces a strict guarantee:
> **An agent cannot use a credential for any action it did not commit to before touching untrusted content.**

SEC is not a credential store, a redaction layer, or a network firewall. It owns one thing: **producing and verifying signed contracts that express agent intent.**

---

## 2. Why SEC? OWASP Top 10 for LLMs Mapping

SEC provides architectural mitigations for critical vulnerabilities identified in the **OWASP Top 10 for Large Language Model Applications**:

*   **OWASP LLM01: Prompt Injection (Direct & Indirect)**:
    *   *The Threat*: A malicious source injects instructions forcing the LLM to call arbitrary APIs or exfiltrate data.
    *   *SEC Mitigation*: The agent cannot make arbitrary API calls because the proxy requires a valid signed contract token matching the target domain. Even if the LLM is hijacked, it cannot sign a contract for unauthorized domains because the signing key is held by the orchestrator.
*   **OWASP LLM02: Insecure Output Handling**:
    *   *The Threat*: The LLM generates outputs (such as API call payloads) that bypass safety checks and are executed directly by downstream systems.
    *   *SEC Mitigation*: All outbound calls are validated by SEC *before* credential resolution. Any unapproved target URL is blocked at the gateway.
*   **OWASP LLM07: Insecure Plugin Design / Privilege Escalation**:
    *   *The Threat*: Plugins (tools) accept raw inputs from the LLM without strict parameter, domain, and authorization boundaries.
    *   *SEC Mitigation*: SEC enforces a cryptographic sandbox around every single step. The agent can only execute tools and target URLs explicitly matching the signed glob patterns in its contract.

---

## 3. Quickstart: Your First Contract in 60 Seconds

### Step 1: Initialize Your Environment
Generate your local Ed25519 signing keys. This registers your keypair under `~/.sec/keys/`.

```bash
sec init
```

### Step 2: Sign a Contract
Let's create a contract that restricts an agent to only reading pull requests on a specific GitHub repository for the next 10 minutes.

```bash
sec sign \
  --objective "summarize repository pull requests" \
  --allow "api.github.com/repos/The-17/agentsecrets/pulls*" \
  --ttl "10m" \
  --out my_run.sec
```

This returns a compact, signed token string saved to `my_run.sec`:
```text
eyJqdGkiOiJmNGU0Yzg5Yi05MTI1LTRhNTUtOGNjMy04Y2NmMTQ5NzhjNTUiLCJraWQiOiJkZWZhdWx0IiwiaWF0IjoxNzg0ODQ4MDIzLCJleHAiOjE3ODQ4NDg2MjMsIm9iaiI6InN1bW1hcml6ZSByZXBvc2l0b3J5IHB1bGwgcmVxdWVzdHMiLCJhbGxvdyI6WyJhcGkuZ2l0aHViLmNvbS9yZXBvcy9UaGUtMTcvYWdlbnRzZWNyZXRzL3B1bGxzKiJdfQ.dGVzdF9zaWduYXR1cmVfZm9yX2RlbW9uc3RyYXRpb25fdG9rZW5fb25seV9jcmVhdGVkX2J5X2VkMjU1MTk
```

### Step 3: Verify the Contract
Simulate an authorized action where the agent calls the GitHub pulls API:

```bash
sec verify \
  --token-file my_run.sec \
  --action "api.github.com/repos/The-17/agentsecrets/pulls/12"
```
*   **Result:** Exit code `0` (Success - authorized!). Prints the decoded contract payload to `stdout`.

If the agent gets hijacked and tries to delete the repository:
```bash
sec verify \
  --token-file my_run.sec \
  --action "api.github.com/repos/The-17/agentsecrets/keys"
```
*   **Result:** Exit code `2` (Policy Violation - Blocked!). Outputs structured JSON error details containing the `SEC_ACTION_NOT_PERMITTED` error code to `stderr`.

---

## 4. The Anatomy of a Contract

Under the hood, an SEC contract is defined as a simple Go struct. It describes the unique execution token metadata, timing constraints, human intent description, and capability allowlists:

```go
package contract

type SECContract struct {
	JTI       string   `json:"jti"`   // Unique token ID for replay protection (UUID v4)
	KID       string   `json:"kid"`   // Key ID used to identify the public key for verification
	IAT       int64    `json:"iat"`   // Issued At (Unix timestamp)
	EXP       int64    `json:"exp"`   // Expiration (Unix timestamp)
	Objective string   `json:"obj"`   // Natural language intent/objective
	Allowed   []string `json:"allow"` // Allowed tool names or API destination glob patterns
}
```

---

## 5. How SEC Works: Core Mechanics

### 1. Detached-Signature Token Format
SEC tokens use a simple, lightweight dot-separated base64url layout:
```text
BASE64URL(CanonicalPayloadJSON).BASE64URL(SignatureBytes)
```

### 2. RFC 8785 Canonical JSON Serialization (JCS)
To cryptographically sign and verify JSON structures, key ordering and whitespace must be deterministic across different languages (e.g., Go, Python, TypeScript). SEC enforces JCS serialization before generating signatures, preventing signature mismatches.

### 3. Wildcard Glob Matching
Allowed targets are matched segment-by-segment:
*   Protocol prefixes (`http://`, `https://`) are automatically stripped.
*   `*` matches any characters within a single segment (split by `/`).
*   Trailing `*` extends to cover the rest of the path.
*   Exact matches are required if no wildcards are present.

---

## 6. The Verification Pipeline

When verifying a contract token locally, SEC runs a 7-step validation sequence:

```text
[ Incoming Token ]
       │
       ▼
 1. Parse Format (split on '.') ───────[ Fail if invalid token format ]
       │
       ▼
 2. Resolve Public Key (via kid) ─────[ Fail if KID not found on disk ]
       │
       ▼
 3. Verify Ed25519 Signature ──────────[ Fail if signature check fails ]
       │
       ▼
 4. Validate Schema Invariants ────────[ Fail if fields missing or invalid ]
       │
       ▼
 5. Validate Timing (iat <= now <= exp) [ Fail if expired or pre-dated ]
       │
       ▼
 6. Check Replay Store (JTI Database) ──[ Fail if JTI has been reused ]
       │
       ▼
 7. Action Glob Match (allow list) ────[ Fail if action is unauthorized ]
       │
       ▼
 [ Authorization Granted (Exit 0) ]
```

---

## 7. CLI Command Reference

### Initialize Environment
```bash
sec init [--kid <key_id>]
```
Generates signing keys under `~/.sec/keys/<kid>.key` and `~/.sec/keys/<kid>.pub` (defaults to `default`).
*   **Exit Codes**: `0` on success, `1` on error.

### Sign a Contract
```bash
sec sign [flags]
```
Generates a signed execution token base64url string.
*   **Flags**:
	*   `--objective`: (Required) Human objective string.
	*   `--allow`: (Required) Comma-separated list of allowed glob patterns.
	*   `--ttl`: Validity duration (default: `10m`).
	*   `--kid`: Key ID to use (default: `default`).
	*   `--out`: Destination file path for token (prints to stdout by default).

### Verify a Contract
```bash
sec verify [flags]
```
Verifies a token string locally against an action.
*   **Flags**:
	*   `--token`: The raw signed token string.
	*   `--token-file`: Path to the signed token file.
	*   `--action`: (Required) The target action namespace or URL to check.
*   **Exit Codes**:
	*   `0` = Contract is valid and action is permitted.
	*   `1` = Cryptographic error, format error, or expired/replayed contract.
	*   `2` = Boundary check failed (policy violation).

### Check Status
```bash
sec status
```
Shows diagnostic status of SEC (initialization status, path to keys, database path, and count of active JTI records).

---

## 8. Integration Guide

For detailed integration guides on incorporating SEC into AI Agent Frameworks (LangChain, CrewAI), IDE assistants (Claude Code, Cursor), or CI/CD pipelines, see the [Integration Instructions](file:///wsl.localhost/Ubuntu/home/theapiartist/work/SEC/docs/integration.md).

---

## 9. License

This project is licensed under the [MIT License](LICENSE).
