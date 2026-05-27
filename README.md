# SEC: Signed Execution Contracts

SEC (Signed Execution Contracts) is an offline policy engine and cryptographic capability boundary designed for autonomous systems and AI agents. It ensures that agents can only execute tools and access APIs that align with their pre-committed, authorized objectives.

## Installation

You can install SEC using Homebrew or build it directly from source.

### Homebrew
Install the official tap:
```bash
brew install The-17/tap/sec
```

### From Source
Clone the repository and compile the binary to your `$GOPATH/bin` directory:
```bash
git clone https://github.com/The-17/sec.git
cd sec
make install
```

## The Security Challenge in Autonomous Systems

In traditional software, API keys and credentials are stateful and binary: if an agent possesses a Stripe or GitHub API key, the receiving gateway assumes the request is valid. 

However, autonomous AI agents introduce a dangerous attack surface. When an agent reads untrusted external data (such as a webpage, email, or pull request), its core reasoning engine is vulnerable to **prompt injection**. If hijacked, the agent can be forced to execute malicious actions—such as exfiltrating data or deleting repositories—using the valid credentials it possesses.

SEC prevents this by enforcing a core security guarantee:
> **An agent cannot utilize a credential for any action it did not explicitly commit to before interacting with untrusted content.**

Rather than redacting data or filtering network traffic, SEC acts as a cryptographic sandbox. It generates signed contracts representing the agent's current task-specific permissions. These contracts are verified by gateway proxies before resolving downstream credentials.

### OWASP Top 10 for LLMs Alignment
SEC provides direct mitigations for several critical vulnerabilities identified in the OWASP LLM security model:
*   **Prompt Injection (LLM01)**: Even if an agent's reasoning is hijacked, it cannot call arbitrary APIs because the validation proxy blocks any destination not matching the signed contract. The signing key is held securely by the orchestrator, preventing the compromised agent from self-signing new capabilities.
*   **Insecure Output Handling (LLM02)**: Outbound payloads and destinations are evaluated against the contract boundary before execution, preventing raw LLM outputs from performing unauthorized state changes.
*   **Insecure Plugin Design (LLM07)**: SEC wraps every tool call in a capability boundary, enforcing strict parameters, HTTP verbs, and destination scopes.

## Getting Started

### 1. Initialize Keys
First, generate the Ed25519 signing keypair used to verify contracts:
```bash
sec init
```
This registers your default keys under `~/.sec/keys/`.

### 2. Sign a Contract
Before launching the agent on a task, the orchestrator signs a contract specifying the objective and allowed actions. For example, to allow an agent to summarize repository pull requests on a specific GitHub repo for 10 minutes:
```bash
sec sign \
  --objective "summarize repository pull requests" \
  --allow "GET:api.github.com/repos/The-17/agentsecrets/pulls*" \
  --ttl "10m" \
  --out my_run.sec
```
This writes a lightweight, signed token to `my_run.sec`.

### 3. Verify an Action
When the agent attempts an action, the gateway proxy validates the contract token against the target URL:
```bash
sec verify \
  --token-file my_run.sec \
  --action "GET:api.github.com/repos/The-17/agentsecrets/pulls/12"
```
*   **Authorized Action**: If the action matches, the command exits with code `0` and outputs the decoded contract JSON.
*   **Unauthorized Action**: If the agent attempts a forbidden action (like accessing repo keys or utilizing an incorrect HTTP verb):
    ```bash
    sec verify \
      --token-file my_run.sec \
      --action "POST:api.github.com/repos/The-17/agentsecrets/pulls"
    ```
    The command exits with code `2` (Policy Violation) and outputs a structured JSON error to `stderr`.

## System Architecture & Mechanics

### Detached-Signature Format
Contracts are represented as lightweight, dot-separated tokens:
```text
BASE64URL(CanonicalPayloadJSON).BASE64URL(SignatureBytes)
```
SEC uses **RFC 8785 JSON Canonicalization Scheme (JCS)** to ensure key ordering and whitespace remain perfectly deterministic across languages (Go, Python, TypeScript) during signing and verification.

### The Verification Pipeline
For every verification request, SEC executes a 7-step security check:
1.  **Format Check**: Validates the dot-separated segment structure.
2.  **Key Resolution**: Loads the verification public key matching the contract's `kid`.
3.  **Signature Verification**: Confirms the cryptographic integrity of the payload using Ed25519.
4.  **Schema Validation**: Verifies that the JSON payload contains all required fields (UUID `jti`, non-empty `obj`, etc.).
5.  **Timing Invariants**: Checks that the token is currently active (`iat` <= current time <= `exp`).
6.  **Replay & Revocation Check**: Queries a local transactional SQLite WAL database to guarantee the token `jti` is not being replayed or has not been revoked.
7.  **Glob Pattern Match**: Ensures the action and HTTP verb strictly match the `allow` patterns.

### Multi-Agent Delegation
When a primary agent delegates sub-tasks to subordinate agents, it can issue a child contract. The child contract must strictly narrow the capabilities of the parent contract:
*   **Subset Constraints**: The child's allowed patterns must be a subset of the parent's allowed patterns.
*   **Timing Constraints**: The child's expiration (`exp`) cannot exceed the parent's expiration.
*   **Delegation Depth**: Parent contracts can specify `max_depth`. Each delegation decrements this counter, and delegation is blocked when it reaches zero.

To delegate a child contract:
```bash
sec delegate \
  --parent parent.sec \
  --objective "read pull request 12" \
  --allow "GET:api.github.com/repos/The-17/agentsecrets/pulls/12" \
  --out child.sec
```

### Proactive Revocation
If a task finishes early, or if an anomaly is detected, contracts can be proactively revoked to prevent reuse:
```bash
sec revoke --token-file my_run.sec
```

## CLI Reference

*   `sec init [--kid <key_id>]`: Generates signing keys.
*   `sec sign [flags]`: Generates a signed execution token.
    *   `--objective`: (Required) Task description.
    *   `--allow`: (Required) Comma-separated allowed glob patterns with optional HTTP verb prefixes.
    *   `--ttl`: Token lifetime (e.g. `10m`, `1h`).
    *   `--out`: Destination file path.
*   `sec verify [flags]`: Verifies a token against an action.
    *   `--token` / `--token-file`: Token inputs.
    *   `--action`: Target action (e.g. `GET:api.github.com/repos/foo`).
*   `sec delegate [flags]`: Derives a child contract.
    *   `--parent`: Path to parent token.
    *   `--objective`: Task description.
    *   `--allow`: Narrowed glob patterns.
*   `sec revoke [flags]`: Revokes a contract JTI.
*   `sec status`: Displays key locations, database path, and active JTI count.

For detailed integration tutorials and SDK guides, refer to [integration.md](file:///wsl.localhost/Ubuntu/home/theapiartist/work/SEC/docs/integration.md).
