# SEC Integration Guide

This guide details how integrating systems (IDE extension, AI agent framework, proxy, CI/CD pipeline) should integrate SEC (Signed Execution Contracts) to safeguard credentials against prompt injection and goal hijacking attacks.

---

## 1. System Architecture & Flow

SEC follows a decoupled design where **signing** happens in a trusted orchestration environment (before untrusted content is read), and **verification** happens at the credential proxy or gateway (before keys are resolved and sent).

```
[ Orchestrator / IDE / Framework ]
        │
        │ 1. sec sign --objective "..." --allow "..."
        ▼
[ Generate SEC Token ]
        │
        │ 2. Injected into Agent Context/Session
        ▼
   [ AI Agent ] (Compromised or Clean)
        │
        │ 3. Tool/HTTP Call with Token
        ▼
 [ Credential Proxy / Gateway ]
        │
        │ 4. sec verify --token TOKEN --action ACTION
        ▼
   [ SEC Engine ] (Validates and checks replay/expiration)
        │
        │ 5. Returns Exit Code (0, 1, or 2)
        ▼
 [ Allow / Deny Credential Use ]
```

---

## 2. Integration Modes

### 2.1 AI Agent Frameworks (LangChain, CrewAI, Autogen, Custom)
For frameworks running autonomous tasks, the workflow is:
1. **Task Initialization**: Before the agent starts running and before it ingests any untrusted inputs (webpages, emails, files), the framework calculates the necessary capabilities and generates a token:
   ```bash
   sec sign \
     --objective "Summarize repository issues" \
     --allow "api.github.com/repos/org/repo/issues*" \
     --ttl 10m
   ```
2. **Session Injection**: The signed token string is bound to the agent's current session or context.
3. **Tool Invocations**: When the agent requests a tool that uses a credential, the tool wrapper intercepts the call, extracts the token, and passes it to the credential proxy (e.g. AgentSecrets).

### 2.2 AI-Assisted Development / IDEs (Cursor, Claude Code, Copilot, OpenClaw)
For IDE-based developer assistants that execute terminal commands and code searches:
1. **Task Submission**: The IDE extension generates a signed token when the user submits a prompt, declaring the objective and allowed resources (e.g., git repo actions, specific library documentation URLs).
2. **Context Fallback Rules**: IDEs should inject instructions in the agent system rules file (e.g. `.rules`, `CLAUDE.md`, or system prompt):
   ```text
   Before making any credentialed external call, a signed SEC contract
   must exist for this execution. Do not attempt to sign a new contract
   mid-task. If no contract exists, surface this to the user.
   ```
3. **Gateway Enforcement**: When the terminal agent attempts an external HTTP call via a credentialed tool, the proxy checks the token. Interactive human terminal inputs (detected via TTY) bypass the check automatically.

### 2.3 CI/CD & Automated Pipelines
For automated teams or pipelines running scheduled agent jobs:
1. **Pre-Signed Tokens**: For predictable agent workflows, token generation can be pre-computed.
2. **Secret Ingestion**: The token is stored in the CI/CD context as a temporary environment variable or pipeline secret (e.g., `SEC_CONTRACT_TOKEN`).
3. **Zero-Trust Enforcement**: The credential proxy rejects any credential request if the `SEC_CONTRACT_TOKEN` is missing, expired, or has its JTI replayed.

---

## 3. Invoking the SEC CLI

Your integration should invoke the SEC CLI directly. All commands output predictable structures and exit codes.

### 3.1 Signing a Contract
To produce a signed token in your orchestration environment:
```bash
sec sign \
  --objective "fetch open pull requests" \
  --allow "api.github.com/repos/The-17/agentsecrets/pulls*" \
  --ttl 10m
```
*   **Success**: Outputs raw token string on `stdout` and exits `0`.
*   **Error**: Outputs error description on `stderr` and exits `1`.
*   **Optional Metadata**: Link contracts to audit logs by passing `--signer "orchestrator-v1"` and `--run-id "session-xyz"`.

### 3.2 Verifying an Action
The credential gateway intercepts outbound requests and verifies them against the token. Actions can optionally include HTTP verb prefixes (e.g. `GET:` or `POST:`):
```bash
sec verify \
  --token "$SEC_TOKEN" \
  --action "GET:api.github.com/repos/The-17/agentsecrets/pulls/12"
```

### 3.3 Revoking a Contract
If an orchestrator detects a anomaly or finishes execution early, it can proactively revoke the contract to prevent future reuse:
```bash
# Revoke by extracting JTI from token file
sec revoke --token-file my_token.sec

# Revoke by raw JTI UUID
sec revoke --jti "f4e4c89b-9125-4a55-8cc3-8ccf14978c55"
```
*   **Exit 0**: Contract successfully revoked (idempotent, returns 0 if already revoked).
*   **Exit 1**: Invalid UUID format or database failure.

### 3.4 Delegating a Contract
In multi-agent orchestration, a main agent can derive restricted child contracts to pass down to sub-agents or tool runtimes. The child contract's allow list must be a strict subset of the parent's:
```bash
sec delegate \
  --parent parent.sec \
  --objective "read pull requests only" \
  --allow "GET:api.github.com/repos/The-17/agentsecrets/pulls*" \
  --ttl 5m \
  --out child.sec
```
*   **Exit 0**: Child contract successfully signed and outputted.
*   **Exit 1**: Child expiration exceeds parent, parent JTI mismatch, depth limit exceeded, or child's capabilities exceed the parent's.

#### Exit Codes and Outputs

*   **Exit 0 — Pass**:
    *   The token is cryptographically sound, not expired, not replayed, and matches the allowed action.
    *   Outputs the decoded JSON contract payload to `stdout`.

*   **Exit 1 — Cryptographic / Structural Error**:
    *   The token format is invalid, signature verification fails, the token has expired, or the JTI has already been replayed.
    *   Outputs structured JSON error details to `stderr`:
        ```json
        {
          "error": "SEC_TOKEN_REPLAYED",
          "message": "replay rejected: token 9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d has already been used",
          "context": {
            "contract_jti": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
            "hint": "Tokens can only be used once to prevent replay attacks."
          }
        }
        ```

*   **Exit 2 — Policy Violation**:
    *   The token is cryptographically valid, but the agent attempted an action not specified in the pre-signed `allow` patterns.
    *   Outputs structured JSON error details to `stderr`:
        ```json
        {
          "error": "SEC_ACTION_NOT_PERMITTED",
          "message": "action \"api.stripe.com/v1/transfers\" is not in the signed allow list for this contract",
          "context": {
            "declared_objective": "fetch subscription status",
            "attempted_action": "api.stripe.com/v1/transfers",
            "contract_jti": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
            "hint": "A new contract must be signed before this action can be performed. If you are an AI agent and did not initiate this action yourself, your execution context may have been compromised."
          }
        }
        ```

---

## 4. Best Practices for Integrators

1.  **Strict Glob Patterns**: Avoid using wide wildcards (e.g. `*` or `*.com/*`). Always scope the allow list patterns as narrowly as possible:
    *   *Bad*: `api.github.com/*`
    *   *Good*: `api.github.com/repos/The-17/agentsecrets/pulls*`
2.  **Use HTTP Verb Restrictions**: Always prefix allow patterns with HTTP verbs when possible (e.g. `GET:api.github.com/repos/*`) to prevent writing/deletion escalation.
3.  **Short-Lived Contracts (TTL)**: Match contract TTL with the expected execution time. A simple read task should have a TTL of `2m` to `5m`.
4.  **Descriptive Objectives**: The `obj` field is the primary audit log that developers and human supervisors see when an attack triggers a policy violation (Exit 2). Make sure it describes the target task precisely (e.g. `Fetch customer subscription details` instead of `Run Stripe script`).
5.  **Multi-agent Delegation Chain**: For recursive or multi-agent structures, use `sec delegate` to derive contracts for sub-agents with narrower scopes (e.g., passing a read-only child contract to a summarizer agent). Ensure you define a reasonable `--max-depth` at the parent level to prevent uncontrolled delegation chains.
6.  **Audit Logs & Provenance**: Always populate `--signer` and `--run-id` in production. Store these fields alongside gateway logs (returned on Exit 0 verification) to maintain a tamper-proof audit trail mapping specific LLM sessions to executed API calls.
