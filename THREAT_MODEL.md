# CloudFracture — Threat Model (STRIDE)

A first-class threat model for the vulnerable AI-agent workload: trust boundaries,
the STRIDE threats at each, how the five intentional flaws realise them, and the
residual risk after least-privilege remediation.

## System & data flow

```
   Client / "analyst"
        │ (1) invoke, untrusted input
        ▼
   Agent runtime (local process, acts AS agent-exec-role)
        │ reads system prompt        │ tool calls
        ▼ (2)                        ▼ (3)
   S3 prompt-store            ┌─ read_s3_object ── S3 sensitive-data
   (RAG / system prompt)      ├─ read_database_secret ── Secrets Manager
                              └─ run_query (simulated)
        │ agent-exec-role permissions
        ▼ (4)
   IAM: PassRole → privileged-role  (escalation boundary)
        │ every API call
        ▼
   CloudTrail → S3 (management + scoped S3 data events)
```

## Trust boundaries

| # | Boundary | Why it matters |
|---|----------|----------------|
| TB1 | Client → Agent | Untrusted user input enters the LLM context |
| TB2 | Agent → Prompt store | The agent's own instructions are loaded from mutable storage |
| TB3 | Agent → Tools / AWS APIs | The agent takes real actions on cloud resources |
| TB4 | Agent role → Privileged role | The privilege-escalation boundary |
| TB5 | Agent → Data stores (S3, Secrets) | Sensitive data and credentials are reachable |

## STRIDE analysis

| STRIDE | Threat in this system | Flaw(s) | Attack path | Detection |
|--------|-----------------------|---------|-------------|-----------|
| **S**poofing | A Lambda/principal the agent controls assumes the privileged role | FLAW 3 (over-broad trust) | Path 1 | `sts` AssumeRole anomaly / rule 01 |
| **T**ampering | Persisted prompt injection rewrites the agent's own instructions | FLAW 4 (agent can write prompt store) | Path 2 | rule 02 (PutObject to prompt store) |
| **R**epudiation | Agent actions are unattributable without an audit trail | — (mitigated) | all | CloudTrail (management + S3 data events) |
| **I**nformation disclosure | DB credential stolen; sensitive bucket exfiltrated | FLAW 5, FLAW 2 | Paths 3, 4 | rules 03, 04 |
| **D**enial of service | Out of scope — the lab optimises for identity/data threats, not availability | — | — | — |
| **E**levation of privilege | Agent role escalates to privileged role via PassRole + CreateFunction | FLAW 1a/1b + FLAW 3 | Path 1 | rule 01 (CreateFunction w/ privileged role) |

## The five flaws → threats (summary)

1. **FLAW 1 (PassRole + Lambda create)** → *Elevation of Privilege* (Path 1).
2. **FLAW 2 (wildcard S3/Secrets)** → *Information Disclosure* (Paths 3, 4).
3. **FLAW 3 (over-broad privileged-role trust)** → *Spoofing / EoP* (Path 1 completion).
4. **FLAW 4 (agent can write prompt store)** → *Tampering* (Path 2, persisted injection).
5. **FLAW 5 (agent can read DB secret)** → *Information Disclosure* (Path 3).

## Residual risk after remediation

Least-privilege (`secure_mode`) closes all four attack paths (verified — every
attack returns `AccessDenied`, `remediation/`). Residual risks that remain and how
they are handled:

- **Prompt injection is not "fixed" — it is contained.** The model can still be
  manipulated by poisoned or malicious input; least privilege shrinks the blast
  radius to only what the agent legitimately holds (read its own prompt). A
  system-prompt guard measurably lowers, but does not eliminate, compliance
  (`experiments/ollama-injection-test/RESULTS.md`).
- **Detection is the backstop.** The Sigma rules fire on the *events* the attacks
  produce, so an attempt is visible even if a new gap appears.
- **The lab operator-assume affordance** on `agent-exec-role` is tooling for the
  hybrid execution model and would be removed entirely in a real deployment.
- **Data events cost/latency.** S3 data-event logging is required to see Paths 2/4;
  it is scoped to the two target buckets to bound cost and avoid a log-of-logs loop.

## Assumptions
- Dedicated throwaway AWS account; synthetic data and secrets only.
- Local LLM (Ollama); no external model API in the trust boundary.
- Availability/DoS, network-layer, and supply-chain-of-the-model threats are out of
  scope for this iteration (supply chain of the *code* is covered by the CI pipeline).
