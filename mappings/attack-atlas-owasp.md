# Framework mapping — ATT&CK Cloud · ATLAS · OWASP LLM/Agentic

Every attack path mapped to the frameworks reviewers screen for, with the flaw it
abuses and the detection that catches it.

## Per-path mapping

| Path | Technique | MITRE ATT&CK (Cloud) | MITRE ATLAS | OWASP LLM / Agentic | Flaw | Detection |
|------|-----------|----------------------|-------------|---------------------|------|-----------|
| **1** | PassRole → Lambda privesc | T1548 Abuse Elevation Control · T1078.004 Valid Accounts: Cloud | — | — | FLAW 1a/1b + 3 | rule 01 |
| **2** | Prompt-store poisoning (persisted injection) | T1565 Data Manipulation (Stored) | AML.T0051 LLM Prompt Injection · AML.T0070 (indirect) | LLM01 Prompt Injection · Agentic: instruction tampering | FLAW 4 | rule 02 |
| **3** | Credential theft via tool layer | T1552 Unsecured Credentials · T1552.004 | AML.T0057 LLM Data Leakage | LLM06 Excessive Agency · LLM02 Sensitive Info Disclosure | FLAW 5 | rule 03 |
| **4** | Data exfiltration from S3 | T1530 Data from Cloud Storage · TA0010 Exfiltration | — | LLM06 Excessive Agency | FLAW 2 | rule 04 |

## ATT&CK tactics touched
- **Privilege Escalation** (Path 1)
- **Persistence** (Path 2 — the poison survives across invocations)
- **Credential Access** (Path 3)
- **Collection / Exfiltration** (Path 4)

## OWASP LLM Top 10 (2025) coverage
- **LLM01 Prompt Injection** — Path 2 (indirect, via the prompt store).
- **LLM02 Sensitive Information Disclosure** — Path 3 (the model emits the secret).
- **LLM06 Excessive Agency** — Paths 3 & 4 (the agent's tools + permissions exceed
  what its task needs; least-privilege remediation is the direct fix).

## MITRE ATLAS
- **AML.T0051 LLM Prompt Injection** and indirect-injection technique — Path 2.
- **AML.T0057 LLM Data Leakage** — Path 3, the model exfiltrating a secret through
  its output channel.

## Notes on scoping
- Paths 2/3 are the AI-native techniques (ATLAS / OWASP LLM) and the project's
  differentiator; Paths 1/4 are classic cloud-identity techniques (ATT&CK Cloud).
- Real-world nuance: the Path-1-adjacent GuardDuty type
  `AttackSequence:IAM/CompromisedCredentials` is AWS **sample-only**, so it is not
  claimed as an organic detection (see the build plan's GuardDuty note).
