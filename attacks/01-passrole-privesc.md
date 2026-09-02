# Path 1 — IAM Privilege Escalation via `iam:PassRole` + `lambda:CreateFunction`

**Result: PROVEN.** A principal holding only `agent-exec-role` — which is *denied*
`iam:ListRoles` — escalated to full `privileged-role` execution and listed every
IAM role in the account.

## Framework mapping
- **MITRE ATT&CK**: T1548 (Abuse Elevation Control Mechanism), T1078.004 (Valid Accounts: Cloud Accounts)
- **Technique class**: Rhino Security Labs AWS privesc — PassRole to a service that runs your code

## Preconditions (the intentional flaws exploited)
| Flaw | Grant | File |
|---|---|---|
| FLAW 1a | `agent-exec-role` may `iam:PassRole` `privileged-role` | `terraform/iam.tf` |
| FLAW 1b | `agent-exec-role` may `lambda:CreateFunction` / `InvokeFunction` | `terraform/iam.tf` |
| FLAW 3 | `privileged-role` trust policy allows `lambda.amazonaws.com` | `terraform/iam.tf` |

Note the agent role is over-permissioned but **not omnipotent**: it lacks
`lambda:GetFunction` and `lambda:DeleteFunction`. Escalation needs only
Create + PassRole + Invoke, which it has.

## Technique
1. **Baseline** — as `agent-exec-role`, call `iam:ListRoles` → **AccessDenied**.
2. **Escalate** — as `agent-exec-role`, `CreateFunction` a Lambda whose *execution
   role* is `privileged-role` (this is the PassRole). Because `privileged-role`
   trusts the Lambda service (FLAW 3), the function is accepted.
3. **Run** — `InvokeFunction`. The attacker-supplied code now executes **as
   `privileged-role`** and calls `iam:ListRoles` — which succeeds.

PoC: [`scripts/path1_passrole_privesc.py`](scripts/path1_passrole_privesc.py).
Runs entirely as the assumed agent role, so CloudTrail attributes CreateFunction /
PassRole / Invoke to the agent. Cleans up the Lambda afterward (operator/admin
delete, since the agent role can't).

## Evidence
Raw: [`evidence/path1/evidence.json`](evidence/path1/evidence.json). Key output:

```
Step A: as agent-exec-role, iam:ListRoles  ->  DENIED (AccessDenied)
Step B: CreateFunction with role=privileged-role  ->  SUCCESS
Step C: invoke ->
  running_as: arn:aws:sts::000000000000:assumed-role/cloudfracture-privileged-role/cloudfracture-privesc-poc
  iam_listroles_worked: true
  role_count: 5
escalation_proven: True
```

Same underlying attacker; the only thing that changed is the role its code ran
under. That is the escalation.

## What to detect (Phase 3 preview)
- `CreateFunction` by `agent-exec-role` **where the passed `role` is
  `privileged-role`** — the smoking gun.
- Immediately followed by `Invoke` of that function by the same principal.
- An `AssumeRole` of `privileged-role` by `lambda.amazonaws.com` for a function
  the agent just created.

## Remediation (Phase 4 preview)
- Remove `lambda:CreateFunction`/`UpdateFunctionCode` from the agent role.
- Constrain `iam:PassRole` with a condition on `iam:PassedToService` **and** a
  scoped, non-privileged role ARN — never `privileged-role`.
- Remove `lambda.amazonaws.com` (and account-root) from `privileged-role`'s trust.
Re-running this PoC against the remediated stack must fail at Step B.
