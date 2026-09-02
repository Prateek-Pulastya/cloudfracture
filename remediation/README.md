# Remediation — closing every path with least privilege

The same stack stands up **vulnerable** or **remediated** via one Terraform toggle:
```bash
terraform apply -var secure_mode=true      # least-privilege build
python ../remediation/verify_remediation.py  # re-attacks it; asserts all blocked
```

## Result (verified on real AWS)
| Attack | Remediated outcome |
|---|---|
| Path 1 — PassRole + CreateFunction | **AccessDenied** |
| Path 2 — write to prompt store | **AccessDenied** |
| Path 3 — read DB secret | **AccessDenied** |
| Path 4 — read sensitive bucket | **AccessDenied** |
| benign — agent reads its own prompt | **OK** (workload intact) |

All four attacks blocked; the agent still functions. Evidence:
[`evidence/verify.json`](evidence/verify.json).

## What changed
Per-flaw before/after policy deltas: [`iam-diffs/`](iam-diffs/README.md). In short:
- Removed the agent's `iam:PassRole`, `lambda:*`, and `s3:*`/`secretsmanager:*`
  wildcard (FLAWS 1a, 1b, 2) — the agent keeps only logging + `s3:GetObject` on its
  own prompt.
- Scoped the privileged-role trust to one admin principal — no `lambda.amazonaws.com`,
  no account root (FLAW 3).
- Dropped the prompt-store write bucket policy (FLAW 4) and the secret resource
  policy (FLAW 5).

## Why this is the artifact that matters
It proves both halves: the flaws are exploitable (see `attacks/`) **and** a
least-privilege fix closes each one, verified by re-running the attacks — without
breaking the workload. That offense-plus-defense loop is rare in a junior portfolio.
