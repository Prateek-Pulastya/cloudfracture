# Checkov suppressions — justification

Checkov flags 39 findings on the vulnerable build. `.checkov.yaml` suppresses them
in two justified groups. This is deliberate: the plan calls for documenting the
intentional flaws as intentional rather than silently passing.

## Group A — Intentional flaws (the project's subject)

These *are* the vulnerabilities. They are exploited in [`attacks/`](../attacks) and
closed by `terraform apply -var secure_mode=true` (see [`remediation/`](../remediation)).
Suppressed so CI is green on the vulnerable build while the flaws stay visible in code.

| Check | Maps to | Where it's fixed |
|---|---|---|
| CKV_AWS_110 (privilege escalation) | FLAW 1 — PassRole + Lambda create | `secure_mode`: perms removed |
| CKV_AWS_108 (data exfiltration) | FLAW 2 — wildcard S3/Secrets | `secure_mode`: scoped to prompt read |
| CKV_AWS_356 (`Resource: "*"`) | FLAW 2 | `secure_mode` |
| CKV_AWS_111 (write w/o constraint) | FLAW 2 | `secure_mode` |
| CKV_AWS_109 (permissions management) | privileged role / FLAW 2 | `secure_mode` |
| CKV_SECRET_6 (high-entropy string) | the **synthetic** DB credential | n/a — not a real secret |

## Group B — Accepted for an ephemeral lab

Legitimate hardening the minimal lab intentionally omits. The lab is destroyed after
every session and holds only synthetic data, so these add cost/complexity without
addressing the identity/AI threats under study. Each would be enabled in a
persistent deployment.

| Check | Gap | Why accepted here |
|---|---|---|
| CKV_AWS_145 | S3 not KMS-encrypted | SSE-S3 default suffices for synthetic data |
| CKV_AWS_21 | S3 versioning off | ephemeral buckets, `force_destroy` |
| CKV_AWS_18 | S3 access logging off | CloudTrail data events already cover the target buckets |
| CKV_AWS_144 | no cross-region replication | single-region ephemeral lab |
| CKV2_AWS_61 | no S3 lifecycle | destroyed after each session |
| CKV2_AWS_62 | no S3 event notifications | not needed for the threat model |
| CKV_AWS_54 / CKV2_AWS_6 | public-access nuance | all buckets have a public access block; policies are account-scoped, not public |
| CKV_AWS_35 | CloudTrail not KMS-encrypted | synthetic logs, ephemeral |
| CKV_AWS_252 | no CloudTrail SNS topic | detection is pulled via S3/Athena, not push |
| CKV2_AWS_10 | no CloudWatch Logs integration | detection uses S3 + the pySigma runner |
| CKV_AWS_149 | secret not KMS-encrypted | synthetic credential |
| CKV2_AWS_57 | no secret auto-rotation | synthetic credential, ephemeral |

## Reproduce
```bash
pip install checkov
checkov -d terraform            # 39 findings on the vulnerable build
checkov --config-file .checkov.yaml   # green (suppressions applied)
```
