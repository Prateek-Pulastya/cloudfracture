# Remediation — before/after IAM diffs

Each intentional flaw and the least-privilege change that closes it. In code this
is the `secure_mode` toggle (`terraform apply -var secure_mode=true`); here it is
the policy delta per flaw. Proof that these close the attacks:
[`../verify_remediation.py`](../verify_remediation.py) re-attempts all four paths
against the remediated stack and asserts each is denied.

---

## FLAW 1a + 1b — agent PassRole + Lambda create (Path 1 privesc)

**Before** (`agent-exec-role` inline policy):
```json
{ "Sid": "Flaw1aPassRoleToPrivileged", "Effect": "Allow",
  "Action": "iam:PassRole", "Resource": ".../role/cloudfracture-privileged-role" }
{ "Sid": "Flaw1bLambdaCreateUpdateInvoke", "Effect": "Allow",
  "Action": ["lambda:CreateFunction","lambda:UpdateFunctionCode","lambda:InvokeFunction", ...],
  "Resource": "*" }
```
**After:** both statements **removed entirely**. The agent has no `iam:PassRole`
and no `lambda:*` — it cannot create a function or pass a role. Path 1 fails at
`CreateFunction` with `AccessDenied`.

---

## FLAW 2 — wildcard S3 / Secrets (Paths 3, 4)

**Before:**
```json
{ "Sid": "Flaw2WildcardDataAccess", "Effect": "Allow",
  "Action": ["s3:*","secretsmanager:*"], "Resource": "*" }
```
**After:** replaced with a single least-privilege statement — the agent may only
**read its own prompt**:
```json
{ "Sid": "ReadOwnPromptOnly", "Effect": "Allow",
  "Action": "s3:GetObject", "Resource": ".../cloudfracture-prompt-store-*/*" }
```
No `secretsmanager` access, no access to the sensitive-data bucket. Paths 3 and 4
fail with `AccessDenied`.

---

## FLAW 3 — over-permissive privileged-role trust (Path 1)

**Before** (`privileged-role` trust policy):
```json
{ "Effect": "Allow", "Action": "sts:AssumeRole",
  "Principal": { "Service": "lambda.amazonaws.com",
                 "AWS": ".../root" } }
```
**After:** trust only a specific legitimate admin principal — no Lambda service,
no account root:
```json
{ "Effect": "Allow", "Action": "sts:AssumeRole",
  "Principal": { "AWS": ".../user/cloudfracture-cli" } }
```
Even if an attacker could create a Lambda, it can no longer assume the privileged
role. Defense in depth with the FLAW-1 fix.

---

## FLAW 4 — prompt-store writable by agent (Path 2)

**Before:** an S3 bucket policy granting `agent-exec-role` `s3:PutObject`.
**After:** the bucket policy is **not attached** (removed in `secure_mode`), and
the agent's identity policy grants only `s3:GetObject`. The agent can read but not
write its prompt store. Path 2 (`PutObject`) fails with `AccessDenied`.

---

## FLAW 5 — DB secret readable by agent (Path 3)

**Before:** a Secrets Manager resource policy granting `agent-exec-role`
`GetSecretValue`.
**After:** the resource policy is **not attached**, and the agent's identity
policy has no `secretsmanager` permission. Path 3 (`GetSecretValue`) fails with
`AccessDenied`.

---

## Note on the lab affordance
The `agent-exec-role` trust that lets the local operator assume the role (hybrid
execution) is lab tooling, not a production grant; in a real deployment it would be
removed. It is intentionally kept in `secure_mode` so the verifier can still assume
the role to *attempt* — and be denied — each attack.
