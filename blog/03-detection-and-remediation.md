---
title: "CloudFracture, Part 3 — Detecting and closing it: tested detections + least-privilege"
tags: [aws, security, detection, appsec]
status: draft
---

# Part 3 — Detection-as-code and remediation

[Part 2](02-attack-paths.md) broke the AI agent four ways. Attacks with no defense
are half a story — and the wrong half for a security portfolio. Here's the other
half: catching the attacks, and proving a fix closes them.

## Detection-as-code — tested, not linted

I wrote four Sigma rules, one per attack path, over CloudTrail:

- `CreateFunction` passing `privileged-role` (Path 1),
- `PutObject` to the prompt store by the agent role (Path 2),
- `GetSecretValue` on the DB credential by the agent role (Path 3),
- `GetObject` on the sensitive-data bucket by the agent role (Path 4).

The important word is **tested**. A lot of "detection-as-code" repos run
`sigma-cli` and call it done — but that only proves the YAML is well-formed, not that
the rule fires on the attack. So each rule ships with two fixtures — a CloudTrail
event that *should* trigger it and one that *shouldn't* — and a small pySigma-based
runner **executes** the rule against both and asserts the result. It runs in CI; a
rule that stops catching its attack, or starts firing on benign activity, fails the
build.

```
rule                            fire  nofire  result
01_iam_passrole_to_new_lambda   True  False   PASS
02_s3_promptstore_write         True  False   PASS
03_secrets_getvalue_agent       True  False   PASS
04_s3_sensitive_data_read       True  False   PASS
```

### A real lesson about CloudTrail

My first fixture capture was missing Paths 2 and 4 entirely. The reason is worth
knowing: `PutObject` and `GetObject` are S3 **data events**, and a management-events-
only trail doesn't record them. I added scoped S3 data-event selectors for the two
target buckets (not the log bucket — that would create a log-of-logs loop). The
Path-1 (`CreateFunction`) and Path-3 (`GetSecretValue`) fixtures are real captured
events; the S3 data-event fixtures are constructed to the documented schema (with the
real agent identity block) because first-time data-event delivery is genuinely slow.
The repo says exactly which is which. Provenance honesty is part of the deliverable.

## Remediation — and proving it

The same Terraform stack applies vulnerable *or* remediated via one toggle,
`-var secure_mode=true`. Secure mode:

- strips the agent's `PassRole`, `lambda:*`, and wildcard `s3:*`/`secretsmanager:*`,
  leaving only "write logs" and "read my own prompt";
- scopes the `privileged-role` trust to a single admin principal — no Lambda service,
  no account root;
- drops the prompt-store write policy and the secret's agent-read policy.

Then I re-ran all four attacks against the remediated stack:

```
Path 1 — PassRole+CreateFunction   blocked (AccessDenied)
Path 2 — write to prompt store      blocked (AccessDenied)
Path 3 — read DB secret             blocked (AccessDenied)
Path 4 — read sensitive bucket      blocked (AccessDenied)
benign — agent reads its own prompt OK
```

All four denied — and the agent still works. That before/after loop, run against real
AWS, is the thing I most want a reviewer to see: I can open a hole *and* close it, and
prove both.

Note what remediation does and doesn't do for the AI-native paths. Least privilege
doesn't stop a model from being manipulated — it shrinks the blast radius to what the
agent legitimately holds. The prompt injection still "works"; it just has nothing
useful to reach. Detection is the backstop for whatever gap appears next.

## Shipping it like software

The whole thing goes through one GitHub Actions pipeline: the detection tests, plus
Semgrep (SAST), pip-audit (SCA), Gitleaks (secrets), Checkov + tfsec (IaC), and Syft
(CycloneDX SBOM). Checkov flags the intentional flaws, of course — so they're
suppressed with a documented, per-check justification split into "intentional (and
here's where it's fixed)" versus "accepted for an ephemeral lab." Green CI that hides
its own vulnerabilities would be worse than useless; the suppressions are the point.

## One honest gap

I couldn't capture a GuardDuty finding: the lab account returns
`SubscriptionRequiredException` for GuardDuty (an account-level state on an old
account near expiry), in every region. The capture script and the finding-type→path
mapping are in the repo, ready to run on a subscribable account. I left it documented
rather than faked — the Sigma layer already covers all four paths.

## Closing

The value here isn't any single exploit. It's the loop: build a realistic flaw,
exploit it with evidence, detect it with a test that fails when the detection breaks,
close it with least privilege, and prove the close — all as code, all reproducible,
all honest about what's real and what isn't. That's the job.

*Code + evidence: the CloudFracture repo.*
