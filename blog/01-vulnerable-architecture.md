---
title: "CloudFracture, Part 1 — A vulnerable AWS AI agent, and why real teams ship these flaws"
tags: [aws, security, ai, iam]
status: draft
---

# Part 1 — The vulnerable architecture (and why real teams build it)

AI agents are quietly becoming one of the softest targets in the cloud. Not because
the models are dangerous on their own, but because of what we *wire them to*: an
execution role, a few tools, a bucket of "context," a database credential "just for
now." Each decision looks reasonable in isolation. Together they are an attack path.

CloudFracture is a deliberately vulnerable LLM-agent workload on AWS that I built as
Terraform so I could attack it, detect the attacks, and then close them — with real
evidence at each step. This first post is about the target: what it is, and why the
flaws in it are the kind a real team ships by accident, not a CTF puzzle.

## The workload

A plausible enterprise pattern — an "AnalyticsAssistant" agent that answers questions
using company data and a set of tools:

- an **agent runtime** (Python) that authenticates as `agent-exec-role`, reasons with
  a local **Ollama** model, and calls tools: read an S3 object, read a database
  secret, run a query;
- an **S3 prompt store** holding the agent's system prompt / RAG context;
- an **S3 sensitive-data** bucket (synthetic customer data);
- a **Secrets Manager** secret — a database credential;
- two IAM roles: `agent-exec-role` (the entry point) and `privileged-role` (the
  escalation target);
- **CloudTrail** delivering events to S3, as the detection data source.

One honest design note up front. The plan originally said "the agent Lambda calls
Ollama." It can't: a Lambda runs inside AWS and can't reach a model on my laptop. So
the agent runs as a **local process that assumes `agent-exec-role`** — every AWS
action it takes is still attributed to that role in CloudTrail, exactly like a real
compromised agent — and the only thing deployed as a Lambda is the escalation
primitive the attack itself creates. Getting this right mattered more than matching
the original diagram.

## The five flaws — and why they're realistic

The point of this project is that the flaws are *plausible*. Each one carries an
in-code comment describing what it is, **why a real team would ship it**, which
attack it enables, and how to fix it.

1. **`agent-exec-role` can `iam:PassRole` the privileged role and create Lambdas.**
   Someone needed the agent to "launch a worker with the right role," couldn't get
   the scoped PassRole condition right, and widened it "just to unblock the demo."
   The scoping condition is the thing that always gets dropped under deadline.

2. **Wildcard `s3:*` / `secretsmanager:*` on `Resource: "*"`.** The classic "we'll
   tighten it later" managed policy. During prototyping the agent kept hitting
   AccessDenied, so someone pasted a wildcard to stop the churn. "Later" never came.

3. **`privileged-role` trusts `lambda.amazonaws.com` and the account root.** `root`
   in a trust policy is the copy-paste default from a hundred blog posts — it reads
   as "trust my own account," which sounds safe. And pointing a worker Lambda at an
   existing powerful role instead of a scoped one is a common shortcut.

4. **The agent can *write* to its own prompt store.** The role that reads the prompts
   got reused for a "let the agent cache results back to the bucket" feature. Read
   and write collapsed onto one identity — and now the agent's own instructions are
   attacker-writable.

5. **The agent can read the DB credential directly.** The secret was wired to the
   agent "for now" during a data-access spike and never moved behind a broker.

None of these require an attacker to be clever. They require an attacker to notice
what a busy team left behind.

## Cost and safety, by design

The whole thing runs on a dedicated throwaway account for under €10. The LLM is
local (Ollama, €0). CloudTrail management events are free; S3/Secrets are pennies.
`terraform destroy` runs after **every** session — the safety net is discipline, not
a simulator. (I deliberately dropped LocalStack/Floci-style emulators: they don't
enforce IAM, and IAM enforcement is the entire mechanic this project tests. An attack
that "works" only because the emulator waved it through proves nothing.)

## What's next

The target stands up and tears down on command, the agent works end to end, and the
flaws are reachable. In **Part 2**, I use them: privilege escalation through
`PassRole`, poisoning the agent's prompt store, stealing a credential through the
model's own output, and exfiltrating a bucket — each with the real terminal evidence.

The most interesting result isn't that the attacks work. It's *how unreliably* the
AI-native ones work, and what that says about small local models. More on that next.

*Code + evidence: the CloudFracture repo.*
