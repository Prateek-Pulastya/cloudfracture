# =============================================================================
# iam.tf  —  CloudFracture's deliberately vulnerable identity layer
# =============================================================================
#
# THIS FILE IS THE PROJECT. Per the build plan (§14), if you cannot name each
# misconfiguration in code, there is no project. Every flaw below is INTENTIONAL
# and carries: (a) what the flaw is, (b) why a real team would ship it by
# accident, (c) which attack path it enables, (d) how it gets remediated.
#
# DO NOT deploy to an account that holds anything real. `terraform destroy`
# after EVERY session (build plan §8) — this is the safety net now that
# LocalStack is out of the workflow.
#
# The five flaws (build plan §3):
#   FLAW 1 — agent-exec-role: iam:PassRole on privileged-role + lambda:Create/Update
#   FLAW 2 — agent-exec-role: wildcard actions + Resource "*" on S3 / Secrets
#   FLAW 3 — privileged-role: over-permissive trust policy (whole-account principal)
#   FLAW 4 — prompt-store bucket policy: agent-exec-role can PutObject  (resource-based; attaches in main.tf, Phase 1 — documented here)
#   FLAW 5 — db-creds secret resource policy: agent-exec-role can GetSecretValue (resource-based; attaches in main.tf, Phase 1 — documented here)
#
# FLAWS 1–3 are pure IAM and live here in full. FLAWS 4–5 are RESOURCE-based
# policies that belong next to the bucket / secret they sit on (main.tf, Phase 1);
# they are specified in full in the commented block at the bottom of this file so
# the "name every flaw" requirement is met in one place. Note that FLAW 2's
# wildcard already grants the agent role that same access from the identity side —
# the resource-based versions make the misconfiguration reachable two ways, which
# is realistic and gives the detection layer two distinct events to catch.
# =============================================================================

# ---- Derived identifiers ----------------------------------------------------
# ARNs are constructed as strings so this file `terraform validate`s on its own,
# before main.tf (the buckets / secret / Lambda) exists. main.tf will create
# those resources under these exact names.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.name

  agent_role_name      = "${var.project}-agent-exec-role"
  privileged_role_name = "${var.project}-privileged-role"

  prompt_store_bucket   = "${var.project}-prompt-store-${local.account_id}"
  sensitive_data_bucket = "${var.project}-sensitive-data-${local.account_id}"
  db_secret_name        = "${var.project}/app/db-creds"

  privileged_role_arn   = "arn:${local.partition}:iam::${local.account_id}:role/${local.privileged_role_name}"
  prompt_store_arn      = "arn:${local.partition}:s3:::${local.prompt_store_bucket}"
  sensitive_data_arn    = "arn:${local.partition}:s3:::${local.sensitive_data_bucket}"
  # Secrets Manager ARNs carry a random 6-char suffix, so match with a wildcard.
  db_secret_arn_pattern = "arn:${local.partition}:secretsmanager:${local.region}:${local.account_id}:secret:${local.db_secret_name}-*"
}

# =============================================================================
# agent-exec-role  —  the attacker's entry point (the Lambda's execution role)
# =============================================================================

data "aws_iam_policy_document" "agent_assume" {
  statement {
    sid     = "LambdaServiceAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }

  # ---- Lab affordance (hybrid execution model) — NOT a deliberate flaw --------
  # The agent's reasoning runs as a LOCAL process, because a deployed Lambda cannot
  # reach the Ollama model on the operator's machine. To act with exactly this
  # role's permissions (so the intentional flaws behave as designed) and to have
  # CloudTrail attribute the activity to agent-exec-role, the local operator
  # assumes this role. Scoped to this account's own principals; it is TIGHTENED in
  # the Phase-4 remediation pass alongside the real flaws. Rationale:
  # specs/001-vulnerable-workload/research.md (D2).
  statement {
    sid     = "OperatorLocalAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_iam_role" "agent_exec" {
  name               = local.agent_role_name
  assume_role_policy = data.aws_iam_policy_document.agent_assume.json
  description        = "Execution role for the CloudFracture agent Lambda. Intentionally over-privileged."
}

data "aws_iam_policy_document" "agent_policy" {

  # -- Legitimate baseline: the Lambda must write its own logs. Not a flaw. -----
  statement {
    sid    = "BaselineLambdaLogging"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:*"]
  }

  # ==========================================================================
  # FLAW 1a — iam:PassRole on the privileged role.
  #
  # What: the agent role may hand privileged-role to another AWS service.
  # Why a real team ships this: someone needed the agent to launch a worker
  #   Lambda "with the right role," couldn't get the scoped PassRole condition
  #   right, and widened it "just to unblock the demo." The scoping condition
  #   (iam:PassedToService + a specific role ARN) is the thing that usually
  #   gets dropped under deadline.
  # Enables: Path 1 (privilege escalation). Combined with FLAW 1b, the agent
  #   creates a new Lambda, passes it privileged-role, invokes it, and now runs
  #   as an admin-ish principal.
  # Remediate: delete this statement, or constrain with a condition on
  #   iam:PassedToService AND a single, non-privileged role ARN.
  # ==========================================================================
  statement {
    sid       = "Flaw1aPassRoleToPrivileged"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [local.privileged_role_arn]
    # NOTE (remediation target): no condition block here. A safe version would add:
    #   condition { test = "StringEquals"
    #               variable = "iam:PassedToService"
    #               values = ["lambda.amazonaws.com"] }
    # ...and point resources at a scoped, non-admin role — not privileged-role.
  }

  # ==========================================================================
  # FLAW 1b — lambda:CreateFunction / UpdateFunctionCode / Invoke on "*".
  #
  # What: the agent role can create and update arbitrary Lambda functions and
  #   invoke them.
  # Why a real team ships this: "the agent needs to deploy tool functions
  #   dynamically." The blast radius of pairing this with PassRole is rarely
  #   noticed because each permission looks reasonable in isolation.
  # Enables: Path 1. This is the execution primitive that turns FLAW 1a's
  #   PassRole into code actually running as privileged-role.
  # Remediate: drop CreateFunction/UpdateFunctionCode entirely; if the agent
  #   truly must invoke, scope InvokeFunction to specific function ARNs.
  # ==========================================================================
  statement {
    sid    = "Flaw1bLambdaCreateUpdateInvoke"
    effect = "Allow"
    actions = [
      "lambda:CreateFunction",
      "lambda:UpdateFunctionCode",
      "lambda:UpdateFunctionConfiguration",
      "lambda:InvokeFunction",
      "lambda:AddPermission",
    ]
    resources = ["*"]
  }

  # ==========================================================================
  # FLAW 2 — wildcard actions + Resource "*" on S3 and Secrets Manager.
  #
  # What: s3:* and secretsmanager:* against every resource in the account.
  # Why a real team ships this: the classic "we'll tighten it later" managed
  #   policy. During prototyping the agent kept hitting AccessDenied on some
  #   new bucket/secret, so someone pasted a wildcard to stop the churn — and
  #   "later" never came.
  # Enables: Path 3 (read the DB credential via the agent's own permission)
  #   and Path 4 (read the sensitive-data bucket). Also the identity-side
  #   route to FLAWS 4 and 5.
  # Remediate: replace with least-privilege statements scoped to exactly the
  #   objects the agent needs (e.g. s3:GetObject on prompt-store/* only).
  # ==========================================================================
  statement {
    sid    = "Flaw2WildcardDataAccess"
    effect = "Allow"
    actions = [
      "s3:*",
      "secretsmanager:*",
    ]
    resources = ["*"]
  }
}

# --- Remediated agent policy (secure_mode = true) ----------------------------
# Least-privilege: the benign agent only needs to write its own logs and READ its
# system prompt. Everything that enabled the attacks is gone — no iam:PassRole
# (fixes FLAW 1a), no lambda:CreateFunction (FLAW 1b), no s3:*/secretsmanager:*
# wildcard (FLAW 2). Applying with -var secure_mode=true makes Paths 1/3/4 fail.
data "aws_iam_policy_document" "agent_policy_secure" {
  statement {
    sid    = "BaselineLambdaLogging"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:*"]
  }
  statement {
    sid       = "ReadOwnPromptOnly"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${local.prompt_store_arn}/*"]
  }
}

resource "aws_iam_role_policy" "agent_policy" {
  name   = "${var.project}-agent-exec-policy"
  role   = aws_iam_role.agent_exec.id
  policy = var.secure_mode ? data.aws_iam_policy_document.agent_policy_secure.json : data.aws_iam_policy_document.agent_policy.json
}

# =============================================================================
# privileged-role  —  the escalation target (admin-ish)
# =============================================================================

# ==========================================================================
# FLAW 3 — over-permissive trust policy.
#
# What: privileged-role trusts BOTH the AWS Lambda service
#   (lambda.amazonaws.com) AND the entire account root principal
#   (arn:aws:iam::<account>:root).
#   - The lambda.amazonaws.com trust is what actually enables the Path-1
#     escalation: it lets the attacker CREATE a Lambda whose execution role IS
#     privileged-role (a function can only use a role its trust policy allows),
#     then invoke it to run code as the privileged role.
#   - The account-root trust is additional over-breadth: any principal in the
#     account holding sts:AssumeRole can assume it directly.
# Why a real team ships this: someone needed "a Lambda that can do admin tasks"
#   and pointed its execution role at an existing powerful role instead of a
#   scoped one; the `root` line is the copy-paste "trust my own account" default
#   from countless blog posts. Both read as harmless in isolation.
# Enables: Path 1 — PassRole + CreateFunction + this trust = code running as
#   privileged-role.
# Remediate: remove lambda.amazonaws.com; scope any trust to the single specific
#   principal that legitimately needs it, never the account root.
# ==========================================================================
data "aws_iam_policy_document" "privileged_assume" {
  statement {
    sid     = "Flaw3TrustLambdaAndAccount"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }
}

# --- Remediated privileged-role trust (secure_mode = true) -------------------
# Fixes FLAW 3: trust ONLY a specific legitimate admin principal — not
# lambda.amazonaws.com, not the account root. This alone breaks Path 1: a Lambda
# the agent creates can no longer assume this role.
data "aws_iam_policy_document" "privileged_assume_secure" {
  statement {
    sid     = "ScopedAdminTrust"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:user/cloudfracture-cli"]
    }
  }
}

resource "aws_iam_role" "privileged" {
  name               = local.privileged_role_name
  assume_role_policy = var.secure_mode ? data.aws_iam_policy_document.privileged_assume_secure.json : data.aws_iam_policy_document.privileged_assume.json
  description        = "The escalation target. Admin-ish; must never be assumable by the agent path."
}

# Admin-ish permissions on the privileged role. This is the prize: once the
# attacker runs as this role, Path 4 (bulk data exfil) becomes trivial.
# Kept as a broad grant on purpose — the interesting failure is that the agent
# path can REACH this role at all (FLAW 3), not that the role is powerful.
data "aws_iam_policy_document" "privileged_policy" {
  statement {
    sid    = "PrivilegedBroadAccess"
    effect = "Allow"
    actions = [
      "s3:*",
      "secretsmanager:*",
      "iam:List*",
      "iam:Get*",
      "sts:GetCallerIdentity",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "privileged_policy" {
  name   = "${var.project}-privileged-policy"
  role   = aws_iam_role.privileged.id
  policy = data.aws_iam_policy_document.privileged_policy.json
}

# =============================================================================
# Handy outputs for the attack scripts (they need the role names/ARNs).
# =============================================================================

output "agent_exec_role_arn" {
  description = "Entry-point role the attack starts from."
  value       = aws_iam_role.agent_exec.arn
}

output "privileged_role_arn" {
  description = "Escalation target role."
  value       = aws_iam_role.privileged.arn
}

# =============================================================================
# FLAWS 4 & 5 — resource-based policies. Specified here in full; they ATTACH in
# main.tf (Phase 1) beside the bucket and secret they belong to. Left commented
# because the bucket/secret resources do not exist in this file.
# =============================================================================
#
# FLAW 4 — prompt-store bucket policy grants the agent role s3:PutObject.
#   What: the agent's execution role can WRITE to the prompt store that feeds
#     its own system prompt / RAG context.
#   Why a real team ships this: the same role that reads the prompts was reused
#     for a one-off "let the agent cache results back to the bucket" feature.
#     Read and write collapsed onto one identity.
#   Enables: Path 2 (persisted prompt injection) — the attacker writes a
#     malicious instruction that the NEXT invocation loads and obeys.
#   Remediate: remove PutObject for the agent role; writes (if any) go through a
#     separate, tightly-scoped identity, and the prompt store is read-only to the agent.
#
#   data "aws_iam_policy_document" "prompt_store_bucket" {
#     statement {
#       sid       = "Flaw4AgentCanWritePromptStore"
#       effect    = "Allow"
#       actions   = ["s3:PutObject"]
#       resources = ["${local.prompt_store_arn}/*"]
#       principals {
#         type        = "AWS"
#         identifiers = [aws_iam_role.agent_exec.arn]
#       }
#     }
#   }
#   resource "aws_s3_bucket_policy" "prompt_store" {
#     bucket = aws_s3_bucket.prompt_store.id           # defined in main.tf
#     policy = data.aws_iam_policy_document.prompt_store_bucket.json
#   }
#
# ---------------------------------------------------------------------------
#
# FLAW 5 — db-creds secret resource policy grants the agent role GetSecretValue.
#   What: the Secrets Manager resource policy on /app/db-creds explicitly lets
#     the agent role read the secret value.
#   Why a real team ships this: the DB credential was wired to the agent "for
#     now" during a data-access spike and never moved behind a scoped proxy.
#   Enables: Path 3 (credential theft) — the injected instruction from Path 2
#     makes the agent read the secret and leak it in its output.
#   Remediate: remove the agent principal from the secret's resource policy;
#     the agent reaches the DB through a broker that never exposes the raw cred.
#
#   data "aws_iam_policy_document" "db_secret_resource" {
#     statement {
#       sid       = "Flaw5AgentCanReadDbCred"
#       effect    = "Allow"
#       actions   = ["secretsmanager:GetSecretValue"]
#       resources = ["*"]
#       principals {
#         type        = "AWS"
#         identifiers = [aws_iam_role.agent_exec.arn]
#       }
#     }
#   }
#   resource "aws_secretsmanager_secret_policy" "db_creds" {
#     secret_arn = aws_secretsmanager_secret.db_creds.arn   # defined in main.tf
#     policy     = data.aws_iam_policy_document.db_secret_resource.json
#   }
# =============================================================================
