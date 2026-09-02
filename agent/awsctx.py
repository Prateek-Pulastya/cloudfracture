"""
awsctx.py — shared AWS context for the CloudFracture agent runtime.

Hybrid execution model: the agent runs LOCALLY but acts AS `agent-exec-role`.
This module resolves the stack's identifiers and returns a boto3 Session whose
credentials are the assumed agent role, so every AWS call the agent makes is
attributed to agent-exec-role in CloudTrail (exactly like a compromised agent).

Config resolution priority per key:  explicit arg  >  CF_* env var  >  terraform output.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import boto3

TERRAFORM_DIR = Path(__file__).resolve().parent.parent / "terraform"


def _terraform_outputs() -> dict:
    """Best-effort read of `terraform output -json`. Empty dict if unavailable."""
    try:
        proc = subprocess.run(
            ["terraform", f"-chdir={TERRAFORM_DIR}", "output", "-json"],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode != 0:
            return {}
        return {k: v.get("value") for k, v in json.loads(proc.stdout).items()}
    except Exception:
        return {}


def resolve_config(role_arn=None, prompt_bucket=None, secret_id=None, prompt_key=None) -> dict:
    tf = _terraform_outputs()
    cfg = {
        "role_arn":         role_arn      or os.environ.get("CF_AGENT_ROLE_ARN") or tf.get("agent_exec_role_arn"),
        "prompt_bucket":    prompt_bucket or os.environ.get("CF_PROMPT_BUCKET")  or tf.get("prompt_store_bucket"),
        "secret_id":        secret_id     or os.environ.get("CF_SECRET_ID")      or tf.get("db_secret_name") or tf.get("db_secret_arn"),
        "sensitive_bucket": os.environ.get("CF_SENSITIVE_BUCKET")               or tf.get("sensitive_data_bucket"),
        "prompt_key":       prompt_key    or os.environ.get("CF_PROMPT_KEY")     or "system_prompt.txt",
    }
    missing = [k for k in ("role_arn", "prompt_bucket", "secret_id") if not cfg[k]]
    if missing:
        raise SystemExit(
            f"Missing config {missing}. Apply the stack first (terraform apply) so its "
            f"outputs exist, or pass CF_AGENT_ROLE_ARN / CF_PROMPT_BUCKET / CF_SECRET_ID."
        )
    return cfg


def assume_agent_session(role_arn: str, session_name: str = "cloudfracture-agent") -> boto3.Session:
    """Assume agent-exec-role and return a boto3 Session bound to its temp creds."""
    creds = boto3.client("sts").assume_role(
        RoleArn=role_arn, RoleSessionName=session_name
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
