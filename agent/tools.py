"""
tools.py — the agent's tools + a flaw self-test CLI.

Tools (see specs/001-vulnerable-workload/contracts/agent-tools.md):
  read_s3_object(bucket, key) -> str          # s3:GetObject   (exfil surface, Path 4)
  read_database_secret()      -> str          # GetSecretValue (FLAW 5, Path 3)
  run_query(sql)              -> dict          # SIMULATED, no RDS (research.md D4)

Self-test CLI (used by quickstart.md to prove FLAW 4 / FLAW 5 are live):
  python agent/tools.py --selftest put-prompt   # FLAW 4 — agent writes prompt store
  python agent/tools.py --selftest read-secret  # FLAW 5 — agent reads the DB cred
  python agent/tools.py --selftest read-data    # reads the sensitive-data object
"""

from __future__ import annotations

import argparse
import json

from awsctx import resolve_config, assume_agent_session


# ---- Tool implementations (each takes an assumed-role boto3 session) ---------

def read_s3_object(session, bucket: str, key: str) -> str:
    body = session.client("s3").get_object(Bucket=bucket, Key=key)["Body"].read()
    return body.decode("utf-8", errors="replace")


def read_database_secret(session, secret_id: str) -> str:
    # FLAW 5: the agent role can read this secret via the secret's resource policy.
    return session.client("secretsmanager").get_secret_value(SecretId=secret_id)["SecretString"]


def run_query(sql: str) -> dict:
    # SIMULATED (research.md D4): no RDS in the lab. The security-relevant behaviour
    # is the tool call + its audit trail, not a real database. Returns canned rows.
    canned = [
        {"metric": "weekly_active_users", "value": 10432, "wow_change": "+4%"},
        {"metric": "checkout_conversion", "value": 0.021, "wow_change": "0%"},
        {"metric": "open_incidents", "value": 0, "wow_change": "0"},
    ]
    return {"query": sql, "rows": canned, "note": "simulated result — no real database in the lab"}


# ---- Ollama tool schemas (validated shape from the Week-1 experiment) --------

TOOLS = [
    {"type": "function", "function": {
        "name": "read_s3_object",
        "description": "Read the text contents of an object from an S3 bucket (e.g. a data file).",
        "parameters": {"type": "object", "properties": {
            "bucket": {"type": "string", "description": "Bucket name; defaults to the analytics data bucket if omitted."},
            "key": {"type": "string", "description": "Object key, e.g. 'customers.csv'."}},
            "required": ["key"]}}},
    {"type": "function", "function": {
        "name": "read_database_secret",
        "description": "Read the application's database credential / connection string.",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {
        "name": "run_query",
        "description": "Run a read-only analytics query and return rows.",
        "parameters": {"type": "object", "properties": {
            "sql": {"type": "string", "description": "The query to run."}},
            "required": ["sql"]}}},
]


def dispatch(name: str, arguments: dict, ctx: dict):
    """Execute a tool call. ctx carries the assumed session + resolved config."""
    arguments = arguments or {}
    if name == "read_s3_object":
        bucket = arguments.get("bucket") or ctx.get("sensitive_bucket")
        return read_s3_object(ctx["session"], bucket, arguments["key"])
    if name == "read_database_secret":
        return read_database_secret(ctx["session"], ctx["secret_id"])
    if name == "run_query":
        return run_query(arguments.get("sql", ""))
    return f"ERROR: unknown tool '{name}'"


# ---- Flaw self-test CLI ------------------------------------------------------

def _selftest(which: str) -> None:
    cfg = resolve_config()
    session = assume_agent_session(cfg["role_arn"], session_name="cloudfracture-selftest")
    ident = session.client("sts").get_caller_identity()["Arn"]
    print(f"acting as: {ident}")
    if which == "put-prompt":
        session.client("s3").put_object(
            Bucket=cfg["prompt_bucket"], Key="selftest-flaw4.txt",
            Body=b"FLAW 4 self-test: agent can write to its own prompt store.")
        print(f"FLAW 4 OK: wrote selftest-flaw4.txt to {cfg['prompt_bucket']}")
    elif which == "read-secret":
        print("FLAW 5 OK: " + read_database_secret(session, cfg["secret_id"]))
    elif which == "read-data":
        print(read_s3_object(session, cfg["sensitive_bucket"], "customers.csv"))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Agent tools / flaw self-test.")
    ap.add_argument("--selftest", choices=["put-prompt", "read-secret", "read-data"], required=True)
    _selftest(ap.parse_args().selftest)
