"""
verify_remediation.py — prove the least-privilege remediation CLOSES every path.

Run against a stack applied with `-var secure_mode=true`. Acting as the agent role
(the same entry point the attacks used), it re-attempts each path's pivotal action
and asserts each is now DENIED:

  Path 1  create a Lambda passing privileged-role   -> AccessDenied (no CreateFunction/PassRole)
  Path 2  PutObject to the prompt store              -> AccessDenied (no s3:PutObject)
  Path 3  GetSecretValue on the DB credential        -> AccessDenied (no secretsmanager access)
  Path 4  GetObject on the sensitive-data bucket      -> AccessDenied (no s3:* wildcard)

It also confirms the BENIGN path still works (the agent can still READ its prompt),
so remediation didn't break the workload.

Exit code is non-zero if any attack is NOT blocked. Evidence -> remediation/evidence/.
"""

from __future__ import annotations

import io
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from awsctx import _terraform_outputs, assume_agent_session  # noqa: E402

EVIDENCE = Path(__file__).resolve().parent / "evidence"
DENY_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}


def _zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("lambda_function.py", "def lambda_handler(e,c):\n    return {}\n")
    return buf.getvalue()


def denied(fn) -> tuple[bool, str]:
    """Return (was_denied, detail). was_denied=True means the attack is blocked."""
    try:
        fn()
        return False, "SUCCEEDED (not blocked!)"
    except ClientError as e:
        code = e.response["Error"]["Code"]
        return (code in DENY_CODES), code
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


def main() -> int:
    tf = _terraform_outputs()
    agent_arn = tf.get("agent_exec_role_arn")
    priv_arn = tf.get("privileged_role_arn")
    prompt_bucket = tf.get("prompt_store_bucket")
    sensitive_bucket = tf.get("sensitive_data_bucket")
    secret_id = tf.get("db_secret_name") or tf.get("db_secret_arn")

    s = assume_agent_session(agent_arn, session_name="cf-verify")
    who = s.client("sts").get_caller_identity()["Arn"]
    print(f"[*] operating as: {who}\n")

    s3, sm, lam = s.client("s3"), s.client("secretsmanager"), s.client("lambda")

    checks = [
        ("Path 1 — PassRole+CreateFunction",
         lambda: lam.create_function(FunctionName="cf-remediation-probe", Runtime="python3.12",
                                     Role=priv_arn, Handler="lambda_function.lambda_handler",
                                     Code={"ZipFile": _zip()}, Timeout=15)),
        ("Path 2 — write to prompt store",
         lambda: s3.put_object(Bucket=prompt_bucket, Key="remediation-probe.txt", Body=b"x")),
        ("Path 3 — read DB secret",
         lambda: sm.get_secret_value(SecretId=secret_id)),
        ("Path 4 — read sensitive bucket",
         lambda: s3.get_object(Bucket=sensitive_bucket, Key="customers.csv")),
    ]

    ev = {"timestamp": datetime.now(timezone.utc).isoformat(), "operating_as": who, "results": {}}
    all_blocked = True
    print(f"{'attack':<38}{'blocked?':<10}detail")
    print("-" * 70)
    for name, fn in checks:
        was_denied, detail = denied(fn)
        all_blocked &= was_denied
        ev["results"][name] = {"blocked": was_denied, "detail": detail}
        print(f"{name:<38}{('YES' if was_denied else 'NO'):<10}{detail}")

    # benign path must still work
    try:
        s3.get_object(Bucket=prompt_bucket, Key="system_prompt.txt")
        benign = "OK (agent can still read its prompt)"
        benign_ok = True
    except Exception as e:  # noqa: BLE001
        benign = f"BROKEN: {type(e).__name__}"
        benign_ok = False
    ev["benign_read_prompt"] = benign
    print("-" * 70)
    print(f"{'benign — read own prompt':<38}{'':<10}{benign}")

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "verify.json").write_text(json.dumps(ev, indent=2), encoding="utf-8")
    ok = all_blocked and benign_ok
    print(f"\n[{'+' if ok else '!'}] remediation verified: "
          f"{'ALL 4 attacks blocked, workload intact' if ok else 'FAILURES above'}")
    print(f"[*] evidence -> {EVIDENCE / 'verify.json'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
