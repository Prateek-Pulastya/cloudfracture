"""
capture_guardduty.py — enable GuardDuty, generate the finding types that map to
CloudFracture's attack paths, and capture them as evidence.

Honesty note (see README.md): these are GuardDuty SAMPLE findings — real GuardDuty
finding *types* and detection logic, with sample data (titles carry "[SAMPLE]").
Organic versions of these types are anomaly-based and require GuardDuty's multi-day
behavioural baseline, which exceeds this ephemeral lab's window; the network-focused
guardduty-tester does not generate IAM/S3 identity findings. Sample findings are the
reliable, honest way to show the detection mapping for this class of attack.

Creates a detector only if none exists, and deletes it again on the way out (so the
account is left clean). Findings are captured to findings.json before deletion.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import boto3

OUT = Path(__file__).resolve().parent

# GuardDuty finding types mapped to our attack paths.
TYPES = {
    "PrivilegeEscalation:IAMUser/AdministrativePermissions": "Path 1 — privilege escalation",
    "CredentialAccess:IAMUser/AnomalousBehavior": "Path 3 — credential theft",
    "Exfiltration:S3/AnomalousBehavior": "Path 4 — data exfiltration",
    "Discovery:S3/AnomalousBehavior": "Path 2/4 — reconnaissance of the buckets",
}


def main() -> int:
    gd = boto3.client("guardduty")
    existing = gd.list_detectors().get("DetectorIds", [])
    created = not existing
    det = existing[0] if existing else gd.create_detector(Enable=True)["DetectorId"]
    print(f"[*] detector: {det} ({'created' if created else 'pre-existing'})")

    print(f"[*] generating {len(TYPES)} sample finding types mapped to the attack paths")
    gd.create_sample_findings(DetectorId=det, FindingTypes=list(TYPES))
    time.sleep(8)  # let the findings register

    ids = gd.list_findings(DetectorId=det).get("FindingIds", [])
    findings = gd.get_findings(DetectorId=det, FindingIds=ids)["Findings"] if ids else []

    slim = []
    for f in findings:
        t = f["Type"]
        slim.append({
            "type": t,
            "severity": f["Severity"],
            "title": f["Title"],
            "resource_type": f.get("Resource", {}).get("ResourceType"),
            "count": f.get("Service", {}).get("Count"),
            "maps_to": TYPES.get(t, "-"),
        })
    slim.sort(key=lambda s: s["severity"], reverse=True)

    (OUT / "findings.json").write_text(json.dumps(slim, indent=2), encoding="utf-8")
    print(f"[+] captured {len(slim)} findings:")
    print(f"    {'sev':<5}{'type':<52}{'maps to'}")
    for s in slim:
        print(f"    {s['severity']:<5}{s['type']:<52}{s['maps_to']}")
    print(f"[*] evidence -> {OUT / 'findings.json'}")

    if created:
        gd.delete_detector(DetectorId=det)
        print("[*] cleanup: deleted the detector we created")
    else:
        print("[*] left the pre-existing detector in place (sample findings will age out)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
