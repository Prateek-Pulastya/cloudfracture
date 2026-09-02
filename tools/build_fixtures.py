"""
build_fixtures.py — assemble the Sigma test fixtures from captured CloudTrail data.

Each detection rule gets a `.fire.json` (an event that MUST trigger it) and a
`.nofire.json` (a similar-but-benign event that MUST NOT).

Provenance is explicit:
  * Path 1 (CreateFunction) and Path 3 (GetSecretValue) fixtures are REAL events
    extracted from detections/fixtures/raw/ (captured live from the attacks).
  * Path 2 (PutObject) and Path 4 (GetObject) are S3 OBJECT-level DATA events. Their
    first-time CloudTrail delivery did not land before teardown, so these are
    CONSTRUCTED from the documented S3 data-event schema, reusing the REAL agent
    assumed-role userIdentity block from the captured CreateFunction event. They are
    marked in fixtures/PROVENANCE.md and can be swapped for live captures later.

Run:  python tools/build_fixtures.py
"""

from __future__ import annotations

import copy
import glob
import gzip
import json
from pathlib import Path

RAW = "detections/fixtures/raw"
OUT = Path("detections/fixtures")
ACCOUNT = "000000000000"
PROMPT_BUCKET = f"cloudfracture-prompt-store-{ACCOUNT}"
SENSITIVE_BUCKET = f"cloudfracture-sensitive-data-{ACCOUNT}"


def load_records():
    recs = []
    for f in glob.glob(f"{RAW}/**/*.json.gz", recursive=True):
        recs += json.load(gzip.open(f)).get("Records", [])
    return recs


def find(recs, name):
    return next((r for r in recs if r.get("eventName") == name), None)


def write(name, event):
    (OUT / name).write_text(json.dumps(event, indent=2, default=str), encoding="utf-8")
    print("wrote", OUT / name)


def s3_data_event(template_ui, event_name, bucket, key):
    """A faithful S3 object-level data event using a real agent userIdentity block."""
    return {
        "eventVersion": "1.09",
        "userIdentity": copy.deepcopy(template_ui),
        "eventSource": "s3.amazonaws.com",
        "eventName": event_name,
        "awsRegion": "eu-central-1",
        "eventType": "AwsApiCall",
        "eventCategory": "Data",
        "readOnly": event_name == "GetObject",
        "requestParameters": {"bucketName": bucket, "key": key, "Host": f"{bucket}.s3.eu-central-1.amazonaws.com"},
        "resources": [
            {"type": "AWS::S3::Object", "ARN": f"arn:aws:s3:::{bucket}/{key}"},
            {"type": "AWS::S3::Bucket", "ARN": f"arn:aws:s3:::{bucket}"},
        ],
    }


def main():
    recs = load_records()
    cf = find(recs, "CreateFunction20150331")
    gsv = find(recs, "GetSecretValue")
    assert cf and gsv, "expected real CreateFunction + GetSecretValue in raw logs"
    agent_ui = cf["userIdentity"]  # real agent assumed-role identity block

    # -- Rule 01: Path 1 — PassRole to new Lambda --------------------------------
    write("01_iam_passrole_to_new_lambda.fire.json", cf)  # REAL
    nofire = copy.deepcopy(cf)  # benign: same call, but a non-privileged role
    nofire["requestParameters"]["role"] = f"arn:aws:iam::{ACCOUNT}:role/cloudfracture-worker-role"
    write("01_iam_passrole_to_new_lambda.nofire.json", nofire)

    # -- Rule 02: Path 2 — write to prompt store (CONSTRUCTED S3 data event) ------
    write("02_s3_promptstore_write.fire.json",
          s3_data_event(agent_ui, "PutObject", PROMPT_BUCKET, "system_prompt.txt"))
    write("02_s3_promptstore_write.nofire.json",  # benign: agent READS the prompt (allowed)
          s3_data_event(agent_ui, "GetObject", PROMPT_BUCKET, "system_prompt.txt"))

    # -- Rule 03: Path 3 — GetSecretValue on db-creds ----------------------------
    write("03_secrets_getvalue_agent.fire.json", gsv)  # REAL
    nofire3 = copy.deepcopy(gsv)  # benign: a different, non-agent principal reads it
    nofire3["userIdentity"]["sessionContext"]["sessionIssuer"]["userName"] = "cloudfracture-ci-deployer"
    nofire3["userIdentity"]["arn"] = f"arn:aws:sts::{ACCOUNT}:assumed-role/cloudfracture-ci-deployer/deploy"
    write("03_secrets_getvalue_agent.nofire.json", nofire3)

    # -- Rule 04: Path 4 — read sensitive-data bucket (CONSTRUCTED S3 data event) -
    write("04_s3_sensitive_data_read.fire.json",
          s3_data_event(agent_ui, "GetObject", SENSITIVE_BUCKET, "customers.csv"))
    write("04_s3_sensitive_data_read.nofire.json",  # benign: reading a non-sensitive bucket
          s3_data_event(agent_ui, "GetObject", f"cloudfracture-public-assets-{ACCOUNT}", "logo.png"))

    # -- provenance note ---------------------------------------------------------
    (OUT / "PROVENANCE.md").write_text(
        "# Fixture provenance\n\n"
        "| Fixture | Source |\n|---|---|\n"
        "| 01_iam_passrole_to_new_lambda.fire | **REAL** captured CloudTrail event (Path 1) |\n"
        "| 03_secrets_getvalue_agent.fire | **REAL** captured CloudTrail event (Path 3) |\n"
        "| 02_s3_promptstore_write.* | **Constructed** S3 data event (real agent userIdentity; live delivery pending) |\n"
        "| 04_s3_sensitive_data_read.* | **Constructed** S3 data event (real agent userIdentity; live delivery pending) |\n"
        "| *.nofire | Derived benign variants (non-privileged role / different principal / different bucket) |\n\n"
        "Constructed data-event fixtures follow the documented S3 data-event schema and "
        "reuse the real agent assumed-role identity block from the captured CreateFunction "
        "event. Swap for live captures once S3 data events deliver.\n",
        encoding="utf-8")
    print("wrote", OUT / "PROVENANCE.md")


if __name__ == "__main__":
    main()
