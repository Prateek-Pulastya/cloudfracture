# Detection-as-code

Portable **Sigma** rules for every CloudFracture attack path, each with fire /
no-fire **test fixtures** that are executed in CI. A rule ships only when it is
proven to catch its attack and stay quiet on benign activity — not merely that its
YAML parses.

## Layout
```
detections/
├── sigma/                     # the rules (one per attack path)
│   ├── 01_iam_passrole_to_new_lambda.yml   # Path 1  (T1548 / T1078.004)
│   ├── 02_s3_promptstore_write.yml         # Path 2  (T1565 / OWASP LLM01)
│   ├── 03_secrets_getvalue_agent.yml       # Path 3  (T1552 / OWASP LLM06)
│   └── 04_s3_sensitive_data_read.yml       # Path 4  (T1530 / TA0010)
├── fixtures/                  # <rule>.fire.json (must match) + .nofire.json (must not)
│   ├── raw/                   # raw CloudTrail logs captured live from the attacks
│   └── PROVENANCE.md          # which fixtures are real vs constructed
├── run_detections.py         # the fixture runner (executes rules, asserts results)
└── requirements.txt
```

## Run it
```bash
pip install -r detections/requirements.txt
python detections/run_detections.py
```
Output is a per-rule table: pySigma validity, whether the rule fired on its
attack fixture, whether it stayed silent on the benign fixture, PASS/FAIL. Exit
code is non-zero on any failure — it runs in CI (`.github/workflows/ci.yml`).

## What the runner does (beyond linting)
`sigma-cli` only validates schema. `run_detections.py` additionally **evaluates**
each rule's detection logic against a real CloudTrail event and asserts:
`fixture.fire.json` matches and `fixture.nofire.json` does not. It supports the
Sigma subset the rules use (equals / `|contains` / `|startswith` / `|endswith`,
list-OR, multi-field-AND, and `and`/`or`/`not` + `all of`/`1 of` conditions), and
parse-validates each rule with pySigma when installed.

## Fixture provenance (honesty matters here)
- **Real, captured live:** Path 1 (`CreateFunction`) and Path 3 (`GetSecretValue`)
  — management events pulled from the trail during the attacks.
- **Constructed, schema-faithful:** Path 2 (`PutObject`) and Path 4 (`GetObject`)
  are S3 **object-level data events**. A real design lesson from this project: a
  management-events-only trail does not record them, so the trail was updated with
  scoped S3 data-event selectors — but first-time data-event delivery is very slow
  and did not land before teardown. These fixtures follow the documented S3 data-
  event schema and reuse the **real** agent `userIdentity` block from the captured
  `CreateFunction` event. See `fixtures/PROVENANCE.md`; swap for live captures later.

## False positives
Each rule carries a `falsepositives` block. In this lab most "false positives" are
really the intentional over-permission the rule is meant to surface; post-Phase-4
remediation these events should not occur at all, making any hit high-signal.
