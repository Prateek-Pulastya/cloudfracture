# Path 4 — Data Exfiltration from Cloud Storage

**Result: PROVEN.** As `agent-exec-role`, enumerated and downloaded the entire
sensitive-data bucket, staging it locally.

## Framework mapping
- **MITRE ATT&CK** T1530 (Data from Cloud Storage Object), **TA0010** (Exfiltration)

## Precondition (intentional flaw)
| Flaw | Grant |
|---|---|
| FLAW 2 | `agent-exec-role` policy uses `s3:*` on `Resource: "*"` (wildcard) |

The same data is *also* reachable via Path 1's escalated `privileged-role`; the
agent role's own over-permission makes it a one-step exfil.

## Technique
As `agent-exec-role`: `ListObjectsV2` on the sensitive-data bucket, then
`GetObject` each key, writing the bytes to a local staging directory —
`T1530` data-from-cloud-storage.

PoC: [`scripts/path4_data_exfil.py`](scripts/path4_data_exfil.py).
Evidence: [`evidence/path4/evidence.json`](evidence/path4/evidence.json) +
the staged copy under `evidence/path4/exfiltrated/`.

## Evidence
```
[*] target bucket: cloudfracture-sensitive-data-000000000000
[*] enumerated 1 object(s): ['customers.csv']
    [+] exfiltrated customers.csv (224 bytes)
[+] sample of stolen data:
    id,name,email,plan,mrr
    1,Ada Lovelace,ada@example.invalid,enterprise,4200
    2,Alan Turing,alan@example.invalid,pro,890
```
(Data is synthetic — no real PII.)

## What to detect (Phase 3 preview)
- `GetObject` on the sensitive-data bucket by `agent-exec-role`, especially bulk
  reads. Requires **S3 data events** on the trail — added to `main.tf` after the
  first capture showed management-only logging misses object reads (a real design
  lesson, documented).

## Remediation (Phase 4 preview)
- Replace the `s3:*`/`Resource:"*"` wildcard (FLAW 2) with least-privilege:
  `s3:GetObject` scoped to only the prompt the agent legitimately needs — never the
  sensitive-data bucket.
