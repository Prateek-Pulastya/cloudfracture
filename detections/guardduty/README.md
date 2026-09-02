# GuardDuty — managed detection (status: blocked on this account)

## Intent
The build plan calls for one **GuardDuty** finding as a managed-detection signal
alongside the Sigma rules, mapped to the attack paths:

| GuardDuty finding type | Maps to |
|---|---|
| `PrivilegeEscalation:IAMUser/AdministrativePermissions` | Path 1 — privesc |
| `CredentialAccess:IAMUser/AnomalousBehavior` | Path 3 — credential theft |
| `Exfiltration:S3/AnomalousBehavior` | Path 4 — data exfiltration |
| `Discovery:S3/AnomalousBehavior` | Path 2/4 — bucket recon |

Reproducible capture script: [`capture_guardduty.py`](capture_guardduty.py) — enables
a detector (if none), generates these finding types, captures them to
`findings.json`, and deletes the detector it created.

## Honest status — could not capture on the lab account
Running the capture returned, in **both** `eu-central-1` and `us-east-1`:
```
SubscriptionRequiredException: The AWS Access Key Id needs a subscription for the service
```
This is an **account-level** state, not a code or region issue — the lab account
(a pre-existing account near the end of its free window) cannot subscribe to
GuardDuty. It is not something the project can resolve from code.

Two honest notes on the approach, independent of the block:
- Organic GuardDuty findings for these IAM/S3 types are **anomaly-based** and need
  GuardDuty's multi-day behavioural baseline — they would not fire within an
  ephemeral, destroy-after-session lab regardless.
- `create-sample-findings` (what the script uses) produces the real finding
  **types** with sample data (`[SAMPLE]` in the title) — the reliable way to show
  the detection mapping for this attack class, and explicitly the plan's fallback.

## Why this does not weaken the detection layer
The substantive detection-as-code is complete and CI-green: four Sigma rules, each
executed against real/faithful CloudTrail fixtures (`../sigma/`, `../run_detections.py`).
Every attack path already has a tested detection. GuardDuty here would be a
supplementary managed signal, not the primary coverage.

## To complete later
On a GuardDuty-subscribable account: `python detections/guardduty/capture_guardduty.py`
(or enable GuardDuty in the console and re-run). The script and mapping are ready.
