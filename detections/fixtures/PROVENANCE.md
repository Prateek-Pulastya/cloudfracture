# Fixture provenance

| Fixture | Source |
|---|---|
| 01_iam_passrole_to_new_lambda.fire | **REAL** captured CloudTrail event (Path 1) |
| 03_secrets_getvalue_agent.fire | **REAL** captured CloudTrail event (Path 3) |
| 02_s3_promptstore_write.* | **Constructed** S3 data event (real agent userIdentity; live delivery pending) |
| 04_s3_sensitive_data_read.* | **Constructed** S3 data event (real agent userIdentity; live delivery pending) |
| *.nofire | Derived benign variants (non-privileged role / different principal / different bucket) |

Constructed data-event fixtures follow the documented S3 data-event schema and reuse the real agent assumed-role identity block from the captured CreateFunction event. Swap for live captures once S3 data events deliver.
