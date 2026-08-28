# AI IRP: Unauthorized Data Access (S3)

Unauthorized access to Amazon S3 buckets — via misconfigured bucket policies, overly permissive ACLs, compromised credentials, or SSRF-based credential theft. Often the exfiltration phase of a broader compromise. Focus: identify what was accessed, stop the bleeding, preserve evidence, then harden.

## Critical Rule

```
╔══════════════════════════════════════════════════════════════╗
║  IDENTIFY THE ACCESS VECTOR BEFORE CONTAINMENT.             ║
║  Is it public exposure (misconfigured bucket) or            ║
║  credential-based access? The containment path differs.     ║
║  Block Public Access ≠ credential revocation.               ║
╚══════════════════════════════════════════════════════════════╝
```

## Priority Assessment

| Signal | Priority |
|--------|----------|
| Bulk GetObject (50+ calls/min) from unknown IP on sensitive bucket | P1 |
| S3 bucket publicly exposed with confirmed data download | P1 |
| Macie alert: sensitive data discovered + unusual access pattern | P2 |
| GuardDuty Exfiltration:S3/AnomalousBehavior | P2 |
| Bucket policy change making data externally accessible | P2 |
| Config rule violation (public bucket) with no confirmed access | P3 |
| Stale bucket policy identified during review | P4 |

## Step 1: Identify Access Vector

Determine HOW the data was accessed — this drives the containment path.

```bash
# Check bucket public access settings
aws s3api get-public-access-block --bucket BUCKET_NAME

# Get bucket policy
aws s3api get-bucket-policy --bucket BUCKET_NAME --output text

# Get bucket ACL
aws s3api get-bucket-acl --bucket BUCKET_NAME

# Check IAM Access Analyzer for external access findings
aws accessanalyzer list-findings --analyzer-name ANALYZER_NAME \
  --filter '{"resourceType":{"eq":["AWS::S3::Bucket"]}}'
```

**Decision: What is the access vector?**

| Vector | Next Action |
|--------|-------------|
| Public bucket (no auth required) | Step 2A — Block Public Access |
| Compromised credential accessing bucket | Step 2B — Revoke credentials (route to `ai-irp-credential-compromise.md` for credential steps, return here for S3 hardening) |
| Cross-account access via permissive bucket policy | Step 2C — Restrict bucket policy |
| SSRF via EC2 instance role | Revoke role sessions + enforce IMDSv2 (route to `ai-irp-sts-token-abuse.md`) |

## Step 2A: Contain — Block Public Access

> ⚠️ **Requires user confirmation before executing.**

This immediately blocks ALL public access to the bucket. Legitimate public access (if any) will break.

```bash
aws s3api put-public-access-block --bucket BUCKET_NAME \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

**Present to user:**
> "I recommend enabling Block All Public Access on BUCKET_NAME. This will immediately prevent any unauthenticated access. If this bucket intentionally serves public content, that access will break. Shall I proceed?"

## Step 2B: Contain — Restrict Bucket Policy (Cross-Account)

> ⚠️ **Requires user confirmation before executing.**

```bash
# First, save current policy for evidence
aws s3api get-bucket-policy --bucket BUCKET_NAME --output text > /tmp/bucket-policy-backup.json

# Apply deny policy for all principals outside your account
aws s3api put-bucket-policy --bucket BUCKET_NAME --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::BUCKET_NAME", "arn:aws:s3:::BUCKET_NAME/*"],
    "Condition": {
      "StringNotEquals": {"aws:PrincipalAccount": "YOUR_ACCOUNT_ID"}
    }
  }]
}'
```

**Present to user:**
> "I recommend restricting BUCKET_NAME to only allow access from your AWS account. This blocks all cross-account access. Any external integrations using this bucket will break. Shall I proceed?"

## Step 3: Scope the Impact — What Was Accessed?

Read-only investigation — execute freely.

```bash
# Check if CloudTrail S3 data events are enabled
aws cloudtrail get-event-selectors --trail-name TRAIL_NAME

# Check S3 server access logs
aws s3api get-bucket-logging --bucket BUCKET_NAME
```

**Key Athena query — identify bulk data access:**

```sql
SELECT DATE(from_iso8601_timestamp(eventTime)) AS access_date,
       sourceIPAddress, userIdentity.arn AS accessor,
       COUNT(*) AS get_object_count,
       APPROX_DISTINCT(requestParameters.key) AS unique_objects
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName = 'GetObject'
  AND requestParameters.bucketName = 'BUCKET_NAME'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
  AND errorCode IS NULL
GROUP BY DATE(from_iso8601_timestamp(eventTime)), sourceIPAddress, userIdentity.arn
ORDER BY get_object_count DESC;
```

**Key Athena query — bucket configuration changes:**

```sql
SELECT eventTime, eventName, userIdentity.arn AS actor,
       sourceIPAddress, requestParameters
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('PutBucketPolicy', 'PutBucketAcl',
                    'PutPublicAccessBlock', 'DeletePublicAccessBlock',
                    'PutObjectAcl')
  AND requestParameters.bucketName = 'BUCKET_NAME'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
```

**Decision: What's the data classification?**

| Classification | Escalation |
|----------------|------------|
| PII / regulated data confirmed accessed | → Also invoke notification workflow from `IRP-PersonalDataBreach.md` |
| Trade secrets / confidential business data | → Notify Legal immediately |
| Internal only / low sensitivity | Continue standard IR process |

## Step 4: Eradicate — Harden Configuration

> ⚠️ **Requires user confirmation before executing.**

```bash
# Enable server-side encryption (SSE-KMS)
aws s3api put-bucket-encryption --bucket BUCKET_NAME \
  --server-side-encryption-configuration '{
    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
  }'

# Enable versioning (protects against future deletion/modification)
aws s3api put-bucket-versioning --bucket BUCKET_NAME \
  --versioning-configuration Status=Enabled

# Enforce IMDSv2 on instances accessing this bucket (if SSRF vector)
aws ec2 modify-instance-metadata-options \
  --instance-id INSTANCE_ID \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

**Remove attacker persistence:**
- [ ] Unauthorized bucket policies or ACL entries removed
- [ ] Cross-account access grants revoked (check bucket policy, ACLs, and Access Points)
- [ ] Any S3 Access Points created by attacker deleted
- [ ] Resource-based policies on related KMS keys reviewed

## Step 5: Recover — Restore Modified Data

> ⚠️ **Requires user confirmation before executing.**

```bash
# If objects were deleted (delete markers placed), restore by removing the marker
aws s3api delete-object --bucket BUCKET_NAME --key OBJECT_KEY \
  --version-id DELETE_MARKER_VERSION_ID

# If objects were overwritten, restore previous version
aws s3api copy-object \
  --bucket BUCKET_NAME \
  --key OBJECT_KEY \
  --copy-source "BUCKET_NAME/OBJECT_KEY?versionId=PREVIOUS_VERSION_ID"
```

Other recovery sources:
- S3 Cross-Region Replication target bucket
- AWS Backup recovery points
- Application-level backups

## Step 6: Hardening Recommendations

Present to user:

- [ ] Block Public Access enabled at the **account level** (not just bucket level)
- [ ] S3 data events enabled in CloudTrail for all sensitive buckets
- [ ] Amazon Macie enabled for automated sensitive data discovery
- [ ] S3 server access logging enabled on sensitive buckets
- [ ] VPC endpoint policies restricting S3 access to authorized buckets only
- [ ] IAM Access Analyzer monitoring for external access findings
- [ ] Bucket policies implement least privilege (specific principals, specific actions)
- [ ] Object Lock or MFA Delete for critical/immutable data

## Escalation Triggers

- Bulk exfiltration confirmed (thousands of objects) → P1, engage AWS CIRT
- Regulated data (PII, PHI, PCI) accessed → Legal + compliance immediately
- Attacker modified data (integrity breach) → Check backups, consider broader compromise
- Access vector is SSRF/instance compromise → Route to `ai-irp-sts-token-abuse.md` or `ai-irp-ec2-compromise.md`

## Reference

Full human playbook: `IRP-DataAccess.md`
