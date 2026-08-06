# AI IRP: Ransomware

Active ransomware in an AWS environment — data encryption, KMS key deletion, ransom demands, or locked-out services. Speed is everything. Every minute of delay means more data encrypted or destroyed.

## Critical Rule

```
╔══════════════════════════════════════════════════════════════╗
║  SPEED IS THE PRIORITY.                                     ║
║  Apply emergency SCP FIRST to stop the spread.              ║
║  Preserve snapshots SECOND.                                 ║
║  Investigate THIRD.                                         ║
║  Payment decisions → Legal counsel + cyber insurance.       ║
╚══════════════════════════════════════════════════════════════╝
```

## Priority Assessment

All ransomware is P1. Determine the variant to guide response.

| Signal | Variant | Key Concern |
|--------|---------|-------------|
| S3 objects encrypted/overwritten, ransom note in bucket | S3 ransomware | Data loss, versioning status |
| EBS volumes encrypted with threat actor KMS key | EBS ransomware | Instance availability |
| RDS snapshots shared to external account, originals deleted | RDS ransomware | Database recovery |
| KMS key scheduled for deletion | KMS abuse | 7-day window to cancel |
| EC2 instances encrypted by malware on disk | Traditional ransomware | Snapshot availability |

## Step 1: Emergency SCP — Stop the Spread

> ⚠️ **Requires user confirmation before executing.**
>
> This SCP blocks ALL activity in the account except from the IR break-glass role and management account. Production WILL be impacted. This is the correct action for confirmed ransomware — stopping encryption takes priority over availability.

Apply this from the management account.

```bash
# Apply emergency deny-all SCP to compromised account
aws organizations attach-policy \
  --policy-id p-RANSOMWARE_EMERGENCY \
  --target-id COMPROMISED_ACCOUNT_ID
```

**Emergency Ransomware SCP:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDestructiveActions",
      "Effect": "Deny",
      "Action": [
        "s3:DeleteObject*",
        "s3:PutObject",
        "ec2:DeleteSnapshot",
        "ec2:DeregisterImage",
        "rds:DeleteDBSnapshot",
        "rds:DeleteDBClusterSnapshot",
        "kms:ScheduleKeyDeletion",
        "kms:DisableKey",
        "backup:DeleteBackupVault",
        "backup:DeleteRecoveryPoint"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyAllExceptIR",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": [
            "arn:aws:iam::ACCOUNT:role/IRBreakGlass"
          ]
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::MGMT_ACCOUNT:*"
        }
      }
    }
  ]
}
```

## Step 2: Preserve Existing Snapshots

Protect what hasn't been destroyed yet.

```bash
# Lock existing EBS snapshots (prevent deletion)
for SNAP in $(aws ec2 describe-snapshots \
  --owner-ids ACCOUNT_ID \
  --query "Snapshots[].SnapshotId" --output text); do
  aws ec2 lock-snapshot \
    --snapshot-id $SNAP \
    --lock-mode compliance \
    --lock-duration 30
done

# Copy critical RDS snapshots to forensic account
aws rds copy-db-snapshot \
  --source-db-snapshot-identifier arn:aws:rds:REGION:ACCOUNT:snapshot:SNAP_NAME \
  --target-db-snapshot-identifier ir-preserved-SNAP_NAME \
  --kms-key-id arn:aws:kms:REGION:FORENSIC_ACCOUNT:key/KEY_ID \
  --source-region REGION

# Cancel any KMS key deletions (7-day window)
aws kms cancel-key-deletion --key-id KEY_ID --region REGION
aws kms enable-key --key-id KEY_ID --region REGION
```

## Step 3: Identify the Attack Vector

**Key Athena query — destructive actions timeline:**

```sql
SELECT eventTime, eventName, eventSource, userIdentity.arn,
       sourceIPAddress, requestParameters, awsRegion
FROM cloudtrail_logs
WHERE eventName IN (
  'DeleteObject', 'PutObject', 'DeleteBucket',
  'DeleteSnapshot', 'DeleteDBSnapshot',
  'ScheduleKeyDeletion', 'DisableKey',
  'DeleteBackupVault', 'DeleteRecoveryPoint',
  'ShareSnapshot', 'ModifySnapshotAttribute'
)
AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
```

**Key Athena query — identify the compromised credential:**

```sql
SELECT userIdentity.arn, userIdentity.accessKeyId,
       sourceIPAddress, COUNT(*) as action_count,
       MIN(eventTime) as first_action
FROM cloudtrail_logs
WHERE eventName IN ('DeleteObject', 'PutObject', 'ScheduleKeyDeletion')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
GROUP BY userIdentity.arn, userIdentity.accessKeyId, sourceIPAddress
ORDER BY action_count DESC;
```

## Step 4: Contain the Credential

> ⚠️ **Requires user confirmation before executing.**

```bash
# Disable the compromised access key
aws iam update-access-key \
  --access-key-id AKIAEXAMPLE \
  --status Inactive \
  --user-name COMPROMISED_USER

# Revoke all active sessions
aws iam put-user-policy \
  --user-name COMPROMISED_USER \
  --policy-name RevokeAllSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {"aws:TokenIssueTime": "CURRENT_UTC_TIMESTAMP"}
      }
    }]
  }'
```

## Step 5: Assess Data Recovery Options

### S3 Ransomware Recovery

```bash
# Check if versioning is enabled (can recover previous versions)
aws s3api get-bucket-versioning --bucket AFFECTED_BUCKET

# If versioning enabled: list previous versions
aws s3api list-object-versions --bucket AFFECTED_BUCKET --prefix PREFIX \
  --query "Versions[?IsLatest==\`false\`].[Key,VersionId,LastModified]"

# Restore previous versions (script for bulk restore)
# For each object, copy the pre-ransomware version back
aws s3api copy-object \
  --bucket AFFECTED_BUCKET \
  --key OBJECT_KEY \
  --copy-source "AFFECTED_BUCKET/OBJECT_KEY?versionId=PRE_RANSOMWARE_VERSION_ID"
```

**Decision: S3 versioning status?**

| Status | Recovery Path |
|--------|--------------|
| Versioning enabled, versions intact | Restore from previous versions |
| Versioning enabled, versions deleted | Check S3 replication destination, AWS Backup |
| Versioning not enabled | AWS Backup, cross-region replication, or data loss |
| MFA Delete enabled | Versions protected, restore from versions |

### EBS/EC2 Recovery

```bash
# List available snapshots (pre-ransomware)
aws ec2 describe-snapshots \
  --owner-ids ACCOUNT_ID \
  --filters "Name=tag:Name,Values=*INSTANCE_NAME*" \
  --query "Snapshots[?StartTime<'RANSOMWARE_TIME'].{Id:SnapshotId,Time:StartTime,Size:VolumeSize}" \
  --output table

# Create volume from clean snapshot
aws ec2 create-volume \
  --snapshot-id snap-CLEAN \
  --availability-zone ORIGINAL_AZ \
  --volume-type gp3 \
  --tag-specifications "ResourceType=volume,Tags=[{Key=IR-Recovery,Value=true}]"
```

### RDS Recovery

```bash
# List available RDS snapshots
aws rds describe-db-snapshots \
  --db-instance-identifier AFFECTED_DB \
  --query "DBSnapshots[?SnapshotCreateTime<'RANSOMWARE_TIME'].{Id:DBSnapshotIdentifier,Time:SnapshotCreateTime}"

# Restore from snapshot
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier RECOVERED_DB \
  --db-snapshot-identifier CLEAN_SNAPSHOT \
  --db-instance-class ORIGINAL_CLASS
```

### AWS Backup Recovery

```bash
# List recovery points
aws backup list-recovery-points-by-resource \
  --resource-arn arn:aws:RESOURCE_ARN

# Start restore job
aws backup start-restore-job \
  --recovery-point-arn RECOVERY_POINT_ARN \
  --iam-role-arn arn:aws:iam::ACCOUNT:role/AWSBackupDefaultServiceRole \
  --metadata '{...resource-specific metadata...}'
```

## Step 6: Eradicate

> ⚠️ **Requires user confirmation before executing.**

```bash
# Remove threat actor persistence (same as credential compromise)
# Check for: unauthorized users, roles, Lambda functions, EventBridge rules
# See Threat Technique Catalog for AWS for comprehensive persistence reference:
# https://aws-samples.github.io/threat-technique-catalog-for-aws/

# Remove the emergency SCP (only after credential is contained)
aws organizations detach-policy \
  --policy-id p-RANSOMWARE_EMERGENCY \
  --target-id COMPROMISED_ACCOUNT_ID
```

## Step 7: Recover and Validate

> ⚠️ **Requires user confirmation before executing.**

```bash
# Restore services from clean backups/snapshots
# Validate data integrity
# Re-enable production access gradually
# Monitor for re-encryption attempts

# Remove containment policies
aws iam delete-user-policy \
  --user-name COMPROMISED_USER \
  --policy-name RevokeAllSessions
```

## Step 8: Harden

- [ ] Enable S3 Versioning on all buckets
- [ ] Enable MFA Delete on critical buckets
- [ ] Configure S3 Object Lock (WORM) for compliance data
- [ ] Enable AWS Backup with Vault Lock (compliance mode) and cross-account vault copy
- [ ] Set KMS key deletion waiting period to maximum (30 days)
- [ ] Restrict `kms:ScheduleKeyDeletion` and `kms:CreateKey` via SCP
- [ ] Restrict `s3:DeleteObject` and `s3:PutBucketVersioning` via SCP
- [ ] Enable EBS Snapshots Lock on critical snapshots
- [ ] Enable GuardDuty with Malware Protection for EC2 and S3
- [ ] Implement least-privilege IAM — remove PowerUserAccess and AdministratorAccess
- [ ] Test backup restoration procedures quarterly
- [ ] Enable AWS Elastic Disaster Recovery for critical workloads

## Regarding Ransom Payment

Ransom payment is a business and legal decision, not a technical one. It is outside the scope of this playbook and the IR team's authority.

**The IR team's job is to:**
1. Exhaust all technical recovery options (backups, versioning, snapshots, DRS)
2. Provide leadership with a recovery status assessment
3. Support whatever decision leadership makes

**If backups are unavailable or incomplete:**
- Engage your organization's **Legal counsel** and **cyber insurance provider** immediately
- Continue all technical recovery efforts in parallel
- Engage **AWS CIRT** for assistance identifying remaining recovery paths
- Report to **law enforcement** (FBI IC3 or local CERT) — coordinate through Legal

> 📌 **The strongest defense against ransom payment is preparation.** AWS Backup Vault Lock (compliance mode), S3 Object Lock, and EBS Snapshots Lock ensure that backups cannot be deleted or modified — even by an administrator with full account access. Investing in immutable backups before an incident ensures that payment is never a consideration during one.

## Escalation Triggers

- Multiple accounts affected → Organization-wide response
- Backup/snapshots also destroyed → Maximum severity, AWS Support engagement
- Threat actor communicating demands → Legal and law enforcement immediately
- Regulated data involved → Compliance notification obligations triggered (see IRP-PersonalDataBreach)
- Recovery not possible from backups → Engage Legal counsel and cyber insurance provider
- Lifecycle policies modified (S3 expiration, KMS deletion, RDS retention) → Check for time-bomb data loss

## Reference

Full human playbook: `IRP-Ransomware.md`
