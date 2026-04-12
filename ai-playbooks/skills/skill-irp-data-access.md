---
description: Incident response playbook for unintended access to Amazon S3 buckets. Use this skill when responding to S3 data exposure, public S3 bucket misconfiguration, unauthorized S3 object access, overly permissive bucket policies, modified object ACLs, S3-related GuardDuty or Macie findings, or any scenario involving unintended access to S3 data.
---

# Playbook: Unintended S3 Data Access

## Incident Type
Unintended access to an Amazon S3 bucket — when bucket misconfiguration, overly permissive policies, modified object ACLs, or compromised credentials result in unauthorized data access.

## Quick Reference

| Phase | Key Action | Verification |
|-------|------------|--------------|
| Evidence | Identify affected bucket(s), access vector, timeline | Bucket name, access method (credential vs public), data classification documented |
| Contain | Disable credentials / restrict bucket policy / enable Block Public Access / identify compromised users and credentials | CloudTrail shows no new unauthorized access for 30+ min |
| Eradicate | Harden S3 config, rotate credentials, mitigate instance-level vectors, isolate compromised users | Least-privilege policies in place, no public access, encryption enabled |
| Recover | Restore modified/deleted objects from versioning or backups | Data integrity confirmed, applications functioning normally |
| Post-Incident | Document lessons learned | Report filed, playbook updated, risk documents revised |

---

## Part 1: Acquire, Preserve, Document Evidence

### 1.1 Identify the Alert Source

Common sources for S3 data access alerts:
- **AWS Config rules** (e.g., `s3-bucket-public-read-prohibited`, `s3-bucket-public-write-prohibited`)
- **GuardDuty findings** (e.g., S3-related findings)
- **Security Hub alerts**
- **CloudWatch/EventBridge alarms** on S3 or IAM changes
- **Amazon Macie** sensitive data discovery alerts
- **Billing anomalies** (unexpected data transfer costs)
- **External notification** (threat actor, security researcher, news article, anonymous tip)

### 1.2 Determine the Access Vector

The incident may stem from misconfigured buckets, compromised credentials, SSRF via misconfigured EC2 settings, or any combination of these.

**Check for overly permissive S3 configuration:**
```bash
# Use IAM Access Analyzer to find publicly accessible or cross-account shared buckets
aws accessanalyzer list-findings --analyzer-name <analyzer-name> \
  --filter '{"resourceType":{"eq":["AWS::S3::Bucket"]}}'

# Check a specific bucket's public access block settings
aws s3api get-public-access-block --bucket <bucket-name>

# Get bucket policy
aws s3api get-bucket-policy --bucket <bucket-name>

# Get bucket ACL
aws s3api get-bucket-acl --bucket <bucket-name>
```

**Check for recent configuration changes via CloudTrail:**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=s3.amazonaws.com \
  --start-time <start-timestamp> \
  --max-results 50
```

Look for these management events: `PutBucketPolicy`, `PutBucketAcl`, `PutPublicAccessBlock`, `DeletePublicAccessBlock`, `PutObjectAcl`.

**Look for bulk `GetObject` as an active exfiltration signal:**

A high volume of `GetObject` calls (50+ within seconds) from a single access key against a single bucket is a strong indicator of in-progress or recent data exfiltration. When reviewing CloudTrail logs, filter for `GetObject` events and check the event density — an attacker scripting an `aws s3 sync` or similar command will produce a burst pattern that stands out from normal application access. Also look for `ListObjects`/`ListBucket` calls immediately preceding the `GetObject` burst, which indicate the attacker was enumerating before downloading.

**Check for IAM role trust policy changes:**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateAssumeRolePolicy \
  --start-time <start-timestamp> \
  --max-results 20
```

**If the credentials belong to a role attached to an EC2 instance:**
```bash
# Describe EC2 instance
aws ec2 describe-instances --instance-id <instance-id>
```

### 1.3 Identify the Affected Bucket(s)

**If you know the data but not the bucket:**
```bash
# List buckets and search for the data
aws s3 ls
aws s3 ls s3://<bucket-name>/<prefix> --recursive

# Query CloudTrail Data Events for a specific object key
# (requires Athena with CloudTrail logs in S3)
```

**If you know the credentials but not the bucket:**
```bash
# Search CloudTrail Data Events filtered by credentials and S3
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<access-key-id> \
  --start-time <compromise-timestamp> \
  --max-results 50
```

**To find publicly accessible buckets across the account:**
```bash
# Check all buckets for public access
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  echo "=== $bucket ==="
  aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null || echo "No Block Public Access config"
done
```

### 1.4 Determine Data Classification

- Check CMDB or data classification documents for the affected bucket/data
- Classification level may escalate the response path (e.g., PII, financial data, health records)

### 1.5 Document and Communicate

- [ ] Create/update incident ticket with: Bucket name(s), access vector, timeline, data classification
- [ ] Identify stakeholders from CMDB / application risk register
- [ ] Open war room bridge
- [ ] Notify: Security team, Application owners, Legal (if regulated data involved)
- [ ] For external communications: Inform legal counsel, PR, and relevant regulatory contacts as needed

---

## Part 2: Contain the Incident

**Goal:** Stop unauthorized access immediately. Address credentials first, then bucket policies, then Block Public Access.

### 2.1 If Compromised Credentials Are Involved

**For long-term IAM user credentials:**
```bash
aws iam update-access-key \
  --user-name <username> \
  --access-key-id <access-key-id> \
  --status Inactive

aws iam list-access-keys --user-name <username>
```

**For STS temporary credentials (assumed role):**
```bash
# Revoke all current sessions
aws iam put-role-policy \
  --role-name <role-name> \
  --policy-name AWSRevokeOlderSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": ["*"],
      "Resource": ["*"],
      "Condition": {
        "DateLessThan": {"aws:TokenIssueTime": "<current-iso-timestamp>"}
      }
    }]
  }'
```

**If role is attached to an EC2 instance**, also consider:
- SSH key compromise (attacker accessing instance directly)
- SSRF attacks using instance role credentials (mitigate with IMDSv2)

⚠️ Revoking role sessions affects all legitimate users/applications using that role.

### 2.2 If Bucket Policy Is Too Permissive

```bash
# Get current bucket policy
aws s3api get-bucket-policy --bucket <bucket-name> --output text > bucket-policy-backup.json

# Replace with a restrictive policy (customize principals as needed)
aws s3api put-bucket-policy --bucket <bucket-name> --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::<bucket-name>",
      "arn:aws:s3:::<bucket-name>/*"
    ],
    "Condition": {
      "StringNotEquals": {"aws:PrincipalAccount": "<your-account-id>"}
    }
  }]
}'
```

Priority order:
1. Restrict control plane access first (`PutBucketPolicy`, `PutBucketAcl`, `PutPublicAccessBlock`)
2. Then restrict data plane access (`GetObject`, `PutObject`, etc.)
3. Review and fix individual object ACLs if needed

### 2.3 If Bucket Allows Public (Unauthenticated) Access

```bash
# Quickest containment: enable Block All Public Access
aws s3api put-public-access-block --bucket <bucket-name> \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

⚠️ This affects all objects in the bucket. Coordinate with application owners.

**To fix individual object ACLs:**
```bash
# Remove public access from a specific object
aws s3api put-object-acl --bucket <bucket-name> --key <object-key> --acl private

# For bulk operations across many objects, use a script or S3 Batch Operations
```

### 2.4 Verify Containment

```bash
# Monitor CloudTrail for continued unauthorized access (30+ min)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=<bucket-name> \
  --start-time $(date -u -v-30M +%Y-%m-%dT%H:%M:%SZ) \
  --max-results 20
```

---

## Part 3: Eradicate the Incident

**Goal:** Remove attack vectors, harden configurations, rotate credentials.

### 3.1 Harden Instance-Level Attack Vectors

If EC2 instances interact with the affected bucket:

```bash
# Enforce IMDSv2 on instances (prevents SSRF credential theft)
aws ec2 modify-instance-metadata-options \
  --instance-id <instance-id> \
  --http-tokens required \
  --http-endpoint enabled
```

For SSH key rotation:
```bash
# Identify instances using a specific key pair
aws ec2 describe-instances \
  --query "Reservations[*].Instances[].[InstanceId,KeyName,State.Name]" \
  --output table
```

Consider terminating and replacing compromised instances rather than rotating keys in place.

### 3.2 Harden S3 Configuration

```bash
# Ensure Block Public Access is enabled
aws s3api put-public-access-block --bucket <bucket-name> \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Enable server-side encryption (SSE-KMS recommended)
aws s3api put-bucket-encryption --bucket <bucket-name> \
  --server-side-encryption-configuration '{
    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
  }'

# Enable versioning
aws s3api put-bucket-versioning --bucket <bucket-name> \
  --versioning-configuration Status=Enabled

# Enable Object Lock (only on new buckets or if already enabled)
# aws s3api put-object-lock-configuration --bucket <bucket-name> \
#   --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"GOVERNANCE","Days":30}}}'
```

Checklist:
- [ ] Object ACLs restored to secure settings
- [ ] Bucket policy implements least privilege
- [ ] Only authorized principals have data and control plane access
- [ ] IAM policies scoped appropriately; Permission Boundaries / SCPs deployed if needed
- [ ] Server-side encryption enabled (SSE-KMS)
- [ ] Versioning enabled
- [ ] Consider Object Lock for critical data

### 3.3 If Credential Compromise Was Involved

```bash
# Issue new credentials after disabling old ones (Part 2)
aws iam create-access-key --user-name <username>

# Remove unauthorized IAM users/roles
aws iam delete-user --user-name <unauthorized-user>
aws iam delete-role --role-name <unauthorized-role>
```

- [ ] Enable MFA Delete on the bucket (requires versioning)
- [ ] For objects that must be publicly readable, use pre-signed URLs instead of public ACLs
- [ ] Close/remove any unauthorized IAM users, roles, or identity providers
- [ ] Flag credential handling processes for post-incident review

---

## Part 4: Recover from the Incident

**Goal:** Restore lost or modified data, verify mitigations are effective.

### 4.1 Restore Modified Objects

```bash
# List object versions to find pre-compromise version
aws s3api list-object-versions --bucket <bucket-name> --prefix <key-prefix>

# Restore a previous version by copying it over the current version
aws s3api copy-object \
  --bucket <bucket-name> \
  --key <object-key> \
  --copy-source <bucket-name>/<object-key>?versionId=<version-id>
```

### 4.2 Restore Deleted Objects

```bash
# If deleted without version ID, a delete marker was placed. Remove it to restore:
aws s3api delete-object --bucket <bucket-name> --key <object-key> \
  --version-id <delete-marker-version-id>

# If deleted with a specific version ID, that version is permanently gone.
# Check for earlier versions:
aws s3api list-object-versions --bucket <bucket-name> --prefix <object-key>
```

Other recovery sources:
- S3 Glacier / S3 IA (check lifecycle policies)
- S3 Cross-Region Replication (CRR) target bucket
- On-premises backups or S3 buckets in other accounts

### 4.3 Verify Recovery

Compare post-mitigation logs to incident-period logs:
- [ ] Data plane activity returned to pre-attack levels
- [ ] No further evidence of unauthorized access in CloudTrail
- [ ] Affected applications functioning normally
- [ ] CMDB updated with any resource changes

If suspicious activity reoccurs, return to Part 1 and reassess the attack vector.

---

## Part 5: Post-Incident Activity

### 5.1 Document Lessons Learned

Create post-incident report covering:
- **Timeline:** When did each phase occur?
- **Root cause:** Misconfiguration, credential compromise, or both?
- **Impact:** What data was accessed/modified/deleted? Data classification?
- **Response effectiveness:** What worked? What didn't?
- **Recommendations:** Process/tooling improvements

### 5.2 Retrospective Questions

- What information would have helped respond more swiftly?
- What detection would have alerted to the issue sooner?
- What configuration would have prevented this exposure?
- What automation or tooling would have made root cause investigation easier?

### 5.3 Update Defenses

Based on findings:
- [ ] Update risk documents with newly discovered threat/vulnerability combinations
- [ ] Implement required infrastructure or application configuration changes
- [ ] Update CMDB entries for affected applications and buckets
- [ ] Review and update this playbook with lessons learned
- [ ] Assign follow-up actions from Parts 3, 4, and 5 and track to completion

### 5.4 Regulatory Notifications

If required by your jurisdiction:
- [ ] Notify relevant authorities within required timeframe
- [ ] Document notification for compliance records

---

## References

- [S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/dev/security-best-practices.html)
- [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [S3 Server-Side Encryption](https://docs.aws.amazon.com/AmazonS3/latest/dev/serv-side-encryption.html)
- [S3 Versioning](https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html)
- [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock.html)
- [IMDSv2 for SSRF Mitigation](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/)
- [Querying CloudTrail Logs with Athena](https://aws.amazon.com/premiumsupport/knowledge-center/athena-tables-search-cloudtrail-logs/)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
