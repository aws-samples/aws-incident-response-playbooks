---
description: Incident response playbook for AWS credential leakage/compromise. Use this skill when responding to compromised credentials, leaked or exposed IAM access keys, unauthorized IAM user activity, GuardDuty findings related to credential exfiltration, or any scenario involving stolen AWS credentials or unauthorized API access.
---

# Playbook: Credential Compromise



## Incident Type
Credential Leakage/Compromise - When AWS credentials (IAM user access keys or STS temporary credentials) have been obtained by an unauthorized actor.

## Quick Reference

| Phase | Key Action | Verification |
|-------|------------|--------------|
| Evidence | Identify compromised credentials + timeline | Access Key ID, Principal ID, compromise timestamp documented |
| Contain | Disable credentials | CloudTrail shows no new activity for 30+ min |
| Eradicate | Remove attacker resources + persistence | No unauthorized IAM entities or resources remain |
| Recover | Restore modified/deleted resources | Applications functioning normally |
| Post-Incident | Document lessons learned | Report filed, playbook updated |

---

## Part 1: Acquire, Preserve, Document Evidence

### 1.1 Identify the Alert Source

Common sources for credential compromise alerts:
- **GuardDuty findings** (e.g., `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`)
- **Security Hub alerts**
- **CloudWatch alarms** on IAM changes
- **AWS Config rules** showing IAM non-compliance
- **Billing alerts** (unexpected cost spike)
- **External notification** (security researcher, anonymous tip)

### 1.2 Identify Compromised Credentials

**From GuardDuty finding:**
- Navigate to GuardDuty console → Findings
- Locate the finding and expand "Resource" section
- Note the `accessKeyDetails`:
  - `accessKeyId` - The compromised access key
  - `principalId` - The IAM principal ID
  - `userType` - IAMUser or AssumedRole
  - `userName` - The IAM user or role name

**CLI to get finding details:**
```bash
# List GuardDuty detectors
aws guardduty list-detectors

# Get findings (replace detector-id)
aws guardduty list-findings --detector-id <detector-id> \
  --finding-criteria '{"Criterion":{"type":{"Eq":["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"]}}}'

# Get specific finding details
aws guardduty get-findings --detector-id <detector-id> --finding-ids <finding-id>
```

### 1.3 Establish Timeline

Document the following timestamps:
- **First seen:** When was the malicious activity first detected? (GuardDuty: `service.eventFirstSeen`)
- **Likely compromise time:** When were credentials likely stolen? (may be earlier than first seen)
- **Current time:** When did you start responding?

**All API actions after the compromise time should be considered malicious.**

### 1.4 Document and Communicate

- [ ] Create/update incident ticket with: Access Key ID, Principal, Timeline
- [ ] Identify stakeholders from CMDB
- [ ] Open war room bridge
- [ ] Notify: Security team, Application owners, Legal (if required)

---

## Part 2: Contain the Incident

**Goal:** Disable compromised credentials immediately.

### 2.1 For Long-Term IAM User Credentials

```bash
# Disable the access key (does NOT delete it)
aws iam update-access-key \
  --user-name <username> \
  --access-key-id <access-key-id> \
  --status Inactive

# Verify the key is disabled
aws iam list-access-keys --user-name <username>
```

### 2.2 For STS Temporary Credentials (Assumed Role)

**Option A: Revoke all sessions (immediate but affects all users of the role)**
```bash
# This adds an inline policy that denies all actions for sessions older than now
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

**Option B: If attacker can obtain new credentials, modify trust policy:**
```bash
# Get current trust policy
aws iam get-role --role-name <role-name> --query 'Role.AssumeRolePolicyDocument'

# Update trust policy to block the attack vector
# (specific changes depend on how credentials were obtained)
```

⚠️ **Warning:** Both options affect legitimate users of the role. Coordinate with application owners.

### 2.3 Verify Containment

Monitor CloudTrail for 30+ minutes:
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<access-key-id> \
  --start-time $(date -u -v-30M +%Y-%m-%dT%H:%M:%SZ) \
  --max-results 10
```

If new events appear, containment failed - investigate how attacker is obtaining new credentials.

---

## Part 3: Eradicate the Incident

**Goal:** Identify and remove everything the attacker created or modified.

### 3.1 Query CloudTrail for Attacker Actions

**Using CloudTrail Lookup (limited to 90 days, recent events):**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<access-key-id> \
  --start-time <compromise-timestamp> \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --max-results 50
```

**For comprehensive analysis, use Athena with CloudTrail logs in S3.**

### 3.2 Correlate Attacker Activity by Source IP

After querying CloudTrail for a known compromised access key, extract the `sourceIPAddress` from attacker events. Then search for **other IAM users or roles that made API calls from the same IP** — the attacker may have compromised multiple credentials and be operating them all from the same host.

```bash
# Extract unique source IPs used by the compromised key
# (run against downloaded CloudTrail logs or Athena)
# Look for the same IP appearing under a different userName in other log entries

# If you identify a suspicious IP, search for all users/keys that called from it:
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=SourceIPAddress,AttributeValue=<attacker-ip> \
  --start-time <compromise-timestamp> \
  --max-results 50
```

Pivot to any additional compromised credentials found and repeat Parts 2 and 3 for each one.

### 3.3 Identify Suspicious Actions (original 3.2)

Look for these API calls in the results:

**Identity/Persistence:**
- `CreateUser`, `CreateRole`, `CreateGroup`
- `CreateAccessKey`, `CreateLoginProfile`
- `AttachUserPolicy`, `AttachRolePolicy`, `PutUserPolicy`, `PutRolePolicy`
- `UpdateAssumeRolePolicy`
- `CreateInstanceProfile`, `AddRoleToInstanceProfile`

**Resource Creation:**
- `RunInstances`, `CreateFunction`, `CreateBucket`
- `CreateDBInstance`, `CreateCluster`
- Any `Create*` calls

**Data Access:**
- `GetObject`, `GetSecretValue`, `GetParameter`
- `Decrypt`, `GenerateDataKey`

**Covering Tracks:**
- `DeleteTrail`, `StopLogging`, `DeleteFlowLogs`
- `DeleteBucket` (CloudTrail bucket)

### 3.3 Check for Persistence Mechanisms

```bash
# List all IAM users (look for unfamiliar ones)
aws iam list-users

# List all roles (look for unfamiliar ones)
aws iam list-roles --query 'Roles[?contains(RoleName, `admin`) || contains(RoleName, `test`)]'

# Scan ALL IAM users for active access keys — do this systematically, not just for known suspects
for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
  keys=$(aws iam list-access-keys --user-name "$user" \
    --query 'AccessKeyMetadata[?Status==`Active`].[AccessKeyId,Status,CreateDate]' --output text)
  if [ -n "$keys" ]; then echo "=== $user ==="; echo "$keys"; fi
done

# Check for new access keys on existing users
aws iam list-access-keys --user-name <each-user>

# List EC2 instances with IAM roles (potential persistence)
aws ec2 describe-instances \
  --query 'Reservations[].Instances[?IamInstanceProfile!=`null`].[InstanceId,IamInstanceProfile.Arn,LaunchTime]' \
  --output table
```

### 3.4 Remove Attacker Resources

For each resource identified as created by the attacker:

```bash
# Delete IAM user (after removing dependencies)
aws iam delete-access-key --user-name <user> --access-key-id <key>
aws iam delete-login-profile --user-name <user>
aws iam detach-user-policy --user-name <user> --policy-arn <policy-arn>
aws iam delete-user --user-name <user>

# Delete IAM role (after removing dependencies)
aws iam detach-role-policy --role-name <role> --policy-arn <policy-arn>
aws iam delete-role-policy --role-name <role> --policy-name <policy>
aws iam delete-role --role-name <role>

# Terminate EC2 instances
aws ec2 terminate-instances --instance-ids <instance-id>

# Delete Lambda functions
aws lambda delete-function --function-name <function-name>
```

### 3.5 Iterate

If you discovered new credentials (new IAM users, roles, access keys), repeat Part 3 for each set of credentials until no new persistence mechanisms are found.

---

## Part 4: Recover from the Incident

### 4.1 Restore Modified Resources

**If resource is replaceable (e.g., EC2 in ASG):**
```bash
# Terminate compromised instance, ASG will replace it
aws ec2 terminate-instances --instance-ids <instance-id>
```

**If resource needs restoration:**
1. Check for backups (snapshots, S3 versioning, RDS snapshots)
2. Restore from backup
3. Or rebuild from CMDB configuration

### 4.2 Restore Deleted Resources

1. Check CMDB for resource configuration
2. Check for backups:
   ```bash
   # List EBS snapshots
   aws ec2 describe-snapshots --owner-ids self

   # List RDS snapshots
   aws rds describe-db-snapshots

   # Check S3 versioning for deleted objects
   aws s3api list-object-versions --bucket <bucket> --prefix <key>
   ```
3. Restore or recreate as needed

### 4.3 Verify Application Functionality

- [ ] Test affected applications
- [ ] Verify legitimate users can access resources
- [ ] Check monitoring dashboards for anomalies
- [ ] Update CMDB with any resource changes

---

## Part 5: Post-Incident Activity

### 5.1 Forensic Analysis

If resources were isolated for forensics:
- Analyze to understand attack methods
- Determine initial compromise vector
- Identify any data exfiltration

### 5.2 Document Lessons Learned

Create post-incident report covering:
- **Timeline:** When did each phase occur?
- **Root cause:** How were credentials compromised?
- **Impact:** What was accessed/modified/deleted?
- **Response effectiveness:** What worked? What didn't?
- **Recommendations:** Process/tooling improvements

### 5.3 Update Defenses

Based on findings:
- [ ] Rotate any potentially exposed credentials
- [ ] Review IAM policies (least privilege)
- [ ] Enable/enhance monitoring (GuardDuty, CloudTrail, Config)
- [ ] Consider SCPs or permission boundaries
- [ ] Update this playbook with lessons learned

### 5.4 Regulatory Notifications

If required by your jurisdiction:
- [ ] Notify relevant authorities within required timeframe
- [ ] Document notification for compliance records

---

## References

- [AWS IAM: Rotating Access Keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)
- [AWS IAM: Revoking Role Sessions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)
- [Querying CloudTrail Logs with Athena](https://aws.amazon.com/premiumsupport/knowledge-center/athena-tables-search-cloudtrail-logs/)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
