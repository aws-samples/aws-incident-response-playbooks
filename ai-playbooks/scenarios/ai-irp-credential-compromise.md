# AI IRP: Credential Compromise

Compromised AWS credentials (access keys, console passwords, or secrets). The most common AWS security incident. Speed matters — attackers automate exploitation within minutes of key exposure.

## Priority Assessment

| Signal | Priority |
|--------|----------|
| Key found on public GitHub/repo | P1 — assume already exploited |
| Unauthorized API calls from unknown IP | P1 |
| GuardDuty UnauthorizedAccess finding | P2 |
| Key exposed in internal system only | P2–P3 |
| Old key, no evidence of use | P3 |

## Step 1: Identify the Compromised Credential

Determine what was compromised and who owns it.

```bash
# Identify the credential type and owner
aws iam get-access-key-last-used --access-key-id AKIAEXAMPLE

# Get the user associated with the key
aws iam list-access-keys --user-name SUSPECTED_USER

# For role-based credentials, check the session
aws sts get-caller-identity
```

**Decision: What type of credential?**

| Type | Next Action |
|------|-------------|
| IAM User access key | Disable key immediately (Step 2) |
| IAM User console password | Disable console access (Step 2) |
| Root account credentials | → Route to `ai-irp-root-takeover.md` |
| Temporary STS token | → Route to `ai-irp-sts-token-abuse.md` |
| Application secret (not IAM) | Rotate in secrets manager, redeploy |

## Step 2: Disable the Credential (Contain)

> ⚠️ **Requires user confirmation before executing.**

Disabling the key and attaching a deny-all policy immediately stops all API activity from this credential. Applications using this key will break.

```bash
# Disable the access key (does NOT delete — preserves for forensics)
aws iam update-access-key \
  --access-key-id AKIAEXAMPLE \
  --status Inactive \
  --user-name COMPROMISED_USER

# If console access is compromised, disable it
aws iam delete-login-profile --user-name COMPROMISED_USER

# Attach explicit deny policy to block all actions while investigating
aws iam put-user-policy \
  --user-name COMPROMISED_USER \
  --policy-name IncidentContainment \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'
```

> **WARNING**: Disabling the key does NOT invalidate active STS sessions. Proceed to Step 3.

## Step 3: Revoke Active Sessions

> ⚠️ **Requires user confirmation before executing.**

Any temporary credentials issued before key disable are still valid for up to 12 hours. This policy invalidates all sessions issued before the current time.

```bash
# Revoke all sessions issued before NOW
aws iam put-user-policy \
  --user-name COMPROMISED_USER \
  --policy-name RevokeOldSessions \
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

Replace `CURRENT_UTC_TIMESTAMP` with the current time in ISO 8601 format (e.g., `2024-01-15T14:30:00Z`).

## Step 4: Scope the Blast Radius

Determine what the attacker did with the compromised credential.

```bash
# Query CloudTrail for all activity by the compromised credential
# Use Athena if available, or CloudTrail Lake
```

**Key Athena query — all actions by compromised key:**

```sql
SELECT eventTime, eventName, eventSource, awsRegion,
       sourceIPAddress, userAgent, errorCode,
       requestParameters, responseElements
FROM cloudtrail_logs
WHERE userIdentity.accessKeyId = 'AKIAEXAMPLE'
  AND eventTime > 'COMPROMISE_START_TIME'
ORDER BY eventTime ASC;
```

**Key Athena query — identify attacker IP addresses:**

```sql
SELECT sourceIPAddress, COUNT(*) as call_count,
       MIN(eventTime) as first_seen, MAX(eventTime) as last_seen
FROM cloudtrail_logs
WHERE userIdentity.accessKeyId = 'AKIAEXAMPLE'
  AND eventTime > 'COMPROMISE_START_TIME'
GROUP BY sourceIPAddress
ORDER BY call_count DESC;
```

**Key Athena query — check for persistence mechanisms created:**

```sql
SELECT eventTime, eventName, requestParameters, responseElements
FROM cloudtrail_logs
WHERE userIdentity.accessKeyId = 'AKIAEXAMPLE'
  AND eventName IN (
    'CreateUser', 'CreateAccessKey', 'CreateRole', 'CreateLoginProfile',
    'AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy', 'PutRolePolicy',
    'CreateFunction', 'UpdateFunctionCode', 'RunInstances'
  )
ORDER BY eventTime ASC;
```

## Step 5: Check for Persistence

The attacker likely created backdoor access. Check for:

```bash
# List all access keys for the user (attacker may have created a second key)
aws iam list-access-keys --user-name COMPROMISED_USER

# Check for new IAM users created during the compromise window
aws iam list-users --query "Users[?CreateDate>='COMPROMISE_TIME']"

# Check for new roles with suspicious trust policies
aws iam list-roles --query "Roles[?CreateDate>='COMPROMISE_TIME']"

# Check for Lambda functions (common persistence mechanism)
aws lambda list-functions --region us-east-1 \
  --query "Functions[?LastModified>='COMPROMISE_TIME']"
```

## Step 6: Eradicate

> ⚠️ **Requires user confirmation before executing.**

Remove everything the attacker created. Present each deletion individually for approval.

```bash
# Delete attacker-created access keys
aws iam delete-access-key --access-key-id ATTACKER_KEY --user-name ATTACKER_USER

# Delete attacker-created users
aws iam delete-user --user-name ATTACKER_CREATED_USER

# Delete attacker-created roles (remove policies first)
aws iam detach-role-policy --role-name ATTACKER_ROLE --policy-arn POLICY_ARN
aws iam delete-role --role-name ATTACKER_ROLE

# Delete unauthorized Lambda functions
aws lambda delete-function --function-name ATTACKER_FUNCTION --region REGION
```

## Step 7: Recover

> ⚠️ **Requires user confirmation before executing.**

```bash
# Create new access key for legitimate user (if still needed)
aws iam create-access-key --user-name LEGITIMATE_USER

# Remove the containment deny policies
aws iam delete-user-policy --user-name COMPROMISED_USER --policy-name IncidentContainment
aws iam delete-user-policy --user-name COMPROMISED_USER --policy-name RevokeOldSessions

# Re-enable console access with new password (force reset)
aws iam create-login-profile --user-name LEGITIMATE_USER --password-reset-required
```

## Step 8: Harden

- [ ] Enable MFA on the user account
- [ ] Reduce IAM permissions to least privilege
- [ ] Enable GuardDuty if not already active
- [ ] Set up CloudWatch alarm for root and high-privilege API usage
- [ ] Consider replacing long-lived keys with IAM roles + temporary credentials
- [ ] If key was in code: implement secrets scanning in CI/CD pipeline

## Escalation Triggers

- Attacker created resources in multiple regions → Multi-region sweep needed
- Evidence of data exfiltration (S3 GetObject, RDS snapshots shared) → Legal notification
- Attacker modified CloudTrail or GuardDuty → Assume full account compromise
- Credential was for a service account with broad permissions → Assume worst case

## Reference

Full human playbook: `IRP-CredentialCompromise.md`
