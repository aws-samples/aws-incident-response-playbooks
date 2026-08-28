# AI IRP: STS Token Abuse

Abuse of temporary security credentials obtained via AssumeRole, GetFederationToken, or instance metadata (IMDS). Attackers use role chaining to pivot across accounts and escalate privileges. Harder to detect than static key abuse because tokens are ephemeral.

## Priority Assessment

| Signal | Priority |
|--------|----------|
| Cross-account AssumeRole from unknown external account | P1 |
| Role chaining depth > 2 from unexpected source | P1 |
| IMDS credentials used from external IP | P1 |
| Unusual AssumeRole pattern from known principal | P2 |
| GuardDuty UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration | P1 |

## Step 1: Identify the Token Source

Determine how the temporary credentials were obtained.

```bash
# Decode the access key prefix to identify token type
# ASIA* = temporary credentials (STS)
# AKIA* = long-lived IAM user key

# Get details about the current session
aws sts get-caller-identity
```

**Decision: What is the token source?**

| Source | Indicator | Next Action |
|--------|-----------|-------------|
| AssumeRole | `arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION` | Trace the role chain (Step 2) |
| Instance profile (IMDS) | Source IP matches EC2 instance | Check for IMDS exfiltration (Step 3) |
| Federation token | `arn:aws:sts::ACCOUNT:federated-user/NAME` | Identify federation source |
| SAML/OIDC | `arn:aws:sts::ACCOUNT:assumed-role/ROLE/email` | Check IdP compromise |

## Step 2: Trace the AssumeRole Chain

Attackers chain roles to obscure their origin. Trace backwards to find the initial access.

**Key Athena query — find the full AssumeRole chain:**

```sql
SELECT eventTime, userIdentity.arn as caller_arn,
       requestParameters.roleArn as assumed_role,
       requestParameters.roleSessionName as session_name,
       sourceIPAddress, userAgent
FROM cloudtrail_logs
WHERE eventName = 'AssumeRole'
  AND requestParameters.roleArn LIKE '%SUSPICIOUS_ROLE%'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
```

**Key Athena query — find cross-account AssumeRole calls:**

```sql
SELECT eventTime, userIdentity.arn as caller_arn,
       userIdentity.accountId as source_account,
       requestParameters.roleArn as target_role,
       sourceIPAddress
FROM cloudtrail_logs
WHERE eventName = 'AssumeRole'
  AND userIdentity.accountId != 'YOUR_ACCOUNT_ID'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
```

**Key Athena query — all actions taken with the abused session:**

```sql
SELECT eventTime, eventName, eventSource, awsRegion,
       sourceIPAddress, errorCode
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%ROLE_NAME/SESSION_NAME%'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
```

## Step 3: Check for IMDS Credential Exfiltration

If credentials came from an EC2 instance metadata service:

```bash
# Check if instance uses IMDSv1 (vulnerable to SSRF exfiltration)
aws ec2 describe-instances \
  --instance-ids i-EXAMPLE \
  --query "Reservations[].Instances[].MetadataOptions" \
  --output json

# Check GuardDuty for credential exfiltration finding
aws guardduty list-findings \
  --detector-id DETECTOR_ID \
  --finding-criteria '{
    "Criterion": {
      "type": {"Eq": ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"]}
    }
  }'
```

**Decision: IMDSv1 or IMDSv2?**

| IMDS Version | `HttpTokens` value | Risk |
|---|---|---|
| IMDSv1 (vulnerable) | `optional` | SSRF can steal credentials. Enforce IMDSv2 after containment. |
| IMDSv2 (hardened) | `required` | SSRF alone cannot steal creds. Look for code execution on instance. |

## Step 4: Contain — Revoke the Sessions

> ⚠️ **Requires user confirmation before executing.**

This invalidates all existing sessions from this role. Legitimate applications using the role will need to re-authenticate.

```bash
# Option A: Revoke sessions via inline deny policy on the role
aws iam put-role-policy \
  --role-name COMPROMISED_ROLE \
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

# Option B: If the role trust policy is the problem, restrict it
aws iam update-assume-role-policy \
  --role-name COMPROMISED_ROLE \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Principal": "*",
      "Action": "sts:AssumeRole"
    }]
  }'
```

> **WARNING**: Option B blocks ALL role assumption including legitimate use. Use only for confirmed compromise where the role must be fully locked.

## Step 5: Contain — Cross-Account Pivot

> ⚠️ **Requires user confirmation before executing.**

If the attacker pivoted to other accounts, revoke sessions in EACH target account. This will impact legitimate users of those roles in the target accounts.

```bash
# In EACH target account, revoke sessions on the role they assumed
aws iam put-role-policy \
  --role-name TARGET_ROLE \
  --policy-name RevokeCompromisedSessions \
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

# Check what the attacker did in each target account
# Run the blast radius query (Step 2) in each account
```

## Step 6: Contain — Instance Credential Theft

> ⚠️ **Requires user confirmation before executing.**

If credentials were stolen from EC2 IMDS:

```bash
# Immediately enforce IMDSv2 (blocks further SSRF-based theft)
aws ec2 modify-instance-metadata-options \
  --instance-id i-EXAMPLE \
  --http-tokens required \
  --http-endpoint enabled

# Rotate the instance role credentials by stopping/starting
# (This forces new credentials to be issued)
# WARNING: Only if instance is not needed for forensics
# For forensic preservation, isolate via security group instead

# Isolate the instance (swap to restrictive security group)
aws ec2 modify-instance-attribute \
  --instance-id i-EXAMPLE \
  --groups sg-forensic-isolation
```

## Step 7: Eradicate

> ⚠️ **Requires user confirmation before executing.**

```bash
# Remove the attacker's ability to re-assume the role
# Fix the trust policy to only allow legitimate principals
aws iam update-assume-role-policy \
  --role-name COMPROMISED_ROLE \
  --policy-document '{ ... legitimate trust policy ... }'

# Remove any unauthorized IAM policies attached during abuse
aws iam detach-role-policy \
  --role-name COMPROMISED_ROLE \
  --policy-arn arn:aws:iam::ACCOUNT:policy/ATTACKER_POLICY

# Delete attacker-created roles in target accounts
aws iam delete-role --role-name ATTACKER_PERSISTENCE_ROLE

# Enforce IMDSv2 across all instances (prevent recurrence)
# Use AWS Config rule: ec2-imdsv2-check
```

## Step 8: Recover and Harden

```bash
# Remove containment policies
aws iam delete-role-policy \
  --role-name COMPROMISED_ROLE \
  --policy-name RevokeOldSessions

# Reduce role session duration (default 1hr, max 12hr)
aws iam update-role \
  --role-name SENSITIVE_ROLE \
  --max-session-duration 3600

# Add external ID requirement for cross-account roles
# Add source IP conditions where feasible
# Enable GuardDuty in all accounts and regions
```

## Hardening Checklist

- [ ] Enforce IMDSv2 on all EC2 instances (`HttpTokens: required`)
- [ ] Reduce `MaxSessionDuration` on sensitive roles
- [ ] Add `aws:SourceIp` conditions to role trust policies where feasible
- [ ] Require `ExternalId` for third-party cross-account roles
- [ ] Enable GuardDuty credential exfiltration detection
- [ ] Monitor for unusual AssumeRole patterns (CloudWatch metric filter)
- [ ] Audit all cross-account trust relationships quarterly

## Escalation Triggers

- Role chain crosses into accounts you don't control → Contact those account owners immediately
- Attacker assumed OrganizationAccountAccessRole → Full org compromise possible
- Evidence of CloudTrail tampering in target accounts → Assume full compromise
- IMDS credentials used from IP outside AWS → Confirmed exfiltration, P1

## Reference

Full human playbook: `IRP-STSTokenAbuse.md`
