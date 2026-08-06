# AI IRP: Root Account Takeover

The root user of an AWS account has been compromised. This is ALWAYS P1. Root has unrestricted access to everything in the account — no IAM policy can deny it. The attacker can delete CloudTrail, modify billing, close the account, or leave the organization.

## Critical Rule

```
╔══════════════════════════════════════════════════════════════╗
║  ROOT COMPROMISE IS ALWAYS P1.                              ║
║  Root bypasses ALL IAM policies, SCPs, and permission       ║
║  boundaries. Immediate response required.                   ║
║  Engage AWS Support immediately if access is lost.          ║
╚══════════════════════════════════════════════════════════════╝
```

## Priority Assessment

All root compromise is P1. The question is which path to take.

| Signal | Path |
|--------|------|
| Root console login from unknown IP | Path A (you still have access) |
| Root MFA device changed without authorization | Path A or B depending on access |
| Root password changed, you're locked out | Path B (lost access) |
| Root access keys created (should never exist) | Path A |
| Account removed from Organization | Path B + AWS Support |
| GuardDuty Policy:IAMUser/RootCredentialUsage | Path A |

## Decision: Do You Still Have Root Access?

```
Can you still log in as root?
│
├── YES → Path A: Immediate Lockdown (Step 1A)
│
└── NO  → Path B: Recovery via AWS Support (Step 1B)
```

---

## Path A: You Still Have Root Access

### Step 1A: Immediate Root Lockdown

> ⚠️ **Requires user confirmation before executing.**

Do these in order, as fast as possible. The attacker may be racing you.

```bash
# 1. Change root password IMMEDIATELY (via console)
# Go to: https://console.aws.amazon.com/iam/home#/security_credentials
# Click "Change password" — use a strong, unique password

# 2. Delete any root access keys (root should NEVER have access keys)
aws iam list-access-keys  # Run as root
aws iam delete-access-key --access-key-id AKIAEXAMPLE  # Delete ALL of them

# 3. Replace MFA device
# Console → IAM → Security credentials → MFA → Deactivate → Re-activate with new device
```

### Step 2A: Check What the Attacker Did as Root

**Key Athena query — all root API activity:**

```sql
SELECT eventTime, eventName, eventSource, sourceIPAddress,
       userAgent, awsRegion, errorCode,
       requestParameters, responseElements
FROM cloudtrail_logs
WHERE userIdentity.type = 'Root'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
```

**Key Athena query — critical root actions to check:**

```sql
SELECT eventTime, eventName, sourceIPAddress, requestParameters
FROM cloudtrail_logs
WHERE userIdentity.type = 'Root'
  AND eventName IN (
    'CreateAccessKey', 'DeleteAccessKey',
    'EnableMFADevice', 'DeactivateMFADevice',
    'CreateUser', 'CreateRole', 'AttachUserPolicy',
    'StopLogging', 'DeleteTrail', 'UpdateTrail',
    'LeaveOrganization', 'CloseAccount',
    'ModifyAccount', 'UpdateContactInformation',
    'PutBucketPolicy', 'DeleteBucket'
  )
ORDER BY eventTime ASC;
```

### Step 3A: Check for Damage

```bash
# Verify CloudTrail is still active
aws cloudtrail get-trail-status --name YOUR_TRAIL_NAME

# Verify the account is still in the Organization
aws organizations describe-account --account-id ACCOUNT_ID

# Check if billing contact/payment method was changed
# (Console only: Billing → Account → Contact Information)

# Check for unauthorized IAM entities created by root
aws iam list-users
aws iam list-roles
```

### Step 4A: Apply Emergency SCP (If in Organization)

> ⚠️ **Requires user confirmation before executing.**

From the **management account**, apply an emergency SCP to restrict the compromised account. This blocks ALL principals in the account except root and the IR role.

```bash
# Emergency SCP: Deny all except IR actions
aws organizations attach-policy \
  --policy-id p-EMERGENCY_LOCKDOWN \
  --target-id COMPROMISED_ACCOUNT_ID
```

Emergency SCP content:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": [
            "arn:aws:iam::ACCOUNT:role/IRBreakGlass",
            "arn:aws:iam::ACCOUNT:root"
          ]
        }
      }
    }
  ]
}
```

> **NOTE**: SCPs do not apply to the root user. This SCP blocks all OTHER principals while you investigate.

---

## Path B: Root Access Lost

### Step 1B: Contact AWS Support Immediately

```
AWS Support Case:
- Severity: Critical / Business-critical system down
- Category: Account → Security
- Subject: "Root account compromised — unauthorized access, locked out"
- Include:
  - Account ID
  - Last known good root email
  - Evidence of compromise (GuardDuty findings, CloudTrail if accessible)
  - Request: Root credential reset and MFA removal
```

If you have access to the management account (Organizations):

```bash
# Apply emergency SCP from management account to limit damage
aws organizations attach-policy \
  --policy-id p-EMERGENCY_LOCKDOWN \
  --target-id COMPROMISED_ACCOUNT_ID

# If the account left the organization, you need AWS Support to help
```

### Step 2B: Attempt Root Password Reset

```
1. Go to https://signin.aws.amazon.com/
2. Click "Forgot password?"
3. Enter the root email address
4. Check email for reset link
```

**Decision: Can you receive the reset email?**

| Situation | Action |
|-----------|--------|
| Reset email received | Reset password, proceed to Path A |
| Attacker changed root email | AWS Support must intervene |
| Email account also compromised | Secure email account first, then AWS Support |

### Step 3B: While Waiting for AWS Support

If you have access to the management account or other admin roles:

```bash
# Monitor for ongoing attacker activity via CloudTrail (if still logging)
# Apply SCPs to limit blast radius
# Identify and contain any cross-account access the compromised account has
# Revoke any roles in OTHER accounts that trust the compromised account

# In each account that trusts the compromised account:
aws iam update-assume-role-policy \
  --role-name CROSS_ACCOUNT_ROLE \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Principal": {"AWS": "arn:aws:iam::COMPROMISED_ACCOUNT:root"},
      "Action": "sts:AssumeRole"
    }]
  }'
```

---

## Both Paths: Eradicate and Recover

### Step 5: Full Credential Rotation

> ⚠️ **Requires user confirmation before executing.**

Once root access is restored:

```bash
# New root password (done in Step 1A or via AWS Support)
# New root MFA device (hardware key preferred)
# Delete ALL root access keys (there should be zero)
aws iam list-access-keys
# Delete each one found

# Rotate all IAM user credentials in the account
# Revoke all active sessions for all roles
# See ai-irp-credential-compromise.md for full credential rotation
```

### Step 6: Verify Account Integrity

```bash
# Verify CloudTrail configuration
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name TRAIL_NAME

# Verify account contact information (console only)
# Verify payment method hasn't been changed
# Verify account is still in correct Organization OU

# Check for unauthorized resources in all regions
for REGION in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  echo "=== $REGION ==="
  aws ec2 describe-instances --region $REGION \
    --filters "Name=instance-state-name,Values=running" \
    --query "Reservations[].Instances[].InstanceId" --output text
done

# Check for S3 bucket policy changes
aws s3api list-buckets --query "Buckets[].Name" --output text | \
  xargs -I {} aws s3api get-bucket-policy --bucket {} 2>/dev/null
```

### Step 7: Harden Root Account

- [ ] Enable hardware MFA on root (YubiKey or similar)
- [ ] Ensure root has NO access keys
- [ ] Set root email to a distribution list (not personal email)
- [ ] Enable root login alerts (CloudWatch alarm on `ConsoleLogin` where `userIdentity.type = Root`)
- [ ] Apply SCP denying root actions except break-glass scenarios
- [ ] Store root credentials in physical safe or secrets vault
- [ ] Test root access recovery procedure annually

### Root Hardening SCP (Apply to All Accounts)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "StringLike": {
        "aws:PrincipalArn": "arn:aws:iam::*:root"
      }
    }
  }]
}
```

> **NOTE**: This SCP blocks root from doing anything. You must remove it for legitimate root operations (rare).

## Escalation Triggers

- Root account is for the Organization management account → MAXIMUM severity, all member accounts at risk
- Attacker used root to leave Organization → AWS Support required for recovery
- Attacker changed billing/payment → Fraud team engagement
- Attacker closed the account → AWS Support emergency, 90-day recovery window
- Multiple root accounts compromised → Coordinated attack, engage AWS CIRT

## Reference

Full human playbook: `IRP-RootTakeover.md`
