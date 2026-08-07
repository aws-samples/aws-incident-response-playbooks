# IRP-STSTokenAbuse: STS Temporary Credential Abuse

> **Playbook Version:** 1.0
> **Last Reviewed:** 2026-05-28
> **Status:** `Active`
> **NIST Framework:** SP 800-61r3 (CSF 2.0 Community Profile)
> **Related Playbooks:** [IRP-CredCompromise](IRP-CredCompromise.md) | [IRP-IdentityCenterCompromise](IRP-IdentityCenterCompromise.md) | [IRP-FederatedAccessAbuse](IRP-FederatedAccessAbuse.md)

---

> ⚠️ **Disclaimer:** This playbook is provided as a template only. It should be customized to suit your organization's specific needs, risks, available tools, and work processes. This guide is not official AWS documentation and is provided as-is. Security and Compliance is a shared responsibility between you and AWS. You are responsible for making your own independent assessment of the information in this document.

---

## Overview

STS temporary credential abuse occurs when an attacker obtains or manipulates AWS Security Token Service (STS) temporary credentials to access AWS resources without authorization. Unlike long-term credential compromise, STS abuse often involves role chaining — where an attacker assumes one role, then uses that session to assume additional roles across accounts, escalating privileges at each hop. Common vectors include theft of temporary credentials from EC2 instance metadata (particularly via IMDSv1), confused deputy attacks exploiting overly permissive role trust policies, and abuse of AssumeRoleWithSAML or AssumeRoleWithWebIdentity tokens. The ephemeral nature of STS tokens (default 1 hour, maximum 12 hours) creates urgency but also limits the window of exposure if detected quickly.

### Out of Scope

This playbook does **not** cover:

- **Long-term IAM credential compromise (access keys, console passwords)** — If the initial compromise vector is a stolen long-term access key or console password rather than STS token manipulation, see [IRP-CredCompromise](IRP-CredCompromise.md).
- **AWS Identity Center (SSO) session compromise** — If the compromise involves Identity Center permission sets, SSO session cookies, or SAML assertions originating from Identity Center, see [IRP-IdentityCenterCompromise](IRP-IdentityCenterCompromise.md).
- **Identity Provider (IdP) compromise leading to federated access** — If the root cause is a compromised identity provider (Okta, Azure AD, Ping) issuing unauthorized SAML assertions or OIDC tokens, see [IRP-FederatedAccessAbuse](IRP-FederatedAccessAbuse.md).

### Applicable Finding Types

| Source | Finding / Event Type | Severity |
|---|---|---|
| Amazon GuardDuty | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | HIGH |
| Amazon GuardDuty | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS` | HIGH |
| Amazon GuardDuty | `Discovery:IAMUser/AnomalousBehavior` | LOW |
| Amazon GuardDuty | `Persistence:IAMUser/AnomalousBehavior` | MEDIUM |
| Amazon GuardDuty | `PrivilegeEscalation:IAMUser/AnomalousBehavior` | HIGH |
| CloudTrail | `eventName: AssumeRole` (from unusual source accounts or IPs) | — |
| CloudTrail | `eventName: AssumeRoleWithSAML` (unexpected identity or source) | — |
| CloudTrail | `eventName: AssumeRoleWithWebIdentity` (unexpected OIDC provider) | — |
| CloudTrail | `eventName: GetSessionToken` (unusual principal or frequency) | — |
| CloudTrail | `eventName: GetCallerIdentity` (reconnaissance indicator) | — |
| IAM Access Analyzer | External access findings on IAM roles | HIGH |
| Custom | Impossible travel detection on role sessions | MEDIUM |
| Custom | Unusual role chaining depth (session → session → session) | HIGH |
| Custom | Cross-account AssumeRole from previously unseen source accounts | MEDIUM |

> 📌 GuardDuty finding types are updated regularly. See the [GuardDuty finding types reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) for the current list.

### Severity Classification

| Priority | Criteria |
|---|---|
| **P1 — Critical** | Confirmed cross-account role chaining with data access or resource creation in production accounts; active lateral movement across multiple accounts in the organization |
| **P2 — High** | Confirmed unauthorized AssumeRole calls from a compromised session, blast radius unclear; or EC2 instance credentials confirmed exfiltrated and used from outside AWS |
| **P3 — Medium** | Anomalous role assumption patterns detected (unusual source account, new role chain, impossible travel on session) but no confirmed malicious action yet |
| **P4 — Low** | Overly permissive role trust policy identified with no evidence of exploitation; or stale cross-account role with no recent usage |

---

## Part 1 — Prepare

> **CSF 2.0 Functions:** Govern · Identify · Protect
> **Goal:** Ensure the right configurations, access, and processes are in place *before* this incident type occurs.

### 1.1 Required AWS Service Configurations

- [ ] Amazon GuardDuty enabled in all regions with findings exported to Security Hub
- [ ] AWS CloudTrail enabled with multi-region trail, management events, and integrity validation
- [ ] CloudTrail Insights enabled (detects unusual AssumeRole call volume)
- [ ] AWS Config enabled with STS/IAM-related rules (e.g., `iam-role-managed-policy-check`, `ec2-imdsv2-check`)
- [ ] IAM Access Analyzer enabled — both external access and unused access analyzers
- [ ] Amazon Detective enabled for graph-based investigation of role assumption chains
- [ ] Security Hub enabled with AWS Foundational Security Best Practices standard
- [ ] IMDSv2 enforced on all EC2 instances (`HttpTokens: required`) — or at minimum, monitored via Config rule
- [ ] CloudWatch alarms configured for cross-account AssumeRole patterns
- [ ] S3 bucket for CloudTrail logs has Object Lock or versioning enabled (tamper protection)
- [ ] EventBridge rules configured to alert on AssumeRole from unexpected source accounts (see Appendix D)

> 🤖 **Automation opportunity:** Deploy AWS Config rule `ec2-imdsv2-check` with auto-remediation to enforce IMDSv2 across all instances. Use EventBridge rules to detect and alert on cross-account AssumeRole calls from previously unseen source accounts.

### 1.2 IAM & Access Prerequisites

- [ ] Break-glass IAM role exists with permissions to: modify role trust policies, attach inline deny policies, query CloudTrail, revoke role sessions, and export GuardDuty findings
- [ ] IR team members can assume the break-glass role with MFA from a trusted account
- [ ] Pre-created inline deny policy template ready for session revocation (see containment section)
- [ ] Access to AWS Security Incident Response console confirmed (if subscribed)
- [ ] Forensic account available for cross-account log analysis
- [ ] SCP templates prepared for emergency cross-account AssumeRole restrictions
- [ ] Inventory of all cross-account roles and their trust policies maintained and current
- [ ] Role session duration limits reviewed and set to organizational minimum (default 1 hour where possible)

### 1.3 Communication & Escalation

> 📋 Do not include names. Use roles only. Maintain a separate, access-controlled contact list.

| Role | Responsibility |
|---|---|
| IR Lead | Overall incident coordination, status updates |
| Account Owner(s) | Business context, authorization for role trust policy changes (may span multiple accounts) |
| Platform / Cloud Engineering | Cross-account role architecture context, SCP deployment |
| Legal / Compliance | Regulatory notification if data accessed across account boundaries |
| AWS CIRT | Engage via AWS Support case or Security Incident Response service (P1/P2, if available) |

**Escalation path:**
Detection → IR Lead notified → Severity assessed → P1/P2: AWS CIRT engaged, all affected Account Owners notified, Legal notified → P3/P4: IR Lead manages internally

> ⚠️ **Multi-account coordination:** STS abuse often spans multiple accounts. Ensure all affected Account Owners are identified and notified early — containment in one account without addressing others leaves the attacker with active sessions.

### 1.4 Game Day Guidance

Recommended testing cadence: **Semi-annually** (this is a P1-capable scenario with multi-account blast radius).

Suggested tabletop scenario:
> *"An attacker has compromised an EC2 instance role in your development account by exploiting IMDSv1 on a publicly accessible instance. Using the stolen temporary credentials from outside AWS, the attacker has called AssumeRole to pivot into three additional accounts in your organization — staging, shared-services, and production. GuardDuty has fired `InstanceCredentialExfiltration.OutsideAWS` in the development account 45 minutes ago. You need to determine the full blast radius, contain all active sessions, and identify what data or resources the attacker accessed in each account."*

Reference: [AWS Security Incident Response Game Days](https://docs.aws.amazon.com/security-ir/latest/userguide/game-days.html)

---

## Part 2 — Detect & Analyze

> **CSF 2.0 Functions:** Detect · Respond (Analyze)
> **Goal:** Confirm whether an incident has occurred, scope its impact, and gather evidence for containment and investigation.

### 2.1 Initial Triage Questions

- [ ] What type of STS credential is involved? (AssumeRole session, GetSessionToken, AssumeRoleWithSAML, AssumeRoleWithWebIdentity)
- [ ] How was the abuse detected? (GuardDuty finding, anomalous CloudTrail pattern, IAM Access Analyzer, custom detection)
- [ ] What is the source of the temporary credential? (EC2 instance role, Lambda execution role, user-assumed role, federated session)
- [ ] Is the credential being used from outside AWS? (Check sourceIPAddress — non-AWS IP ranges indicate exfiltration)
- [ ] How many accounts are affected? (Trace the AssumeRole chain — each hop may cross an account boundary)
- [ ] What is the maximum permission set across the role chain? (Check policies on each assumed role)
- [ ] Is the attacker still actively assuming roles? (Check for ongoing AssumeRole calls in CloudTrail)
- [ ] What is the session expiration time? (Determines urgency — sessions expire naturally but can be extended via role chaining)
- [ ] Was IMDSv1 enabled on the source instance? (If EC2 credential theft is suspected)
- [ ] Are there confused deputy indicators? (Unexpected ExternalId values or missing ExternalId in trust policies)

**If cross-account role chaining is confirmed with data access in production → P1 immediately.**

### 2.2 Evidence Collection Checklist

> ⚠️ **Collect evidence BEFORE revoking sessions.** Revoking sessions may alert the attacker and trigger accelerated destructive actions in other active sessions.

| Evidence Type | How to Collect | Where to Store |
|---|---|---|
| CloudTrail AssumeRole events | Athena query across all affected accounts (see below) | Forensic S3 bucket |
| GuardDuty findings (all affected accounts) | `aws guardduty get-findings` in each account | Forensic S3 bucket |
| Role trust policies (current) | `aws iam get-role --role-name ROLE` for each role in chain | IR ticket |
| Role session details | CloudTrail `responseElements.credentials` from AssumeRole events | Forensic S3 bucket |
| EC2 instance metadata configuration | `aws ec2 describe-instances` (check `MetadataOptions`) | IR ticket |
| All API calls made with stolen session | Athena query filtered by session token (see below) | Forensic S3 bucket |
| IAM Access Analyzer findings | Security Hub or IAM Access Analyzer console | IR ticket |
| VPC Flow Logs (source instance) | CloudWatch Logs / S3 export | Forensic S3 bucket |
| EC2 instance memory / disk (if IMDS theft) | EBS snapshot + memory capture | Forensic account |

**Key CloudTrail / Athena queries:**

```sql
-- Query 1: All AssumeRole calls that crossed account boundaries
-- Identifies cross-account pivoting by comparing the caller account with the target role account
SELECT eventTime, userIdentity.accountId AS source_account,
       SPLIT_PART(requestParameters.roleArn, ':', 5) AS target_account,
       requestParameters.roleArn AS assumed_role,
       userIdentity.arn AS caller_arn,
       sourceIPAddress, userAgent, errorCode
FROM cloudtrail_logs
WHERE eventName = 'AssumeRole'
  AND userIdentity.accountId != SPLIT_PART(requestParameters.roleArn, ':', 5)
  AND eventTime BETWEEN '2026-05-01T00:00:00Z' AND '2026-05-28T23:59:59Z'
ORDER BY eventTime ASC;
```

```sql
-- Query 2: Role chaining depth analysis (session assuming session assuming session)
-- Detects multi-hop role chaining by identifying AssumeRole calls made by assumed-role sessions
SELECT eventTime, userIdentity.arn AS caller_session,
       userIdentity.sessionContext.sessionIssuer.arn AS original_role,
       requestParameters.roleArn AS next_role_in_chain,
       sourceIPAddress,
       requestParameters.roleSessionName,
       requestParameters.durationSeconds
FROM cloudtrail_logs
WHERE eventName = 'AssumeRole'
  AND userIdentity.type = 'AssumedRole'
  AND eventTime BETWEEN '2026-05-01T00:00:00Z' AND '2026-05-28T23:59:59Z'
ORDER BY eventTime ASC;
```

```sql
-- Query 3: All actions taken with a specific role session token
-- Use the roleSessionName or accessKeyId from the AssumeRole response to trace all activity
SELECT eventTime, eventName, eventSource, awsRegion,
       sourceIPAddress, userAgent, errorCode,
       requestParameters, responseElements
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%ROLE_SESSION_NAME%'
  AND eventTime BETWEEN '2026-05-01T00:00:00Z' AND '2026-05-28T23:59:59Z'
ORDER BY eventTime ASC;
```

```sql
-- Query 4: Detect unusual AssumeRole patterns (new source accounts, unusual times, high frequency)
SELECT userIdentity.accountId AS source_account,
       requestParameters.roleArn AS target_role,
       COUNT(*) AS assume_count,
       MIN(eventTime) AS first_seen,
       MAX(eventTime) AS last_seen,
       ARRAY_AGG(DISTINCT sourceIPAddress) AS source_ips
FROM cloudtrail_logs
WHERE eventName = 'AssumeRole'
  AND eventTime BETWEEN '2026-05-01T00:00:00Z' AND '2026-05-28T23:59:59Z'
  AND errorCode IS NULL
GROUP BY userIdentity.accountId, requestParameters.roleArn
ORDER BY assume_count DESC;
```

```sql
-- Query 5: GetCallerIdentity calls (reconnaissance indicator)
-- Attackers frequently call GetCallerIdentity to understand what credentials they have
SELECT eventTime, userIdentity.arn, userIdentity.accountId,
       sourceIPAddress, userAgent,
       userIdentity.type, userIdentity.accessKeyId
FROM cloudtrail_logs
WHERE eventName = 'GetCallerIdentity'
  AND eventTime BETWEEN '2026-05-01T00:00:00Z' AND '2026-05-28T23:59:59Z'
  AND sourceIPAddress NOT IN ('AWS Internal')
ORDER BY eventTime ASC;
```

### 2.3 Severity Determination

Based on triage and initial evidence, assign a priority using the criteria in [Severity Classification](#severity-classification).

| Confirmed? | Priority Assignment |
|---|---|
| Cross-account role chaining with data access or resource creation in production | P1 |
| Instance credentials exfiltrated and used from outside AWS with active sessions | P1 |
| Unauthorized AssumeRole confirmed, scope unclear or limited to non-production | P2 |
| Anomalous role assumption pattern, no confirmed malicious action | P3 |
| Overly permissive trust policy identified, no evidence of exploitation | P4 |

### 2.4 Getting Help from AWS

> 📌 **If your organization has the AWS Security Incident Response service enabled, or has AWS Support, you can request assistance from the AWS Customer Incident Response Team (CIRT).**

If this incident is P1 or P2, consider engaging AWS for support:

- **If you have the AWS Security Incident Response service enabled:** Open a case via the [Security Incident Response console](https://console.aws.amazon.com/security-ir/), attach relevant findings, and grant AWS CIRT access to the affected account(s).
- **If you need assistance from AWS CIRT:** Open a support case with Critical severity and request assistance from the AWS Customer Incident Response Team (CIRT). Include relevant finding IDs and a summary of what you have observed.

> 📌 You do not need the Security Incident Response service to get help from AWS CIRT. All AWS customers can request CIRT assistance through a support case, regardless of support plan level.

> 🤖 **Automation opportunity:** Security Hub custom actions can auto-create Security Incident Response cases when `InstanceCredentialExfiltration` findings are detected.

---

## Part 3 — Contain

> **CSF 2.0 Function:** Respond (Contain)
> **Goal:** Stop the spread of the incident and prevent further damage without destroying evidence.

### 3.1 Containment Decision

Before acting, consider the tradeoff:

```
Is the attacker actively chaining roles or accessing data?
│
├── YES (active cross-account movement / data access)
│     └── Proceed to 3.2 — revoke sessions in ALL affected accounts simultaneously
│         Accept potential service disruption from session revocation
│
└── NO (sessions may have expired or attacker appears inactive)
      └── Consult Account Owners across all affected accounts
            Can we contain without service disruption?
            ├── YES → Proceed to 3.2 (trust policy modification + session revocation)
            └── NO  → Document business impact per account, obtain authorization, then proceed
```

> ⚠️ **Multi-account coordination is critical.** Revoking sessions in one account while leaving others active gives the attacker time to establish persistence in the remaining accounts. Coordinate containment across all affected accounts simultaneously.

### 3.2 Containment Actions

> `[IR Lead]` coordinates across all affected accounts. `[Account Owner(s)]` authorize actions in their respective accounts.

**Step 1: Revoke all active role sessions using inline deny policy**

Attach an inline deny policy to the compromised role that denies all actions for sessions issued before the current time. This invalidates all existing sessions without affecting new legitimate sessions.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "2026-05-28T12:00:00Z"
        }
      }
    }
  ]
}
```

```bash
# Apply the session revocation policy to the compromised role
aws iam put-role-policy \
  --role-name COMPROMISED_ROLE_NAME \
  --policy-name RevokeOlderSessions \
  --policy-document file://revoke-sessions-policy.json
```

> ⚠️ Set the `aws:TokenIssueTime` to the time just before the earliest known unauthorized AssumeRole call. This revokes attacker sessions while preserving sessions created after containment.

**Step 2: Modify role trust policies to remove unauthorized principals**

If the attacker is assuming roles from an unauthorized principal or account, update the trust policy to explicitly deny the source.

```bash
# Get current trust policy
aws iam get-role --role-name TARGET_ROLE --query 'Role.AssumeRolePolicyDocument'

# Update trust policy to remove unauthorized principal
aws iam update-assume-role-policy \
  --role-name TARGET_ROLE \
  --policy-document file://updated-trust-policy.json
```

**Step 3: Apply emergency SCP to block cross-account AssumeRole (if lateral movement is active)**

Deploy an SCP to the affected organizational units to prevent further cross-account role assumption while investigation continues.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCrossAccountAssumeRoleEmergency",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "${aws:ResourceOrgID}"
        }
      }
    }
  ]
}
```

> ⚠️ This SCP blocks ALL cross-account AssumeRole calls from outside the organization. Use only as an emergency measure and scope to specific OUs if possible.

**Step 4: Reduce role session duration limits**

For all roles in the chain, reduce the maximum session duration to the minimum (1 hour) to limit the window of any sessions you may have missed.

```bash
# Reduce maximum session duration to 1 hour (3600 seconds)
aws iam update-role \
  --role-name AFFECTED_ROLE \
  --max-session-duration 3600
```

**Step 5: Enforce IMDSv2 on affected instances (if IMDS theft vector)**

If the initial credential theft was via IMDSv1, immediately enforce IMDSv2 on the affected instance and all similar instances.

```bash
# Enforce IMDSv2 on the compromised instance
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

**Step 6: Revoke specific session tokens via inline deny policy (targeted)**

If you have identified the specific `accessKeyId` of the stolen session (from CloudTrail `responseElements`), you can target that specific session:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "ec2:RoleDelivery": "1.0"
        }
      }
    }
  ]
}
```

> 📌 The condition `ec2:RoleDelivery: 1.0` specifically targets credentials delivered via IMDSv1. This blocks only IMDSv1-delivered credentials while allowing IMDSv2-delivered credentials to continue working.

> 🤖 **Automation opportunity:** AWS Systems Manager Automation runbook to simultaneously revoke sessions across multiple accounts. Trigger via EventBridge when `InstanceCredentialExfiltration` findings are detected.

### 3.3 Evidence Preservation Reminders

After containment begins, ensure the following before modifying or terminating any resources:

- [ ] EBS snapshots taken for all affected EC2 instances (especially if IMDS theft suspected)
- [ ] Memory capture completed on compromised instances (if required)
- [ ] All CloudTrail logs exported from every account in the role chain to forensic S3 bucket
- [ ] Role trust policies documented (before and after modification)
- [ ] GuardDuty findings exported from all affected accounts
- [ ] S3 Object Lock or legal hold applied to forensic bucket
- [ ] CloudTrail integrity validation confirmed on exported logs
- [ ] VPC Flow Logs exported for the source instance's VPC

---

## Part 4 — Eradicate & Recover

> **CSF 2.0 Function:** Respond (Eradicate) · Recover
> **Goal:** Remove the root cause, validate the environment is clean, and restore normal operations.

### 4.1 Root Cause Identification

> `[IR Lead]` owns this step. Document findings in the IR ticket in real time.

Determine the root cause before beginning eradication. Common root causes for STS token abuse:

- **IMDSv1 exploitation** — Attacker accessed EC2 instance metadata service (v1) via SSRF vulnerability or direct instance access to steal the instance role's temporary credentials
- **Overly permissive role trust policy** — Role trust policy allows AssumeRole from overly broad principals (e.g., entire accounts, `*`, or missing ExternalId for third-party access)
- **Confused deputy attack** — Third-party service or cross-account role exploited due to missing or weak ExternalId condition in trust policy
- **Compromised application with AssumeRole permissions** — Application code or configuration exposed that has permissions to assume high-privilege roles
- **Stolen session token from developer workstation** — Temporary credentials cached in `~/.aws/cli/cache/` or environment variables exfiltrated from a compromised workstation
- **Overly long session duration** — Roles configured with 12-hour maximum session duration giving attackers extended access windows

Use evidence collected in Part 2 to trace the initial access vector and full attack path across all accounts.

### 4.2 Eradication Actions

> `[IR Lead]` coordinates. `[Account Owner(s)]` approve changes in their respective accounts.

**1. Remediate the initial access vector**

Based on root cause:
- **IMDSv1 theft:** Enforce IMDSv2 across all instances in the account (not just the compromised one). Patch the SSRF vulnerability that enabled metadata access.
- **Permissive trust policy:** Rewrite trust policies with least-privilege principals and mandatory conditions.
- **Confused deputy:** Add or strengthen `sts:ExternalId` conditions on all third-party cross-account roles.
- **Stolen session from workstation:** Rotate all credentials on the affected workstation, scan for malware, revoke all cached sessions.

**2. Harden all role trust policies in the chain**

For every role that was part of the attack chain, review and tighten the trust policy:

```bash
# Audit all roles with cross-account trust
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS]]' \
  --output table
```

Ensure each trust policy:
- [ ] Specifies exact principal ARNs (not account-wide principals)
- [ ] Includes `sts:ExternalId` condition for third-party access
- [ ] Includes `aws:PrincipalOrgID` condition where appropriate
- [ ] Does not use wildcard (`*`) in the Principal field

**3. Remove attacker persistence mechanisms**

Check for and remove across ALL affected accounts:
- [ ] Unauthorized IAM users, roles, or access keys created during the incident
- [ ] Modified trust policies on existing roles (compare to known-good baseline)
- [ ] New or modified SCPs that weaken security controls
- [ ] Unauthorized Lambda functions or EC2 instances (potential backdoors)
- [ ] Modified resource policies (S3 bucket policies, KMS key policies, SQS policies)
- [ ] New cross-account resource shares (RAM shares)
- [ ] EventBridge rules or CloudWatch alarms that were disabled or modified

**4. Enforce IMDSv2 organization-wide (if IMDS was the vector)**

```bash
# Set account-level default to require IMDSv2 for all new instances
aws ec2 modify-instance-metadata-defaults \
  --http-tokens required \
  --http-put-response-hop-limit 1

# Enforce via SCP for the entire organization
# (prevents launching instances with IMDSv1)
```

> 🤖 **Automation opportunity:** AWS Config auto-remediation rule `ec2-imdsv2-check` can automatically enforce IMDSv2 on non-compliant instances. Deploy organization-wide via AWS CloudFormation StackSets.

### 4.3 Recovery Actions

**1. Restore legitimate cross-account access**

After eradication, restore legitimate cross-account role access with hardened trust policies:
- [ ] Rewrite trust policies with least-privilege principals
- [ ] Set appropriate maximum session durations (1 hour default, extend only with justification)
- [ ] Add `sts:ExternalId` conditions where applicable
- [ ] Add `aws:SourceIp` or `aws:SourceVpc` conditions where feasible
- [ ] Test legitimate workflows to confirm access is restored

**2. Remove emergency containment controls**

- [ ] Remove emergency SCPs blocking cross-account AssumeRole (replace with permanent, scoped controls)
- [ ] Remove inline deny policies used for session revocation (once all attacker sessions have expired)
- [ ] Restore role session duration limits to operational requirements (with justification)

**3. Harden against recurrence**

- [ ] Enforce IMDSv2 across all accounts via SCP
- [ ] Implement role assumption monitoring (see Appendix D — Automation Hooks)
- [ ] Deploy IAM Access Analyzer organization-wide to detect overly permissive trust policies
- [ ] Implement role chaining depth limits via SCP (deny AssumeRole when session depth exceeds threshold)
- [ ] Review and reduce maximum session durations on all cross-account roles
- [ ] Enable GuardDuty in all accounts and regions (if not already)

### 4.4 Recovery Validation

Confirm the environment is clean before declaring the incident resolved.

- [ ] No unauthorized resources remain in any affected account
- [ ] All role trust policies reviewed and hardened across the role chain
- [ ] All attacker sessions have expired (verify via CloudTrail — no new API calls from attacker sessions)
- [ ] Emergency containment controls removed and replaced with permanent controls
- [ ] GuardDuty / Security Hub show no active findings related to this incident in any affected account
- [ ] Legitimate cross-account workflows validated and operational
- [ ] IMDSv2 enforcement confirmed on all instances (if IMDS was the vector)
- [ ] Monitoring and alerting confirmed operational (including new detections added)
- [ ] AWS Security Incident Response case updated / closed (if applicable)

---

## Part 5 — Post-Incident Activity

> **CSF 2.0 Function:** Identify (Improve) — continuous improvement, not a one-time activity
> **Goal:** Learn from this incident to reduce the likelihood and impact of future occurrences.

### 5.1 Timeline Reconstruction

Document the full incident timeline across all affected accounts. Complete this within 24–48 hours while memory is fresh.

| Timestamp (UTC) | Event | Source / Evidence | Actor | Account |
|---|---|---|---|---|
| YYYY-MM-DD HH:MM | Initial credential theft (e.g., IMDS access) | VPC Flow Logs / CloudTrail | Threat actor | Source account |
| YYYY-MM-DD HH:MM | First unauthorized AssumeRole call | CloudTrail | Threat actor | Source account |
| YYYY-MM-DD HH:MM | Cross-account pivot (hop 1) | CloudTrail | Threat actor | Target account 1 |
| YYYY-MM-DD HH:MM | Cross-account pivot (hop 2) | CloudTrail | Threat actor | Target account 2 |
| YYYY-MM-DD HH:MM | Data access or resource creation | CloudTrail | Threat actor | Target account |
| YYYY-MM-DD HH:MM | GuardDuty finding generated | GuardDuty | AWS | Source account |
| YYYY-MM-DD HH:MM | IR team notified | On-call alert | IR Lead | — |
| YYYY-MM-DD HH:MM | Containment completed (all accounts) | IR ticket | IR Lead | All |
| YYYY-MM-DD HH:MM | Recovery validated | IR ticket | IR Lead | All |

**Key metrics to capture:**

| Metric | Value |
|---|---|
| Time to Detect (TTD) | *HH:MM from initial compromise to detection* |
| Time to Notify (TTN) | *HH:MM from detection to IR team notified* |
| Time to Contain (TTC) | *HH:MM from notification to containment across all accounts* |
| Time to Recover (TTR) | *HH:MM from containment to recovery validated* |
| Total Incident Duration | *HH:MM* |
| Accounts Affected | *Count* |
| Role Chain Depth | *Number of hops* |
| Data Impact | *Confirmed / Suspected / None* |
| Sessions Revoked | *Count across all accounts* |

### 5.2 Post-Incident Review

Conduct a blameless post-incident review within **5 business days** for P1/P2, **15 business days** for P3/P4.

Discussion questions:

1. What was the initial access vector? Was IMDSv2 enforced? Were trust policies appropriately scoped?
2. How was the incident detected? Did GuardDuty catch it, or was it a custom detection? How fast?
3. Could the role chain have been prevented? Were there unnecessary cross-account trust relationships?
4. Were all affected accounts identified quickly? Was there a complete inventory of cross-account roles?
5. Did containment actions work simultaneously across all accounts? Were there coordination gaps?
6. Was the maximum session duration appropriate? Would shorter sessions have limited the blast radius?
7. Were there confused deputy protections (ExternalId) on third-party roles?
8. What single change would most reduce the blast radius of this scenario in future?

### 5.3 Detection Gap Analysis

For each detection source that *did not* catch this incident early, document why and what would have:

| Gap | Root Cause | Recommended Fix | Owner | Target Date |
|---|---|---|---|---|
| No alert on cross-account AssumeRole from new source | EventBridge rule not deployed | Deploy cross-account AssumeRole alerting (Appendix D) | | |
| IMDSv1 still enabled on instance | Config rule not enforcing remediation | Enable auto-remediation on `ec2-imdsv2-check` | | |
| Role chaining not monitored | No custom detection for session depth | Implement role chain depth detection | | |
| GuardDuty not enabled in all regions | Partial deployment | Enable GuardDuty organization-wide via delegated admin | | |

### 5.4 Playbook Update Checklist

Review and update this playbook based on what you learned. Do not wait for the next scheduled review.

- [ ] Were triage questions sufficient for multi-account scenarios? Add/remove as needed.
- [ ] Were the Athena queries effective for tracing the role chain? Update with lessons learned.
- [ ] Were containment actions effective across all accounts simultaneously? Update coordination steps.
- [ ] Were any new automation opportunities identified? Add to Appendix D.
- [ ] Were severity criteria accurate? Adjust if incidents were under- or over-classified.
- [ ] Were there new AssumeRole patterns not covered? Add to detection sources.
- [ ] Update **Last Reviewed** date and increment **Playbook Version**.

---

## Appendix A — Useful Queries

### CloudTrail (Athena)

```sql
-- All AssumeRole activity in a time window (baseline for investigation)
SELECT eventTime, eventName, userIdentity.arn AS caller,
       userIdentity.accountId AS source_account,
       requestParameters.roleArn AS target_role,
       requestParameters.roleSessionName,
       requestParameters.externalId,
       sourceIPAddress, userAgent, errorCode
FROM cloudtrail_logs
WHERE eventName IN ('AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
```

```sql
-- Identify all unique source IPs and user agents for a specific role session
SELECT sourceIPAddress, userAgent, COUNT(*) AS api_call_count,
       MIN(eventTime) AS first_seen, MAX(eventTime) AS last_seen
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%ROLE_SESSION_NAME%'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
GROUP BY sourceIPAddress, userAgent
ORDER BY api_call_count DESC;
```

```sql
-- Find all roles assumed by a specific EC2 instance role
-- (trace the full chain from the initial compromised instance)
SELECT eventTime, requestParameters.roleArn AS assumed_role,
       requestParameters.roleSessionName,
       requestParameters.durationSeconds,
       sourceIPAddress, errorCode
FROM cloudtrail_logs
WHERE eventName = 'AssumeRole'
  AND userIdentity.arn LIKE '%i-1234567890abcdef0%'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
```

```sql
-- Detect GetSessionToken abuse (unusual for service accounts, common for attackers)
SELECT eventTime, userIdentity.arn, userIdentity.accessKeyId,
       sourceIPAddress, userAgent,
       requestParameters.durationSeconds
FROM cloudtrail_logs
WHERE eventName = 'GetSessionToken'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
```

```sql
-- High-volume API calls from assumed role sessions (potential enumeration or exfiltration)
SELECT eventName, COUNT(*) AS call_count, sourceIPAddress,
       userIdentity.arn AS session_arn
FROM cloudtrail_logs
WHERE userIdentity.type = 'AssumedRole'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
  AND errorCode IS NULL
GROUP BY eventName, sourceIPAddress, userIdentity.arn
HAVING call_count > 50
ORDER BY call_count DESC;
```

### GuardDuty Finding Export (CLI)

```bash
# List STS-related findings across all detectors
aws guardduty list-findings \
  --detector-id DETECTOR_ID \
  --finding-criteria '{
    "Criterion": {
      "type": {
        "Eq": [
          "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
          "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS"
        ]
      }
    }
  }' \
  --region us-east-1

# Get full finding details
aws guardduty get-findings \
  --detector-id DETECTOR_ID \
  --finding-ids FINDING_ID_1 FINDING_ID_2
```

### IAM Access Analyzer (CLI)

```bash
# List findings for roles with external access (potential confused deputy targets)
aws accessanalyzer list-findings \
  --analyzer-arn arn:aws:access-analyzer:us-east-1:123456789012:analyzer/my-analyzer \
  --filter '{"resourceType": {"eq": ["AWS::IAM::Role"]}, "status": {"eq": ["ACTIVE"]}}'
```

---

## Appendix B — Regulatory & Compliance Considerations

> `[Legal / Compliance]` owns this section during an active incident.

See [Regulatory Context](../REGULATORY_CONTEXT.md) for the full notification obligation matrix by regulation and incident type.

**Quick reference for this scenario:**

| Regulation | Trigger Condition | Timeframe |
|---|---|---|
| GDPR Art. 33 | Personal data confirmed accessed via cross-account role chain | 72 hours to supervisory authority |
| HIPAA Breach Notification | PHI accessed in healthcare workloads via unauthorized role assumption | 60 days to HHS (individual notification varies) |
| PCI DSS 4.0 (Req. 12.10) | Cardholder data environment accessed via compromised STS session | Immediately to acquirer and card brands |
| SOC 2 (CC7.3) | Security incident affecting systems in scope of SOC 2 report | Per contractual obligations |

> ⚠️ The clock starts at **awareness**, not confirmation. When in doubt, assume notification is required and consult Legal immediately. Cross-account incidents may trigger notification obligations in multiple jurisdictions if different accounts serve different customer populations.

---

## Appendix C — Reference Links

- [NIST SP 800-61r3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html)
- [AWS Security Incident Response Service Documentation](https://docs.aws.amazon.com/security-ir/latest/userguide/what-is-security-ir.html)
- [AWS Well-Architected Framework — Security Pillar: Incident Response](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/incident-response.html)
- [Amazon GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [AWS STS API Reference](https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html)
- [IAM Roles — Revoking Temporary Security Credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)
- [EC2 Instance Metadata Service Version 2 (IMDSv2)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [IAM Access Analyzer — External Access Findings](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html)
- [Confused Deputy Problem — AWS Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)
- [AWS CloudTrail Query Examples (Athena)](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)
- [AWS Organizations — Service Control Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)

---

## Appendix D — Automation Hooks

### EventBridge Rule: Cross-Account AssumeRole Alerting

Deploy this EventBridge rule to detect and alert on AssumeRole calls that cross account boundaries from previously unseen source accounts.

```json
{
  "Source": ["aws.sts"],
  "DetailType": ["AWS API Call via CloudTrail"],
  "Detail": {
    "eventSource": ["sts.amazonaws.com"],
    "eventName": ["AssumeRole"],
    "errorCode": [{"exists": false}]
  }
}
```

**Target:** Lambda function that:
1. Extracts `userIdentity.accountId` (source) and parses account ID from `requestParameters.roleArn` (target)
2. Compares against an approved list of cross-account role assumptions (maintained in DynamoDB or Parameter Store)
3. If the source account is not in the approved list → sends alert to SNS topic / Security Hub custom finding
4. Enriches alert with: source principal ARN, target role, source IP, user agent

### EventBridge Rule: Instance Credential Use Outside AWS

```json
{
  "Source": ["aws.guardduty"],
  "DetailType": ["GuardDuty Finding"],
  "Detail": {
    "type": [
      "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
      "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS"
    ]
  }
}
```

**Target:** Step Functions state machine that:
1. Extracts the affected instance ID and role ARN from the finding
2. Automatically enforces IMDSv2 on the affected instance
3. Attaches the session revocation inline deny policy to the instance role
4. Creates a Security Hub custom finding with containment status
5. Sends notification to IR team via SNS

### EventBridge Rule: Role Chaining Depth Detection

```json
{
  "Source": ["aws.sts"],
  "DetailType": ["AWS API Call via CloudTrail"],
  "Detail": {
    "eventSource": ["sts.amazonaws.com"],
    "eventName": ["AssumeRole"],
    "userIdentity": {
      "type": ["AssumedRole"]
    },
    "errorCode": [{"exists": false}]
  }
}
```

**Target:** Lambda function that:
1. Detects when an assumed-role session is assuming another role (role chaining)
2. Tracks chain depth by parsing the `userIdentity.arn` for session indicators
3. Alerts when chain depth exceeds organizational threshold (recommended: 2 hops)
4. Logs the full chain path for investigation

### SCP: Limit Role Chaining Depth (Preventive Control)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDeepRoleChaining",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "*",
      "Condition": {
        "NumericGreaterThan": {
          "aws:CalledViaCount": "2"
        }
      }
    }
  ]
}
```

> 📌 `aws:CalledViaCount` is not currently a supported condition key for this use case. This SCP is a conceptual example — implement role chaining depth limits via custom Lambda-based detection (EventBridge rule above) until AWS provides native support.

---

## Appendix E — STS Token Abuse Attack Patterns

### Pattern 1: IMDSv1 Credential Theft → Cross-Account Pivot

```
Attacker → SSRF on web app → IMDSv1 (169.254.169.254/latest/meta-data/iam/security-credentials/ROLE)
         → Obtains temporary credentials (AccessKeyId, SecretAccessKey, Token)
         → Uses credentials from attacker infrastructure (outside AWS)
         → Calls AssumeRole to pivot to other accounts via cross-account trust
```

**Detection signals:** GuardDuty `InstanceCredentialExfiltration.OutsideAWS`, API calls from non-AWS IP using instance role credentials.

### Pattern 2: Confused Deputy Attack

```
Attacker → Creates AWS account → Configures service to call AssumeRole on victim's role
         → Victim's role trust policy allows the service principal without ExternalId
         → Attacker's service assumes victim's role → Access to victim's resources
```

**Detection signals:** AssumeRole calls with unexpected `aws:SourceAccount` or missing `sts:ExternalId`, IAM Access Analyzer external access findings.

### Pattern 3: Role Chain Privilege Escalation

```
Attacker → Compromises low-privilege role (Role A: read-only)
         → Role A can AssumeRole to Role B (Role B: write access)
         → Role B can AssumeRole to Role C (Role C: admin access)
         → Attacker escalates from read-only to admin via chain
```

**Detection signals:** Unusual role chaining depth, AssumeRole calls from sessions that don't normally chain, privilege escalation pattern in API calls.

### Pattern 4: GetSessionToken for MFA Bypass

```
Attacker → Steals long-term access key (no MFA device access)
         → Calls GetSessionToken (does not require MFA for basic session)
         → Uses session token to call APIs that don't enforce MFA condition
         → Bypasses MFA requirements on specific actions
```

**Detection signals:** GetSessionToken calls from unusual IPs, API calls succeeding without MFA from principals that normally use MFA.

### Pattern 5: AssumeRoleWithWebIdentity Abuse

```
Attacker → Compromises OIDC token (e.g., from CI/CD pipeline, mobile app)
         → Calls AssumeRoleWithWebIdentity with stolen token
         → Obtains temporary AWS credentials scoped to the web identity role
         → Accesses AWS resources as the federated identity
```

**Detection signals:** AssumeRoleWithWebIdentity from unexpected OIDC providers or with unexpected subject claims, unusual source IPs for web identity sessions.

---

## Revision History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | 2026-05-28 | AWS CIRT | Initial release |
