# IRP-InsiderThreat: Insider Threat Detection and Response

> **Playbook Version:** 1.0
> **Last Reviewed:** 2026-05-28
> **Status:** `Active`
> **NIST Framework:** SP 800-61r3 (CSF 2.0 Community Profile)
> **Related Playbooks:** [IRP-CredCompromise](IRP-CredCompromise.md) | [IRP-DataAccess](IRP-DataAccess.md) | [IRP-PersonalDataBreach](IRP-PersonalDataBreach.md)

---

> ⚠️ **Disclaimer:** This playbook is provided as a template only. It should be customized to suit your organization's specific needs, risks, available tools, and work processes. This guide is not official AWS documentation and is provided as-is. Security and Compliance is a shared responsibility between you and AWS. You are responsible for making your own independent assessment of the information in this document.

---

> 🔒 **CRITICAL SCOPE LIMITATION — READ BEFORE PROCEEDING**
>
> This playbook is **strictly limited to technical detection and containment** of anomalous authorized user behavior in AWS environments. The IR team provides **technical evidence only**.
>
> This playbook does **NOT** cover and the IR team does **NOT** perform:
> - HR processes, disciplinary actions, or employment decisions
> - Physical security or surveillance activities
> - Legal proceedings against any individual
> - Psychological profiling or behavioral assessment
>
> **All response decisions beyond technical monitoring and containment must be driven by organizational policy and Legal counsel.** The IR team acts on explicit authorization from Legal and HR leadership — never independently.

---

## Overview

Insider threat in AWS environments occurs when an authorized user — an employee, contractor, or partner with legitimate access — uses that access in ways that violate organizational policy, exfiltrate data, or cause harm to the organization's cloud resources. Unlike external threats, the actor already possesses valid credentials and authorized access paths, making detection significantly harder. Common patterns include bulk data downloads before departure, self-escalation of privileges, creation of backdoor access mechanisms, resource sabotage, and unauthorized resource creation for personal benefit. The IR team's role is to detect anomalous technical patterns, preserve evidence, and provide findings to Legal and HR for decision-making.

### Out of Scope

This playbook does **not** cover:

- **External credential compromise** — If the anomalous activity originates from an unauthorized party who obtained credentials through theft, phishing, or exposure, see [IRP-CredCompromise](IRP-CredCompromise.md).
- **Unauthorized data access by external actors** — If data access patterns are from compromised credentials rather than a legitimate insider, see [IRP-DataAccess](IRP-DataAccess.md).
- **Personal data breach notification** — If insider activity results in confirmed personal data exposure requiring regulatory notification, pivot to [IRP-PersonalDataBreach](IRP-PersonalDataBreach.md) for notification workflows once technical containment here is complete.
- **HR investigation processes** — This playbook provides technical evidence to HR/Legal. It does not define or execute HR investigation procedures, performance management, or termination workflows.

### Applicable Finding Types

| Source | Finding / Event Type | Severity |
|---|---|---|
| Amazon GuardDuty | `Exfiltration:S3/AnomalousBehavior` | HIGH |
| Amazon GuardDuty | `Impact:S3/AnomalousBehavior.Write` | HIGH |
| Amazon GuardDuty | `Persistence:IAMUser/AnomalousBehavior` | MEDIUM |
| Amazon GuardDuty | `PrivilegeEscalation:IAMUser/AnomalousBehavior` | HIGH |
| Amazon GuardDuty | `Discovery:IAMUser/AnomalousBehavior` | LOW |
| Amazon Macie | Sensitive data discovery — unusual access patterns | HIGH |
| Amazon Macie | Policy findings — bucket policy changes by authorized users | MEDIUM |
| IAM Access Analyzer | Unused access findings (over-privileged users) | MEDIUM |
| CloudTrail | Bulk `GetObject` calls from known principals (volume anomaly) | — |
| CloudTrail | `CreateAccessKey`, `PutUserPolicy` by user on their own principal | — |
| CloudTrail | Off-hours API activity from known users in unusual regions | — |
| CloudWatch | Data transfer spikes from known principals | HIGH |
| Custom / SIEM | Impossible travel for authorized users | MEDIUM |
| Custom / SIEM | Bulk S3 downloads outside business hours | HIGH |
| HR Signal | Resignation notice, PIP, termination pending (input only — not investigated by IR) | — |

> 📌 GuardDuty finding types are updated regularly. See the [GuardDuty finding types reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) for the current list.

### Severity Classification

| Priority | Criteria |
|---|---|
| **P1 — Critical** | Confirmed large-scale data exfiltration by insider (e.g., bulk download of trade secrets, copying data to external accounts), active sabotage of production resources, or confirmed backdoor access creation with ongoing use |
| **P2 — High** | Confirmed anomalous data access patterns by authorized user with sensitive data involvement (e.g., off-hours bulk downloads, access to data outside job function), or confirmed privilege self-escalation |
| **P3 — Medium** | Anomalous behavior detected from authorized user (unusual hours, new regions, elevated API volume) but no confirmed data impact or policy violation yet |
| **P4 — Low** | HR-flagged user with no technical anomalies detected, or minor policy violation (e.g., personal project on company infrastructure) with no data sensitivity concerns |

---

## Part 1 — Prepare

> **CSF 2.0 Functions:** Govern · Identify · Protect
> **Goal:** Ensure the right configurations, access, and processes are in place *before* this incident type occurs.

### 1.1 Required AWS Service Configurations

- [ ] Amazon GuardDuty enabled in all regions with anomaly detection for known principals
- [ ] AWS CloudTrail enabled with multi-region trail, management events, **and S3 data events** on sensitive buckets
- [ ] CloudTrail Insights enabled (detects unusual API call volume — critical for insider baseline deviation)
- [ ] Amazon Macie enabled on buckets containing sensitive/proprietary data with automated discovery jobs
- [ ] IAM Access Analyzer enabled (both external access and unused access analyzers)
- [ ] Amazon Detective enabled for graph-based investigation of user activity patterns
- [ ] CloudWatch alarms configured for data transfer anomalies and off-hours API activity
- [ ] VPC Flow Logs enabled for all VPCs (detect unusual data transfer volumes)
- [ ] S3 access logging enabled on all buckets containing proprietary or sensitive data
- [ ] S3 Object Lock or versioning enabled on forensic and log buckets (tamper protection)
- [ ] AWS Config enabled with rules for IAM self-service changes (`iam-policy-no-statements-with-admin-access`)

> 🤖 **Automation opportunity:** Deploy EventBridge rules to detect off-hours sensitive data access and bulk download patterns. See [Appendix D](#appendix-d--automation-hooks) for implementation details.

### 1.2 IAM & Access Prerequisites

- [ ] Break-glass IAM role exists with permissions to: query CloudTrail, read S3 access logs, export GuardDuty/Macie findings, modify IAM policies (for containment), and manage VPC endpoint policies
- [ ] IR team members can assume the break-glass role with MFA from a trusted account
- [ ] Pre-built "reduce-to-minimum" IAM policies exist for common job functions (allows continued work while restricting sensitive data access)
- [ ] Pre-built "enhanced-monitoring" CloudTrail data event configurations ready to deploy per-user
- [ ] Access to AWS Security Incident Response console confirmed (if subscribed)
- [ ] Forensic account available with S3 buckets configured for legal hold
- [ ] S3 bucket policies for sensitive data stores support rapid restriction (deny specific principals)
- [ ] VPC endpoint policies are modifiable to restrict cross-account data transfer paths

### 1.3 Communication & Escalation

> 📋 Do not include names. Use roles only. Maintain a separate, access-controlled contact list.
>
> ⚠️ **Insider threat cases require strict need-to-know.** Do not discuss the investigation with anyone outside the authorized circle. The subject must not be alerted.

| Role | Responsibility |
|---|---|
| IR Lead | Technical investigation coordination, evidence preservation |
| Legal Counsel | Authorization for monitoring/containment actions, legal hold, evidence admissibility |
| HR Leadership | Context on employment status, authorization for access changes |
| Account Owner | Business context on normal vs. anomalous access patterns |
| Data Owner | Classification of accessed data, impact assessment |
| AWS CIRT | Engage via AWS Support case or Security Incident Response service (P1/P2, if available) |

**Escalation path:**
HR/Detection Signal → Legal Counsel notified → Legal authorizes IR involvement → IR Lead begins technical investigation → Severity assessed → P1/P2: AWS CIRT engaged → All containment actions authorized by Legal before execution

> ⚠️ **Key difference from external threat response:** In insider cases, Legal counsel must authorize each phase of response. The IR team does not independently decide to revoke access or confront the subject.

### 1.4 Game Day Guidance

Recommended testing cadence: **Semi-annually** (this is a P1-capable scenario with significant legal sensitivity).

Suggested tabletop scenario:
> *"A senior engineer who submitted their resignation 2 weeks ago has been downloading large volumes of proprietary data from S3 buckets containing trade secrets. CloudTrail shows 15,000 GetObject calls in the past 3 days from their IAM role, compared to a baseline of ~200/day. The downloads are happening between 11 PM and 3 AM. HR has flagged this to the security team. Legal counsel has been engaged and has authorized monitoring but not yet authorized access revocation. Walk through your detection, evidence preservation, and containment decision process."*

Reference: [AWS Security Incident Response Game Days](https://docs.aws.amazon.com/security-ir/latest/userguide/game-days.html)

---

## Part 2 — Detect & Analyze

> **CSF 2.0 Functions:** Detect · Respond (Analyze)
> **Goal:** Confirm whether an incident has occurred, scope its impact, and gather evidence for containment and investigation.

### 2.1 Initial Triage Questions

- [ ] What triggered this investigation? (GuardDuty finding, Macie alert, HR signal, manager report, automated anomaly detection)
- [ ] Is the subject a current employee, contractor, or recently departed? What is their employment status? (Active, resigned, PIP, terminated)
- [ ] What is the subject's normal job function and expected data access pattern? (Establish baseline)
- [ ] What permissions does the subject currently have? (IAM policies, group memberships, role assumptions)
- [ ] Which AWS accounts and regions does the subject normally operate in?
- [ ] Is the anomalous activity occurring during or outside normal business hours?
- [ ] What data classifications are involved? (Public, internal, confidential, restricted/trade secret)
- [ ] Has Legal counsel been engaged and authorized the technical investigation?
- [ ] Is there a legal hold requirement for evidence preservation?
- [ ] Could this be a false positive? (Legitimate project work, authorized data migration, new job responsibilities)

**If Legal has not authorized the investigation → STOP. Engage Legal before proceeding.**

**If confirmed bulk access to trade secrets/restricted data AND subject has resignation/termination pending → P1 immediately (with Legal authorization).**

### 2.2 Evidence Collection Checklist

> ⚠️ **Evidence in insider cases may be used in legal proceedings.** Maintain strict chain of custody. All evidence must be collected under Legal authorization and stored with integrity validation (checksums, Object Lock). Do not modify, delete, or access the subject's resources directly — use read-only forensic methods.

| Evidence Type | How to Collect | Where to Store |
|---|---|---|
| CloudTrail events for subject (full time window) | Athena query against CloudTrail logs | Forensic S3 bucket (Object Lock) |
| S3 access logs for affected buckets | Copy from S3 access log bucket | Forensic S3 bucket (Object Lock) |
| GuardDuty findings for subject | `aws guardduty get-findings` | Forensic S3 bucket |
| Macie findings for affected buckets | Macie console → Export findings | Forensic S3 bucket |
| IAM policy history for subject | AWS Config timeline for IAM resources | Forensic S3 bucket |
| Subject's current IAM permissions | `aws iam list-attached-user-policies`, `list-user-policies`, `list-groups-for-user` | IR ticket (restricted access) |
| VPC Flow Logs (data transfer volumes) | CloudWatch Logs / S3 export | Forensic S3 bucket |
| CloudTrail Insights events | CloudTrail console → Insights | Forensic S3 bucket |
| Resource creation by subject | CloudTrail query for Create*/Put*/Run* events | Forensic S3 bucket |
| Cross-account activity | CloudTrail in destination accounts (if accessible) | Forensic S3 bucket |

**Key CloudTrail / Athena queries for insider threat investigation:**

```sql
-- Query 1: All API activity by a specific user outside business hours (UTC)
-- Adjust hours for subject's timezone. This example flags 03:00-11:00 UTC (11 PM - 7 AM ET)
SELECT eventTime, eventName, eventSource, sourceIPAddress, userAgent,
       awsRegion, requestParameters, errorCode
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%arn:aws:iam::123456789012:user/SUBJECT_USER%'
  AND eventTime BETWEEN '2026-05-01T00:00:00Z' AND '2026-05-28T23:59:59Z'
  AND (
    CAST(hour(from_iso8601_timestamp(eventTime)) AS INTEGER) >= 3
    AND CAST(hour(from_iso8601_timestamp(eventTime)) AS INTEGER) < 11
  )
ORDER BY eventTime ASC;
```

```sql
-- Query 2: Bulk data access patterns — S3 GetObject volume by user over time
-- Identifies unusual download volumes compared to baseline
SELECT DATE(from_iso8601_timestamp(eventTime)) as access_date,
       COUNT(*) as get_object_count,
       COUNT(DISTINCT JSON_EXTRACT_SCALAR(requestParameters, '$.bucketName')) as unique_buckets,
       APPROX_DISTINCT(JSON_EXTRACT_SCALAR(requestParameters, '$.key')) as unique_objects
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%arn:aws:iam::123456789012:user/SUBJECT_USER%'
  AND eventSource = 's3.amazonaws.com'
  AND eventName = 'GetObject'
  AND eventTime BETWEEN '2026-05-01T00:00:00Z' AND '2026-05-28T23:59:59Z'
GROUP BY DATE(from_iso8601_timestamp(eventTime))
ORDER BY access_date ASC;
```

```sql
-- Query 3: Self-service IAM changes — user modifying their own permissions
-- Detects privilege escalation attempts by authorized users
SELECT eventTime, eventName, requestParameters, responseElements, sourceIPAddress
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%arn:aws:iam::123456789012:user/SUBJECT_USER%'
  AND eventName IN (
    'CreateAccessKey', 'PutUserPolicy', 'AttachUserPolicy',
    'AddUserToGroup', 'CreateLoginProfile', 'UpdateLoginProfile',
    'PutRolePolicy', 'AttachRolePolicy', 'UpdateAssumeRolePolicy',
    'CreateRole', 'CreatePolicy', 'CreatePolicyVersion'
  )
  AND eventTime BETWEEN '2026-05-01T00:00:00Z' AND '2026-05-28T23:59:59Z'
ORDER BY eventTime ASC;
```

```sql
-- Query 4: Resource creation in unusual regions by known users
-- Detects cryptomining, personal projects, or staging infrastructure
SELECT eventTime, eventName, awsRegion, eventSource, sourceIPAddress,
       requestParameters, responseElements
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%arn:aws:iam::123456789012:user/SUBJECT_USER%'
  AND eventName LIKE 'Create%'
  AND awsRegion NOT IN ('us-east-1', 'us-west-2', 'eu-west-1')  -- adjust to your normal regions
  AND eventTime BETWEEN '2026-05-01T00:00:00Z' AND '2026-05-28T23:59:59Z'
ORDER BY eventTime ASC;
```

```sql
-- Query 5: Data transfer patterns — cross-account copies and external sharing
-- Detects data staging to personal or external accounts
SELECT eventTime, eventName, eventSource, sourceIPAddress,
       requestParameters, recipientAccountId, resources
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%arn:aws:iam::123456789012:user/SUBJECT_USER%'
  AND (
    eventName IN ('CopyObject', 'PutBucketPolicy', 'PutBucketAcl',
                  'PutObjectAcl', 'CreateGrant', 'PutResourcePolicy')
    OR (eventName = 'PutObject' AND requestParameters LIKE '%x-amz-copy-source%')
    OR (eventName = 'AssumeRole' AND requestParameters LIKE '%arn:aws:iam::%')
  )
  AND eventTime BETWEEN '2026-05-01T00:00:00Z' AND '2026-05-28T23:59:59Z'
ORDER BY eventTime ASC;
```

### 2.3 Severity Determination

| Confirmed? | Priority Assignment |
|---|---|
| Active bulk exfiltration of trade secrets/restricted data by departing employee | P1 |
| Confirmed privilege self-escalation with backdoor access creation | P1 |
| Confirmed anomalous data access to sensitive data, scope and intent unclear | P2 |
| Confirmed unauthorized resource creation (cryptomining, personal projects) | P2 |
| Anomalous behavior detected (off-hours, new regions, volume spike) but no confirmed data impact | P3 |
| HR-flagged user with minor policy violations, no sensitive data involvement | P4 |

### 2.4 Getting Help from AWS

If this incident is P1 or P2 (and Legal has authorized engagement), consider engaging AWS for support:

- **If you have the AWS Security Incident Response service enabled:** Open a case via the [Security Incident Response console](https://console.aws.amazon.com/security-ir/), attach relevant GuardDuty/Macie findings and CloudTrail evidence, and grant AWS CIRT access to the affected account(s). Note: inform AWS CIRT this is an insider threat case — different handling protocols apply.
- **If you need assistance from AWS CIRT:** Open a support case with Critical severity and request assistance from the AWS Customer Incident Response Team (CIRT). Include relevant finding IDs and note that this is an insider threat investigation.

> 📌 You do not need the Security Incident Response service to get help from AWS CIRT. All AWS customers can request CIRT assistance through a support case, regardless of support plan level.

> 🤖 **Automation opportunity:** EventBridge rules can trigger automated evidence collection when Macie or GuardDuty findings exceed severity thresholds for known principals. See [Appendix D](#appendix-d--automation-hooks).

---

## Part 3 — Contain

> **CSF 2.0 Function:** Respond (Contain)
> **Goal:** Stop the spread of the incident and prevent further damage without destroying evidence.

> ⚠️ **INSIDER THREAT CONTAINMENT IS FUNDAMENTALLY DIFFERENT FROM EXTERNAL THREAT CONTAINMENT.**
>
> With external threats, you typically want to block access immediately. With insider threats, you often want to **monitor first** to understand the full scope of activity before the subject becomes aware of the investigation. The decision to monitor vs. block **must involve Legal counsel** and is driven by:
> - Risk of ongoing data loss vs. risk of tipping off the subject
> - Legal requirements for evidence collection
> - Employment law considerations
> - Whether the subject's access can be reduced without alerting them

### 3.1 Containment Decision

```
Has Legal authorized containment actions?
│
├── NO → STOP. Continue monitoring only. Return to Legal with evidence update.
│
└── YES → What level of containment has Legal authorized?
      │
      ├── MONITOR ONLY (Legal wants full scope before action)
      │     └── Proceed to 3.2A — Enhanced Monitoring
      │
      ├── REDUCE ACCESS (Legal authorizes limiting without full revocation)
      │     └── Proceed to 3.2B — Graduated Containment
      │
      └── FULL REVOCATION (Legal authorizes immediate access removal)
            └── Proceed to 3.2C — Full Containment
                  (Typically only when active sabotage or imminent departure)
```

### 3.2A Enhanced Monitoring (Monitor-Only Containment)

> `[Legal]` has authorized monitoring but NOT access changes. Goal: understand full scope without alerting subject.

**Step 1: Enable enhanced CloudTrail logging for the subject**

Enable S3 data events for all buckets the subject accesses (if not already enabled):
```bash
# Add S3 data event logging for specific buckets accessed by subject
aws cloudtrail put-event-selectors \
  --trail-name management-trail \
  --advanced-event-selectors '[
    {
      "Name": "S3DataEventsForSensitiveBuckets",
      "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
        {"Field": "resources.ARN", "StartsWith": ["arn:aws:s3:::sensitive-bucket-name/"]}
      ]
    }
  ]'
```

**Step 2: Create CloudWatch metric filters for the subject's activity**

```bash
# Create metric filter for subject's API call volume
aws logs put-metric-filter \
  --log-group-name /aws/cloudtrail/management-events \
  --filter-name "InsiderMonitor-SUBJECT_USER-APIVolume" \
  --filter-pattern '{ $.userIdentity.arn = "*SUBJECT_USER*" }' \
  --metric-transformations \
    metricName=SubjectAPICallCount,metricNamespace=InsiderThreat/Monitoring,metricValue=1
```

**Step 3: Set up real-time alerting on high-risk actions**

```bash
# CloudWatch alarm for bulk S3 access by subject
aws cloudwatch put-metric-alarm \
  --alarm-name "InsiderThreat-BulkS3Access-SUBJECT" \
  --metric-name SubjectS3GetObjectCount \
  --namespace InsiderThreat/Monitoring \
  --statistic Sum \
  --period 3600 \
  --threshold 500 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:insider-threat-alerts
```

**Step 4: Monitor for data exfiltration paths**

- [ ] Review VPC Flow Logs for unusual outbound data volumes from subject's workloads
- [ ] Check for new S3 bucket policies granting cross-account access
- [ ] Monitor for AssumeRole calls to external accounts
- [ ] Watch for S3 presigned URL generation (`GetObject` with specific user agents)

### 3.2B Graduated Containment (Reduce Without Alerting)

> `[Legal]` has authorized reducing access. Goal: limit blast radius while maintaining appearance of normal access.

**Step 1: Reduce IAM permissions to minimum required for current job function**

Apply a scoped-down policy that allows the subject to continue normal work but removes access to sensitive data stores:
```bash
# Attach a permissions boundary that restricts access to sensitive buckets
aws iam put-user-permissions-boundary \
  --user-name SUBJECT_USER \
  --permissions-boundary arn:aws:iam::123456789012:policy/RestrictedDataAccess-Boundary
```

**Step 2: Restrict data transfer paths without alerting**

Apply S3 bucket policies that deny the subject's principal access to the most sensitive buckets:
```bash
# Add deny statement to bucket policy for subject's principal
aws s3api put-bucket-policy --bucket sensitive-data-bucket --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenySubjectAccess",
      "Effect": "Deny",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:user/SUBJECT_USER"
      },
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::sensitive-data-bucket",
        "arn:aws:s3:::sensitive-data-bucket/*"
      ]
    }
  ]
}'
```

**Step 3: Restrict VPC endpoint policies to block cross-account transfers**

```bash
# Modify VPC endpoint policy to deny cross-account S3 operations for subject
aws ec2 modify-vpc-endpoint --vpc-endpoint-id vpce-0123456789abcdef0 \
  --policy-document '{
    "Statement": [
      {
        "Sid": "DenyCrossAccountForSubject",
        "Effect": "Deny",
        "Principal": "arn:aws:iam::123456789012:user/SUBJECT_USER",
        "Action": "s3:*",
        "Resource": "*",
        "Condition": {
          "StringNotEquals": {
            "s3:ResourceAccount": "123456789012"
          }
        }
      }
    ]
  }'
```

**Step 4: Continue enhanced monitoring (all steps from 3.2A remain active)**

### 3.2C Full Containment (Immediate Access Revocation)

> `[Legal]` has authorized full access revocation. Typically used when: active sabotage detected, imminent departure (last day), or Legal determines monitoring is no longer necessary.

**Step 1: Attach explicit deny-all policy to the subject's IAM principal**

```bash
# Attach deny-all inline policy — immediate effect, all sessions
aws iam put-user-policy \
  --user-name SUBJECT_USER \
  --policy-name EmergencyDenyAll \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'
```

**Step 2: Deactivate all access keys**

```bash
# List and deactivate all access keys
aws iam list-access-keys --user-name SUBJECT_USER

aws iam update-access-key \
  --user-name SUBJECT_USER \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --status Inactive
```

**Step 3: Invalidate active sessions (for role-based access)**

```bash
# If subject uses role assumption, revoke active sessions
aws iam put-role-policy \
  --role-name SUBJECT_ROLE \
  --policy-name RevokeOlderSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "2026-05-28T12:00:00Z"
        }
      }
    }]
  }'
```

**Step 4: Disable console access**

```bash
aws iam delete-login-profile --user-name SUBJECT_USER
```

**Step 5: Remove from all IAM groups**

```bash
# List and remove from all groups
for group in $(aws iam list-groups-for-user --user-name SUBJECT_USER --query 'Groups[].GroupName' --output text); do
  aws iam remove-user-from-group --user-name SUBJECT_USER --group-name $group
done
```

> 🤖 **Automation opportunity:** AWS Systems Manager Automation runbook for graduated containment — accepts user ARN and containment level (monitor/reduce/revoke) as parameters. Requires Legal authorization token in execution metadata.

### 3.3 Evidence Preservation Reminders

After any containment action, ensure the following:

- [ ] All CloudTrail logs for the investigation period exported to forensic S3 bucket with Object Lock
- [ ] S3 access logs for affected buckets preserved under legal hold
- [ ] VPC Flow Logs for relevant time window exported and preserved
- [ ] GuardDuty and Macie findings exported with full JSON detail
- [ ] IAM policy versions captured (AWS Config timeline) showing state before and after containment
- [ ] SHA-256 checksums generated for all preserved evidence files
- [ ] Chain of custody documented: who collected what, when, and how
- [ ] Legal hold notification sent to relevant data custodians (no deletion of any logs)
- [ ] CloudTrail integrity validation confirmed on all exported log files

> ⚠️ **Do not access, modify, or delete any resources owned by the subject** (S3 objects they uploaded, EC2 instances they launched, etc.) without explicit Legal authorization. These may be evidence.

---

## Part 4 — Eradicate & Recover

> **CSF 2.0 Function:** Respond (Eradicate) · Recover
> **Goal:** Remove the root cause, validate the environment is clean, and restore normal operations.

> ⚠️ **Eradication in insider threat cases is driven by Legal/HR decisions, not IR team decisions.** The IR team executes technical actions as authorized. Timing of eradication often aligns with HR actions (termination, resignation effective date).

### 4.1 Root Cause Identification

> `[IR Lead]` owns technical root cause analysis. `[Legal/HR]` own organizational response decisions.

Determine the technical root cause and full scope of insider activity. Common patterns:

- **Over-provisioned access:** Subject had permissions far exceeding job requirements, enabling access to data outside their function
- **Lack of data access monitoring:** No baseline or anomaly detection on sensitive data stores, allowing bulk access to go undetected
- **Insufficient separation of duties:** Subject could self-escalate privileges without approval workflows
- **No off-boarding access review process:** Departing employees retain full access until termination date with no enhanced monitoring
- **Absence of data loss prevention controls:** No restrictions on bulk downloads, cross-account copies, or external sharing

Use evidence collected in Part 2 to document:
1. Complete timeline of anomalous activity
2. All data accessed (buckets, objects, databases, secrets)
3. All persistence mechanisms created (new keys, roles, policies)
4. All data exfiltration paths used (cross-account, external, local download)
5. Any resources created for unauthorized purposes

### 4.2 Eradication Actions

> `[IR Lead]` coordinates. `[Legal/HR]` authorizes timing. Execute only after Legal confirms.

**Step 1: Remove all backdoor access created by the subject**

Check for and remove:
- [ ] Additional access keys created by the subject on any principal
- [ ] IAM roles with trust policies modified by the subject
- [ ] IAM users created by the subject
- [ ] Lambda functions or EC2 instances that could provide persistent access
- [ ] S3 bucket policies granting access to external accounts
- [ ] Resource policies (KMS, SQS, SNS, Lambda) modified by the subject
- [ ] SSM parameters or Secrets Manager secrets containing credentials created by subject

```bash
# Find all IAM resources created by the subject
SELECT eventTime, eventName, requestParameters, responseElements
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%SUBJECT_USER%'
  AND eventName IN ('CreateUser', 'CreateRole', 'CreateAccessKey',
                    'CreatePolicy', 'PutRolePolicy', 'PutUserPolicy',
                    'AttachRolePolicy', 'AttachUserPolicy', 'UpdateAssumeRolePolicy')
ORDER BY eventTime ASC;
```

**Step 2: Revoke any shared credentials or secrets the subject had access to**

- [ ] Rotate all secrets in AWS Secrets Manager that the subject accessed
- [ ] Rotate any shared service account credentials the subject knew
- [ ] Rotate KMS keys if the subject had key management permissions
- [ ] Invalidate any API keys or tokens for third-party services the subject accessed

**Step 3: Remove unauthorized resources**

- [ ] Terminate EC2 instances created for unauthorized purposes (after forensic snapshot)
- [ ] Delete Lambda functions used as backdoors (after code preservation)
- [ ] Remove unauthorized S3 buckets (after content preservation for evidence)
- [ ] Clean up any CloudFormation stacks or infrastructure created by subject
- [ ] Remove any EventBridge rules or scheduled actions created by subject

**Step 4: Restore modified configurations**

- [ ] Revert any S3 bucket policies modified by the subject to pre-incident state
- [ ] Revert any IAM trust policies modified by the subject
- [ ] Revert any VPC security group or NACL changes made by the subject
- [ ] Revert any AWS Config rules disabled by the subject
- [ ] Restore any GuardDuty suppression rules created by the subject

> 🤖 **Automation opportunity:** AWS Config auto-remediation can detect and revert unauthorized configuration changes. Use Config rules with remediation actions for IAM policy changes and S3 bucket policy modifications.

### 4.3 Recovery Actions

**Step 1: Restore normal access controls**

- [ ] Remove emergency containment policies (deny-all, permissions boundaries) applied during containment
- [ ] Restore normal IAM group memberships for any principals affected by containment
- [ ] Re-enable any services or access paths restricted during containment
- [ ] Verify VPC endpoint policies are restored to normal operation

**Step 2: Implement least-privilege for the subject's former role**

- [ ] Review and reduce permissions for the job function the subject held
- [ ] Implement approval workflows for sensitive data access
- [ ] Add permissions boundaries to prevent self-escalation
- [ ] Enable mandatory MFA for sensitive operations

**Step 3: Harden against recurrence**

- [ ] Implement automated off-boarding access reviews (trigger on HR status change)
- [ ] Enable S3 data event logging on all sensitive buckets permanently
- [ ] Deploy anomaly detection baselines for data access patterns per user
- [ ] Implement separation of duties for IAM self-service changes
- [ ] Add SCPs preventing users from modifying their own permissions boundaries
- [ ] Configure data transfer restrictions (VPC endpoint policies, S3 bucket policies)

### 4.4 Recovery Validation

Confirm the environment is clean before declaring the incident resolved.

- [ ] No unauthorized resources remain in affected accounts (full resource audit)
- [ ] All backdoor access mechanisms created by subject have been removed
- [ ] All shared credentials the subject accessed have been rotated
- [ ] GuardDuty / Security Hub / Macie show no active findings related to this incident
- [ ] Enhanced monitoring confirms no continued anomalous activity from any principal
- [ ] Data access patterns for the subject's former role are within normal baseline
- [ ] Legal has confirmed evidence preservation is complete and adequate
- [ ] HR has confirmed organizational actions are complete
- [ ] AWS Security Incident Response case updated / closed (if applicable)

---

## Part 5 — Post-Incident Activity

> **CSF 2.0 Function:** Identify (Improve) — continuous improvement, not a one-time activity
> **Goal:** Learn from this incident to reduce the likelihood and impact of future occurrences.

### 5.1 Timeline Reconstruction

Document the full incident timeline. Complete this within 24–48 hours while memory is fresh.

| Timestamp (UTC) | Event | Source / Evidence | Actor |
|---|---|---|---|
| YYYY-MM-DD HH:MM | Subject's employment status changed (resignation/PIP) | HR notification | HR |
| YYYY-MM-DD HH:MM | Anomalous data access pattern began | CloudTrail / Macie | Subject |
| YYYY-MM-DD HH:MM | Detection signal triggered (GuardDuty/Macie/HR flag) | Detection source | AWS / HR |
| YYYY-MM-DD HH:MM | Legal counsel engaged and investigation authorized | IR ticket | IR Lead |
| YYYY-MM-DD HH:MM | Enhanced monitoring deployed | CloudTrail configuration | IR team |
| YYYY-MM-DD HH:MM | Containment authorized by Legal | Legal authorization | Legal |
| YYYY-MM-DD HH:MM | Containment actions executed | IAM / S3 policy changes | IR team |
| YYYY-MM-DD HH:MM | Evidence preservation completed | Forensic S3 bucket | IR team |
| YYYY-MM-DD HH:MM | Eradication completed | Resource cleanup | IR team |
| YYYY-MM-DD HH:MM | Recovery validated | Monitoring confirmation | IR team |

**Key metrics to capture:**

| Metric | Value |
|---|---|
| Time to Detect (TTD) | *HH:MM from first anomalous activity to detection* |
| Time to Notify (TTN) | *HH:MM from detection to IR team + Legal notified* |
| Time to Contain (TTC) | *HH:MM from Legal authorization to containment executed* |
| Time to Recover (TTR) | *HH:MM from containment to recovery validated* |
| Total Incident Duration | *HH:MM from first anomalous activity to case closed* |
| Monitoring Duration | *HH:MM from detection to containment (monitor-only period)* |
| Data Volume Accessed | *GB/TB of data accessed by subject during anomalous period* |
| Data Classification | *Highest classification of data accessed* |
| Affected Resources | *Count and type of resources involved* |
| Data Exfiltration Confirmed | *Yes / No / Suspected* |

### 5.2 Post-Incident Review

Conduct a blameless post-incident review within **5 business days** for P1/P2, **15 business days** for P3/P4.

> ⚠️ **Insider threat post-incident reviews have restricted attendance.** Only authorized personnel (IR team, Legal, HR leadership) should participate. Do not include the subject's manager or team members unless Legal approves.

Discussion questions:

1. What was the initial detection signal? Could we have detected this earlier?
2. Were access controls appropriate for the subject's role? Was least-privilege enforced?
3. Was there a gap between the HR status change (resignation/PIP) and enhanced monitoring?
4. Did the monitoring-vs-containment decision process work effectively? Was Legal engaged quickly enough?
5. Were evidence preservation procedures adequate for potential legal proceedings?
6. Did containment actions work without alerting the subject (if stealth was required)?
7. Were there data loss prevention controls that should have prevented exfiltration?
8. What single change would most reduce the window between insider activity and detection?

### 5.3 Detection Gap Analysis

| Gap | Root Cause | Recommended Fix | Owner | Target Date |
|---|---|---|---|---|
| No baseline for per-user data access volume | S3 data events not enabled on sensitive buckets | Enable S3 data events; build per-user access baselines | | |
| No automated alert on off-hours bulk downloads | No CloudWatch alarm for time-based access patterns | Deploy EventBridge rule for off-hours sensitive data access | | |
| No enhanced monitoring trigger on HR status change | No integration between HR systems and security tooling | Build automated workflow: HR flag → enhanced monitoring | | |
| Self-service IAM changes not detected | No Config rule for user self-modification | Deploy Config rule + alarm for IAM self-service changes | | |
| No data transfer restrictions for departing employees | VPC endpoint policies not scoped per-user | Implement graduated access reduction for departing staff | | |

### 5.4 Playbook Update Checklist

- [ ] Were triage questions sufficient? Did we miss any critical early indicators?
- [ ] Were evidence collection steps adequate for legal proceedings?
- [ ] Was the monitor-vs-contain decision framework clear and actionable?
- [ ] Were containment actions effective at each graduated level?
- [ ] Were automation opportunities identified? Add implementations to Appendix D.
- [ ] Were severity criteria accurate? Adjust if incidents were under- or over-classified.
- [ ] Were Legal/HR coordination touchpoints clearly defined and followed?
- [ ] Update **Last Reviewed** date and increment **Playbook Version**.

---

## Appendix A — Useful Queries

### CloudTrail (Athena)

```sql
-- All API activity by subject in a time window (comprehensive)
SELECT eventTime, eventName, eventSource, awsRegion, sourceIPAddress,
       userAgent, requestParameters, responseElements, errorCode, errorMessage
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%arn:aws:iam::123456789012:user/SUBJECT_USER%'
  AND eventTime BETWEEN '2026-05-01T00:00:00Z' AND '2026-05-28T23:59:59Z'
ORDER BY eventTime ASC;
```

```sql
-- High-volume API calls by subject (potential bulk operations)
SELECT eventName, eventSource, COUNT(*) as call_count,
       MIN(eventTime) as first_call, MAX(eventTime) as last_call
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%arn:aws:iam::123456789012:user/SUBJECT_USER%'
  AND eventTime BETWEEN '2026-05-01T00:00:00Z' AND '2026-05-28T23:59:59Z'
GROUP BY eventName, eventSource
HAVING call_count > 50
ORDER BY call_count DESC;
```

```sql
-- S3 objects accessed by subject — identify what data was downloaded
SELECT eventTime, JSON_EXTRACT_SCALAR(requestParameters, '$.bucketName') as bucket,
       JSON_EXTRACT_SCALAR(requestParameters, '$.key') as object_key,
       sourceIPAddress, userAgent
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%arn:aws:iam::123456789012:user/SUBJECT_USER%'
  AND eventSource = 's3.amazonaws.com'
  AND eventName = 'GetObject'
  AND eventTime BETWEEN '2026-05-01T00:00:00Z' AND '2026-05-28T23:59:59Z'
ORDER BY eventTime ASC;
```

```sql
-- Detect AssumeRole to external accounts (data staging)
SELECT eventTime, requestParameters, responseElements, sourceIPAddress
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%arn:aws:iam::123456789012:user/SUBJECT_USER%'
  AND eventName = 'AssumeRole'
  AND JSON_EXTRACT_SCALAR(requestParameters, '$.roleArn') NOT LIKE '%123456789012%'
  AND eventTime BETWEEN '2026-05-01T00:00:00Z' AND '2026-05-28T23:59:59Z'
ORDER BY eventTime ASC;
```

```sql
-- Compare subject's daily API volume to establish baseline deviation
SELECT DATE(from_iso8601_timestamp(eventTime)) as activity_date,
       COUNT(*) as total_api_calls,
       COUNT(CASE WHEN eventSource = 's3.amazonaws.com' THEN 1 END) as s3_calls,
       COUNT(CASE WHEN eventName LIKE 'Get%' THEN 1 END) as read_calls,
       COUNT(CASE WHEN eventName LIKE 'Create%' OR eventName LIKE 'Put%' THEN 1 END) as write_calls
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%arn:aws:iam::123456789012:user/SUBJECT_USER%'
  AND eventTime BETWEEN '2026-04-01T00:00:00Z' AND '2026-05-28T23:59:59Z'
GROUP BY DATE(from_iso8601_timestamp(eventTime))
ORDER BY activity_date ASC;
```

### GuardDuty Finding Export (CLI)

```bash
# List findings for a specific principal (filter by resource)
aws guardduty list-findings \
  --detector-id DETECTOR_ID \
  --finding-criteria '{
    "Criterion": {
      "resource.accessKeyDetails.userName": {
        "Eq": ["SUBJECT_USER"]
      }
    }
  }' \
  --region us-east-1

# Get full finding details
aws guardduty get-findings \
  --detector-id DETECTOR_ID \
  --finding-ids FINDING_ID_1 FINDING_ID_2
```

### Amazon Macie Finding Export (CLI)

```bash
# List Macie findings for specific S3 buckets
aws macie2 list-findings \
  --finding-criteria '{
    "criterion": {
      "resourcesAffected.s3Bucket.name": {
        "eq": ["sensitive-data-bucket"]
      }
    }
  }' \
  --sort-criteria '{"attributeName": "updatedAt", "orderBy": "DESC"}'
```

---

## Appendix B — Regulatory & Compliance Considerations

> `[Legal / Compliance]` owns this section during an active incident.

See [Regulatory Context](../REGULATORY_CONTEXT.md) for the full notification obligation matrix.

**Quick reference for insider threat scenarios:**

| Regulation | Trigger Condition | Timeframe |
|---|---|---|
| GDPR Art. 33 | Personal data confirmed accessed/exfiltrated by insider | 72 hours to supervisory authority |
| CCPA / CPRA | California resident personal information exfiltrated | 72 hours to affected individuals |
| SEC Rule 10b-5 | Material non-public information accessed (insider trading risk) | Immediate notification to Legal |
| SOX Section 302 | Financial data integrity compromised by insider | Immediate notification to Legal/Audit |
| HIPAA Breach Notification | PHI accessed without authorization (even by workforce member) | 60 days to HHS; without unreasonable delay to individuals |
| PCI DSS Req. 12.10 | Cardholder data accessed by unauthorized insider | Per incident response plan; notify acquirer |

> ⚠️ **Insider threat cases have additional legal complexity.** Employment law, whistleblower protections, and privacy regulations may limit what monitoring and evidence collection is permissible. **Always consult Legal before initiating or expanding monitoring.**

---

## Appendix C — Reference Links

- [NIST SP 800-61r3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html)
- [AWS Security Incident Response Service Documentation](https://docs.aws.amazon.com/security-ir/latest/userguide/what-is-security-ir.html)
- [AWS Well-Architected Framework — Security Pillar: Incident Response](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/incident-response.html)
- [Amazon GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [Amazon Macie User Guide](https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html)
- [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [AWS CloudTrail Query Examples (Athena)](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)
- [NIST SP 800-53 Rev. 5 — PS (Personnel Security) Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [CISA Insider Threat Mitigation Guide](https://www.cisa.gov/topics/physical-security/insider-threat-mitigation)
- [Carnegie Mellon CERT Insider Threat Center](https://www.sei.cmu.edu/our-work/insider-threat/)

---

## Appendix D — Automation Hooks

### EventBridge Rule: Off-Hours Sensitive Data Access

Triggers when S3 GetObject calls on sensitive buckets occur outside business hours from known principals.

```json
{
  "source": ["aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["s3.amazonaws.com"],
    "eventName": ["GetObject"],
    "requestParameters": {
      "bucketName": ["sensitive-data-bucket", "trade-secrets-bucket", "proprietary-code-bucket"]
    }
  }
}
```

**Target:** Lambda function that checks:
1. Is the current time outside business hours (configurable per timezone)?
2. Is the calling principal a known user (not a service role)?
3. Has the call volume exceeded baseline for this user in the past hour?

If all conditions met → Send alert to insider threat investigation SNS topic.

### EventBridge Rule: Bulk Download Alert

Triggers on CloudTrail Insights events indicating unusual S3 read volume.

```json
{
  "source": ["aws.cloudtrail"],
  "detail-type": ["AWS Insight via CloudTrail"],
  "detail": {
    "insightType": ["ApiCallRateInsight"],
    "insightContext": {
      "statistics": {
        "insightDuration": [{"numeric": [">=", 300]}]
      }
    }
  }
}
```

**Target:** Lambda function that:
1. Extracts the principal from the Insight event
2. Checks if principal is a known user (vs. service role)
3. Queries recent S3 GetObject volume for that principal
4. If volume exceeds 5x baseline → Alert insider threat team

### EventBridge Rule: IAM Self-Modification Detection

Triggers when a user modifies their own IAM permissions.

```json
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": [
      "AttachUserPolicy", "PutUserPolicy", "AddUserToGroup",
      "CreateAccessKey", "CreateLoginProfile", "UpdateAssumeRolePolicy"
    ]
  }
}
```

**Target:** Lambda function that:
1. Compares `userIdentity.arn` with the target principal in `requestParameters`
2. If the actor is modifying their own permissions → Alert immediately
3. Enriches alert with the specific permissions being added

### CloudWatch Alarm: Data Transfer Volume Anomaly

```bash
# Create alarm for unusual outbound data transfer from VPC
aws cloudwatch put-metric-alarm \
  --alarm-name "InsiderThreat-DataTransferAnomaly" \
  --namespace "AWS/EC2" \
  --metric-name "NetworkOut" \
  --dimensions Name=VpcId,Value=vpc-0123456789abcdef0 \
  --statistic Sum \
  --period 3600 \
  --threshold 10737418240 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:insider-threat-alerts \
  --alarm-description "Alert when outbound data transfer exceeds 10GB/hour from monitored VPC"
```

---

## Appendix E — Insider Threat Indicators Reference

> ⚠️ **These are technical indicators only.** The IR team does not assess intent, motivation, or behavioral patterns. These indicators trigger technical investigation — organizational response is determined by Legal/HR.

### Technical Indicators (Detected by AWS Services)

| Category | Indicator | Detection Source |
|---|---|---|
| **Data Access Anomaly** | GetObject volume >5x baseline for user | CloudTrail + CloudWatch |
| **Data Access Anomaly** | Access to buckets outside user's normal scope | Macie / CloudTrail |
| **Data Access Anomaly** | Bulk downloads during off-hours | CloudTrail + EventBridge |
| **Privilege Escalation** | User attaching policies to their own principal | CloudTrail + Config |
| **Privilege Escalation** | User creating additional access keys | CloudTrail |
| **Privilege Escalation** | User modifying role trust policies | CloudTrail + Config |
| **Data Staging** | Cross-account AssumeRole to unknown accounts | CloudTrail |
| **Data Staging** | S3 bucket policy changes granting external access | CloudTrail + Config |
| **Data Staging** | Presigned URL generation at unusual volume | CloudTrail |
| **Sabotage** | Bulk DeleteObject or TerminateInstances calls | CloudTrail + GuardDuty |
| **Sabotage** | Security control modifications (GuardDuty disable, Config disable) | CloudTrail + Config |
| **Sabotage** | KMS key deletion scheduling | CloudTrail |
| **Unauthorized Resources** | EC2/Lambda creation in unusual regions | CloudTrail |
| **Unauthorized Resources** | GPU instance launches (cryptomining indicator) | CloudTrail + Cost Explorer |
| **Unauthorized Resources** | Resources with no tags or personal-project tags | AWS Config |

### Contextual Signals (Received from HR — Not Investigated by IR)

| Signal | Risk Level | Recommended Technical Action |
|---|---|---|
| Resignation submitted | Elevated | Enable enhanced monitoring on user's activity |
| Performance improvement plan (PIP) | Elevated | Enable enhanced monitoring on user's activity |
| Termination pending | High | Enable enhanced monitoring; prepare containment |
| Contractor end-of-engagement | Elevated | Review access scope; enable monitoring |
| Role change (losing access to sensitive data) | Moderate | Monitor for pre-change bulk access |
| Reported workplace conflict | Moderate | Enable baseline monitoring |

> 📌 **HR signals are inputs to the technical monitoring decision — they are NOT evidence of wrongdoing.** Enhanced monitoring is a precautionary measure, not an accusation.

---

## Revision History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | 2026-05-28 | AWS CIRT | Initial release — insider threat detection and response for AWS environments |
