# IRP-DataAccess: Unauthorized Data Access

> **Playbook Version:** 2.1
> **Last Reviewed:** 2026-06-18
> **Status:** `Active`
> **NIST Framework:** SP 800-61r3 (CSF 2.0 Community Profile)
> **Related Playbooks:** [IRP-CredCompromise](IRP-CredCompromise.md) | [IRP-S3DataExfiltration](IRP-S3DataExfiltration.md) (Coming Soon) | [IRP-PersonalDataBreach](IRP-PersonalDataBreach.md) | [IRP-InsiderThreat](IRP-InsiderThreat.md) (Coming Soon)

---

> ⚠️ **Disclaimer:** This playbook is provided as a template only. It should be customized to suit your organization's specific needs, risks, available tools, and work processes. This guide is not official AWS documentation and is provided as-is. Security and Compliance is a shared responsibility between you and AWS. You are responsible for making your own independent assessment of the information in this document.

---

## Overview

Unauthorized data access occurs when a party — external threat actor or internal actor — accesses, copies, or exfiltrates data stored in AWS services without proper authorization. This includes bulk reads from S3 buckets, database queries extracting sensitive records, access to secrets or parameters, and download of backups or snapshots. The incident may result from compromised credentials, misconfigured resource policies, overly permissive access grants, or insider abuse. The severity depends on the sensitivity of the data accessed, the volume, and whether data left the AWS environment.

### Out of Scope

This playbook does **not** cover:

- **Bulk S3 exfiltration with specific presigned URL or VPC endpoint abuse** — For dedicated S3 exfiltration patterns, see [IRP-S3DataExfiltration](IRP-S3DataExfiltration.md). (Coming Soon)
- **Credential compromise as the root cause** — If the data access resulted from stolen credentials, start with [IRP-CredCompromise](IRP-CredCompromise.md) for containment, then return here for data impact assessment.
- **Personal data breach regulatory response** — If personal/regulated data is confirmed accessed, cross-reference [IRP-PersonalDataBreach](IRP-PersonalDataBreach.md) for notification obligations.
- **Insider threat investigation** — If the accessor is an authorized user acting outside their role, see [IRP-InsiderThreat](IRP-InsiderThreat.md). (Coming Soon)

### Applicable Finding Types

| Source | Finding / Event Type | Severity |
|---|---|---|
| Amazon GuardDuty | `Exfiltration:S3/MaliciousIPCaller` | HIGH |
| Amazon GuardDuty | `Exfiltration:S3/AnomalousBehavior` | HIGH |
| Amazon GuardDuty | `Discovery:S3/MaliciousIPCaller.Custom` | MEDIUM |
| Amazon GuardDuty | `UnauthorizedAccess:S3/MaliciousIPCaller.Custom` | HIGH |
| Amazon GuardDuty | `Policy:S3/BucketBlockPublicAccessDisabled` | LOW |
| Amazon GuardDuty | `Policy:S3/BucketAnonymousAccessGranted` | HIGH |
| Amazon Macie | Sensitive data discovery findings (PII, credentials, financial) | HIGH |
| Amazon Macie | Policy findings (public bucket, unencrypted, shared externally) | MEDIUM |
| AWS Security Hub | S3 public access findings | HIGH |
| CloudTrail | Unusual volume of `GetObject`, `GetItem`, `Query`, `Scan` events | — |
| CloudTrail | `GetSecretValue`, `GetParameter` from unexpected principals | — |
| CloudTrail | S3 data events from unfamiliar IPs or cross-account roles | — |
| AWS Config | `s3-bucket-public-read-prohibited`, `s3-bucket-public-write-prohibited` | HIGH |
| VPC Flow Logs | Large outbound data transfers to external IPs | — |

> 📌 GuardDuty finding types are updated regularly. See the [GuardDuty finding types reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) for the current list.

### Severity Classification

| Priority | Criteria |
|---|---|
| **P1 — Critical** | Confirmed exfiltration of sensitive/regulated data outside AWS, or public exposure of customer data confirmed |
| **P2 — High** | Confirmed unauthorized data access (reads confirmed), data sensitivity unclear or data hasn't left AWS yet |
| **P3 — Medium** | Anomalous data access patterns detected, no confirmed unauthorized access yet |
| **P4 — Low** | Misconfiguration found (public bucket, overly permissive policy) with no evidence of exploitation |

---

## Part 1 — Prepare

> **CSF 2.0 Functions:** Govern · Identify · Protect
> **Goal:** Ensure the right configurations, access, and processes are in place *before* this incident type occurs.

### 1.1 Recommended AWS Service Configurations

The following services each contribute to your ability to detect, investigate, and respond to unauthorized data access. None are strictly required, but each addresses a specific gap in visibility — the more you have enabled, the faster you can detect anomalous access and the more complete your forensic picture will be during an investigation.

- [ ] **Amazon GuardDuty** enabled with S3 protection activated — provides continuous threat detection for S3 exfiltration patterns, anomalous access, and malicious IP callers
- [ ] **Amazon Macie** enabled with automated sensitive data discovery on critical buckets — identifies where sensitive data lives and alerts on policy violations or unexpected access patterns
- [ ] **AWS CloudTrail** enabled with **S3 data events** for sensitive buckets (GetObject, PutObject, DeleteObject) — without data events, individual object-level access is invisible to investigation
- [ ] **AWS CloudTrail** enabled with **DynamoDB data events** for sensitive tables (if applicable) — captures individual item-level reads and writes
- [ ] **AWS Config** enabled with S3-related rules (`s3-bucket-public-read-prohibited`, `s3-bucket-ssl-requests-only`, `s3-bucket-logging-enabled`) — provides continuous compliance assessment and drift detection
- [ ] **S3 server access logging** enabled on all sensitive buckets — captures access details (including presigned URL usage) that CloudTrail data events may not cover
- [ ] **VPC Flow Logs** enabled — detects large outbound data transfers that may indicate exfiltration
- [ ] **Amazon Detective** enabled — provides graph-based investigation of access patterns, reducing time to scope impact
- [ ] **S3 Block Public Access** enabled at the account level — prevents accidental public exposure of any bucket in the account
- [ ] **AWS Security Lake** enabled — centralizes security data across services for cross-service correlation and analysis

> 🤖 **Automation opportunity:** Use Macie automated sensitive data discovery to continuously classify data in S3 buckets. Configure EventBridge rules to alert on Macie HIGH findings.
>
> 📖 **Reference:** [SEC10-BP06 Pre-deploy tools](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_deploy_tools.html) — AWS Well-Architected Framework recommends pre-deploying investigation and response tooling so capabilities are available immediately when needed.

### 1.2 IAM & Access Prerequisites

Effective incident response depends on having the right access available *before* an incident occurs. Provisioning break-glass access during an active data exfiltration wastes time and introduces risk of error under pressure. The following recommendations align with [SEC10-BP05 Pre-provision access](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_provision_access.html) from the AWS Well-Architected Framework.

- [ ] **Break-glass IAM role** with permissions to: query CloudTrail, list/get S3 objects, describe bucket policies, query Macie findings, and modify bucket policies — pre-tested and documented
- [ ] **IR team members can assume the break-glass role** with MFA from a trusted (non-production) account — validate this works at least quarterly
- [ ] **Data classification inventory** exists (which buckets/tables contain sensitive data) — you cannot assess impact without knowing what the data is
- [ ] **S3 Access Grants inventory** documented (who has access to what via Access Grants) — provides baseline for detecting unauthorized grants
- [ ] **Forensic S3 bucket** available with Object Lock enabled — optional but recommended for preserving evidence copies with tamper protection
- [ ] **Access to AWS Security Incident Response console** confirmed, if subscribed — verify case creation workflow before you need it

### 1.3 Communication & Escalation

Clear communication paths reduce confusion during high-pressure incidents. Define who needs to be involved, at what severity threshold, and through which channel *before* you need them. The goal is to avoid spending incident time figuring out who to call.

> 📋 Do not include names in this playbook. Use roles only. Maintain a separate, access-controlled contact list (e.g., internal wiki, sealed envelope, or secure document) with current names, phone numbers, and escalation preferences.

| Role | Responsibility | When to Engage |
|---|---|---|
| IR Lead | Overall incident coordination, status updates, decision authority for containment actions | All severity levels — first notified |
| Data Owner | Classify data sensitivity, authorize access restrictions, confirm legitimate access patterns | P1–P3, or when data sensitivity is unclear |
| Account Owner | Business context, authorization for containment actions that may impact services | P1–P3, or when containment may disrupt services |
| Legal / Compliance | Regulatory notification assessment, evidence hold | P1–P2, or when regulated data may have been accessed |
| Privacy Officer | Personal data impact assessment (if applicable) | When personal/health/financial data is confirmed accessed |
| AWS CIRT | Technical assistance with scoping, containment guidance, help determining if access was unauthorized | P1–P2 via AWS Support case (any support plan) or Security Incident Response service (if subscribed) |

**Escalation path:**

1. **Detection:** Automated alert (Macie, GuardDuty, Config, SIEM) or human report triggers initial notification.
2. **Triage (IR Lead, < 15 min):** IR Lead assesses severity using [Section 2.3](#23-severity-determination). Determines if the access is ongoing and whether it is confirmed unauthorized.
3. **Severity-based escalation:**
   - **P1/P2:** IR Lead notifies Data Owner and Legal/Compliance immediately. Opens AWS Support case (severity: Critical) requesting CIRT assistance. If AWS Security Incident Response service is enabled, creates a case there instead.
   - **P3/P4:** IR Lead manages internally with Data Owner. Escalates to P2 if investigation confirms unauthorized access to sensitive data.
4. **Status updates:** IR Lead provides updates to stakeholders every 30 minutes (P1), every 2 hours (P2), or at key milestones (P3/P4).

> 📖 **Reference:** [SEC10-BP01 Identify key personnel and external resources](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_identify_personnel.html) — recommends identifying and documenting internal and external resources and contact information ahead of time.

### 1.4 Game Day Guidance

Practicing incident response before a real incident occurs builds muscle memory, identifies gaps in tooling and access, and validates that escalation paths work. Data access scenarios are particularly important to rehearse because they often involve regulatory notification decisions under time pressure.

Recommended testing cadence: **Semi-annually** (P1-capable scenario with regulatory implications).

Suggested tabletop scenario:
> *"Amazon Macie has flagged a sensitive data discovery finding: a production S3 bucket containing customer PII has been accessed 4,000 times in the last hour from an IAM role in a different account. The role belongs to a third-party vendor with a data processing agreement. Normal access volume for this role is ~50 requests/hour."*

**Practice resources (no paid service or support plan required):**

- [AWS CIRT Incident Response Workshops](https://aws.amazon.com/blogs/security/aws-cirt-announces-the-release-of-five-publicly-available-workshops/) — free, hands-on workshops covering credential compromise, S3 ransomware, and more. Deployable in any AWS account.
- [AWS Incident Response Playbooks Workshop](https://github.com/aws-samples/aws-incident-response-playbooks-workshop/) — open-source workshop for building and testing IR playbooks.
- [AWS Security Workshops catalog](https://workshops.aws/categories/Security) — broader collection of security-focused hands-on labs.

> 📖 **Reference:** [SEC10-BP04 Develop and test security incident response playbooks](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_playbooks.html) — recommends creating and regularly testing playbooks to verify response processes.

---

## Part 2 — Detect & Analyse

> **CSF 2.0 Functions:** Detect · Respond (Analyse)
> **Goal:** Determine whether unauthorized data access has occurred, scope its impact, and document the evidence needed to support containment and recovery decisions.

### 2.1 Initial Triage Questions

Not every alert is a confirmed incident. The purpose of triage is to quickly determine whether you are dealing with confirmed unauthorized access, a potential issue requiring investigation, or a false positive that can be closed. Answer these questions to establish scope and urgency — each should take less than 2 minutes.

- [ ] What data store was accessed? (S3, DynamoDB, RDS, Secrets Manager, Parameter Store, Redshift, other)
- [ ] What is the data classification? (Public, internal, confidential, restricted/regulated)
- [ ] Who accessed it? (Known principal, unknown principal, cross-account, anonymous)
- [ ] Was the access authorized? (Check IAM policies, resource policies, Access Grants, Lake Formation permissions)
- [ ] Is the access confirmed unauthorized, or could it be legitimate but unusual? (New integration, batch job, vendor access within agreement)
- [ ] What volume of data was accessed? (Number of objects/records, total bytes)
- [ ] Did data leave the AWS environment? (Check VPC Flow Logs, CloudTrail for cross-region copies, external transfers)
- [ ] Is the access ongoing or historical? (Is the accessor still active?)
- [ ] Does the data include personal data, health data, financial data, or credentials?

**If regulated data confirmed accessed by unauthorized party → P1 immediately. Notify Legal.**
**If the activity is anomalous but could be legitimate → investigate further before containment (avoid unnecessary disruption).**

### 2.2 Evidence Documentation

Whether the activity is confirmed malicious or still under investigation, document the current state of the affected data stores and access patterns. For data access scenarios, the primary evidence sources are CloudTrail (with S3 data events), S3 server access logs, and Macie findings. The priority here is *documenting what you observe* rather than copying logs to a separate location.

> 📌 **Note on evidence storage:** CloudTrail logs and S3 server access logs persist in their configured destinations — they don't disappear if you don't copy them immediately. If you have a dedicated forensic S3 bucket with Object Lock, export findings there for tamper protection. If you don't, that's fine — the primary logs, findings in the console, and notes in your IR ticket are sufficient for most investigations.
>
> ⚠️ **Do not modify bucket policies or revoke access before documenting current state.** Capture the current configuration first.

**Document the following:**

| What to Document | How | Notes |
|---|---|---|
| Current bucket policy | `aws s3api get-bucket-policy --bucket BUCKET` | Capture before modification |
| Current bucket ACL | `aws s3api get-bucket-acl --bucket BUCKET` | Identify unexpected grantees |
| S3 Access Grants | `aws s3control list-access-grants --account-id ACCOUNT` | Identify unexpected grants |
| Lake Formation permissions | `aws lakeformation list-permissions` | If applicable |
| Macie findings | Macie console → Export findings | Data sensitivity classification |
| GuardDuty findings | GuardDuty console or `aws guardduty get-findings` | Threat detection context |
| VPC Flow Logs (if applicable) | CloudWatch Logs / S3 | Large outbound transfers |
| S3 server access logs | Copy from logging bucket for affected time window | Presigned URL and anonymous access |

**CloudTrail / Athena investigation queries:**

For detailed Athena queries to investigate data access (bulk read detection, principal analysis, data staging, secrets access, policy changes), see:

📁 [`resources/athena-queries-data-access.sql`](resources/athena-queries-data-access.sql)

**Quick CloudTrail Console approach (no Athena required):**

If Athena is not configured, you can investigate directly in the CloudTrail console:

1. Navigate to **CloudTrail → Event history**
2. Filter by **Event source** = `s3.amazonaws.com` and **Event name** = `GetObject`
3. Review source IPs and principals — compare against known legitimate access patterns
4. Look for volume anomalies — many `GetObject` calls in a short window from one principal
5. Check for policy modification events (`PutBucketPolicy`, `DeleteBucketPublicAccessBlock`)
6. Filter by **Event source** = `secretsmanager.amazonaws.com` to check for secrets access

> 📌 CloudTrail Event history only shows management events by default. S3 data events (GetObject, PutObject) require a trail configured with data event logging.

### 2.3 Severity Determination

| Confirmed? | Priority Assignment |
|---|---|
| Regulated/sensitive data confirmed exfiltrated outside AWS | P1 |
| Sensitive data confirmed accessed, exfiltration unclear | P2 |
| Public exposure of data confirmed (misconfigured bucket) | P2 |
| Anomalous access patterns, data sensitivity unclear | P3 |
| Misconfiguration found, no evidence of exploitation | P4 |

### 2.4 Getting Help from AWS

For P1, P2, or P3 incidents, consider engaging AWS for support. AWS Support and AWS CIRT can help you determine whether access was truly unauthorized, assist with scoping the data impact, and advise on containment approaches — you do not need to be certain of a compromise before reaching out.

- **AWS Security Incident Response service** (if enabled): Sign into [AWS Security Incident Response](https://console.aws.amazon.com/security-ir/) via the console, choose **Create Case**, select **Resolve case with AWS**, and choose **Active Security Incident** for urgent support or **Investigations and Inquiries** for log analysis and secondary confirmation of findings.
- **AWS Support** (any support plan): Open a support case requesting assistance from the AWS Customer Incident Response Team (CIRT). Include the finding ID(s), the affected data stores, and a summary of the anomalous access you have observed.

> 📌 You do not need the Security Incident Response service to get help from experts. All AWS customers can request CIRT assistance through a support case, regardless of support plan level. For P3 (anomalous access patterns, not yet confirmed), AWS CIRT can help you determine whether the activity is unauthorized or legitimate.
>
> 🤖 **Automation opportunity:** EventBridge rule on Macie HIGH-severity findings → auto-create Security Incident Response case.

---

## Part 3 — Contain

> **CSF 2.0 Function:** Respond (Contain)
> **Goal:** Stop further unauthorized data access and prevent data from leaving the environment, while minimizing disruption to legitimate users and services. Containment should be deliberate — restrict access rather than delete resources, so you preserve evidence and can reverse actions if the alert turns out to be a false positive.

### 3.1 Containment Decision

The goal of containment is to close the access path so data can no longer be reached by the threat actor, while understanding the impact of that action on legitimate users. Restricting (not deleting) is preferred because it allows you to: (1) observe if legitimate services are impacted, (2) retain the configuration for investigation, and (3) reverse the action if needed.

```text
Is data actively being exfiltrated RIGHT NOW?
│
├── YES (ongoing bulk reads, active transfer)
│     └── Proceed to 3.2 immediately — block access
│
├── PUBLIC EXPOSURE (bucket/resource is publicly accessible)
│     └── Proceed to 3.2 immediately — remove public access
│
└── HISTORICAL (access occurred in the past, not ongoing)
      └── Assess: Is the access path still open?
            ├── YES → Proceed to 3.2 (close the path)
            └── NO (credential already revoked, policy already fixed) → Skip to Part 4
```

### 3.2 Containment Actions

> `[IR Lead]` coordinates. `[Data Owner]` authorizes access restrictions. `[Account Owner]` authorizes service-impacting changes.

**Step 1: Identify the access path**

Determine HOW the unauthorized access is occurring:

| Access Path | Containment Approach |
|---|---|
| Compromised IAM credential | Revoke credential (see [IRP-CredCompromise](IRP-CredCompromise.md)) |
| Overly permissive bucket policy | Restrict bucket policy to deny the unauthorized principal |
| Public access (ACL or Block Public Access disabled) | Enable Block Public Access at the bucket level |
| Cross-account role with excessive permissions | Modify trust policy or attached permissions to block the unauthorized account |
| S3 Access Grant misconfiguration | Revoke the specific grant |
| Lake Formation permission grant | Revoke the specific permission |
| VPC endpoint policy too broad | Restrict endpoint policy to specific buckets and principals |
| Presigned URL abuse | Cannot revoke individual URLs — rotate the signing credential |

**Step 2: Block unauthorized access to S3**

Based on the identified access path, take the appropriate containment action:

- **If public exposure:** Enable S3 Block Public Access on the affected bucket. This immediately blocks all public access regardless of bucket policy or ACL settings.
- **If unauthorized principal:** Add an explicit deny statement to the bucket policy for the unauthorized principal (account, role, or user ARN). Use `"Effect": "Deny"` with `"Action": "s3:*"` on the bucket and all objects.
- **If VPC endpoint is the path:** Modify the VPC endpoint policy to restrict which principals and buckets are accessible through the endpoint.

> 📌 An explicit deny in a bucket policy overrides any allow. This is the fastest way to block a specific principal without disrupting other legitimate access.

**Step 3: Block unauthorized access to DynamoDB / other data stores**

For data stores that don't support resource-based policies (DynamoDB, Secrets Manager, SSM Parameter Store), containment must be applied at the IAM level:

- Attach an explicit deny inline policy to the unauthorized principal, blocking access to the affected data services (`dynamodb:*`, `s3:*`, `secretsmanager:*`, `ssm:GetParameter*`).
- If the unauthorized principal is in a different account, modify the trust policy on any roles they were using, or apply an SCP to the affected account.

**Step 4: Revoke S3 Access Grants (if applicable)**

If unauthorized access was via S3 Access Grants, list the grants scoped to the affected bucket and delete the unauthorized grant using the S3 Access Grants API.

**Step 5: Revoke Lake Formation permissions (if applicable)**

If unauthorized access was via Lake Formation permissions, revoke the specific permission grant for the unauthorized principal on the affected database/table.

> 🤖 **Automation opportunity:** Security Hub custom action → Lambda function that automatically enables S3 Block Public Access on flagged buckets.

### 3.3 Document Containment Actions

Record all containment actions taken, including timestamps, who performed them, and what was affected. This documentation supports the post-incident timeline (Part 5) and is important for any regulatory inquiries.

- [ ] What access path was blocked and when (timestamp, resource affected, who performed the action)
- [ ] What the bucket policy / ACL / grant looked like *before* modification (captured in Section 2.2)
- [ ] What services or applications were impacted by the access restriction
- [ ] Whether the containment was effective (did unauthorized activity stop?)
- [ ] Any additional containment actions taken (VPC endpoint changes, SCP application, credential revocation)
- [ ] Whether the threat actor had access to other data stores that also need containment

---

## Part 4 — Eradicate

> **CSF 2.0 Function:** Respond (Eradicate)
> **Goal:** Identify the root cause of the unauthorized access, remove any persistence mechanisms, and confirm the environment is clean. Eradication often uncovers additional exposed data stores — if new findings emerge during this phase, return to Part 3 (Contain) for any newly identified access paths before continuing.

### 4.1 Root Cause Identification

> `[IR Lead]` owns this step. Document findings in the IR ticket in real time.

Understanding how the unauthorized access occurred is essential before restoring access — if the root cause isn't resolved, the same exposure will recur.

Common root causes for unauthorized data access:

- **Misconfigured resource policy:** Bucket policy or ACL granting broader access than intended (wildcard principals, missing conditions)
- **Overly permissive IAM policy:** Principal had access to data beyond their role requirements
- **Credential compromise:** Threat actor used stolen credentials to access data (see [IRP-CredCompromise](IRP-CredCompromise.md))
- **Cross-account trust misconfiguration:** Role trust policy allowed assumption from unintended accounts
- **S3 Access Grants misconfiguration:** Grant scope too broad or granted to wrong identity
- **Lake Formation permission drift:** Permissions accumulated over time without review
- **VPC endpoint policy too permissive:** Allowed any principal in the VPC to access any S3 bucket
- **Presigned URL leakage:** Long-lived presigned URLs shared beyond intended recipients

### 4.2 Eradication Actions

This section focuses on data-access-specific persistence — policy changes, grants, and endpoint configurations that would allow re-access even after initial containment. If the root cause is credential compromise, address credential-based persistence using [IRP-CredCompromise](IRP-CredCompromise.md) eradication steps. For a comprehensive reference of persistence techniques observed in AWS environments, see the [Threat Technique Catalog for AWS](https://aws-samples.github.io/threat-technique-catalog-for-aws/).

**Step 1: Fix the root cause**

| Root Cause | Eradication Action |
|---|---|
| Public bucket policy | Rewrite policy with least-privilege; enable Block Public Access at account level |
| Overly permissive IAM | Use IAM Access Analyzer recommendations to scope down permissions |
| Cross-account trust | Remove unauthorized principals from trust policy |
| Access Grants | Delete or scope down the grant |
| Lake Formation | Revoke excessive permissions, implement column-level security |
| VPC endpoint | Restrict endpoint policy to specific buckets and principals |
| Presigned URL | Rotate the signing credential; reduce URL expiry to minimum needed |

**Step 2: Remove data-access-specific persistence**

Check for changes the threat actor may have made to maintain access:

- [ ] Bucket policy modifications (new principals added, conditions removed)
- [ ] S3 Access Grants created by the threat actor
- [ ] Lake Formation permissions granted by the threat actor
- [ ] VPC endpoint policy modifications
- [ ] Cross-account role trust policy modifications (adding external principals)
- [ ] S3 replication rules added (replicating data to threat-actor-controlled buckets)
- [ ] S3 event notifications added (Lambda triggers on object creation for data exfiltration)
- [ ] Lifecycle rules modified (accelerating object deletion to cover tracks)

**Step 3: Rotate any secrets or credentials that were accessed**

- [ ] Secrets Manager secrets that were read → rotate immediately
- [ ] SSM Parameter Store values that were read → update with new values
- [ ] Database credentials that were accessed → rotate at both SSM/Secrets Manager and the database level
- [ ] API keys or tokens stored in accessed objects → revoke and reissue

> ⚠️ **If you discover additional exposed data stores or persistence mechanisms during eradication, return to Part 3 (Contain) and block those access paths before continuing.** Eradication is iterative — it's common to cycle between containment and eradication multiple times.

### 4.3 Eradication Validation

Before moving to recovery, confirm that the threat actor's access has been fully removed:

- [ ] Root cause identified and fixed
- [ ] All access paths closed (policy, credential, grant, endpoint)
- [ ] All persistence mechanisms identified in 4.2 have been removed
- [ ] All accessed secrets/credentials rotated
- [ ] No additional data stores compromised (verified via CloudTrail)
- [ ] IAM Access Analyzer shows no unintended external access
- [ ] Macie scan confirms no remaining public/shared exposure
- [ ] CloudTrail shows no continued unauthorized activity for at least 30 minutes after eradication actions

> 🤖 **Automation opportunity:** AWS Config auto-remediation for `s3-bucket-public-read-prohibited` can automatically re-enable Block Public Access if it's disabled.

---

## Part 4b — Recover

> **CSF 2.0 Function:** Recover
> **Goal:** Restore legitimate access, remove containment controls, and harden the environment against recurrence. Recovery should only proceed once eradication is validated — restoring access prematurely can re-expose the environment if persistence mechanisms were missed.

### 4.4 Restore Legitimate Access

> ⚠️ Before restoring access, confirm eradication validation (Section 4.3) is complete.

1. **Restore proper access** — ensure legitimate users/services can still access the data they need. If bucket policies were restricted during containment, carefully re-enable only the required access.
2. **Verify applications** dependent on the data store are functioning. Check application health metrics and logs for access errors.
3. **If access was overly restricted during containment**, carefully re-enable legitimate access. Review each permission before re-granting — this is an opportunity to implement least privilege.

### 4.5 Harden Against Recurrence

Based on the root cause identified in Section 4.1, implement targeted hardening:

- [ ] **Enable S3 Block Public Access at the account level** (not just bucket level) — prevents future accidental public exposure
- [ ] **Implement S3 bucket policies with explicit deny** for cross-account access unless specifically needed
- [ ] **Enable Macie automated sensitive data discovery** on all buckets — ensures data classification stays current
- [ ] **Implement VPC endpoint policies** that restrict S3 access to specific buckets
- [ ] **Enable S3 Object Lock** on buckets containing critical data
- [ ] **Review and reduce IAM permissions** using Access Analyzer unused access findings
- [ ] **Implement SCPs** to prevent disabling of S3 Block Public Access
- [ ] **Consider S3 Access Points** for fine-grained access control
- [ ] **Enable CloudTrail data events** for all sensitive data stores (not just management events)
- [ ] **Address the specific root cause:**
  - If public exposure: implement account-level Block Public Access SCP, enable Config rule with auto-remediation
  - If permission drift: implement regular access reviews, use Access Analyzer to detect unused permissions
  - If VPC endpoint: implement restrictive endpoint policies as default, use condition keys in bucket policies
  - If presigned URL: reduce URL expiry, implement VPC endpoint conditions on bucket policies

### 4.6 Recovery Validation

- [ ] Legitimate access patterns restored and verified
- [ ] Applications and services that use the data stores are functioning normally
- [ ] No GuardDuty or Macie findings related to this incident remain active
- [ ] IAM Access Analyzer shows no unintended external or unused access
- [ ] Application health metrics normal
- [ ] Data integrity verified (no unauthorized modifications or deletions)
- [ ] All containment controls have been removed
- [ ] Monitoring and alerting confirmed operational for affected data stores
- [ ] AWS Security Incident Response case updated (if applicable)

---

## Part 5 — Post-Incident Activity

> **CSF 2.0 Function:** Identify (Improve) — continuous improvement, not a one-time activity
> **Goal:** Capture what happened, when, and why — then use those findings to improve detection, response, and prevention for next time. Post-incident activity is not a one-time report; it generates action items that feed back into Part 1 (Prepare) for this and other playbooks.

### 5.1 Timeline Reconstruction

Build a complete timeline of the incident from initial unauthorized access through recovery. This should be completed within 24–48 hours while events are fresh and CloudTrail data is readily queryable. A clear timeline supports post-incident review, regulatory inquiries, and future detection tuning.

| Timestamp (UTC) | Event | Source / Evidence | Actor |
|---|---|---|---|
| | Data first accessed by unauthorized party | CloudTrail data events | Threat actor |
| | Detection alert fired | Macie / GuardDuty / custom | AWS / tooling |
| | IR team notified | On-call alert | IR Lead |
| | Data sensitivity confirmed | Data Owner / Macie | Data Owner |
| | Access path blocked (containment) | CloudTrail | IR team |
| | Root cause fixed (eradication) | CloudTrail | IR team |
| | Recovery validated | IR ticket | IR Lead |

**Key metrics:**

These metrics help you measure response effectiveness over time and identify where investment would reduce future incident duration.

| Metric | Value | Why It Matters |
|---|---|---|
| Time to Detect (TTD) | *Time from first unauthorized access to detection alert* | Measures detection coverage — are data events and Macie catching anomalies? |
| Time to Notify (TTN) | *Time from detection to IR team notified* | Measures alerting pipeline effectiveness |
| Time to Contain (TTC) | *Time from notification to access path blocked* | Measures response readiness and pre-provisioned access |
| Time to Recover (TTR) | *Time from containment to recovery validated* | Measures eradication thoroughness |
| Total Incident Duration | | End-to-end impact window |
| Data Volume Accessed | *Objects/records count, bytes* | Determines notification scope and business impact |
| Data Sensitivity | *Classification level* | Drives regulatory notification decisions |
| Data Exfiltrated? | *Confirmed / Suspected / No* | Determines severity of regulatory response |
| Regulatory Notification Required? | *Yes / No / Under assessment* | Legal/compliance outcome |

### 5.2 Post-Incident Review

Conduct a blameless post-incident review within **5 business days** for P1/P2, **15 business days** for P3/P4. The goal is to identify systemic improvements, not assign blame. Include all stakeholders who participated in the response.

Discussion questions specific to data access:

1. Why was this data accessible to the unauthorized party? Was least privilege applied?
2. Was the data classified correctly? Did we know it was sensitive before the incident?
3. How long was the data exposed before detection? Could Macie or GuardDuty have caught it sooner?
4. Were CloudTrail data events enabled? If not, would they have provided earlier detection?
5. Was the data encrypted? Did encryption provide any protection in this scenario?
6. Should this data be in a more restricted environment (dedicated account, VPC endpoint only)?
7. Are there other data stores with similar exposure risk? (Conduct a broader audit)
8. Were our preparation steps (Part 1) adequate? Did we have the access, tools, and documentation we needed?

### 5.3 Detection Gap Analysis

For each gap identified during the incident — whether a detection that didn't fire, an alert that wasn't actioned, or a blind spot in coverage — document the root cause and assign an owner to fix it. Detection gaps are the most actionable output of a post-incident review because they directly reduce future time-to-detect.

| Gap | Root Cause | Recommended Fix | Owner | Target Date |
|---|---|---|---|---|
| *(e.g., No alert on bulk S3 reads)* | *(CloudTrail data events not enabled)* | *(Enable data events for sensitive buckets)* | | |
| *(e.g., Public bucket existed for 6 months)* | *(No Macie policy finding alerting)* | *(Enable Macie policy findings + EventBridge alert)* | | |
| *(e.g., Cross-account access not detected)* | *(No IAM Access Analyzer external access analyzer)* | *(Enable Access Analyzer in all accounts)* | | |

### 5.4 Playbook Update Checklist

Use this incident to improve this playbook. Do not wait for the next scheduled review — update immediately while the gaps are clear. Each incident is an opportunity to make the next response faster and more effective.

- [ ] Were triage questions (Part 2) sufficient? Add/remove as needed.
- [ ] Were evidence documentation steps accurate for the data store involved?
- [ ] Were containment actions effective? Any legitimate access disrupted?
- [ ] Were any new access patterns observed that aren't covered in the containment table?
- [ ] Were automation opportunities identified? Add references to relevant sections.
- [ ] Were severity criteria accurate? Did this incident get classified at the right level?
- [ ] Update **Last Reviewed** date and increment **Playbook Version**.

---

## Appendix A — Investigation Resources

For detailed Athena queries, S3 server access log analysis, and CLI commands relevant to data access investigations, see:

📁 [`resources/athena-queries-data-access.sql`](resources/athena-queries-data-access.sql)

These queries cover:

- All S3 data access events for a specific bucket
- Top accessors of a bucket (identifying anomalous principals)
- Bulk data access detection (high-volume reads in short time)
- DynamoDB data access (Scan operations as exfiltration indicators)
- Secrets Manager / Parameter Store access
- Principal-grouped access counts and time windows
- Data staging detection (copies to other buckets or accounts)
- Specific objects accessed (for impact assessment)
- Bucket policy and ACL changes (persistence via policy modification)
- S3 server access log analysis (presigned URLs and anonymous access)
- Cross-bucket access by a suspect principal
- Data copy and snapshot operations (confirming exfiltration)

**Macie CLI commands:**

```bash
# List Macie findings for a specific bucket
aws macie2 list-findings \
  --finding-criteria '{
    "criterion": {
      "resourcesAffected.s3Bucket.name": {"eq": ["BUCKET_NAME"]},
      "severity.description": {"eq": ["High", "Critical"]}
    }
  }'

# Get finding details
aws macie2 get-findings --finding-ids FINDING_ID_1 FINDING_ID_2
```

**IAM Access Analyzer CLI:**

```bash
# Check for external access to S3 buckets
aws accessanalyzer list-findings \
  --analyzer-arn arn:aws:access-analyzer:REGION:ACCOUNT:analyzer/ANALYZER_NAME \
  --filter '{
    "resourceType": {"eq": ["AWS::S3::Bucket"]},
    "status": {"eq": ["ACTIVE"]}
  }'
```

---

## Appendix B — Regulatory & Compliance Considerations

> `[Legal / Compliance]` owns this section during an active incident.

See [Regulatory Context](../REGULATORY_CONTEXT.md) for the full notification obligation matrix.

**Quick reference for data access incidents:**

| Regulation | Trigger Condition | Timeframe |
|---|---|---|
| GDPR Art. 33 | Personal data of EU residents confirmed accessed | 72 hours to supervisory authority |
| GDPR Art. 34 | High risk to individuals (bulk PII, financial, health) | Without undue delay to individuals |
| HIPAA | Protected health information accessed | 60 days to HHS + individuals |
| PCI-DSS | Cardholder data accessed | Immediately to card brands |
| CCPA/CPRA | California resident personal information accessed | "Most expedient time possible" |
| PIPEDA | Personal information accessed, real risk of significant harm | As soon as feasible to OPC + individuals |

> ⚠️ The clock starts at **awareness**. If you know sensitive data was accessed, assume notification is required until Legal confirms otherwise.

---

## Appendix C — Reference Links

- [NIST SP 800-61r3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html)
- [AWS Security Incident Response Service](https://docs.aws.amazon.com/security-ir/latest/userguide/what-is-security-ir.html)
- [AWS Well-Architected Framework — Security Pillar: Incident Response](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/incident-response.html)
- [Amazon Macie User Guide](https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html)
- [S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [S3 Access Grants](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-grants.html)
- [S3 Access Points](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-points.html)
- [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [AWS Lake Formation Permissions](https://docs.aws.amazon.com/lake-formation/latest/dg/lake-formation-permissions.html)
- [CloudTrail Data Events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- [VPC Endpoint Policies for S3](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html)
- [Amazon GuardDuty S3 Protection](https://docs.aws.amazon.com/guardduty/latest/ug/s3-protection.html)
- [AWS CIRT Incident Response Workshops](https://aws.amazon.com/blogs/security/aws-cirt-announces-the-release-of-five-publicly-available-workshops/)
- [Threat Technique Catalog for AWS](https://aws-samples.github.io/threat-technique-catalog-for-aws/)

---

## Revision History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | 2020-10-01 | AWS | Initial release |
| 2.0 | 2026-05-28 | AWS CIRT | Full rewrite: NIST r3 alignment, template standardization, added Macie integration, S3 Access Grants, Lake Formation, VPC endpoint policies, IAM Access Analyzer, AWS Security IR service, expanded Athena queries, data classification guidance |
| 2.1 | 2026-06-18 | AWS CIRT | Structural refresh: separated eradication and recovery phases, moved Athena queries to resources file, added context paragraphs and Well-Architected references, removed inline bash commands in favour of procedural descriptions, added "Why It Matters" to metrics, expanded escalation path, added practice workshop resources |
