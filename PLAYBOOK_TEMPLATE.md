<!--
  CONTRIBUTOR NOTE:
  - Delete all italicized placeholder text when filling in this template.
  - Sections marked "if applicable" can be removed entirely if not relevant to your scenario.
  - Refer to CONTRIBUTING.md for quality checklist and submission guidelines.
  - Use P1–P4 severity nomenclature consistently (see Severity Classification section).
-->

# IRP-[INCIDENT-TYPE]: [Incident Type Display Name]

> **Playbook Version:** 1.0
> **Last Reviewed:** YYYY-MM-DD
> **Status:** `Draft` | `Active` | `Deprecated`
> **NIST Framework:** SP 800-61r3 (CSF 2.0 Community Profile)
> **Related Playbooks:** [IRP-CredCompromise](../IRP-CredCompromise.md) | [IRP-Ransomware](../IRP-Ransomware.md) | *(add as applicable)*

---

> ⚠️ **Disclaimer:** This playbook is provided as a template only. It should be customized to suit your organization's specific needs, risks, available tools, and work processes. This guide is not official AWS documentation and is provided as-is. Security and Compliance is a shared responsibility between you and AWS. You are responsible for making your own independent assessment of the information in this document.

---

## Overview

**One-paragraph summary of this incident type:** What it is, how it typically manifests in AWS environments, and why it matters. Keep this to 3–5 sentences — just enough context for a responder who may be new to this scenario.

### Out of Scope

This playbook does **not** cover:

- *(e.g., "If you are seeing AssumeRole chain abuse without initial credential theft, see [IRP-STSTokenAbuse](../IRP-STSTokenAbuse.md) instead.")*
- *(e.g., "For ransomware that originated from this compromise type, pivot to [IRP-Ransomware](../IRP-Ransomware.md) once containment here is complete.")*
- *(List 2–4 adjacent scenarios and where to route them)*

### Applicable Finding Types

List the detection signals that should route a responder to this playbook.

| Source | Finding / Event Type | Severity |
|---|---|---|
| Amazon GuardDuty | `GuardDuty:FindingType/Example` | HIGH |
| AWS Security Hub | `Control ID / Finding Title` | CRITICAL |
| CloudTrail | `eventName: ExampleAPI` | — |
| Custom / Third-Party | *(describe)* | — |

> 📌 GuardDuty finding types are updated regularly. See the [GuardDuty finding types reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) for the current list.

### Severity Classification

Use this table to determine incident priority at time of detection. Escalate immediately if P1 criteria are met.

| Priority | Criteria |
|---|---|
| **P1 — Critical** | *(e.g., active data exfiltration confirmed, production account fully compromised)* |
| **P2 — High** | *(e.g., suspicious activity confirmed but blast radius unclear)* |
| **P3 — Medium** | *(e.g., anomalous behavior detected, no confirmed impact yet)* |
| **P4 — Low** | *(e.g., policy violation with no active threat, informational finding)* |

---

## Part 1 — Prepare

> **CSF 2.0 Functions:** Govern · Identify · Protect
> **Goal:** Ensure the right configurations, access, and processes are in place *before* this incident type occurs.

### 1.1 Required AWS Service Configurations

Confirm the following are enabled and configured in all applicable accounts and regions before an incident occurs.

- [ ] Amazon GuardDuty enabled with findings exported to Security Hub
- [ ] AWS CloudTrail enabled with multi-region trail logging to S3 with integrity validation
- [ ] AWS Config enabled with delivery channel configured
- [ ] VPC Flow Logs enabled for all relevant VPCs
- [ ] S3 access logging enabled on sensitive buckets
- [ ] Amazon Detective enabled (for graph-based investigation)
- [ ] *(Add scenario-specific requirements here)*

> 🤖 **Automation opportunity:** Use AWS Config conformance packs or Security Hub standards to continuously validate these prerequisites. [Link TBD]

### 1.2 IAM & Access Prerequisites

Ensure the following access is pre-provisioned and tested — *do not provision break-glass access during an active incident*.

- [ ] Break-glass IAM role with least-privilege IR permissions exists and is documented
- [ ] IR team members can assume the break-glass role with MFA
- [ ] Access to AWS Security Incident Response console (if subscribed) is confirmed
- [ ] Forensic account (isolated) is available for evidence preservation
- [ ] *(Add scenario-specific IAM requirements)*

### 1.3 Communication & Escalation

> 📋 Do not include names. Use roles only. Maintain a separate, access-controlled contact list.

| Role | Responsibility |
|---|---|
| IR Lead | Overall incident coordination, status updates |
| Account Owner | Business context, authorization for containment actions |
| Legal / Compliance | Regulatory notification obligations, evidence hold |
| Communications | Internal and external messaging |
| AWS CIRT | Engage via AWS Support case or Security Incident Response service (P1/P2, if available) |
| *(Add role)* | *(Add responsibility)* |

**Escalation path:**
Detection → IR Lead notified → Severity assessed → P1/P2: AWS CIRT engaged, Legal notified → P3/P4: IR Lead manages internally

### 1.4 Game Day Guidance

This playbook should be exercised before it is needed. Recommended testing cadence: **annually at minimum, semi-annually for P1 scenarios.**

Suggested tabletop scenario for this incident type:
> *[Describe a 2–3 sentence scenario prompt that an exercise facilitator can use to kick off a tabletop for this specific incident type.]*

Reference: [AWS Security Incident Response Game Days](https://docs.aws.amazon.com/security-ir/latest/userguide/game-days.html)

---

## Part 2 — Detect & Analyze

> **CSF 2.0 Functions:** Detect · Respond (Analyze)
> **Goal:** Confirm whether an incident has occurred, scope its impact, and gather evidence for containment and investigation.

### 2.1 Initial Triage Questions

Answer these quickly to determine scope and priority. Each question should take < 2 minutes to answer.

- [ ] Is this a confirmed incident or an anomalous finding requiring investigation?
- [ ] Which AWS accounts and regions are potentially affected?
- [ ] Are production workloads or sensitive data involved?
- [ ] Is the threat actor potentially still active in the environment?
- [ ] Has any data left the AWS environment (exfiltration)?
- [ ] Are there downstream customers, partners, or regulatory implications?
- [ ] *(Add scenario-specific triage questions)*

**If 3 or more questions are answered YES → escalate to P1 immediately.**

### 2.2 Evidence Collection Checklist

Collect and preserve the following **before taking any containment actions**. Evidence collected after containment may be incomplete or altered.

> ⚠️ **Do not terminate instances or delete resources before snapshotting and preserving evidence.**

| Evidence Type | How to Collect | Where to Store |
|---|---|---|
| CloudTrail logs (relevant time window) | AWS Console / Athena query / CLI | Forensic S3 bucket |
| GuardDuty finding JSON | GuardDuty console → Export | Forensic S3 bucket |
| VPC Flow Logs | CloudWatch Logs / S3 | Forensic S3 bucket |
| EC2 instance memory / disk snapshot | *(if applicable)* | Forensic account |
| IAM credential last-used data | `aws iam get-credential-report` | IR ticket / notes |
| *(Add scenario-specific evidence)* | | |

**Useful CloudTrail / Athena queries for this scenario:**

```sql
-- Example: Find all API calls from a suspected IAM principal in a time window
SELECT eventTime, eventName, sourceIPAddress, userAgent, errorCode
FROM cloudtrail_logs
WHERE userIdentity.arn LIKE '%SUSPECTED_PRINCIPAL%'
  AND eventTime BETWEEN '2024-01-01T00:00:00Z' AND '2024-01-02T00:00:00Z'
ORDER BY eventTime ASC;
```

> *(Add 2–3 queries specific to this incident type. Contributors: the generic queries in Appendix A are starting points — the real value is scenario-specific queries. See [CloudTrail query examples](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html).)*

### 2.3 Severity Determination

Based on triage and initial evidence, assign a priority using the criteria in [Severity Classification](#severity-classification).

| Confirmed? | Priority Assignment |
|---|---|
| Active threat actor in environment | P1 |
| Confirmed data impact, actor no longer active | P2 |
| Suspicious activity, scope unclear | P3 |
| Policy violation, no active threat | P4 |

### 2.4 Getting Help from AWS

For P1 or P2 incidents, consider engaging AWS for additional support:

- **AWS Security Incident Response service** (if enabled): Open a case via the [Security Incident Response console](https://console.aws.amazon.com/security-ir/), attach relevant findings, and grant AWS CIRT access to the affected account(s).
- **AWS Support** (any AWS Support plan): Open a support case with severity "Critical" or "Urgent" and request assistance from the AWS Customer Incident Response Team (CIRT).
- **AWS Trust & Safety** (for abuse reports): If the incident involves resources being used to attack others, report via the [AWS abuse form](https://support.aws.amazon.com/#/contacts/report-abuse).

> 📌 You do not need the AWS Security Incident Response service to get help. All AWS customers can request CIRT assistance through a support case, regardless of support plan level. The Security Incident Response service provides additional automation, case management, and proactive triage capabilities.

---

## Part 3 — Contain

> **CSF 2.0 Function:** Respond (Contain)
> **Goal:** Stop the spread of the incident and prevent further damage without destroying evidence.

### 3.1 Containment Decision

Before acting, consider the tradeoff:

```
Is containment action required immediately?
│
├── YES (active exfiltration / lateral movement)
│     └── Proceed to 3.2 — accept potential service disruption
│
└── NO (threat appears inactive)
      └── Consult Account Owner and IR Lead before proceeding
            Can we contain without service disruption?
            ├── YES → Proceed to 3.2
            └── NO  → Document business impact, obtain authorization, then proceed
```

### 3.2 Containment Actions

> `[IR Lead]` coordinates. `[Account Owner]` authorizes actions that may cause service disruption.

**Step-by-step containment for this incident type:**

1. **Step title**
   Description of the action. Be specific — include CLI commands or console navigation path where possible.
   ```bash
   # Example CLI command
   aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --user-name compromised-user
   ```

2. **Step title**
   *(Repeat as needed)*

3. **Isolate affected resource(s)**
   *(Describe isolation approach specific to this incident — e.g., security group modification, IAM policy deny, network ACL)*
   ```bash
   # Example: Attach restrictive security group to isolate EC2 instance
   aws ec2 modify-instance-attribute \
     --instance-id i-1234567890abcdef0 \
     --groups sg-forensic-isolation
   ```

> 🤖 **Automation opportunity:** AWS Systems Manager Automation runbook for [describe action]. [Link TBD]

### 3.3 Evidence Preservation Reminders

After containment begins, ensure the following before modifying or terminating any resources:

- [ ] EBS snapshots taken for all affected EC2 instances
- [ ] Memory capture completed (if required for this incident type)
- [ ] All relevant logs exported to forensic S3 bucket
- [ ] S3 Object Lock or legal hold applied to forensic bucket
- [ ] CloudTrail integrity validation confirmed on exported logs

---

## Part 4 — Eradicate & Recover

> **CSF 2.0 Function:** Respond (Eradicate) · Recover
> **Goal:** Remove the root cause, validate the environment is clean, and restore normal operations.

### 4.1 Root Cause Identification

> `[IR Lead]` owns this step. Document findings in the IR ticket in real time.

Determine the root cause before beginning eradication. Common root causes for this incident type:

- *(List 3–5 common root causes specific to this scenario)*
- *(e.g., for CredCompromise: hardcoded credentials in public repo, phishing, overly permissive IAM policy)*

Use evidence collected in Part 2 to trace the initial access vector and full attack path.

### 4.2 Eradication Actions

> `[IR Lead]` coordinates. `[Account Owner]` approves changes to production resources.

1. **Step title**
   *(Specific remediation action)*

2. **Step title**
   *(Repeat as needed)*

3. **Remove attacker persistence mechanisms**
   Check for and remove:
   - [ ] Unauthorized IAM users, roles, or access keys created during incident
   - [ ] Unauthorized Lambda functions, EC2 instances, or other resources
   - [ ] Modified SCPs, resource policies, or trust relationships
   - [ ] Backdoors in application code or configuration
   - [ ] *(Add scenario-specific persistence mechanisms)*

> 🤖 **Automation opportunity:** AWS Config auto-remediation rules can detect and revert some configuration changes automatically. [Link TBD]

### 4.3 Recovery Actions

1. **Restore from known-good state**
   *(Describe restore procedure — AMI, backup, IaC re-deployment, etc.)*

2. **Re-enable services and access**
   - [ ] Restore IAM access for legitimate principals (with new credentials)
   - [ ] Re-enable any services suspended during containment
   - [ ] Validate application functionality

3. **Harden against recurrence**
   - [ ] *(Specific hardening action for this incident type)*
   - [ ] *(e.g., enable MFA enforcement, rotate all credentials, restrict public access)*

### 4.4 Recovery Validation

Confirm the environment is clean before declaring the incident resolved.

- [ ] No unauthorized resources remain in affected accounts
- [ ] All credentials created or used by attacker have been revoked
- [ ] GuardDuty / Security Hub show no active findings related to this incident
- [ ] Application and service health metrics are within normal range
- [ ] Monitoring and alerting confirmed operational
- [ ] AWS Security Incident Response case updated / closed (if applicable)

---

## Part 5 — Post-Incident Activity

> **CSF 2.0 Function:** Identify (Improve) — continuous improvement, not a one-time activity
> **Goal:** Learn from this incident to reduce the likelihood and impact of future occurrences.

### 5.1 Timeline Reconstruction

Document the full incident timeline. Complete this within 24–48 hours while memory is fresh.

| Timestamp (UTC) | Event | Source / Evidence | Actor |
|---|---|---|---|
| YYYY-MM-DD HH:MM | *(e.g., Initial compromise occurred)* | CloudTrail log | Threat actor |
| YYYY-MM-DD HH:MM | *(e.g., GuardDuty finding generated)* | GuardDuty | AWS |
| YYYY-MM-DD HH:MM | *(e.g., IR team notified)* | On-call alert | IR Lead |
| YYYY-MM-DD HH:MM | *(e.g., Containment completed)* | IR ticket | IR Lead |
| YYYY-MM-DD HH:MM | *(e.g., Recovery validated)* | IR ticket | IR Lead |

**Key metrics to capture:**

| Metric | Value |
|---|---|
| Time to Detect (TTD) | *HH:MM from initial event to detection* |
| Time to Notify (TTN) | *HH:MM from detection to IR team notified* |
| Time to Contain (TTC) | *HH:MM from notification to containment* |
| Time to Recover (TTR) | *HH:MM from containment to recovery validated* |
| Total Incident Duration | *HH:MM* |
| Affected Resources | *Count and type* |
| Data Impact | *Confirmed / Suspected / None* |

### 5.2 Post-Incident Review

Conduct a blameless post-incident review within **5 business days** for P1/P2, **15 business days** for P3/P4.

Discussion questions:

1. What was the initial access vector? Could it have been prevented with existing controls?
2. How was the incident detected? Was detection fast enough?
3. Were the right people notified at the right time?
4. Did containment actions work as expected? Were there unintended side effects?
5. Were there any gaps in runbooks, automation, or tooling that slowed response?
6. What would have reduced the blast radius?
7. What single change would most improve our response to this scenario in future?

### 5.3 Detection Gap Analysis

For each detection source that *did not* catch this incident early, document why and what would have:

| Gap | Root Cause | Recommended Fix | Owner | Target Date |
|---|---|---|---|---|
| *(e.g., GuardDuty finding suppressed)* | *(Suppression rule too broad)* | *(Narrow suppression rule)* | | |
| *(e.g., No alert on root API usage)* | *(CloudWatch alarm not configured)* | *(Create alarm for root API calls)* | | |

### 5.4 Playbook Update Checklist

Review and update this playbook based on what you learned. Do not wait for the next scheduled review.

- [ ] Were triage questions sufficient? Add/remove as needed.
- [ ] Were evidence collection steps accurate for this scenario?
- [ ] Were containment actions effective? Update steps if not.
- [ ] Were any automation opportunities identified? Add stubs to relevant sections.
- [ ] Were severity criteria accurate? Adjust if incidents were under- or over-classified.
- [ ] Update **Last Reviewed** date and increment **Playbook Version**.

---

## Appendix A — Useful Queries

### CloudTrail (Athena)

```sql
-- Template query: All API activity in a time window for a specific principal
SELECT eventTime, eventName, awsRegion, sourceIPAddress, userAgent,
       errorCode, errorMessage
FROM cloudtrail_logs
WHERE userIdentity.arn = 'arn:aws:iam::123456789012:user/SUSPECTED_USER'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
```

```sql
-- Template query: High-volume API calls (potential enumeration or exfiltration)
SELECT eventName, COUNT(*) as call_count, sourceIPAddress
FROM cloudtrail_logs
WHERE eventTime BETWEEN 'START_TIME' AND 'END_TIME'
GROUP BY eventName, sourceIPAddress
HAVING call_count > 100
ORDER BY call_count DESC;
```

> **Contributors:** The generic queries above are starting points. The real value is scenario-specific queries — e.g., "find all AssumeRole calls that crossed account boundaries" for the STS playbook, or "identify S3 GetObject calls exceeding normal volume" for data exfiltration. Please add 2–3 queries tailored to this incident type.

### GuardDuty Finding Export (CLI)

```bash
# List findings for a detector filtered by severity
aws guardduty list-findings \
  --detector-id DETECTOR_ID \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}' \
  --region us-east-1

# Get full finding details
aws guardduty get-findings \
  --detector-id DETECTOR_ID \
  --finding-ids FINDING_ID_1 FINDING_ID_2
```

---

## Appendix B — Regulatory & Compliance Considerations

> `[Legal / Compliance]` owns this section during an active incident.

See [Regulatory Context](../REGULATORY_CONTEXT.md) for the full notification obligation matrix by regulation and incident type.

**Quick reference for this scenario:**

| Regulation | Trigger Condition | Timeframe |
|---|---|---|
| *(e.g., GDPR Art. 33)* | *(e.g., Personal data confirmed accessed)* | *(e.g., 72 hours to supervisory authority)* |
| *(Add only rows relevant to this specific incident type)* | | |

> ⚠️ The clock starts at **awareness**, not confirmation. When in doubt, assume notification is required and consult Legal immediately.

---

## Appendix C — Reference Links

- [NIST SP 800-61r3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html)
- [AWS Security Incident Response Service Documentation](https://docs.aws.amazon.com/security-ir/latest/userguide/what-is-security-ir.html)
- [AWS Well-Architected Framework — Security Pillar: Incident Response](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/incident-response.html)
- [Amazon GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [AWS CloudTrail Query Examples (Athena)](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)
- *(Add scenario-specific references)*

---

## Revision History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | YYYY-MM-DD | *(Author / team)* | Initial draft |
