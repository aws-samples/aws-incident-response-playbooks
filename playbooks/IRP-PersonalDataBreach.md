# IRP-PersonalDataBreach: Personal Data Breach Response

> **Playbook Version:** 2.1
> **Last Reviewed:** 2026-06-18
> **Status:** `Active`
> **NIST Framework:** SP 800-61r3 (CSF 2.0 Community Profile)
> **Related Playbooks:** [IRP-DataAccess](IRP-DataAccess.md) | [IRP-CredCompromise](IRP-CredCompromise.md) | [IRP-InsiderThreat](IRP-InsiderThreat.md) (Coming Soon) | [IRP-Ransomware](IRP-Ransomware.md)

---

> ⚠️ **Disclaimer:** This playbook is provided as a template only. It should be customized to suit your organization's specific needs, risks, available tools, and work processes. This guide is not official AWS documentation and is provided as-is. Security and Compliance is a shared responsibility between you and AWS. You are responsible for making your own independent assessment of the information in this document.

---

## Overview

A personal data breach occurs when personal, regulated, or sensitive data is confirmed to have been accessed, disclosed, altered, or destroyed without authorization. This playbook is activated when an incident — potentially already being handled technically by another playbook — is confirmed to involve personal or regulated data. The focus here is on **regulatory obligation assessment, notification timeline management, evidence preservation for regulators, and individual notification coordination**. Technical containment may already be underway via IRP-CredCompromise, IRP-DataAccess, or IRP-InsiderThreat; this playbook runs in parallel to manage the legal, privacy, and communications workstream that a personal data breach triggers.

### Out of Scope

This playbook does **not** cover:

- **Unauthorized data access without personal data involvement** — If the accessed data is purely operational (infrastructure configs, non-personal telemetry), see [IRP-DataAccess](IRP-DataAccess.md) for technical response only.
- **Credential compromise as the initial vector** — If you are still investigating the initial access method, see [IRP-CredCompromise](IRP-CredCompromise.md). Return here once personal data involvement is confirmed.
- **Insider threat investigation and HR coordination** — If the breach was caused by an authorized insider acting outside their role, see [IRP-InsiderThreat](IRP-InsiderThreat.md) (Coming Soon) for the personnel and investigation aspects. This playbook still applies for the notification obligations.
- **Ransomware with data unavailability** — If personal data has been encrypted (availability breach under GDPR), pivot to [IRP-Ransomware](IRP-Ransomware.md) for technical recovery while continuing notification assessment here.

### Applicable Finding Types

| Source | Finding / Event Type | Severity |
|---|---|---|
| Amazon Macie | `SensitiveData:S3Object/Personal` | HIGH |
| Amazon Macie | `SensitiveData:S3Object/Financial` | HIGH |
| Amazon Macie | `SensitiveData:S3Object/Credentials` | CRITICAL |
| Amazon Macie | `Policy:IAMUser/S3BucketPublic` (on buckets with PII) | CRITICAL |
| Amazon GuardDuty | `Exfiltration:S3/MaliciousIPCaller` | HIGH |
| Amazon GuardDuty | `Exfiltration:S3/AnomalousBehavior` | HIGH |
| Amazon GuardDuty | `UnauthorizedAccess:S3/TorIPCaller` | HIGH |
| Amazon GuardDuty | `Discovery:S3/AnomalousBehavior` | MEDIUM |
| AWS Security Hub | S3 bucket findings on data stores containing personal data | HIGH |
| CloudTrail | `eventName: GetObject` (bulk access to PII-classified buckets) | — |
| CloudTrail | `eventName: CopyObject` (cross-account copy of personal data) | — |
| CloudTrail | `eventName: SelectObjectContent` (S3 Select on PII buckets) | — |
| Third-Party DLP | Data loss prevention alerts indicating PII in transit | HIGH |
| External Report | Customer/individual report of data misuse or exposure | — |

> 📌 Amazon Macie sensitive data discovery jobs and automated discovery provide the primary signal for personal data classification. See the [Macie finding types reference](https://docs.aws.amazon.com/macie/latest/user/findings-types.html) for the current list.

> 📌 GuardDuty finding types are updated regularly. See the [GuardDuty finding types reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) for the current list.

### Severity Classification

| Priority | Criteria |
|---|---|
| **P1 — Critical** | Confirmed exfiltration of personal data outside the AWS environment, large-scale breach, or data types with high harm potential (health, financial, biometric, children's data) |
| **P2 — High** | Confirmed unauthorized access to personal data, data may have left the environment, or regulatory notification deadline is imminent (<24 hours remaining on 72-hour clock) |
| **P3 — Medium** | Personal data exposure suspected but not confirmed (e.g., bucket was public but access logs show no external downloads), or low-sensitivity data with limited individual count |
| **P4 — Low** | Policy violation involving personal data stores with no evidence of unauthorized access (e.g., encryption disabled briefly, access logging gap) |

---

## Part 1 — Prepare

> **CSF 2.0 Functions:** Govern · Identify · Protect
> **Goal:** Ensure the right configurations, access, and processes are in place *before* this incident type occurs.

### 1.1 Recommended AWS Service Configurations

The following services each contribute to your ability to detect, scope, and document a personal data breach for regulatory purposes. None are strictly required, but each addresses a specific gap — the more you have enabled, the faster you can determine breach scope and the more defensible your notification decisions will be.

- [ ] **Amazon Macie** enabled with automated sensitive data discovery running across all S3 buckets — provides continuous identification of where personal data resides and what categories it contains
- [ ] **Macie custom data identifiers** configured for organization-specific PII patterns (employee IDs, customer numbers, etc.) — extends Macie's detection to organization-specific personal data formats
- [ ] **Amazon GuardDuty** enabled with S3 protection in all regions — detects exfiltration patterns and unauthorized access to data stores
- [ ] **AWS CloudTrail** enabled with S3 data events on all buckets containing personal data — the primary evidence source for determining what personal data was accessed and by whom
- [ ] **CloudTrail management events** enabled with multi-region trail and integrity validation — captures configuration changes to data stores
- [ ] **AWS Config** enabled with S3-related rules (`s3-bucket-public-read-prohibited`, `s3-bucket-server-side-encryption-enabled`, `s3-bucket-logging-enabled`) — detects misconfigurations that could expose personal data
- [ ] **Security Hub** enabled with findings aggregation from Macie and GuardDuty — provides unified view of personal data exposure risks
- [ ] **S3 access logging** enabled on all buckets classified as containing personal data — provides granular access records for scope determination
- [ ] **S3 Object Lock or versioning** enabled on buckets containing personal data (prevents silent deletion) — protects evidence from tampering
- [ ] **Amazon Detective** enabled for graph-based investigation of access patterns — reduces time to determine breach scope
- [ ] **AWS Artifact** access confirmed for compliance documentation retrieval — regulators may request proof of infrastructure security controls
- [ ] **Data classification tags** applied to all data stores (e.g., `DataClassification: PII`, `DataClassification: PHI`, `DataClassification: PCI`) — enables rapid identification of affected data categories during an incident

> 🤖 **Automation opportunity:** Use Macie automated sensitive data discovery with classification jobs to maintain a continuously updated inventory of where personal data resides. Combine with AWS Config rules to alert when untagged buckets contain Macie-identified PII.

> 📌 **Don't have Macie enabled?** Macie can be enabled *during* an incident — it doesn't require historical data to be useful. Enable it on the affected bucket(s) and run an on-demand classification job. Initial results are typically available within 1–4 hours, well within the 72-hour GDPR notification window. If Macie is not available, see [Section 2.2 — Alternative classification approaches](#without-macie-alternative-classification-approaches) for manual methods.

> 📖 **Reference:** [SEC10-BP06 Pre-deploy tools](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_deploy_tools.html) — AWS Well-Architected Framework recommends pre-deploying investigation and response tooling so capabilities are available immediately when needed.

### 1.2 IAM & Access Prerequisites

Effective incident response for personal data breaches requires having the right access available *before* an incident occurs. Privacy-specific response actions (Macie queries, S3 legal holds, data event exports) use different permissions than typical security response. Pre-provisioning these ensures the Privacy Officer's technical liaison can immediately scope the breach without waiting for access approvals. This aligns with [SEC10-BP05 Pre-provision access](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_provision_access.html) from the AWS Well-Architected Framework.

- [ ] **Break-glass IAM role** exists with permissions to: query Macie findings, read S3 access logs, query CloudTrail data events, export GuardDuty findings, and apply S3 Object Lock — pre-tested and documented
- [ ] **IR team members can assume the break-glass role** with MFA from a trusted account — validate this works at least quarterly
- [ ] **Access to AWS Security Incident Response console** confirmed (if subscribed)
- [ ] **Forensic account** available with S3 buckets configured for legal hold (Object Lock in Governance or Compliance mode)
- [ ] **Pre-approved S3 bucket policy** for emergency access restriction (deny all except IR role) is documented and tested
- [ ] **Macie classification export permissions** confirmed (IR team can retrieve finding details)
- [ ] **Privacy Officer has AWS console access** or a designated liaison who can retrieve Macie findings on their behalf

### 1.3 Communication & Escalation

Personal data breach escalation is time-critical due to hard regulatory deadlines. Unlike purely technical incidents where containment can proceed before leadership is informed, personal data breaches start a notification clock at the moment of awareness. This means the escalation path must be fast, pre-tested, and well understood by all parties. Everyone in this table should know their role *before* an incident occurs.

> 📋 Do not include names. Use roles only. Maintain a separate, access-controlled contact list.

| Role | Responsibility | When to Engage |
|---|---|---|
| IR Lead | Overall incident coordination, technical workstream | Immediately upon incident detection |
| Privacy Officer / DPO | Regulatory obligation assessment, notification decisions, DPA liaison | Within 1 hour of personal data involvement confirmed |
| Legal Counsel | Legal privilege, notification content review, regulatory strategy | When notification obligation is likely (P1/P2) or within 4 hours of awareness |
| Account Owner | Business context, data inventory knowledge | When scope of affected data stores needs clarification |
| Communications Lead | Individual notification drafting, media response (if required) | When notification decision is made (typically 12–24 hours into incident) |
| Customer Support Lead | Individual inquiry handling post-notification | 24–48 hours before individual notifications are sent |
| AWS CIRT | Engage via AWS Support case or Security Incident Response service (P1/P2, if available) | P1: Immediately. P2: Within 4 hours. P3/P4: As needed for evidence gathering. |

**Escalation path:**

1. **Personal data involvement confirmed** → IR Lead documents the exact timestamp (this starts the notification clock)
2. **Within 1 hour:** Privacy Officer / DPO notified — this is a hard internal SLA, non-negotiable
3. **Within 2 hours:** IR Lead + Privacy Officer jointly assess severity using the classification table above
4. **P1/P2:** Legal Counsel engaged immediately; AWS CIRT engaged; Communications Lead placed on standby
5. **P3/P4:** Privacy Officer assesses notification obligation; IR Lead manages technical response via parallel playbook
6. **Within 24 hours:** Notification decision made and documented (notify or documented justification for non-notification)

> ⚠️ **Critical:** The Privacy Officer / DPO must be notified within **1 hour** of personal data involvement being confirmed. The 72-hour GDPR notification clock starts at awareness — delays in internal escalation directly consume the notification window.

> 📖 **Reference:** [SEC10-BP01 Identify key personnel and external resources](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_identify_personnel.html) — pre-identify all stakeholders (including legal, privacy, and communications) and establish clear escalation paths before an incident occurs.

### 1.4 Game Day Guidance

Personal data breach scenarios are uniquely challenging because they require coordination across technical, legal, privacy, and communications workstreams — often with hard regulatory deadlines. Testing this playbook validates not just technical capability but also the speed of internal escalation, the accuracy of your data inventory, and the readiness of notification templates. Include your Privacy Officer and Legal Counsel in exercises.

Recommended testing cadence: **Semi-annually** (this is a P1-capable scenario with hard regulatory deadlines).

Suggested tabletop scenario:
> *"Amazon Macie has generated a finding showing that an S3 bucket containing 50,000 customer records (names, email addresses, dates of birth, and Canadian Social Insurance Numbers) was accessed by a cross-account IAM role belonging to a third-party analytics vendor. The access occurred 6 hours ago. CloudTrail shows 12,000 GetObject calls from this role in a 30-minute window. Your customers span the EU, Canada, Australia, and California. You have 66 hours remaining on the GDPR 72-hour notification clock. Determine: (1) Was data exfiltrated? (2) Which regulators must be notified? (3) What is the notification content for each jurisdiction?"*

**Practice resources (no paid service or support plan required):**

- [Data Discovery and Classification with Amazon Macie](https://catalog.workshops.aws/data-discovery/en-US) — hands-on workshop covering S3 data scanning, custom data identifiers, Macie classification jobs, and Security Hub integration for understanding data exposure.
- [AWS Foundational Security, Identity and Governance Workshop](https://catalog.us-east-1.prod.workshops.aws/workshops/05554d54-07cc-483e-b810-d69f7d99b2ab/en-US) — demos and hands-on practice with security controls, governance frameworks, and compliance checks for AWS environments.
- [Data Perimeter Workshop](https://catalog.workshops.aws/workshops/a11f0f32-cc23-4c95-b243-43c53bdc7177/en-US) — five lab modules teaching data perimeter controls for data loss prevention, including identity-based policies, resource-based policies, and VPC endpoint policies to restrict data access to authorized users from expected network locations.

> 📖 **Reference:** [SEC10-BP04 Develop and test security incident response playbooks](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_develop_test_playbooks.html) — regularly test playbooks through tabletop exercises, simulations, and game days to verify processes work under time pressure.

---

## Part 2 — Detect & Analyze

> **CSF 2.0 Functions:** Detect · Respond (Analyze)
> **Goal:** Confirm personal data involvement, determine scope, assess exfiltration, and establish notification obligations.

### 2.1 Initial Triage Questions

These questions determine whether this playbook is activated and at what priority. The first three are activation gates — if any is "No," handle the incident with the appropriate technical playbook only. The scope assessment questions feed directly into the Privacy Officer's notification obligation assessment.

Answer these quickly to determine scope and priority. The first three questions determine whether this playbook is activated.

**Activation questions (all must be YES to proceed with this playbook):**

- [ ] Has an unauthorized access, disclosure, or loss of data been confirmed or strongly suspected?
- [ ] Does the affected data store contain personal data (PII, PHI, PCI, financial, biometric)?
- [ ] Is the data identifiable to specific individuals (directly or through combination with other available data)?

**Scope assessment questions:**

- [ ] What categories of personal data are involved? (Names, emails, health records, financial data, government IDs, biometric data, children's data)
- [ ] How many individuals are potentially affected?
- [ ] In which jurisdictions do the affected individuals reside? (Determines which regulations apply)
- [ ] Was the data encrypted at rest? Was the encryption key also compromised?
- [ ] Has data left the AWS environment? (Check VPC Flow Logs, S3 server access logs, CloudTrail)
- [ ] Is the technical containment already handled by another playbook? (If yes, this playbook focuses on regulatory/notification workstream)
- [ ] When did the organization first become aware of the breach? (This starts the notification clock)
- [ ] Is there a Record of Processing Activities (ROPA) that documents this data processing?
- [ ] Was a Data Protection Impact Assessment (DPIA) conducted for this processing activity?

**If personal data is confirmed involved AND data may have left the environment → P1 immediately. Notify Privacy Officer within 1 hour.**

### 2.2 Data Classification & Sensitivity Assessment

> `[Privacy Officer]` leads this assessment with support from `[IR Lead]` for technical evidence.

Use Amazon Macie findings and your organization's data classification framework to determine what was exposed.

**Data sensitivity tiers (highest to lowest regulatory impact):**

| Tier | Data Types | Regulatory Implications |
|---|---|---|
| **Tier 1 — Special Category** | Health/medical (PHI), biometric, genetic, racial/ethnic origin, political opinions, religious beliefs, sexual orientation, children's data | GDPR Art. 9, HIPAA, mandatory individual notification in most jurisdictions |
| **Tier 2 — High Sensitivity** | Government identifiers (SSN, SIN, TFN, passport), financial account numbers, payment card data (PAN), login credentials | PCI-DSS, identity theft risk, credit monitoring obligations likely |
| **Tier 3 — Standard PII** | Names, email addresses, phone numbers, physical addresses, dates of birth, employment information | Standard notification obligations per jurisdiction |
| **Tier 4 — Low Sensitivity** | Business contact information, publicly available information, pseudonymized data (where key not compromised) | Notification may not be required (assess per jurisdiction) |

**Amazon Macie data identifiers to check:**

| Macie Managed Data Identifier | Maps to Tier |
|---|---|
| `AUSTRALIA_TAX_FILE_NUMBER`, `CANADA_SOCIAL_INSURANCE_NUMBER`, `UK_NATIONAL_INSURANCE_NUMBER` | Tier 2 |
| `CREDIT_CARD_NUMBER`, `BANK_ACCOUNT_NUMBER` | Tier 2 |
| `AWS_CREDENTIALS`, `OPENSSH_PRIVATE_KEY` | Tier 2 |
| `USA_SOCIAL_SECURITY_NUMBER`, `USA_PASSPORT_NUMBER` | Tier 2 |
| `PHONE_NUMBER`, `EMAIL_ADDRESS`, `NAME` | Tier 3 |
| `DATE_OF_BIRTH`, `ADDRESS` | Tier 3 |
| Custom data identifiers (organization-specific) | Per classification |

> 📌 Run a Macie classification job on the affected bucket(s) if automated discovery has not recently scanned them. Results typically available within 1–4 hours depending on data volume.

#### Without Macie: Alternative Classification Approaches

If Amazon Macie was not enabled prior to the incident, you can still determine data classification — it requires more manual effort but is achievable within notification timelines.

**Option 1: Enable Macie now and run an on-demand classification job (recommended)**

Macie can be enabled during an active incident. It does not require historical data or prior configuration to classify current bucket contents. Enable Macie, create a classification job scoped to the affected bucket(s), and results will be available within 1–4 hours. This is still the fastest path to defensible classification.

**Option 2: Manual classification using available information**

If Macie is not an option (organizational constraints, time pressure, or the data has already been deleted):

1. **Check object key naming patterns** — filenames often indicate content type (e.g., `customer-export.csv`, `user-data/`, `pii-backup-20260501.json.gz`). This provides a quick initial signal.
2. **Review application documentation** — check data dictionaries, database schemas, API documentation, or architecture diagrams that describe what the application stores in the affected bucket.
3. **Ask the data owner directly** — the application team or data owner typically knows what data is stored and its sensitivity. This is often the fastest path during an incident.
4. **Sample and inspect** — download a small sample of objects (2–3 files) to a forensic environment and manually review contents for personal data categories. Document what you find.
5. **Check existing data classification tags** — if `DataClassification` tags are applied to the bucket or objects, use those as the starting point for sensitivity assessment.
6. **Review CloudTrail object keys** — even without Macie, CloudTrail data events show which specific object keys were accessed. Object key names may indicate data type.

**Regulatory posture without Macie:**

> ⚠️ If you cannot definitively determine whether accessed data contains personal information, the conservative regulatory approach is to assume it does. Under GDPR, the inability to exclude personal data involvement is itself a factor that supports notification. Document your classification methodology and any limitations — regulators evaluate the reasonableness of your assessment, not whether you had perfect tooling.

### 2.3 Evidence Documentation

> ⚠️ **Evidence preservation is critical for regulatory investigations.** Regulators may request evidence months after the incident. Apply legal hold immediately. Failure to preserve evidence can result in adverse inferences and increased regulatory penalties.

| Evidence Type | How to Collect | Where to Store |
|---|---|---|
| Macie sensitive data findings | Macie console → Findings → Export JSON | Forensic S3 bucket (Object Lock) |
| Macie classification job results | Macie console → Jobs → Results | Forensic S3 bucket (Object Lock) |
| S3 server access logs (affected buckets) | Copy from logging bucket for relevant time window | Forensic S3 bucket (Object Lock) |
| CloudTrail data events (S3 GetObject, etc.) | Athena query (see resources file) | Forensic S3 bucket (Object Lock) |
| CloudTrail management events | Athena query for IAM/S3 configuration changes | Forensic S3 bucket (Object Lock) |
| GuardDuty exfiltration findings | `aws guardduty get-findings --detector-id ... --finding-ids ...` | Forensic S3 bucket (Object Lock) |
| VPC Flow Logs (if data accessed via EC2/Lambda) | CloudWatch Logs export or S3 copy | Forensic S3 bucket (Object Lock) |
| S3 bucket policy history | AWS Config timeline for the bucket resource | IR ticket |
| IAM policy of accessing principal | `aws iam get-policy-version` + `aws iam list-attached-*-policies` | IR ticket |
| Data inventory / ROPA extract | Internal privacy management system | IR ticket (restricted access) |
| Notification clock start documentation | Screenshot/log of when awareness occurred | IR ticket |

**Initiate legal hold immediately:**

```bash
# Apply Object Lock legal hold to forensic evidence bucket
aws s3api put-object-legal-hold \
  --bucket forensic-evidence-bucket \
  --key "incidents/PDB-2026-001/" \
  --legal-hold Status=ON

# Confirm Object Lock is enabled on the forensic bucket
aws s3api get-object-lock-configuration \
  --bucket forensic-evidence-bucket
```

**Investigation queries for evidence collection:**

The companion resource file [`resources/athena-queries-personal-data-breach.sql`](resources/athena-queries-personal-data-breach.sql) contains the full set of Athena queries for personal data breach investigation, including:

- All S3 data access events on PII-classified buckets (Section 1.1–1.4)
- Cross-account access detection
- Bulk download pattern detection (exfiltration indicators)
- Macie finding correlation with CloudTrail access events
- GuardDuty and Macie CLI export commands

Use these queries to build a complete evidence package for regulatory submissions.

### 2.4 Determining Data Access Scope

> `[IR Lead]` performs technical analysis. Results feed into `[Privacy Officer]`'s notification assessment.

**Step 1: Identify what was accessed**

Use CloudTrail data events to determine exactly which objects containing personal data were accessed. The Privacy Officer needs to understand what questions are being answered and what the results mean — this analysis is integral to the notification obligation assessment.

> 📌 **Without Macie:** If Macie findings are not available to identify which objects contain PII, use the alternative approaches from [Section 2.2](#without-macie-alternative-classification-approaches) to determine which accessed objects are likely to contain personal data. Replace the Macie-derived object key list with keys identified through manual classification, data owner consultation, or naming pattern analysis.

Run the following queries from [`resources/athena-queries-personal-data-breach.sql`](resources/athena-queries-personal-data-breach.sql):

| Query | What It Answers | Feeds Into |
|---|---|---|
| **1.5 — Macie finding correlation** | Were objects *confirmed by Macie to contain PII* actually accessed during the incident window? | Notification obligation: confirms personal data was accessed, not just that the bucket was accessed |
| **2.2 — Data volume determination** | How many unique objects were accessed and how much data was transferred? | GDPR Art. 33: "approximate number of records" field in regulator notification |
| **1.3 — Individual count estimation** | How many individuals are potentially affected? | All jurisdictions: notification scope and individual notification feasibility |
| **1.2 — Cross-account access** | Was data accessed from an account outside the organization? | Indicates disclosure to a third party — stronger notification trigger |

**Step 2: Determine if data left the AWS environment**

This is the critical question for notification obligations. Data accessed within AWS (e.g., by another AWS service or account) may have different risk implications than data confirmed exfiltrated to an external location.

Indicators of exfiltration:
- GuardDuty `Exfiltration:S3/MaliciousIPCaller` or `Exfiltration:S3/AnomalousBehavior` findings
- CloudTrail `GetObject` calls from IP addresses outside known AWS ranges
- VPC Flow Logs showing large outbound data transfers to unknown IPs
- S3 replication configured to an external account
- `CopyObject` calls to a bucket in an unknown account
- CloudTrail `PutObject` to a bucket outside the organization (cross-account)

Run query **2.3 — Exfiltration indicators** from the resources file. This identifies `GetObject` calls from non-private IP addresses — the single most important indicator for notification decisions.

> 📌 **Important:** Even if you cannot confirm exfiltration, if data was accessed by an unauthorized party, most regulations treat this as a breach requiring notification. The inability to prove data *did not* leave the environment is itself a risk factor.

### 2.5 Notification Obligation Assessment

> `[Privacy Officer]` leads with `[Legal Counsel]` support. Complete within **24 hours** of awareness to preserve notification timeline options.

For each jurisdiction where affected individuals reside, assess notification obligations:

| Regulation | Jurisdiction | Trigger Met? | Notification Deadline | Authority to Notify | Notes |
|---|---|---|---|---|---|
| **GDPR Art. 33/34** | EU/EEA | ☐ Yes ☐ No ☐ TBD | 72 hours to DPA; without undue delay to individuals (if high risk) | Lead Supervisory Authority (DPA) | Clock starts at awareness. Incomplete notification acceptable with follow-up. |
| **UK GDPR / DPA 2018** | United Kingdom | ☐ Yes ☐ No ☐ TBD | 72 hours to ICO | Information Commissioner's Office (ICO) | Separate from EU GDPR post-Brexit. |
| **PIPEDA** | Canada | ☐ Yes ☐ No ☐ TBD | "As soon as feasible" to OPC and individuals | Office of the Privacy Commissioner (OPC) | Trigger: real risk of significant harm (RROSH). |
| **CCPA/CPRA** | California, US | ☐ Yes ☐ No ☐ TBD | "Most expedient time possible" | California AG + affected individuals | Applies to unencrypted personal information. |
| **HIPAA** | US (if PHI) | ☐ Yes ☐ No ☐ TBD | 60 days to HHS; without unreasonable delay to individuals | HHS OCR + individuals; media if >500 | Only if unsecured PHI. |
| **PCI-DSS** | Global (if PAN) | ☐ Yes ☐ No ☐ TBD | Immediately to payment brands | Acquiring bank + card brands | Forensic investigation by PCI QSA may be required. |
| **Australian NDB** | Australia | ☐ Yes ☐ No ☐ TBD | "As soon as practicable" (30-day assessment window) | OAIC + affected individuals | Trigger: likely to result in serious harm. |
| **NIS2** | EU (if essential/important entity) | ☐ Yes ☐ No ☐ TBD | Early warning 24 hours; notification 72 hours; final report 1 month | National CSIRT or competent authority | Applies to essential and important entities. |
| **DORA** | EU (if financial entity) | ☐ Yes ☐ No ☐ TBD | Initial 4 hours; intermediate 72 hours; final 1 month | National financial regulator | Major ICT-related incident classification required. |
| **SEC Rules** | US (if public company) | ☐ Yes ☐ No ☐ TBD | 4 business days after materiality determination | SEC (Form 8-K) | Materiality assessment required. |

> ⚠️ **The clock starts at awareness, not confirmation.** For GDPR, "awareness" means when you have a reasonable degree of certainty that a breach has occurred. Do not delay notification to complete investigation — submit an incomplete initial notification and follow up.

### 2.6 Severity Determination

| Confirmed? | Priority Assignment |
|---|---|
| Personal data confirmed exfiltrated outside AWS, large individual count, or high-sensitivity data (Tier 1/2) | P1 |
| Personal data accessed by unauthorized party, exfiltration unclear, notification deadline approaching | P2 |
| Personal data exposure suspected (e.g., bucket was public) but no confirmed access | P3 |
| Policy violation on personal data store, no evidence of unauthorized access | P4 |

### 2.7 AWS Security Incident Response Service

> 📌 **If your organization has the AWS Security Incident Response service enabled, or has AWS Support, you can request assistance from the AWS Customer Incident Response Team (CIRT).**

**P1 — Critical:** Engage AWS immediately.

- **If you have the AWS Security Incident Response service enabled:** Sign into [AWS Security Incident Response](https://console.aws.amazon.com/security-ir/) via the console, choose **Create Case**, select **Resolve case with AWS**, and choose the appropriate request type — **Active Security Incident** for urgent incident response support, or **Investigations and Inquiries** for log analysis support, secondary confirmation, or general security posture questions.
- **If you need assistance from AWS CIRT:** Open a support case with Critical severity and request assistance from the AWS Customer Incident Response Team (CIRT). Include relevant finding IDs and a summary of what you have observed.

**P2 — High:** Engage AWS within 4 hours of awareness.

- AWS CIRT can assist with evidence gathering and scope determination that directly supports your notification obligation assessment. They can help determine whether data left the AWS environment — often the critical question for notification decisions.

**P3 — Medium:** Engage AWS as needed for evidence gathering support.

- Even for lower-severity incidents, AWS CIRT can assist with CloudTrail analysis, Macie interpretation, and evidence documentation that supports regulatory submissions. Consider engaging if your team lacks experience with Athena queries against CloudTrail data events.

> 📌 You do not need the Security Incident Response service to get help from AWS CIRT. All AWS customers can request CIRT assistance through a support case, regardless of support plan level.

> The AWS Security Incident Response service can assist with evidence gathering and documentation that supports regulatory notification requirements. They do not provide legal advice on notification obligations.

---

## Part 3 — Contain

> **CSF 2.0 Function:** Respond (Contain)
> **Goal:** Stop further data access, preserve evidence for regulatory investigation, initiate legal hold, and document the notification clock.

> 📌 **Note:** Technical containment of the underlying incident (credential revocation, network isolation, etc.) may already be handled by the parallel technical playbook (IRP-CredCompromise, IRP-DataAccess, IRP-InsiderThreat). This section focuses on containment actions specific to the personal data breach workstream.

### 3.1 Containment Decision

```
Is personal data still actively being accessed or exfiltrated?
│
├── YES (active access ongoing)
│     └── Coordinate with technical IR playbook for immediate access revocation
│           Then proceed to 3.2 for evidence preservation
│
└── NO (access has stopped or technical containment already applied)
      └── Proceed directly to 3.2 — focus on evidence preservation and clock documentation
```

### 3.2 Containment Actions

> `[IR Lead]` coordinates technical actions. `[Privacy Officer]` coordinates regulatory actions. Both run in parallel.

**Step 1: Stop further data access (coordinate with technical playbook)**

If not already handled by the parallel technical playbook, restrict access to affected data stores immediately:

```bash
# Emergency: Apply deny-all bucket policy (preserves data, blocks all access)
aws s3api put-bucket-policy --bucket customer-pii-bucket --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "EmergencyDenyAll",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::customer-pii-bucket",
      "arn:aws:s3:::customer-pii-bucket/*"
    ],
    "Condition": {
      "StringNotLike": {
        "aws:PrincipalArn": [
          "arn:aws:iam::123456789012:role/IncidentResponseRole",
          "arn:aws:iam::123456789012:role/ForensicPreservationRole"
        ]
      }
    }
  }]
}'
```

> ⚠️ **Warning:** This will break any applications reading from this bucket. Obtain `[Account Owner]` authorization before applying in production unless active exfiltration is confirmed (P1).

**Step 2: Preserve evidence under legal hold**

```bash
# Enable Object Lock on forensic bucket (if not already configured)
# Note: Object Lock must be enabled at bucket creation — use a pre-configured forensic bucket

# Copy affected S3 access logs to forensic bucket with legal hold
aws s3 cp s3://access-logs-bucket/customer-pii-bucket/ \
  s3://forensic-evidence-bucket/incidents/PDB-2026-001/s3-access-logs/ \
  --recursive

# Apply legal hold to all preserved evidence
aws s3api put-object-legal-hold \
  --bucket forensic-evidence-bucket \
  --key "incidents/PDB-2026-001/" \
  --legal-hold Status=ON
```

**Step 3: Preserve CloudTrail logs**

```bash
# Export relevant CloudTrail logs to forensic bucket
# Use Athena to query and export, or copy raw log files
aws s3 cp s3://cloudtrail-logs-bucket/AWSLogs/123456789012/CloudTrail/ \
  s3://forensic-evidence-bucket/incidents/PDB-2026-001/cloudtrail/ \
  --recursive \
  --exclude "*" \
  --include "*2026-05-2*"
```

**Step 4: Document the notification clock**

> `[Privacy Officer]` owns this step. This is a legal record that will be reviewed by regulators.

The notification clock documentation must be created within 1 hour of personal data involvement being confirmed. This record is your primary defense against claims of delayed notification.

Document the following in your incident management system:

1. **Exact timestamp (UTC)** when the organization became aware of the personal data breach
2. **How** awareness was achieved (Macie finding, GuardDuty alert, customer report, etc.) — include the finding ID or alert reference
3. **Who** was first aware (role, not name) and who made the determination that personal data was involved
4. **What** was known at the time of awareness — be specific about what was confirmed vs. suspected
5. **Notification clock deadlines** calculated from the awareness timestamp (e.g., GDPR 72h = [specific UTC timestamp])

This record establishes the start of the notification clock for GDPR (72 hours), NIS2 (24 hours early warning), and other time-bound obligations.

**Step 5: Initiate legal hold on all relevant systems**

> `[Legal Counsel]` authorizes. `[IR Lead]` implements.

Legal hold prevents the routine deletion or modification of evidence that may be required by regulators months or years after the incident. Implement legal hold across all systems that may contain evidence of the breach scope, timeline, or response actions.

Place legal hold on:
- [ ] All S3 access logs for affected buckets (full retention period)
- [ ] CloudTrail logs for affected accounts (full retention period)
- [ ] VPC Flow Logs for affected VPCs
- [ ] Application logs that may contain access records
- [ ] Email and messaging records related to the incident
- [ ] Macie findings and classification job results
- [ ] GuardDuty findings related to the incident
- [ ] Any backup or replica of the affected data

For S3-stored evidence, apply Object Lock legal hold:

```bash
# Apply legal hold to preserved evidence (run after copying to forensic bucket)
aws s3api put-object-legal-hold \
  --bucket forensic-evidence-bucket \
  --key "incidents/PDB-2026-001/" \
  --legal-hold Status=ON
```

Notify all system administrators that legal hold is in effect and no logs or data within the hold scope may be deleted, modified, or allowed to expire through normal retention policies.

### 3.3 Document Containment Actions

After containment, document and confirm the following before any data modification or deletion. This checklist serves as both an operational gate and a regulatory evidence record — regulators will ask what containment measures were taken and when.

- [ ] All S3 access logs for affected buckets copied to forensic bucket with Object Lock
- [ ] CloudTrail logs (management + data events) preserved for the full incident window
- [ ] Macie findings exported and preserved
- [ ] GuardDuty findings exported and preserved
- [ ] VPC Flow Logs exported (if applicable)
- [ ] Legal hold applied to all forensic evidence
- [ ] CloudTrail log integrity validation confirmed on preserved logs
- [ ] Chain of custody documented (who collected what, when, how)
- [ ] Notification clock start time formally documented and communicated to Privacy Officer

---

## Part 4 — Eradicate & Recover

> **CSF 2.0 Function:** Respond (Eradicate) · Recover
> **Goal:** Confirm the full scope of personal data affected, determine notification content, prepare regulatory submissions, and implement individual protections.

> 📌 **Note:** Technical eradication (removing threat actor access, closing vulnerabilities) is handled by the parallel technical playbook. This section focuses on the regulatory, notification, and individual protection workstream.

### 4.1 Full Scope Determination

> `[IR Lead]` provides technical findings. `[Privacy Officer]` interprets for regulatory purposes.

Before preparing notifications, confirm the following with as much precision as possible:

**Data scope:**
- [ ] Exact data categories involved (names, emails, government IDs, health data, financial data, etc.)
- [ ] Number of unique individuals affected (or best estimate with confidence range)
- [ ] Jurisdictions of affected individuals (determines which regulations apply)
- [ ] Time period of exposure (when did unauthorized access begin and end?)
- [ ] Whether data was encrypted and whether encryption keys were also compromised
- [ ] Whether data has been confirmed exfiltrated or only accessed

**Individual impact assessment:**
- [ ] What is the likely harm to individuals? (Identity theft, financial fraud, discrimination, reputational damage)
- [ ] Are vulnerable populations affected? (Children, patients, employees)
- [ ] Can affected individuals be individually identified for notification?
- [ ] What protective measures can be offered? (Credit monitoring, identity protection, password resets)

### 4.2 Notification Content Preparation

> `[Privacy Officer]` leads content preparation. `[Legal Counsel]` reviews. `[Communications Lead]` finalizes language.

**Regulator notification content (GDPR Art. 33 template elements):**

Each regulatory notification should include (adapt per jurisdiction requirements):

1. **Nature of the breach** — What happened, categories of data, approximate number of individuals
2. **Contact details** — DPO or privacy contact point name and details
3. **Likely consequences** — Assessment of potential harm to individuals
4. **Measures taken** — Actions taken to address the breach and mitigate harm
5. **Measures to mitigate** — Steps individuals can take to protect themselves

**Individual notification content (GDPR Art. 34 template elements):**

1. **Clear, plain language description** of what happened
2. **What personal data was involved** (be specific — "your name, email address, and date of birth")
3. **What we are doing about it** (containment, investigation, remediation)
4. **What you can do** (change passwords, monitor accounts, credit monitoring enrollment)
5. **Contact information** for questions (dedicated support line/email)
6. **Apology and commitment** to preventing recurrence

> ⚠️ **Legal privilege:** Draft notifications under legal privilege until finalized. Mark all drafts as "PRIVILEGED AND CONFIDENTIAL — PREPARED AT THE DIRECTION OF LEGAL COUNSEL."

### 4.3 Regulatory Submission Preparation

> `[Privacy Officer]` prepares submissions. `[Legal Counsel]` approves before filing.

**For each applicable jurisdiction:**

| Jurisdiction | Submission Method | Key Deadlines | Status |
|---|---|---|---|
| EU/EEA (GDPR) | DPA online portal (varies by member state) | 72 hours initial; follow-up as needed | ☐ Submitted ☐ Pending |
| UK (ICO) | [ICO breach reporting tool](https://ico.org.uk/for-organizations/report-a-breach/) | 72 hours | ☐ Submitted ☐ Pending |
| Canada (PIPEDA) | [OPC breach report form](https://www.priv.gc.ca/en/report-a-concern/report-a-privacy-breach-at-your-organization/) | As soon as feasible | ☐ Submitted ☐ Pending |
| California (CCPA) | [California AG breach reporting](https://oag.ca.gov/privacy/databreach/reporting) | Most expedient time possible | ☐ Submitted ☐ Pending |
| Australia (NDB) | [OAIC NDB form](https://www.oaic.gov.au/privacy/notifiable-data-breaches/report-a-data-breach) | As soon as practicable | ☐ Submitted ☐ Pending |
| US (HIPAA) | [HHS breach portal](https://ocrportal.hhs.gov/ocr/breach/wizard_breach.jsf) | 60 days | ☐ Submitted ☐ Pending |
| US (SEC) | Form 8-K filing | 4 business days after materiality determination | ☐ Submitted ☐ Pending |

**AWS Artifact for compliance documentation:**

Use [AWS Artifact](https://console.aws.amazon.com/artifact/) to retrieve:
- AWS SOC 2 Type II report (demonstrates AWS infrastructure security controls)
- AWS PCI-DSS Attestation of Compliance (if PCI data involved)
- AWS ISO 27001 certificate
- AWS HIPAA compliance documentation (if PHI involved)

These documents may be requested by regulators to demonstrate the security posture of the infrastructure hosting the affected data.

### 4.4 Individual Notification & Protection

> `[Communications Lead]` manages notification delivery. `[Customer Support Lead]` manages incoming inquiries.

**Notification delivery:**
- [ ] Individual notification content finalized and approved by Legal
- [ ] Notification delivery method determined (email, postal mail, public notice)
- [ ] Dedicated support channel established (phone line, email address, FAQ page)
- [ ] Customer support team briefed on incident details and approved responses
- [ ] Notification sent to all identifiable affected individuals
- [ ] Delivery confirmation tracked (email delivery receipts, postal tracking)

**Individual protection measures (if applicable):**
- [ ] Credit monitoring service enrolled for affected individuals (if government IDs or financial data exposed)
- [ ] Identity protection service offered (if Tier 1 or Tier 2 data exposed)
- [ ] Password reset forced for affected accounts (if credentials exposed)
- [ ] Fraud alert placement guidance provided to individuals
- [ ] Dedicated FAQ page published with incident details and self-help guidance

### 4.5 Recovery Validation

Confirm the following before declaring the personal data breach workstream resolved:

- [ ] All applicable regulatory notifications submitted within required timeframes
- [ ] Individual notifications sent to all identifiable affected individuals
- [ ] Credit monitoring or identity protection services activated (if applicable)
- [ ] Dedicated support channel operational and staffed
- [ ] Technical root cause addressed (confirmed with technical IR playbook lead)
- [ ] No further unauthorized access to personal data detected
- [ ] AWS Security Incident Response case updated with regulatory submission details (if applicable)
- [ ] All evidence preserved under legal hold with documented chain of custody
- [ ] Privacy Officer confirms notification obligations are satisfied (or follow-up timeline documented)

---

## Part 5 — Post-Incident Activity

> **CSF 2.0 Function:** Identify (Improve) — continuous improvement, not a one-time activity
> **Goal:** Complete regulatory follow-up, track individual notifications, update privacy controls, and improve data protection posture.

Post-incident activities for personal data breaches extend well beyond the typical technical incident. Regulatory follow-up can continue for months (GDPR final reports, HIPAA annual reporting, enforcement proceedings), and individual notification tracking may require dedicated resources. The key difference from technical post-incident work is that *regulators will evaluate your response quality* — documentation produced here may be reviewed under enforcement action.

### 5.1 Timeline Reconstruction

Document the full incident timeline including both technical and regulatory workstreams. Complete within 24–48 hours while memory is fresh. This timeline will be referenced by regulators during any enforcement proceedings and should be treated as a formal record.

| Timestamp (UTC) | Event | Source / Evidence | Actor |
|---|---|---|---|
| YYYY-MM-DD HH:MM | Initial unauthorized access to personal data | CloudTrail data events | Threat actor |
| YYYY-MM-DD HH:MM | Detection (Macie/GuardDuty/other) | Finding ID | AWS service |
| YYYY-MM-DD HH:MM | IR team notified | On-call alert | IR Lead |
| YYYY-MM-DD HH:MM | **Personal data involvement confirmed (CLOCK STARTS)** | Macie finding / manual review | IR Lead |
| YYYY-MM-DD HH:MM | Privacy Officer notified | Internal escalation | IR Lead |
| YYYY-MM-DD HH:MM | Technical containment applied | Technical playbook | IR Lead |
| YYYY-MM-DD HH:MM | Legal hold initiated | Legal authorization | Legal Counsel |
| YYYY-MM-DD HH:MM | Scope determination completed | Investigation findings | IR Lead + Privacy Officer |
| YYYY-MM-DD HH:MM | Notification decision made | Regulatory assessment | Privacy Officer + Legal |
| YYYY-MM-DD HH:MM | Regulator notification submitted | Submission confirmation | Privacy Officer |
| YYYY-MM-DD HH:MM | Individual notifications sent | Delivery confirmation | Communications Lead |
| YYYY-MM-DD HH:MM | Incident resolved | Recovery validation | IR Lead |

**Key metrics to capture:**

| Metric | Value | Why It Matters |
|---|---|---|
| Time to Detect (TTD) | *HH:MM from initial access to detection* | Indicates whether monitoring (Macie, GuardDuty) is tuned for personal data stores |
| Time to Awareness (TTA) | *HH:MM from detection to personal data involvement confirmed* | Measures gap between generic alert and privacy-specific escalation |
| Time to Notify Privacy Officer | *HH:MM from awareness to Privacy Officer notification* | Must be ≤1 hour. Directly consumes notification window. |
| Time to Contain (TTC) | *HH:MM from awareness to access stopped* | Ongoing access increases both breach scope and regulatory exposure |
| Time to Regulator Notification | *HH:MM from awareness to regulatory submission* | Must be ≤72 hours for GDPR. Late notification is itself a violation. |
| Time to Individual Notification | *HH:MM from awareness to individual notifications sent* | Delayed individual notification increases harm to data subjects |
| GDPR 72-hour compliance | *Yes/No — was regulator notified within 72 hours?* | Binary pass/fail metric for the most common regulatory deadline |
| Total Incident Duration | *HH:MM from initial access to recovery validated* | Measures overall response effectiveness across both workstreams |
| Individuals Affected | *Count (confirmed)* | Primary metric for regulatory severity assessment and media exposure risk |
| Data Categories Involved | *List* | Determines which notification obligations apply and what protections to offer |
| Jurisdictions Notified | *List* | Audit trail for regulatory compliance across all applicable jurisdictions |

### 5.2 Regulatory Follow-Up

> `[Privacy Officer]` owns ongoing regulatory engagement. `[Legal Counsel]` advises.

Many regulations require follow-up after the initial notification:

- [ ] **GDPR:** Final report submitted to DPA with complete investigation findings
- [ ] **NIS2:** Final report submitted within 1 month of incident notification
- [ ] **DORA:** Final report submitted within 1 month of initial notification
- [ ] **HIPAA:** Annual report to HHS if breach affected >500 individuals
- [ ] **Regulator questions:** All additional information requests from regulators answered within requested timeframes
- [ ] **Enforcement actions:** Monitor for and respond to any regulatory enforcement proceedings
- [ ] **Documentation:** Complete incident file maintained for minimum regulatory retention period (typically 5+ years)

### 5.3 Individual Notification Tracking

- [ ] Delivery confirmation received for all individual notifications
- [ ] Undeliverable notifications re-sent via alternative method (postal if email bounced)
- [ ] Support channel inquiry volume tracked and adequately staffed
- [ ] Credit monitoring / identity protection enrollment rates tracked
- [ ] Individual complaints or escalations documented and addressed
- [ ] Public notice published (if individual notification not feasible for all affected persons)

### 5.4 Post-Incident Review

Conduct a blameless post-incident review within **5 business days** for P1/P2, **15 business days** for P3/P4. For personal data breaches, include the Privacy Officer and Legal Counsel in the review — their perspective on notification effectiveness and regulatory interaction is as important as the technical root cause analysis.

Discussion questions (in addition to standard technical review):

1. Was personal data involvement identified quickly enough? Could classification or tagging have accelerated this?
2. Was the Privacy Officer notified within the 1-hour internal target?
3. Were notification obligations assessed within 24 hours of awareness?
4. Were regulatory notifications submitted within required timeframes? If not, why?
5. Was the data inventory (ROPA) accurate and helpful during scope determination?
6. Were individual notifications clear, complete, and delivered effectively?
7. Did the organization have adequate data classification to quickly identify what was exposed?
8. Were there gaps in S3 data event logging that hindered scope determination?
9. Was Macie coverage sufficient to identify all personal data in the affected data stores?
10. Were the preparation steps in Part 1 adequate? Were there tools, access, or processes we needed during the incident that weren't pre-provisioned?
11. What single change would most reduce the likelihood or impact of a similar breach?

### 5.5 Privacy & Data Protection Improvements

Based on lessons learned, implement improvements:

- [ ] **DPIA update:** Update the Data Protection Impact Assessment for the affected processing activity
- [ ] **ROPA update:** Ensure Record of Processing Activities accurately reflects current data flows
- [ ] **Data minimization:** Review whether all personal data in the affected store was necessary for the stated purpose
- [ ] **Retention review:** Implement or enforce data retention policies to reduce volume of personal data at risk
- [ ] **Macie coverage:** Expand Macie automated discovery to cover any gaps identified during the incident
- [ ] **Access controls:** Implement least-privilege access to personal data stores (review IAM policies, bucket policies, VPC endpoints)
- [ ] **Encryption:** Ensure all personal data is encrypted at rest with customer-managed keys (CMK) where appropriate
- [ ] **Monitoring:** Enhance monitoring on personal data stores (CloudTrail data events, S3 access logging, GuardDuty S3 protection)
- [ ] **Privacy by design:** Incorporate findings into development practices (data classification at creation, automated tagging, access logging by default)
- [ ] **Training:** Update privacy and security awareness training based on incident root cause

### 5.6 Detection Gap Analysis

| Gap | Root Cause | Recommended Fix | Owner | Target Date |
|---|---|---|---|---|
| *(e.g., Macie not enabled on affected bucket)* | *(Bucket created after Macie onboarding)* | *(Automate Macie coverage for new buckets via Config rule)* | | |
| *(e.g., No CloudTrail data events on PII bucket)* | *(Data events not enabled for this bucket)* | *(Enable data events on all buckets tagged DataClassification:PII)* | | |
| *(e.g., Cross-account access not alerted)* | *(No alarm on cross-account S3 access)* | *(Create CloudWatch alarm for cross-account GetObject on PII buckets)* | | |

### 5.7 Playbook Update Checklist

- [ ] Were triage questions sufficient to quickly identify personal data involvement?
- [ ] Was the notification obligation assessment table complete for all applicable jurisdictions?
- [ ] Were notification templates adequate or did they require significant modification?
- [ ] Were evidence preservation steps sufficient for regulatory requirements?
- [ ] Were any new regulations or jurisdictions identified that should be added?
- [ ] Were Athena queries effective for scope determination?
- [ ] Were communication templates clear and approved quickly by Legal?
- [ ] Update **Last Reviewed** date and increment **Playbook Version**.

---

## Appendix A — Investigation Resources

The full set of Athena queries and CLI commands for personal data breach investigation are maintained in a companion file for easier use in Athena consoles and scripts:

📄 **[`resources/athena-queries-personal-data-breach.sql`](resources/athena-queries-personal-data-breach.sql)**

This file contains:

| Section | Queries | Purpose |
|---|---|---|
| **Evidence Collection** | 1.1–1.5 | Broad evidence capture for regulatory preservation — all access events, cross-account detection, individual count estimation, bulk download patterns, Macie correlation |
| **Scope Determination** | 2.1–2.4 | Help the Privacy Officer determine breach scope — all access by suspect principal, data volume quantification, exfiltration indicators, configuration change detection |
| **Finding Exports** | 3 (CLI) | GuardDuty and Macie CLI commands for exporting findings as regulatory evidence |

> 📌 **Usage:** Replace placeholder values (bucket names, account IDs, role ARNs, time windows) with your actual values before running. The queries in Section 2.4 of the main playbook body are the most critical for the Privacy Officer's notification assessment and are kept inline for immediate reference.

---

## Appendix B — Regulatory & Compliance Considerations

> `[Legal Counsel]` and `[Privacy Officer]` own this section during an active incident.

See [Regulatory Context](../REGULATORY_CONTEXT.md) for the full notification obligation matrix by regulation and incident type.

### Notification Timeline Summary

| Regulation | Clock Starts At | Initial Notification Deadline | Follow-Up Required |
|---|---|---|---|
| **GDPR Art. 33** | Awareness of breach | 72 hours to supervisory authority | Yes — final report when investigation complete |
| **GDPR Art. 34** | Determination of high risk | Without undue delay to individuals | No fixed follow-up (but must be complete) |
| **UK GDPR** | Awareness of breach | 72 hours to ICO | Yes — update if new information |
| **PIPEDA** | Determination of RROSH | As soon as feasible to OPC + individuals | Records must be kept for 24 months |
| **CCPA/CPRA** | Discovery of breach | Most expedient time possible (no fixed hours) | No fixed follow-up |
| **HIPAA** | Discovery of breach | 60 days to HHS; without unreasonable delay to individuals | Annual report for breaches >500 |
| **PCI-DSS** | Confirmation of compromise | Immediately to payment brands | Forensic investigation report required |
| **Australian NDB** | Completion of assessment (30-day window) | As soon as practicable after assessment | Statement must remain on website for 12 months |
| **NIS2** | Awareness of significant incident | 24 hours (early warning); 72 hours (notification); 1 month (final) | Final report within 1 month |
| **DORA** | Classification as major incident | 4 hours (initial); 72 hours (intermediate); 1 month (final) | Final report within 1 month |
| **SEC** | Materiality determination | 4 business days (Form 8-K) | Annual report (10-K) disclosure |

### Key Principles for Notification Decisions

1. **When in doubt, notify.** It is better to submit an incomplete initial notification and update later than to miss a deadline. Most regulations explicitly allow for phased reporting.

2. **The clock starts at awareness, not confirmation.** For GDPR, "awareness" means a reasonable degree of certainty that a breach has occurred. You do not need to complete your investigation before notifying.

3. **Containment does not eliminate notification obligations.** Even if you contained the breach within minutes, if personal data was accessed by an unauthorized party, notification obligations likely apply.

4. **Encryption matters.** If data was encrypted with a strong algorithm AND the encryption key was not compromised, some regulations (notably HIPAA "safe harbor" and some GDPR interpretations) may not require notification. Document this analysis carefully.

5. **Document the decision either way.** Whether you decide to notify or not, document the rationale. Regulators may later ask why you did or did not notify.

### AWS Shared Responsibility for Breach Notification

- **AWS responsibility:** Notify customers if AWS infrastructure is compromised (per AWS Customer Agreement and Shared Responsibility Model)
- **Customer responsibility:** Notify regulators and individuals if customer data is breached due to customer configuration, access management, or application vulnerabilities
- **AWS support:** AWS Security Incident Response service can assist with evidence gathering and documentation but does not provide legal advice on notification obligations

---

## Appendix C — Communication Templates

> ⚠️ **These are starting templates only.** All notifications must be reviewed and approved by `[Legal Counsel]` before submission. Adapt language to your organization's tone, the specific incident facts, and jurisdictional requirements.

### C.1 Regulator Notification Template (GDPR Art. 33)

```
PERSONAL DATA BREACH NOTIFICATION
Submitted pursuant to Article 33 of the General Data Protection Regulation

1. NATURE OF THE BREACH
   - Type of breach: [Confidentiality / Integrity / Availability]
   - Description: [Brief factual description of what occurred]
   - Date/time breach occurred: [If known]
   - Date/time breach discovered: [Timestamp]
   - Categories of personal data: [e.g., names, email addresses, dates of birth,
     government identification numbers]
   - Approximate number of data subjects: [Number or range]
   - Approximate number of records: [Number or range]

2. DATA PROTECTION OFFICER CONTACT
   - Name: [DPO name]
   - Email: [DPO email]
   - Phone: [DPO phone]

3. LIKELY CONSEQUENCES
   - [Description of potential impact on individuals — e.g., risk of identity theft,
     financial fraud, reputational damage]

4. MEASURES TAKEN OR PROPOSED
   - Containment: [Actions taken to stop the breach]
   - Mitigation: [Actions to reduce harm to individuals — e.g., credit monitoring,
     password resets, enhanced monitoring]
   - Prevention: [Actions to prevent recurrence]

5. INDIVIDUAL NOTIFICATION
   - Have individuals been notified? [Yes / No / Planned]
   - If no, justification: [e.g., investigation ongoing, disproportionate effort,
     data rendered unintelligible]

6. ADDITIONAL INFORMATION
   - [Any other relevant details]
   - [Note: This is an initial notification. A supplementary report will follow
     when the investigation is complete.]
```

### C.2 Individual Notification Template

```
Subject: Important Notice About Your Personal Data

Dear [Name / "Valued Customer"],

We are writing to inform you of a security incident that may have affected
your personal data. We take the protection of your information seriously and
want to provide you with the details of what happened, what we are doing
about it, and what you can do to protect yourself.

WHAT HAPPENED
[Clear, factual description in plain language. Avoid technical jargon.
Include approximate dates.]

WHAT INFORMATION WAS INVOLVED
The following categories of your personal data may have been affected:
- [List specific data types — e.g., "your name, email address, and date of birth"]

WHAT WE ARE DOING
- [Containment action taken]
- [Investigation status]
- [Remediation steps]
- [Offer of credit monitoring / identity protection if applicable]

WHAT YOU CAN DO
- [Specific, actionable steps — e.g., "Change your password at [URL]"]
- [Monitor your accounts for unusual activity]
- [Enroll in the complimentary credit monitoring service we are providing:
  [enrollment URL/instructions]]
- [Contact your bank if you notice unauthorized transactions]

FOR MORE INFORMATION
If you have questions or concerns, please contact our dedicated support team:
- Email: [dedicated email]
- Phone: [dedicated phone line]
- FAQ: [URL to incident FAQ page]

We sincerely apologize for this incident and any concern it may cause you.
We are committed to protecting your information and are taking steps to
prevent this from happening again.

Sincerely,
[Organization name]
[Date]
```

### C.3 Internal Stakeholder Briefing Template

```
PERSONAL DATA BREACH — INTERNAL BRIEFING
Classification: CONFIDENTIAL — DO NOT DISTRIBUTE EXTERNALLY

Incident ID: [ID]
Briefing Date: [Date]
Prepared by: [Role]

SUMMARY
- Incident type: Personal data breach
- Status: [Active / Contained / Resolved]
- Severity: [P1/P2/P3/P4]
- Individuals affected: [Count]
- Data types: [Categories]
- Jurisdictions: [List]

NOTIFICATION STATUS
- Regulator notifications: [Submitted / Pending / Not required]
- Individual notifications: [Sent / Pending / Not required]
- Deadlines: [Next deadline and countdown]

ACTIONS REQUIRED
- [Role]: [Action needed] by [deadline]
- [Role]: [Action needed] by [deadline]

NEXT UPDATE: [Date/time]
```

---

## Appendix D — Data Classification Quick Reference

### Amazon Macie Managed Data Identifiers (Key Categories)

| Category | Examples | Regulatory Relevance |
|---|---|---|
| **Financial** | Credit card numbers (PAN), bank account numbers, SWIFT codes | PCI-DSS, CCPA, GDPR |
| **Personal Identification** | SSN (US), SIN (Canada), TFN (Australia), NI number (UK), passport numbers | GDPR, PIPEDA, NDB, CCPA |
| **Health** | Medical record numbers, health insurance IDs, prescription information | HIPAA, GDPR Art. 9 |
| **Contact** | Email addresses, phone numbers, physical addresses | GDPR, CCPA, PIPEDA |
| **Credentials** | AWS access keys, private keys, API tokens | All (if used to access personal data) |
| **Demographic** | Dates of birth, gender, ethnicity, religious affiliation | GDPR Art. 9 (special categories) |

### Data Classification Tags (Recommended)

Apply these tags to S3 buckets, DynamoDB tables, RDS instances, and other data stores:

| Tag Key | Tag Values | Purpose |
|---|---|---|
| `DataClassification` | `PII`, `PHI`, `PCI`, `Financial`, `Biometric`, `Public`, `Internal`, `Confidential` | Primary classification |
| `DataSubjects` | `Customers`, `Employees`, `Partners`, `Patients`, `Children` | Identifies whose data |
| `DataJurisdictions` | `EU`, `UK`, `CA`, `US-CA`, `AU`, `Global` | Determines applicable regulations |
| `RetentionPolicy` | `30d`, `1y`, `3y`, `7y`, `Indefinite` | Data retention period |
| `DPIARequired` | `Yes`, `No`, `Completed` | DPIA status |

---

## Appendix E — Reference Links

### AWS Services & Documentation

- [Amazon Macie User Guide](https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html)
- [Amazon Macie Finding Types](https://docs.aws.amazon.com/macie/latest/user/findings-types.html)
- [Amazon Macie Managed Data Identifiers](https://docs.aws.amazon.com/macie/latest/user/managed-data-identifiers.html)
- [Amazon GuardDuty S3 Protection](https://docs.aws.amazon.com/guardduty/latest/ug/s3-protection.html)
- [AWS CloudTrail Data Events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- [AWS Security Incident Response Service](https://docs.aws.amazon.com/security-ir/latest/userguide/what-is-security-ir.html)
- [AWS Artifact](https://aws.amazon.com/artifact/)
- [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html)

### Frameworks & Standards

- [NIST SP 800-61r3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST CSF 2.0](https://www.nist.gov/cyberframework)
- [AWS Well-Architected Framework — Security Pillar: Incident Response](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/incident-response.html)
- [AWS Well-Architected Framework — Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [AWS CIRT Workshop Materials (GitHub)](https://github.com/aws-samples/aws-incident-response-playbooks-workshop/)

### Regulatory References

- [GDPR Full Text (Art. 33 & 34)](https://gdpr-info.eu/art-33-gdpr/)
- [UK ICO Breach Reporting](https://ico.org.uk/for-organizations/report-a-breach/)
- [CCPA/CPRA Text](https://oag.ca.gov/privacy/ccpa)
- [HIPAA Breach Notification Rule](https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html)
- [PCI-DSS v4.0 Requirement 12.10](https://www.pcisecuritystandards.org/)
- [PIPEDA Breach Reporting (OPC)](https://www.priv.gc.ca/en/privacy-topics/business-privacy/safeguards-and-breaches/privacy-breaches/respond-to-a-privacy-breach-at-your-business/)
- [Australian NDB Scheme (OAIC)](https://www.oaic.gov.au/privacy/notifiable-data-breaches)
- [NIS2 Directive](https://digital-strategy.ec.europa.eu/en/policies/nis2-directive)
- [DORA Regulation](https://www.digital-operational-resilience-act.com/)
- [SEC Cybersecurity Disclosure Rules](https://www.sec.gov/rules/final/2023/33-11216.pdf)

### Privacy & Data Protection

- [EDPB Guidelines on Personal Data Breach Notification](https://edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-92022-personal-data-breach-notification-under_en)
- [ICO Personal Data Breach Assessment Guidance](https://ico.org.uk/for-organizations/report-a-breach/personal-data-breach-assessment/)
- [OAIC Data Breach Preparation and Response Guide](https://www.oaic.gov.au/privacy/guidance-and-advice/data-breach-preparation-and-response)
- [Threat Technique Catalog for AWS](https://aws-samples.github.io/threat-technique-catalog-for-aws/)

---

## Revision History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | 2025-03-15 | IR Team | Initial draft — basic notification workflow |
| 2.0 | 2026-05-28 | IR Team | Complete rewrite: NIST SP 800-61r3 alignment, expanded regulatory coverage (NIS2, DORA, SEC), Macie integration, Athena queries, communication templates, DPIA/ROPA references, Game Day scenario |
| 2.1 | 2026-06-18 | IR Team | Modernization pass: Well-Architected references (SEC10-BP01/04/05/06), context paragraphs for all preparation sections, expanded escalation path to numbered steps, metrics with "Why It Matters" rationale, Athena queries moved to resources file, Section 2.7 expanded to P1–P3, Section 3.3 reframed as containment documentation, preparation adequacy review question, spelling standardization (American English), workshop resources added |
