# IRP-Ransomware: Ransomware in AWS Environments

> **Playbook Version:** 2.1
> **Last Reviewed:** 2026-06-18
> **Status:** `Active`
> **NIST Framework:** SP 800-61r3 (CSF 2.0 Community Profile)
> **Related Playbooks:** [IRP-CredCompromise](IRP-CredCompromise.md) | [IRP-EC2Compromise](IRP-EC2Compromise.md) (Coming Soon) | [IRP-DataAccess](IRP-DataAccess.md) | [IRP-S3DataExfiltration](IRP-S3DataExfiltration.md) (Coming Soon)

---

> ⚠️ **Disclaimer:** This playbook is provided as a template only. It should be customized to suit your organization's specific needs, risks, available tools, and work processes. This guide is not official AWS documentation and is provided as-is. Security and Compliance is a shared responsibility between you and AWS. You are responsible for making your own independent assessment of the information in this document.

---

## Overview

Ransomware in AWS environments differs significantly from traditional on-premises ransomware. Rather than encrypting local filesystems via malware execution, cloud-native ransomware typically leverages compromised credentials to perform destructive actions through AWS APIs — encrypting EBS volumes with threat actor-controlled KMS keys, deleting S3 object versions and replacing them with ransom notes, destroying RDS/Aurora snapshots, or disabling backup protections. The threat actor's goal is to deny the organization access to its own data and demand payment for restoration. Detection relies heavily on CloudTrail analysis, GuardDuty findings for unusual KMS and deletion activity, and monitoring for bulk destructive API patterns. Recovery depends on the organization's backup posture — particularly immutable backups via AWS Backup Vault Lock, S3 Object Lock, and EBS Snapshots Lock.

### Out of Scope

This playbook does **not** cover:

- **Initial credential compromise** — If you are still in the process of identifying and containing the compromised credential that enabled the ransomware activity, start with [IRP-CredCompromise](IRP-CredCompromise.md) and return here once containment of the credential is complete.
- **EC2 instance-level malware (file-encrypting ransomware running inside an instance)** — If ransomware is executing as a process within an EC2 instance (traditional file encryption), see [IRP-EC2Compromise](IRP-EC2Compromise.md) (Coming Soon) for instance isolation and forensics. Return here if the threat actor is also performing API-level destructive actions.
- **Data exfiltration without encryption/destruction** — If the threat actor is copying data out without encrypting or destroying it (double-extortion exfiltration component), see [IRP-S3DataExfiltration](IRP-S3DataExfiltration.md) (Coming Soon) for the exfiltration response. This playbook focuses on the denial-of-access component.
- **Extortion without technical action** — If you receive a ransom demand but no technical evidence of encryption or deletion, treat as a threat/social engineering event and engage Legal.

### Applicable Finding Types

| Source | Finding / Event Type | Severity |
|---|---|---|
| Amazon GuardDuty | `Execution:EC2/MaliciousFile` | HIGH |
| Amazon GuardDuty | `Execution:ECS/MaliciousFile` | HIGH |
| Amazon GuardDuty | `Execution:EC2/SuspiciousFile` | MEDIUM |
| Amazon GuardDuty | `Impact:EC2/BitcoinDomainRequest.Reputation` | HIGH |
| Amazon GuardDuty | `CryptoCurrency:EC2/BitcoinTool.B!DNS` | HIGH |
| Amazon GuardDuty | `UnauthorizedAccess:IAMUser/AnomalousBehavior` | MEDIUM |
| Amazon GuardDuty | `Persistence:IAMUser/AnomalousBehavior` | MEDIUM |
| Amazon GuardDuty | `Impact:S3/AnomalousBehavior.Delete` | HIGH |
| Amazon GuardDuty | `Impact:S3/AnomalousBehavior.Write` | HIGH |
| Amazon GuardDuty | `Exfiltration:S3/AnomalousBehavior` | HIGH |
| AWS Security Hub | AWS Foundational Security Best Practices — S3 controls | MEDIUM |
| AWS Security Hub | AWS Foundational Security Best Practices — Backup controls | MEDIUM |
| CloudTrail | `eventName: CreateKey` (KMS — from unusual principal or region) | — |
| CloudTrail | `eventName: Encrypt` / `ReEncrypt*` (KMS — bulk operations) | — |
| CloudTrail | `eventName: DeleteSnapshot` / `DeregisterImage` (bulk) | — |
| CloudTrail | `eventName: PutBucketVersioning` (Status: Suspended) | — |
| CloudTrail | `eventName: DeleteObjects` / `DeleteObject` (bulk) | — |
| CloudTrail | `eventName: DeleteDBSnapshot` / `DeleteDBClusterSnapshot` | — |
| CloudTrail | `eventName: PutObject` (ransom note files — e.g., `RANSOM_NOTE.txt`) | — |
| CloudTrail | `eventName: DisableKey` / `ScheduleKeyDeletion` (KMS) | — |
| CloudTrail | `eventName: DeleteBackupVault` / `DeleteRecoveryPoint` | — |
| Custom / Third-Party | SIEM correlation: bulk deletion patterns, unusual KMS usage spikes | HIGH |
| Custom / Third-Party | Billing anomaly: unexpected KMS charges or cross-region data transfer | MEDIUM |

> 📌 GuardDuty finding types are updated regularly. See the [GuardDuty finding types reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) for the current list.

### Severity Classification

| Priority | Criteria |
|---|---|
| **P1 — Critical** | Active encryption or deletion of production data confirmed; threat actor still has access; ransom demand received with evidence of data destruction; backup integrity uncertain |
| **P2 — High** | Bulk destructive API calls detected (snapshots deleted, versioning disabled), threat actor access revoked but damage scope unclear; OR ransom demand received with no confirmed technical action yet |
| **P3 — Medium** | Anomalous KMS or deletion activity detected, no confirmed data loss; OR single non-production account affected with confirmed good backups |
| **P4 — Low** | Ransom demand received with no technical evidence of compromise; OR post-incident review of a contained ransomware event |

---

## Part 1 — Prepare

> **CSF 2.0 Functions:** Govern · Identify · Protect
> **Goal:** Ensure the right configurations, access, and processes are in place *before* this incident type occurs.

### 1.1 Recommended AWS Service Configurations

The following services each contribute to your ability to detect, investigate, and respond to ransomware. None are strictly required, but each addresses a specific gap — the more you have enabled, the faster you can detect destructive activity and the more complete your recovery options will be during an incident.

- [ ] **Amazon GuardDuty** enabled in all regions with Malware Protection for EC2 and S3 enabled — provides continuous threat detection for malware execution, anomalous deletion patterns, and KMS abuse
- [ ] **AWS CloudTrail** enabled with multi-region trail, management + data events for S3 and KMS — the primary audit log for all API activity; without S3 and KMS data events, ransomware investigation is severely limited
- [ ] **CloudTrail Insights** enabled — detects unusual API call volume, critical for identifying bulk deletion patterns that indicate automated ransomware tooling
- [ ] **AWS Config** enabled with rules for backup compliance (`backup-plan-min-frequency-and-min-retention-check`, `backup-recovery-point-encrypted`) — continuous validation that backup posture meets requirements
- [ ] **AWS Backup** configured with Backup Vault Lock (compliance mode) on critical backup vaults — the single most important ransomware defense; compliance-mode locks cannot be removed, even by account administrators
- [ ] **S3 Object Lock** enabled on buckets containing critical data (Governance or Compliance mode) — prevents deletion or overwriting of object versions
- [ ] **S3 Versioning** enabled on all production buckets (cannot be disabled once Object Lock is set) — allows recovery of deleted or overwritten objects
- [ ] **EBS Snapshots Lock** enabled on critical snapshots (lock in compliance mode for immutability) — prevents snapshot deletion during an attack
- [ ] **KMS key policies** restrict `CreateKey`, `CreateGrant`, and `ScheduleKeyDeletion` to authorized principals only — limits threat actor ability to create encryption keys
- [ ] **SCPs** in place to prevent disabling of versioning, deletion of backup vaults, or KMS key deletion in production OUs — organizational guardrails that even compromised admin credentials cannot override
- [ ] **Amazon Detective** enabled for graph-based investigation of API activity chains — reduces time to scope the extent of destructive operations
- [ ] **Security Hub** enabled with AWS Foundational Security Best Practices standard — aggregates backup, S3, and KMS findings into a single view
- [ ] **AWS Elastic Disaster Recovery** configured for critical workloads (RPO/RTO validated) — provides fastest recovery path for full-instance restoration
- [ ] **VPC Flow Logs** enabled for all production VPCs — supports investigation of lateral movement and C2 communication

> 🤖 **Automation opportunity:** Deploy an EventBridge rule that triggers automatic EBS snapshot creation when GuardDuty generates a malware finding for an EC2 instance. This preserves the pre-encryption state. See [Appendix D](#appendix-d--automation-hooks) for implementation.

> 📖 **Reference:** [SEC10-BP06 Pre-deploy tools](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_deploy_tools.html) — AWS Well-Architected Framework recommends pre-deploying investigation and response tooling so capabilities are available immediately when needed.

### 1.2 IAM & Access Prerequisites

Effective incident response depends on having the right access available *before* an incident occurs. Provisioning break-glass access during an active ransomware event wastes critical minutes — minutes during which data is being encrypted or deleted. The following recommendations align with [SEC10-BP05 Pre-provision access](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_provision_access.html) from the AWS Well-Architected Framework.

- [ ] **Break-glass IAM role** exists in each account with permissions to: attach deny policies, modify security groups, copy/create snapshots, manage KMS keys, and query CloudTrail — pre-tested and documented
- [ ] **IR team members can assume the break-glass role** with MFA from a trusted (non-production) account — validate this works at least quarterly
- [ ] **Pre-built IAM deny policies** ready to attach during containment (see [Part 3 — Contain](#part-3--contain)):
  - `DenyAllKMSActions` — blocks `kms:Encrypt`, `kms:CreateKey`, `kms:CreateGrant`, `kms:ScheduleKeyDeletion`
  - `DenyDestructiveS3Actions` — blocks `s3:DeleteObject*`, `s3:PutBucketVersioning`
  - `DenySnapshotDeletion` — blocks `ec2:DeleteSnapshot`, `rds:DeleteDBSnapshot`, `rds:DeleteDBClusterSnapshot`
- [ ] **Forensic account** available with cross-account snapshot copy permissions — isolated from production
- [ ] **Access to AWS Security Incident Response console** confirmed (if subscribed) — verify case creation workflow before you need it
- [ ] **AWS Backup restore permissions** tested and validated (restore to forensic account) — do not discover permission gaps during a P1
- [ ] **SCP templates** prepared for emergency deployment to block destructive actions org-wide — pre-tested in a non-production OU

### 1.3 Communication & Escalation

Clear communication paths reduce confusion during high-pressure incidents. Ransomware events escalate quickly, involve multiple stakeholders (Legal, executives, potentially law enforcement), and may require time-sensitive decisions about ransom payment. Define who needs to be involved, at what severity threshold, and through which channel *before* you need them.

> 📋 Do not include names in this playbook. Use roles only. Maintain a separate, access-controlled contact list (e.g., internal wiki, sealed envelope, or secure document) with current names, phone numbers, and escalation preferences.

| Role | Responsibility | When to Engage |
|---|---|---|
| IR Lead | Overall incident coordination, status updates, recovery prioritization | All severity levels — first notified |
| Account Owner | Business context, authorization for containment actions, recovery decisions | P1–P3, or when containment may disrupt services |
| Backup Administrator | Validate backup integrity, execute restore operations | All severity levels — critical for recovery |
| Legal / Compliance | Regulatory notification, ransom payment decision guidance, law enforcement liaison | P1–P2, or when ransom demand received at any severity |
| Communications | Internal messaging, customer notification (if applicable) | P1–P2, or when customer-facing services are impacted |
| Executive Sponsor | Authorize business-impacting decisions (e.g., ransom payment, extended downtime) | P1–P2, or when ransom payment is being considered |
| AWS CIRT | Engage via AWS Support case or Security Incident Response service | P1–P2 (if available); P3 for backup integrity validation |
| Law Enforcement | FBI IC3 / local CERT reporting (coordinate through Legal) | When ransom demand received, or when required by regulation |

**Escalation path:**

1. **Detection:** Automated alert (GuardDuty, Security Hub, SIEM) or human report triggers initial notification.
2. **Triage (IR Lead, < 10 min):** IR Lead assesses severity using [Section 2.3](#23-severity-determination). Determines if the threat actor is still active and whether data destruction is confirmed.
3. **Severity-based escalation:**
   - **P1 (active destruction):** IR Lead begins containment immediately (standing authority — see [Section 3.1](#31-containment-decision)). Notifies Account Owner, Legal, and Executive Sponsor in parallel. Opens AWS Support case (severity: Critical) requesting CIRT assistance.
   - **P2 (confirmed damage, contained):** IR Lead notifies Account Owner and Legal. Opens AWS Support case for CIRT assistance with scoping and recovery.
   - **P3 (anomalous, unconfirmed):** IR Lead manages internally with Backup Administrator. Escalates to P2 if investigation confirms data loss.
4. **Status updates:** IR Lead provides updates every 15 minutes (P1), every 1 hour (P2), or at key milestones (P3/P4).

> ⚠️ **Ransom payment decisions** require Executive Sponsor and Legal involvement. IR Lead does not have authority to approve or deny payment. Consult your organization's Legal counsel and cyber insurance provider.

> 📖 **Reference:** [SEC10-BP01 Identify key personnel and external resources](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_identify_personnel.html) — recommends identifying and documenting internal and external resources and contact information ahead of time.

### 1.4 Game Day Guidance

Practicing incident response before a real incident occurs builds muscle memory, identifies gaps in backup coverage and tooling access, and validates that recovery procedures work under time pressure. Teams that exercise regularly contain ransomware incidents faster and make better recovery decisions.

Recommended testing cadence: **Semi-annually** (this is a P1-capable scenario with complex recovery procedures).

Suggested tabletop scenario:
> *"A threat actor has compromised an IAM user's access key (obtained from a phishing campaign targeting developers). The key has PowerUserAccess in a production account. Over the past 2 hours, the threat actor has: (1) created a new KMS key in us-east-1, (2) begun re-encrypting EBS volumes attached to production EC2 instances with the threat actor-controlled key, (3) suspended versioning on three S3 buckets and is bulk-deleting objects while uploading RANSOM_NOTE.txt files, and (4) deleted 5 RDS automated snapshots. Your GuardDuty finding fired 15 minutes ago. The threat actor appears to still be active. You have AWS Backup Vault Lock enabled on your primary backup vault, but you're unsure if all critical resources are covered by backup plans."*

Exercise should validate:
- Speed of credential revocation and SCP deployment
- Backup integrity verification process
- Cross-account snapshot copy procedures
- Communication flow to Legal and Executive Sponsor
- Recovery prioritization decisions under pressure

**Practice resources (no paid service or support plan required):**

- [AWS CIRT Incident Response Workshops](https://aws.amazon.com/blogs/security/aws-cirt-announces-the-release-of-five-publicly-available-workshops/) — free, hands-on workshops covering credential compromise, S3 ransomware, and more. Deployable in any AWS account.
- [Incident Response Playbooks Workshop](https://catalog.workshops.aws/incident-response-playbooks) — step-by-step exercises aligned with these playbooks.
- [AWS Security Workshops catalog](https://workshops.aws/categories/Security) — broader collection of security-focused hands-on labs.

> 📖 **Reference:** [SEC10-BP04 Develop and test security incident response playbooks](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_playbooks.html) — recommends creating and regularly testing playbooks to verify response processes.

---

## Part 2 — Detect & Analyze

> **CSF 2.0 Functions:** Detect · Respond (Analyze)
> **Goal:** Confirm whether an incident has occurred, scope its impact, and gather evidence for containment and investigation.

### 2.1 Initial Triage Questions

Not every alert is confirmed ransomware. The purpose of triage is to quickly determine whether active data destruction is occurring (requiring immediate containment) or whether you have time to investigate before acting. Answer these questions to establish scope and urgency — each should take less than 2 minutes. For ransomware, speed of assessment directly correlates with data preserved.

- [ ] What type of destructive activity is occurring? (EBS encryption, S3 deletion, snapshot destruction, backup deletion)
- [ ] Is the threat actor still active? (Check for ongoing API calls from the compromised principal)
- [ ] Which accounts and regions are affected? (Check CloudTrail across the organization)
- [ ] Has a ransom demand been received? (Check for ransom note files in S3, emails, or other channels)
- [ ] What is the compromised principal? (IAM user, role, federated session — route to IRP-CredCompromise for credential containment)
- [ ] Are backups intact? (Check AWS Backup vault, S3 versioned objects, cross-region/cross-account copies)
- [ ] Is AWS Backup Vault Lock enabled on relevant vaults? (If yes, recovery points are protected)
- [ ] Are production workloads currently impacted? (Application health, customer impact)
- [ ] Has the threat actor modified lifecycle or deletion policies? (Check KMS key policies for scheduled deletion, S3 lifecycle rules for accelerated expiration, RDS backup retention reduced to 0, AWS Backup vault deletion attempts — any of these could cause data loss mid-investigation or make recovery impossible)
- [ ] Are there signs of data exfiltration in addition to encryption/deletion? (Double extortion)

**If the threat actor is still active AND production data is being destroyed → P1 immediately. Proceed to containment in parallel with evidence collection.**

### 2.2 Evidence Documentation

> ⚠️ **For active ransomware (P1): Begin containment IMMEDIATELY while collecting evidence in parallel.** Unlike credential compromise where you collect before acting, active data destruction requires simultaneous containment and evidence collection.

Whether the activity is confirmed malicious or still under investigation, document the current state. For ransomware scenarios, the primary evidence sources are CloudTrail (API-level destruction) and service-specific state (snapshot inventory, versioning status, key policies).

| Evidence Type | How to Collect | Where to Store |
|---|---|---|
| CloudTrail events (KMS, EC2, S3, RDS, Backup) | Athena query (see resources file) | Forensic S3 bucket |
| GuardDuty findings (malware, anomalous behavior) | `aws guardduty get-findings` | Forensic S3 bucket |
| KMS key policies (threat actor-created keys) | `aws kms get-key-policy --key-id ...` | Forensic S3 bucket |
| List of deleted/modified snapshots | CloudTrail `DeleteSnapshot` events | IR ticket |
| S3 bucket versioning status | `aws s3api get-bucket-versioning` for affected buckets | IR ticket |
| S3 deleted object versions | `aws s3api list-object-versions --bucket ... --prefix ...` | Forensic S3 bucket |
| AWS Backup recovery point inventory | `aws backup list-recovery-points-by-backup-vault` | IR ticket |
| Ransom note content | Download from S3 / screenshot from email | Forensic S3 bucket (legal hold) |
| EBS volume encryption status | `aws ec2 describe-volumes --filters Name=encrypted,Values=true` | IR ticket |
| IAM credential report | `aws iam generate-credential-report` | IR ticket |
| Billing/Cost Explorer anomalies | AWS Cost Explorer — filter by KMS, EC2, S3 | IR ticket |

**CloudTrail / Athena investigation queries:**

For detailed Athena queries to investigate ransomware activity (KMS operations, bulk deletions, snapshot manipulation, S3 versioning changes, backup vault operations), see:

📁 [`resources/athena-queries-ransomware.sql`](resources/athena-queries-ransomware.sql)

These queries cover:
- KMS key creation and encryption operations by a suspected principal
- Bulk deletion activity across S3, EBS, RDS, and AWS Backup
- Snapshot operations (deletion, cross-account sharing, copying)
- S3 versioning suspension and Object Lock modifications
- Ransom note file uploads (common filename patterns)
- RDS/Aurora snapshot and backup destruction
- AWS Backup recovery point deletion attempts (including Vault Lock blocks)

### 2.3 Severity Determination

| Confirmed? | Priority Assignment |
|---|---|
| Active encryption/deletion in progress, threat actor still has access, production impacted | P1 |
| Confirmed data destruction, threat actor access revoked, backup integrity uncertain | P1 |
| Bulk destructive API calls detected, threat actor contained, backups confirmed intact | P2 |
| Ransom demand received, no confirmed technical action, investigation ongoing | P2 |
| Anomalous KMS/deletion activity, single non-production account, no confirmed data loss | P3 |
| Post-incident analysis or ransom demand with no evidence of compromise | P4 |

### 2.4 Getting Help from AWS

> 📌 **If your organization has the AWS Security Incident Response service enabled, or has AWS Support, you can request assistance from the AWS Customer Incident Response Team (CIRT).**

For P1, P2, or P3 incidents, consider engaging AWS for support. Ransomware recovery is complex and time-sensitive — AWS CIRT can help validate backup integrity, advise on recovery sequencing, and provide threat intelligence on the threat actor.

- **If you have the AWS Security Incident Response service enabled:** Sign into [AWS Security Incident Response](https://console.aws.amazon.com/security-ir/) via the console, choose **Create Case**, select **Resolve case with AWS**, and choose **Active Security Incident** for urgent incident response support. This provides direct access to AWS Security Incident Response engineers for containment guidance, backup validation, and recovery sequencing.
- **If you need assistance from AWS CIRT:** Open a support case with Critical severity and request assistance from the AWS Customer Incident Response Team (CIRT). Include relevant finding IDs and a summary of what you have observed.

> 📌 You do not need the Security Incident Response service to get help from AWS CIRT. All AWS customers can request CIRT assistance through a support case, regardless of support plan level.

AWS CIRT can assist with:
- Scoping the extent of destructive operations
- Validating backup integrity and advising on recovery sequencing
- Providing threat intelligence on the threat actor's tactics
- Advising on containment strategy for active encryption/deletion
- Supporting regulatory notification decisions with technical evidence

> 🤖 **Automation opportunity:** Security Hub custom actions can auto-create Security Incident Response cases when GuardDuty generates malware findings or when bulk deletion patterns are detected.

---

## Part 3 — Contain

> **CSF 2.0 Function:** Respond (Contain)
> **Goal:** Stop the spread of the incident and prevent further damage without destroying evidence.

### 3.1 Containment Decision

For ransomware, containment speed is paramount. Every minute of delay means more data encrypted or deleted. Unlike other incident types where you may investigate before acting, active data destruction requires immediate action.

```
Is active encryption/deletion in progress?
│
├── YES (threat actor still active)
│     └── IMMEDIATE containment — proceed to 3.2 without waiting for authorization
│         (IR Lead has standing authority for P1 ransomware containment)
│
└── NO (threat actor appears inactive or already contained)
      └── Has the compromised credential been revoked?
            ├── YES → Proceed to 3.2 for defensive hardening
            └── NO  → Revoke credential FIRST (see IRP-CredCompromise), then proceed
```

> ⚠️ **For active ransomware (P1), containment takes priority over evidence collection.** You can reconstruct the attack timeline from CloudTrail after the fact. You cannot recover data that has been encrypted with a threat actor-controlled key and then had the key deleted.

### 3.2 Containment Actions

> `[IR Lead]` coordinates. For P1 active ransomware, IR Lead has standing authority to execute Steps 1–4 without waiting for Account Owner approval.

**Step 1: Revoke threat actor access (if not already done)**

If the compromised credential has not yet been contained via IRP-CredCompromise, immediately disable the credential and attach an explicit deny:

```bash
# Disable the compromised access key
aws iam update-access-key --access-key-id AKIAIOSFODNN7EXAMPLE \
  --status Inactive --user-name compromised-user

# Attach explicit deny-all policy to the compromised principal
aws iam attach-user-policy --user-name compromised-user \
  --policy-arn arn:aws:iam::123456789012:policy/DenyAll

# Revoke all active sessions for the compromised role (if role-based)
aws iam put-role-policy --role-name compromised-role \
  --policy-name RevokeOlderSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {"aws:TokenIssueTime": "2026-05-28T12:00:00Z"}
      }
    }]
  }'
```

**Step 2: Deploy emergency SCP to block destructive actions org-wide**

Apply this SCP to the affected OU (or root, if scope is unclear) to prevent further destruction even if additional credentials are compromised. This is the broadest containment lever — it stops all destructive actions regardless of which principal is performing them:

```bash
# Create and attach emergency SCP
aws organizations create-policy \
  --name "EmergencyRansomwareContainment" \
  --type SERVICE_CONTROL_POLICY \
  --description "Emergency: Block destructive actions during ransomware incident" \
  --content '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyDestructiveActions",
        "Effect": "Deny",
        "Action": [
          "kms:CreateKey",
          "kms:ScheduleKeyDeletion",
          "kms:DisableKey",
          "kms:CreateGrant",
          "ec2:DeleteSnapshot",
          "rds:DeleteDBSnapshot",
          "rds:DeleteDBClusterSnapshot",
          "s3:DeleteObject*",
          "s3:PutBucketVersioning",
          "backup:DeleteRecoveryPoint",
          "backup:DeleteBackupVault"
        ],
        "Resource": "*",
        "Condition": {
          "StringNotLike": {
            "aws:PrincipalArn": [
              "arn:aws:iam::*:role/IncidentResponseBreakGlass"
            ]
          }
        }
      }
    ]
  }'

# Attach to affected OU
aws organizations attach-policy \
  --policy-id p-EXAMPLE123 \
  --target-id ou-EXAMPLE
```

> ⚠️ **This SCP will block legitimate operations.** Document the time applied and plan for removal once the incident is contained.

**Step 3: Network isolation for affected EC2 instances**

If ransomware is executing as a process on EC2 instances, isolate them via security group swap. This cuts C2 communication and lateral movement while preserving the instance for forensics:

```bash
# Create forensic isolation security group (if not pre-created)
aws ec2 create-security-group \
  --group-name forensic-isolation \
  --description "IR: No inbound/outbound - forensic isolation" \
  --vpc-id vpc-EXAMPLE

# The group has no rules by default (deny all) — that's the desired state

# Apply to affected instances (replaces all existing security groups)
aws ec2 modify-instance-attribute \
  --instance-id i-1234567890abcdef0 \
  --groups sg-forensic-isolation
```

> ⚠️ Do NOT stop or terminate instances. Stopping an instance with an instance-store volume will destroy volatile evidence. Isolation via security group swap preserves the instance state.

**Step 4: Preserve snapshots (copy to forensic account)**

Immediately copy any remaining EBS snapshots and RDS snapshots to a forensic account before the threat actor can delete them. This is your safety net if primary backups are compromised:

```bash
# Copy EBS snapshot to forensic account (cross-account)
aws ec2 modify-snapshot-attribute \
  --snapshot-id snap-EXAMPLE \
  --attribute createVolumePermission \
  --operation-type add \
  --user-ids 999888777666  # Forensic account ID

# From the forensic account — copy the snapshot
aws ec2 copy-snapshot \
  --source-region us-east-1 \
  --source-snapshot-id snap-EXAMPLE \
  --description "IR-preserved: ransomware incident 2026-06-18"

# Copy RDS snapshot to forensic account
aws rds copy-db-snapshot \
  --source-db-snapshot-identifier arn:aws:rds:us-east-1:123456789012:snapshot:my-snapshot \
  --target-db-snapshot-identifier ir-preserved-snapshot-2026-06-18 \
  --kms-key-id arn:aws:kms:us-east-1:999888777666:key/forensic-key-id
```

**Step 5: Lock remaining EBS snapshots**

Apply EBS Snapshots Lock to prevent deletion of any remaining snapshots. Compliance mode locks cannot be removed early — even by an administrator:

```bash
# Lock snapshot in compliance mode (cannot be unlocked early)
aws ec2 lock-snapshot \
  --snapshot-id snap-EXAMPLE \
  --lock-mode compliance \
  --lock-duration 30  # days — adjust based on investigation timeline
```

**Step 6: Disable delete operations on critical S3 buckets**

Apply a bucket policy that denies delete operations from all principals except the IR break-glass role. This stops ongoing S3 destruction immediately:

```bash
aws s3api put-bucket-policy --bucket critical-data-bucket \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "DenyDeleteDuringIncident",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutBucketVersioning"],
      "Resource": [
        "arn:aws:s3:::critical-data-bucket",
        "arn:aws:s3:::critical-data-bucket/*"
      ],
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::123456789012:role/IncidentResponseBreakGlass"
        }
      }
    }]
  }'
```

> 🤖 **Automation opportunity:** An EventBridge rule triggered by GuardDuty `Impact:S3/AnomalousBehavior.Delete` findings can automatically apply protective bucket policies. See [Appendix D](#appendix-d--automation-hooks).

### 3.3 Document Containment Actions

After containment begins, document what was done and verify evidence is preserved:

- [ ] EBS snapshots taken for all affected EC2 instances (before any recovery actions)
- [ ] Remaining EBS snapshots locked with EBS Snapshots Lock (compliance mode)
- [ ] RDS/Aurora snapshots copied to forensic account
- [ ] S3 object versions preserved (verify versioning was not successfully suspended)
- [ ] CloudTrail logs exported to forensic S3 bucket with Object Lock
- [ ] Threat actor-created KMS key policies captured (`aws kms get-key-policy`)
- [ ] Ransom note files preserved (do not delete — evidence)
- [ ] AWS Backup recovery points inventory documented
- [ ] CloudTrail integrity validation confirmed on exported logs
- [ ] Timeline of containment actions documented in IR ticket (what was done, when, by whom)

---

## Part 4 — Eradicate & Recover

> **CSF 2.0 Function:** Respond (Eradicate) · Recover
> **Goal:** Remove the root cause, validate the environment is clean, and restore normal operations.

### 4.1 Root Cause Identification

> `[IR Lead]` owns this step. Document findings in the IR ticket in real time.

Common root causes for cloud-native ransomware:

- **Compromised IAM credentials** — Long-term access keys exposed via phishing, public repository, or credential stuffing (most common)
- **Overly permissive IAM policies** — PowerUserAccess or AdministratorAccess on principals that don't require it
- **Missing preventive controls** — No SCPs blocking destructive actions, no Backup Vault Lock, no S3 Object Lock
- **Compromised EC2 instance role** — Malware on an instance leveraging the instance metadata service to obtain role credentials
- **Third-party integration compromise** — SaaS tool or CI/CD pipeline with excessive AWS permissions compromised
- **Insider threat** — Disgruntled employee or contractor with legitimate access performing destructive actions

> 📌 This is not an exhaustive list. Root causes vary by environment and threat actor. Use evidence from Part 2 to identify the specific initial access vector for your incident.

Use evidence collected in Part 2 to trace:
1. Initial access vector (how did the threat actor get credentials?)
2. Privilege escalation path (how did they get destructive permissions?)
3. Full scope of destructive actions (what was encrypted/deleted?)
4. Persistence mechanisms (are there additional backdoors?)

### 4.2 Eradication Actions

> `[IR Lead]` coordinates. `[Account Owner]` approves changes to production resources.

1. **Remove threat actor persistence mechanisms**
   Check for and remove:
   - [ ] Unauthorized IAM users, roles, or access keys created during incident
   - [ ] Threat actor-created KMS keys and grants (document key IDs before deletion)
   - [ ] Unauthorized Lambda functions or EC2 instances (potential C2 or re-encryption tools)
   - [ ] Modified resource policies (S3 bucket policies, KMS key policies, trust relationships)
   - [ ] Modified SCPs or permission boundaries
   - [ ] Unauthorized CloudFormation stacks or Terraform state modifications
   - [ ] EventBridge rules or scheduled actions created by threat actor

   > 📌 **This list is not exhaustive.** Threat actors employ many persistence techniques beyond those listed here. For a comprehensive reference of persistence mechanisms observed in AWS environments, see the [Threat Technique Catalog for AWS](https://aws-samples.github.io/threat-technique-catalog-for-aws/).

2. **Rotate all credentials in affected accounts**
   ```bash
   # Generate new access keys for legitimate users (after deleting compromised ones)
   aws iam create-access-key --user-name legitimate-user
   
   # Force password reset for all console users in affected account
   # (Coordinate with Account Owner — this will disrupt users)
   ```

3. **Validate KMS key integrity**
   - Confirm all legitimate KMS keys are still enabled and accessible
   - Verify key policies have not been modified to grant threat actor access
   - If threat actor scheduled key deletion, cancel it immediately:
   ```bash
   aws kms cancel-key-deletion --key-id arn:aws:kms:us-east-1:123456789012:key/KEY_ID
   aws kms enable-key --key-id arn:aws:kms:us-east-1:123456789012:key/KEY_ID
   ```

4. **Remove emergency containment controls (when safe)**
   - Remove emergency SCP (replace with permanent preventive SCPs)
   - Remove emergency bucket policies (replace with proper access controls)
   - Restore security groups on isolated instances (only after forensics complete)

> 🤖 **Automation opportunity:** AWS Config auto-remediation rules can detect unauthorized IAM resources and automatically delete them. Use with caution during active incidents.

### 4.3 Recovery Decision: Backup-First Approach

> `[IR Lead]` provides technical assessment of backup integrity. Payment decisions are outside the scope of this playbook — consult your organization's Legal counsel and cyber insurance provider.

```
Can we recover from backups?
│
├── YES — Backups confirmed intact (Vault Lock / Object Lock / cross-account copies)
│     └── Proceed to recovery from backups (Section 4.4)
│
└── NO or UNCERTAIN — Backups may be compromised or incomplete
      │
      └── Can we validate backup integrity?
            ├── YES → Test restore in isolated environment
            │           ├── Restore successful → Proceed to 4.4
            │           └── Restore failed or incomplete → See below
            └── NO  → See below
```

**If backups are unavailable or incomplete:**

- Engage your organization's **Legal counsel** and **cyber insurance provider** immediately. Payment decisions involve legal, regulatory, and business considerations that are outside the scope of technical incident response.
- Continue all technical recovery efforts in parallel — exhaust every backup and restore option before concluding that data is unrecoverable.
- Engage **AWS CIRT** (via support case) for assistance identifying any remaining recovery paths (cross-region snapshots, S3 versioned objects, Backup recovery points in other vaults).
- Report to **law enforcement** (FBI IC3 or local CERT) — coordinate through Legal.

> 📌 **The strongest defense against ransom payment is preparation.** AWS Backup Vault Lock (compliance mode), S3 Object Lock, and EBS Snapshots Lock ensure that backups cannot be deleted or modified — even by an administrator with full account access. Investing in immutable backups before an incident ensures that payment is never a consideration during one.

### 4.4 Recovery Actions

Recovery is often the most complex phase of a ransomware incident. Multiple recovery methods may be needed depending on which services were affected and what backup mechanisms were in place. The priority order is: (1) Validate backup integrity, (2) Restore critical workloads, (3) Restore supporting services, (4) Validate and harden.

**Recovery Method 1: AWS Backup (with Vault Lock validation)**

If AWS Backup Vault Lock (compliance mode) is enabled, recovery points in that vault are guaranteed to be unmodified. This is the fastest path to confident recovery:

```bash
# List recovery points in the vault-locked backup vault
aws backup list-recovery-points-by-backup-vault \
  --backup-vault-name production-vault-locked

# Verify vault lock status (compliance mode = immutable)
aws backup describe-backup-vault \
  --backup-vault-name production-vault-locked
# Confirm: "Locked": true, "LockDate": <date>, "MinRetentionDays": <value>

# Start restore job (EBS volume example)
aws backup start-restore-job \
  --recovery-point-arn arn:aws:ec2:us-east-1::snapshot/snap-EXAMPLE \
  --iam-role-arn arn:aws:iam::123456789012:role/AWSBackupRestoreRole \
  --metadata '{"availabilityZone":"us-east-1a","encrypted":"true","kmsKeyId":"arn:aws:kms:us-east-1:123456789012:key/LEGITIMATE-KEY-ID"}'

# Start restore job (RDS example)
aws backup start-restore-job \
  --recovery-point-arn arn:aws:rds:us-east-1:123456789012:snapshot:awsbackup-EXAMPLE \
  --iam-role-arn arn:aws:iam::123456789012:role/AWSBackupRestoreRole \
  --metadata '{"DBInstanceClass":"db.r5.large","DBInstanceIdentifier":"restored-production-db","MultiAZ":"true"}'
```

**Recovery Method 2: S3 versioning (restoring previous object versions)**

If versioning was enabled and the threat actor deleted current versions or uploaded ransom notes, previous versions may still be retrievable:

```bash
# List object versions to find pre-attack versions
aws s3api list-object-versions \
  --bucket affected-bucket \
  --prefix important-data/ \
  --max-keys 1000

# Restore a specific previous version (copy it as the current version)
aws s3api copy-object \
  --bucket affected-bucket \
  --key important-data/file.dat \
  --copy-source "affected-bucket/important-data/file.dat?versionId=PRE_ATTACK_VERSION_ID"

# Bulk restore script (for many objects):
# List all delete markers created during the attack window and remove them
aws s3api list-object-versions \
  --bucket affected-bucket \
  --prefix important-data/ \
  --query "DeleteMarkers[?LastModified>='2026-06-18T10:00:00' && LastModified<='2026-06-18T14:00:00'].{Key:Key,VersionId:VersionId}" \
  --output json > delete_markers_to_remove.json

# Then iterate and remove each delete marker to "undelete" objects
# (Use a script — see Appendix D for automation)
```

**Recovery Method 3: EBS snapshot restore**

For EC2 workloads where volumes were encrypted with a threat actor-controlled KMS key, restore from pre-attack snapshots:

```bash
# Create volume from pre-attack snapshot
aws ec2 create-volume \
  --snapshot-id snap-PRE_ATTACK_SNAPSHOT \
  --availability-zone us-east-1a \
  --volume-type gp3 \
  --encrypted \
  --kms-key-id arn:aws:kms:us-east-1:123456789012:key/LEGITIMATE-KEY-ID

# Detach compromised volume and attach restored volume
aws ec2 detach-volume --volume-id vol-COMPROMISED --instance-id i-EXAMPLE
aws ec2 attach-volume --volume-id vol-RESTORED --instance-id i-EXAMPLE --device /dev/sda1
```

**Recovery Method 4: RDS point-in-time recovery**

For databases where snapshots were deleted or the instance was modified, point-in-time recovery allows restoration to any second within the backup retention window:

```bash
# Restore to a point in time before the attack
aws rds restore-db-instance-to-point-in-time \
  --source-db-instance-identifier production-db \
  --target-db-instance-identifier production-db-restored \
  --restore-time "2026-06-18T09:00:00Z" \
  --db-instance-class db.r5.large \
  --multi-az

# For Aurora clusters
aws rds restore-db-cluster-to-point-in-time \
  --source-db-cluster-identifier production-cluster \
  --db-cluster-identifier production-cluster-restored \
  --restore-to-time "2026-06-18T09:00:00Z" \
  --engine aurora-postgresql
```

**Recovery Method 5: AWS Elastic Disaster Recovery failover**

For workloads configured with AWS Elastic Disaster Recovery (DRS), this provides the fastest RTO for full-instance recovery:

```bash
# Initiate recovery launch for affected source servers
aws drs start-recovery \
  --source-servers '[{"sourceServerID": "s-1234567890abcdef0"}]' \
  --is-drill false

# Monitor recovery job status
aws drs describe-jobs --filters '{"jobIDs": ["j-EXAMPLE"]}'
```

> ⚠️ Elastic Disaster Recovery provides the fastest RTO for full-instance recovery. If configured, prefer this method for EC2 workloads over manual snapshot restore.

### 4.5 Recovery Validation

Confirm the environment is clean and functional before declaring the incident resolved.

- [ ] All restored data validated for integrity (checksums, application-level validation)
- [ ] No unauthorized resources remain in affected accounts
- [ ] All threat actor-created KMS keys disabled or deleted (after confirming they're not needed for evidence)
- [ ] All credentials created or used by threat actor have been revoked
- [ ] Legitimate KMS keys confirmed accessible and functional
- [ ] Application and service health metrics are within normal range
- [ ] Database connectivity and query results validated
- [ ] S3 bucket versioning re-enabled (if it was suspended by threat actor)
- [ ] GuardDuty / Security Hub show no active findings related to this incident
- [ ] Emergency SCP removed and replaced with permanent preventive controls
- [ ] Monitoring and alerting confirmed operational
- [ ] AWS Backup jobs running successfully on restored resources
- [ ] AWS Security Incident Response case updated (if applicable)

### 4.6 Harden Against Recurrence

- [ ] Enable AWS Backup Vault Lock (compliance mode) on all backup vaults containing critical data
- [ ] Enable S3 Object Lock on buckets containing critical data
- [ ] Enable EBS Snapshots Lock on critical snapshots
- [ ] Implement SCPs to prevent disabling of versioning, Vault Lock, and Object Lock in production OUs
- [ ] Restrict KMS `CreateKey` and `ScheduleKeyDeletion` permissions to authorized principals only
- [ ] Enable MFA Delete on S3 buckets containing critical data
- [ ] Implement least-privilege IAM — remove PowerUserAccess and AdministratorAccess from non-admin principals
- [ ] Configure AWS Elastic Disaster Recovery for critical workloads (if not already)
- [ ] Enable cross-account and cross-region backup copies
- [ ] Implement backup integrity testing (automated restore validation)

---

## Part 5 — Post-Incident Activity

> **CSF 2.0 Function:** Identify (Improve) — continuous improvement, not a one-time activity
> **Goal:** Learn from this incident to reduce the likelihood and impact of future occurrences.

### 5.1 Timeline Reconstruction

Build a complete timeline of the incident from initial compromise through recovery. This should be completed within 24–48 hours while events are fresh and CloudTrail data is readily queryable. A clear timeline supports post-incident review, regulatory inquiries, and future detection tuning.

| Timestamp (UTC) | Event | Source / Evidence | Actor |
|---|---|---|---|
| YYYY-MM-DD HH:MM | Initial credential compromise | CloudTrail / phishing report | Threat actor |
| YYYY-MM-DD HH:MM | Threat actor-controlled KMS key created | CloudTrail `kms:CreateKey` | Threat actor |
| YYYY-MM-DD HH:MM | EBS volume encryption began | CloudTrail `ec2:CreateSnapshot`, `kms:Encrypt` | Threat actor |
| YYYY-MM-DD HH:MM | S3 versioning suspended on buckets | CloudTrail `s3:PutBucketVersioning` | Threat actor |
| YYYY-MM-DD HH:MM | Bulk S3 object deletion began | CloudTrail `s3:DeleteObject` | Threat actor |
| YYYY-MM-DD HH:MM | RDS snapshots deleted | CloudTrail `rds:DeleteDBSnapshot` | Threat actor |
| YYYY-MM-DD HH:MM | Ransom note uploaded to S3 | CloudTrail `s3:PutObject` | Threat actor |
| YYYY-MM-DD HH:MM | GuardDuty finding generated | GuardDuty | AWS |
| YYYY-MM-DD HH:MM | IR team notified | On-call alert | IR Lead |
| YYYY-MM-DD HH:MM | Credential revoked | CloudTrail `iam:UpdateAccessKey` | IR Lead |
| YYYY-MM-DD HH:MM | Emergency SCP deployed | CloudTrail `organizations:AttachPolicy` | IR Lead |
| YYYY-MM-DD HH:MM | Containment confirmed | IR ticket | IR Lead |
| YYYY-MM-DD HH:MM | Recovery from backup initiated | AWS Backup console | Backup Admin |
| YYYY-MM-DD HH:MM | Recovery validated, services restored | Application monitoring | IR Lead |

**Key metrics:**

These metrics help you measure response effectiveness over time and identify where investment would reduce future incident duration or data loss.

| Metric | Value | Why It Matters |
|---|---|---|
| Time to Detect (TTD) | *HH:MM from initial destructive action to detection* | Measures detection coverage — every minute undetected is more data lost |
| Time to Notify (TTN) | *HH:MM from detection to IR team notified* | Measures alerting pipeline effectiveness |
| Time to Contain (TTC) | *HH:MM from notification to threat actor access revoked* | Measures response readiness — the critical window for ransomware |
| Time to Recover (TTR) | *HH:MM from containment to services restored* | Measures backup posture and recovery process maturity |
| Total Incident Duration | *HH:MM* | End-to-end impact window |
| Data Loss Window | *Time between last good backup and attack start* | Measures backup frequency adequacy — drives RPO decisions |
| Resources Affected | *Count: EBS volumes, S3 buckets, RDS instances, snapshots deleted* | Blast radius |
| Data Impact | *Confirmed / Suspected / None — quantify GB/TB if possible* | Drives regulatory notification and business impact assessment |
| Recovery Method Used | *Backup Vault Lock / S3 Versioning / Snapshot / DRS / Other* | Validates which investments paid off |
| Ransom Paid | *Yes / No — if yes, document amount and outcome* | Organizational record |

### 5.2 Post-Incident Review

Conduct a blameless post-incident review within **3 business days** for P1, **5 business days** for P2, **15 business days** for P3/P4. The goal is to identify systemic improvements — particularly to backup posture and preventive controls — not to assign blame.

Discussion questions specific to ransomware:

1. What was the initial access vector? Could it have been prevented with existing controls?
2. Did the threat actor have more permissions than necessary? Would least-privilege have limited the scope of impact?
3. Were immutable backups (Vault Lock, Object Lock) in place for all critical data? If not, why not?
4. How quickly was the attack detected? Could detection have been faster with better monitoring?
5. Were containment actions effective? Did the emergency SCP deploy quickly enough?
6. Was the recovery process smooth? Were there gaps in backup coverage?
7. Did the team know where to find backups and how to restore? Was documentation adequate?
8. Were communication and escalation paths clear? Did Legal and Executive Sponsor engage at the right time?
9. What single preventive control would have most reduced the impact of this incident?
10. Is our backup strategy adequate? Do we need to expand Vault Lock / Object Lock coverage?
11. Were our preparation steps (Part 1) adequate? Did we have the access, tools, and documentation we needed?

### 5.3 Detection Gap Analysis

For each gap identified during the incident — whether a detection that didn't fire, an alert that wasn't actioned, or a blind spot in backup coverage — document the root cause and assign an owner to fix it.

| Gap | Root Cause | Recommended Fix | Owner | Target Date |
|---|---|---|---|---|
| *(e.g., Bulk deletion not detected for 2 hours)* | *(No CloudWatch alarm on S3 delete volume)* | *(Create alarm for >100 deletes/hour)* | | |
| *(e.g., KMS key creation not alerted)* | *(No EventBridge rule for CreateKey)* | *(Deploy EventBridge rule + SNS alert)* | | |
| *(e.g., Versioning suspension not detected)* | *(No Config rule for versioning status)* | *(Enable `s3-bucket-versioning-enabled` rule)* | | |
| *(e.g., No alert on snapshot deletion)* | *(GuardDuty doesn't cover this natively)* | *(Custom EventBridge rule for DeleteSnapshot)* | | |

### 5.4 Playbook Update Checklist

Use this incident to improve this playbook. Do not wait for the next scheduled review — update immediately while the gaps are clear.

- [ ] Were triage questions sufficient? Add/remove as needed.
- [ ] Were evidence collection steps accurate for this scenario?
- [ ] Were containment actions effective? Update steps if not.
- [ ] Were recovery procedures accurate? Update with lessons learned.
- [ ] Was the recovery decision tree useful? Refine based on actual decision process.
- [ ] Were any automation opportunities identified? Add to Appendix D.
- [ ] Were severity criteria accurate? Adjust if incidents were under- or over-classified.
- [ ] Update **Last Reviewed** date and increment **Playbook Version**.

---

## Appendix A — Investigation Resources

For detailed Athena queries, GuardDuty CLI commands, and CloudTrail investigation patterns relevant to ransomware investigations, see:

📁 [`resources/athena-queries-ransomware.sql`](resources/athena-queries-ransomware.sql)

These queries cover:
- KMS key creation and encryption operations by a suspected principal
- Bulk deletion activity across S3, EBS, RDS, and AWS Backup (with anomaly detection)
- Snapshot operations — deletion, cross-account sharing, copying
- S3 versioning suspension and Object Lock modifications
- Ransom note file uploads (common filename patterns)
- RDS/Aurora snapshot and backup destruction
- AWS Backup recovery point deletion attempts (including Vault Lock blocks)

**GuardDuty Finding Export (CLI):**

```bash
# List malware and impact findings
aws guardduty list-findings \
  --detector-id DETECTOR_ID \
  --finding-criteria '{
    "Criterion": {
      "type": {
        "Eq": ["Execution:EC2/MaliciousFile", "Impact:S3/AnomalousBehavior.Delete",
               "Impact:S3/AnomalousBehavior.Write"]
      },
      "severity": {"Gte": 7}
    }
  }' \
  --region us-east-1

# Get full finding details
aws guardduty get-findings \
  --detector-id DETECTOR_ID \
  --finding-ids FINDING_ID_1 FINDING_ID_2
```

---

## Appendix B — Regulatory & Compliance Considerations

> `[Legal / Compliance]` owns this section during an active incident.

Ransomware incidents trigger notification obligations under most regulatory frameworks because they involve both a security breach (unauthorized access) and potential data loss (availability impact). Even if no data was exfiltrated, the loss of availability alone may trigger notification requirements.

**Quick reference for ransomware scenarios:**

| Regulation / Framework | Trigger Condition | Timeframe | Notes |
|---|---|---|---|
| **GDPR Art. 33/34** | Personal data unavailable due to encryption/deletion (availability breach) | 72 hours to supervisory authority; "without undue delay" to data subjects if high risk | Ransomware is explicitly called out in EDPB guidance as a notifiable breach even without exfiltration |
| **HIPAA Breach Notification** | ePHI encrypted or destroyed by unauthorized party | 60 days to HHS; 60 days to individuals; media if >500 affected | Presumed breach unless low probability of compromise demonstrated |
| **PCI DSS v4.0 (Req. 12.10)** | Cardholder data environment affected | Immediately to acquirer and card brands | May trigger forensic investigation requirement (PFI) |
| **SOC 2 (Trust Services Criteria)** | Availability or confidentiality criteria impacted | Per engagement terms | Document in management assertion; notify auditor |
| **SEC Cybersecurity Rules (2023)** | Material cybersecurity incident | 4 business days (Form 8-K) | Materiality determination required — ransomware with significant operational impact likely qualifies |
| **NIS2 Directive (EU)** | Significant incident affecting essential/important entity | 24 hours early warning; 72 hours incident notification | Ransomware causing service disruption meets "significant incident" threshold |
| **PIPEDA (Canada)** | Real risk of significant harm from breach | "As soon as feasible" to Privacy Commissioner and affected individuals | Encryption/destruction of personal information qualifies |
| **Australian NDB Scheme** | Eligible data breach involving personal information | 30 days to OAIC; "as soon as practicable" to individuals | Loss of access to personal information through ransomware is an eligible breach |
| **DORA (EU Financial)** | Major ICT-related incident | 4 hours initial notification; 72 hours intermediate report | Financial entities — ransomware disrupting services is a major ICT incident |
| **State Breach Laws (US)** | Personal information of state residents affected | Varies by state (24 hours to 60 days) | Check each applicable state; some require AG notification |
| **CISA Reporting (CIRCIA)** | Covered entity experiences substantial cyber incident | 72 hours (when final rule effective) | Ransomware payment: 24 hours |

> ⚠️ The clock starts at **awareness**, not confirmation. When in doubt, assume notification is required and consult Legal immediately. For ransomware, the availability impact alone (inability to access data) is sufficient to trigger most frameworks — you do not need to prove exfiltration.

> ⚠️ **Ransom payments** have additional reporting requirements. CISA requires reporting within 24 hours. OFAC sanctions screening is mandatory before any payment. Consult Legal before any payment decision.

---

## Appendix C — Reference Links

- [NIST SP 800-61r3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html)
- [AWS Security Incident Response Service Documentation](https://docs.aws.amazon.com/security-ir/latest/userguide/what-is-security-ir.html)
- [AWS Well-Architected Framework — Security Pillar: Incident Response](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/incident-response.html)
- [AWS Well-Architected Framework — Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [Amazon GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [Amazon GuardDuty Malware Protection](https://docs.aws.amazon.com/guardduty/latest/ug/malware-protection.html)
- [AWS Backup Vault Lock](https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html)
- [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [EBS Snapshots Lock](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-snapshot-lock.html)
- [AWS Elastic Disaster Recovery](https://docs.aws.amazon.com/drs/latest/userguide/what-is-drs.html)
- [AWS KMS Key Management Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- [CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [AWS CloudTrail Query Examples (Athena)](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)
- [AWS Organizations — Service Control Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [AWS CIRT Incident Response Workshops](https://aws.amazon.com/blogs/security/aws-cirt-announces-the-release-of-five-publicly-available-workshops/)

---

## Appendix D — Automation Hooks

### EventBridge Rule: Auto-Snapshot on GuardDuty Malware Finding

When GuardDuty detects malware on an EC2 instance, automatically create EBS snapshots of all attached volumes to preserve the pre-encryption state.

**EventBridge Rule Pattern:**
```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "type": [
      {"prefix": "Execution:EC2/MaliciousFile"},
      {"prefix": "Execution:EC2/SuspiciousFile"},
      {"prefix": "CryptoCurrency:EC2/BitcoinTool"}
    ],
    "severity": [{"numeric": [">=", 7]}]
  }
}
```

**Target: Lambda function (or Step Functions state machine)**

```python
# Lambda function: auto-snapshot on GuardDuty malware finding
import boto3
import json
from datetime import datetime

ec2 = boto3.client('ec2')

def handler(event, context):
    """Create EBS snapshots for all volumes attached to the affected instance."""
    
    detail = event['detail']
    instance_id = detail['resource']['instanceDetails']['instanceId']
    finding_id = detail['id']
    finding_type = detail['type']
    
    # Describe instance to get attached volumes
    response = ec2.describe_instances(InstanceIds=[instance_id])
    
    if not response['Reservations']:
        print(f"Instance {instance_id} not found")
        return
    
    instance = response['Reservations'][0]['Instances'][0]
    volumes = [bdm['Ebs']['VolumeId'] 
               for bdm in instance.get('BlockDeviceMappings', [])
               if 'Ebs' in bdm]
    
    snapshot_ids = []
    for volume_id in volumes:
        snapshot = ec2.create_snapshot(
            VolumeId=volume_id,
            Description=f"IR-AUTO: GuardDuty {finding_type} - {finding_id}",
            TagSpecifications=[{
                'ResourceType': 'snapshot',
                'Tags': [
                    {'Key': 'CreatedBy', 'Value': 'IR-Automation'},
                    {'Key': 'GuardDutyFinding', 'Value': finding_id},
                    {'Key': 'SourceInstance', 'Value': instance_id},
                    {'Key': 'CreatedAt', 'Value': datetime.utcnow().isoformat()},
                    {'Key': 'Purpose', 'Value': 'forensic-preservation'}
                ]
            }]
        )
        snapshot_ids.append(snapshot['SnapshotId'])
        
        # Lock the snapshot immediately (governance mode — can be unlocked by IR team)
        ec2.lock_snapshot(
            SnapshotId=snapshot['SnapshotId'],
            LockMode='governance',
            LockDuration=30  # days
        )
    
    print(f"Created and locked {len(snapshot_ids)} snapshots for instance {instance_id}: {snapshot_ids}")
    return {'snapshotIds': snapshot_ids, 'instanceId': instance_id}
```

### EventBridge Rule: Alert on Bulk Deletion Patterns

```json
{
  "source": ["aws.s3", "aws.ec2", "aws.rds"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": [
      "DeleteObject", "DeleteObjects", "DeleteSnapshot",
      "DeleteDBSnapshot", "DeleteDBClusterSnapshot",
      "DeleteRecoveryPoint", "PutBucketVersioning"
    ]
  }
}
```

**Target:** SNS topic → IR team notification + CloudWatch metric for alarm threshold (>50 delete operations in 5 minutes).

### EventBridge Rule: Alert on KMS Key Creation from Unusual Principal

```json
{
  "source": ["aws.kms"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["CreateKey", "CreateGrant", "ScheduleKeyDeletion"],
    "userIdentity": {
      "type": [{"anything-but": "AssumedRole"}]
    }
  }
}
```

**Target:** SNS topic → immediate IR team notification. Any KMS key creation outside of expected automation roles warrants investigation.

### S3 Bulk Restore Script

For restoring many objects after a ransomware attack that deleted current versions:

```bash
#!/bin/bash
# restore_s3_versions.sh — Remove delete markers created during attack window
# Usage: ./restore_s3_versions.sh <bucket> <prefix> <attack_start> <attack_end>

BUCKET=$1
PREFIX=$2
ATTACK_START=$3
ATTACK_END=$4

echo "Listing delete markers created between ${ATTACK_START} and ${ATTACK_END}..."

aws s3api list-object-versions \
  --bucket "${BUCKET}" \
  --prefix "${PREFIX}" \
  --query "DeleteMarkers[?LastModified>='${ATTACK_START}' && LastModified<='${ATTACK_END}'].[Key,VersionId]" \
  --output text | while read KEY VERSION_ID; do
    echo "Removing delete marker: ${KEY} (${VERSION_ID})"
    aws s3api delete-object \
      --bucket "${BUCKET}" \
      --key "${KEY}" \
      --version-id "${VERSION_ID}"
done

echo "Restore complete. Verify object accessibility."
```

---

## Appendix E — Ransomware Attack Patterns in AWS

The patterns below represent common cloud-native ransomware attack chains observed in AWS environments. For a comprehensive catalog of individual techniques (including those not specific to ransomware), see the [Threat Technique Catalog for AWS](https://aws-samples.github.io/threat-technique-catalog-for-aws/).

### Pattern 1: EBS Volume Encryption

1. Threat actor creates a new KMS key (customer-managed) in the target account
2. Threat actor creates snapshots of target EBS volumes
3. Threat actor creates new encrypted volumes from snapshots using threat actor-controlled KMS key
4. Threat actor swaps volumes on running instances (or stops instances and replaces root volumes)
5. Threat actor deletes original snapshots and schedules deletion of the KMS key
6. Threat actor leaves ransom note (often via S3 or instance user data)

**Detection indicators:** Unusual `kms:CreateKey`, `ec2:CreateSnapshot`, `ec2:CopySnapshot` with new KMS key, `ec2:DeleteSnapshot` in rapid succession.

### Pattern 2: S3 Ransomware (Delete + Ransom Note)

1. Threat actor suspends versioning on target buckets (`PutBucketVersioning` with Status: Suspended)
2. Threat actor deletes all objects in the bucket (or specific high-value prefixes)
3. Threat actor uploads ransom note files (e.g., `RANSOM_NOTE.txt`, `README_RESTORE.html`)
4. If versioning was already enabled, threat actor may create delete markers on all objects instead

**Detection indicators:** `PutBucketVersioning` (Suspended), bulk `DeleteObject`/`DeleteObjects`, `PutObject` for ransom note filenames.

### Pattern 3: S3 Ransomware (Server-Side Encryption Swap)

1. Threat actor creates a KMS key with a restrictive key policy (only threat actor can decrypt)
2. Threat actor copies objects back to the same bucket with new server-side encryption using threat actor's KMS key
3. Threat actor deletes the original object versions
4. Data is now encrypted with a key the organization cannot access

**Detection indicators:** `s3:CopyObject` with `x-amz-server-side-encryption-aws-kms-key-id` pointing to an unknown key, followed by version deletion.

### Pattern 4: RDS/Aurora Snapshot Destruction

1. Threat actor deletes automated snapshots (`DeleteDBSnapshot`, `DeleteDBClusterSnapshot`)
2. Threat actor modifies backup retention to 0 days (disables automated backups)
3. Threat actor may delete the database instance itself
4. Without snapshots or backups, recovery is impossible without payment

**Detection indicators:** Bulk `DeleteDBSnapshot`, `ModifyDBInstance` with `BackupRetentionPeriod: 0`, `DeleteDBInstance` with `SkipFinalSnapshot: true`.

### Pattern 5: AWS Backup Destruction

1. Threat actor attempts to delete recovery points from backup vaults
2. If Vault Lock is not enabled, threat actor deletes recovery points
3. Threat actor may attempt to delete the backup vault itself
4. If Vault Lock IS enabled (compliance mode), deletion fails — this is the primary defense

**Detection indicators:** `DeleteRecoveryPoint`, `DeleteBackupVault` (will fail if Vault Lock is enabled — look for `errorCode` in CloudTrail).

---

## Revision History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | 2024-03-15 | AWS CIRT | Initial draft — basic ransomware response procedures |
| 1.1 | 2024-09-01 | AWS CIRT | Added S3 Object Lock and Backup Vault Lock guidance |
| 2.0 | 2026-05-28 | AWS CIRT | Complete rewrite — NIST SP 800-61r3 alignment, CSF 2.0 mapping, expanded recovery procedures, automation hooks, EBS Snapshots Lock, Elastic Disaster Recovery, regulatory matrix, attack pattern appendix |
| 2.1 | 2026-06-18 | AWS CIRT | PR2 refresh — context paragraphs added, queries moved to resources file, forward references updated, "threat actor" terminology, SEC10 references, Well-Architected links, escalation path expanded, Game Day resources added, pay/don't-pay messaging fixed |
