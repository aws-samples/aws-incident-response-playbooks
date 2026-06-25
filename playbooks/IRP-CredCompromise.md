# IRP-CredCompromise: IAM Credential Compromise

> **Playbook Version:** 2.0
> **Last Reviewed:** 2026-06-18
> **Status:** `Active`
> **NIST Framework:** SP 800-61r3 (CSF 2.0 Community Profile)
> **Related Playbooks:** [IRP-STSTokenAbuse](IRP-STSTokenAbuse.md) | [IRP-IdentityCenterCompromise](IRP-IdentityCenterCompromise.md) | [IRP-FederatedAccessAbuse](IRP-FederatedAccessAbuse.md) | [IRP-Ransomware](IRP-Ransomware.md)

---

> ⚠️ **Disclaimer:** This playbook is provided as a template only. It should be customized to suit your organization's specific needs, risks, available tools, and work processes. This guide is not official AWS documentation and is provided as-is. Security and Compliance is a shared responsibility between you and AWS. You are responsible for making your own independent assessment of the information in this document.

---

## Overview

IAM credential compromise occurs when an unauthorized party obtains valid AWS credentials — long-term access keys, console passwords, or session tokens — and uses them to access AWS resources. This is one of the most common incident types in AWS environments. Compromised credentials may be obtained through phishing, credential stuffing, accidental exposure in public repositories, malware on developer workstations, or social engineering. The scope of impact depends on the permissions attached to the compromised principal and how quickly the compromise is detected and contained.

### Out of Scope

This playbook does **not** cover:

- **STS temporary credential abuse via AssumeRole chains** — If the primary vector is cross-account role assumption or session token manipulation without initial long-term credential theft, see [IRP-STSTokenAbuse](IRP-STSTokenAbuse.md). (Coming Soon)
- **Identity Center (SSO) compromise** — If the compromise involves AWS Identity Center permission sets or SSO sessions, see [IRP-IdentityCenterCompromise](IRP-IdentityCenterCompromise.md). (Coming Soon)
- **Federated identity / IdP compromise** — If the initial compromise is at the identity provider level (Okta, Azure AD, etc.) leading to AWS access, see [IRP-FederatedAccessAbuse](IRP-FederatedAccessAbuse.md). (Coming Soon)
- **Ransomware resulting from credential compromise** — Once containment here is complete, pivot to [IRP-Ransomware](IRP-Ransomware.md) if encryption or extortion activity is detected.

### Applicable Finding Types

| Source | Finding / Event Type | Severity |
|---|---|---|
| Amazon GuardDuty | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | HIGH |
| Amazon GuardDuty | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS` | HIGH |
| Amazon GuardDuty | `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` | MEDIUM |
| Amazon GuardDuty | `Discovery:IAMUser/AnomalousBehavior` | LOW |
| Amazon GuardDuty | `Persistence:IAMUser/AnomalousBehavior` | MEDIUM |
| Amazon GuardDuty | `CredentialAccess:IAMUser/AnomalousBehavior` | MEDIUM |
| Amazon GuardDuty | `InitialAccess:IAMUser/AnomalousBehavior` | MEDIUM |
| AWS Security Hub | IAM Access Analyzer external access findings | HIGH |
| AWS Security Hub | IAM Access Analyzer unused access findings | MEDIUM |
| CloudTrail | `eventName: CreateAccessKey` (for unexpected principals) | — |
| CloudTrail | `eventName: ConsoleLogin` (from unusual sourceIP/userAgent) | — |
| CloudTrail | `eventName: GetCallerIdentity` (reconnaissance indicator) | — |
| Third-Party | GitHub/GitLab secret scanning alerts | HIGH |
| Third-Party | SIEM correlation: impossible travel, credential stuffing patterns | MEDIUM |

> 📌 GuardDuty finding types are updated regularly. See the [GuardDuty finding types reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) for the current list.

### Severity Classification

| Priority | Criteria |
|---|---|
| **P1 — Critical** | Confirmed credential use with data access/exfiltration, resource creation in production accounts, or lateral movement to additional accounts |
| **P2 — High** | Confirmed unauthorized API calls from compromised credential, scope unclear, or credential exposed publicly (GitHub, paste site) |
| **P3 — Medium** | Anomalous behavior detected on a principal (unusual IP, user agent, or API pattern) but no confirmed malicious action yet |
| **P4 — Low** | Stale credential identified with no evidence of use, or policy violation (e.g., access key older than 90 days) |

---

## Part 1 — Prepare

> **CSF 2.0 Functions:** Govern · Identify · Protect
> **Goal:** Ensure the right configurations, access, and processes are in place *before* this incident type occurs.

### 1.1 Recommended AWS Service Configurations

The following services each contribute to your ability to detect, investigate, and respond to credential compromise. None are strictly required, but each addresses a specific gap — the more you have enabled, the faster you can detect anomalous activity and the more complete your forensic picture will be during an investigation.

- [ ] **Amazon GuardDuty** enabled in all regions with findings exported to Security Hub — provides continuous threat detection for IAM anomalies, credential exfiltration, and reconnaissance patterns
- [ ] **AWS CloudTrail** enabled with multi-region trail, management events, and integrity validation — the primary audit log for all API activity; without it, investigation is severely limited
- [ ] **CloudTrail Insights** enabled — detects unusual API call volume that may indicate automated credential abuse
- [ ] **AWS Config** enabled with IAM-related rules (e.g., `iam-user-mfa-enabled`, `access-keys-rotated`) — provides continuous compliance assessment of IAM configuration
- [ ] **IAM Access Analyzer** enabled (both external access and unused access analyzers) — identifies overly permissive or unused access that increases the scope of impact if a credential is compromised
- [ ] **Amazon Detective** enabled — provides graph-based investigation of credential usage patterns, reducing time to scope an incident
- [ ] **AWS Security Hub** enabled with AWS Foundational Security Best Practices standard — aggregates and prioritizes findings across services into a single pane
- [ ] **CloudWatch alarms** configured for root account usage and console login failures — provides immediate alerting on high-risk authentication events
- [ ] **S3 bucket for CloudTrail logs** has Object Lock or versioning enabled — protects audit trail from tampering by a threat actor who gains administrative access

> 🤖 **Automation opportunity:** Deploy the [AWS Security Hub Automated Response and Remediation (SHARR)](https://aws.amazon.com/solutions/implementations/automated-security-response-on-aws/) solution to auto-remediate common IAM findings.

> 📖 **Reference:** [SEC10-BP06 Pre-deploy tools](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_deploy_tools.html) — AWS Well-Architected Framework recommends pre-deploying investigation and response tooling so capabilities are available immediately when needed.

### 1.2 IAM & Access Prerequisites

Effective incident response depends on having the right access available *before* an incident occurs. Provisioning break-glass access during an active compromise wastes time, may be blocked by the threat actor, and introduces risk of error under pressure. The following recommendations align with [SEC10-BP05 Pre-provision access](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_provision_access.html) from the AWS Well-Architected Framework.

- [ ] **Break-glass IAM role** exists in each account with scoped permissions to: list/delete access keys, deactivate MFA, attach deny policies, query CloudTrail, and export GuardDuty findings — pre-tested and documented
- [ ] **IR team members can assume the break-glass role** with MFA from a trusted (non-production) account — validate this works at least quarterly
- [ ] **Deny-all IAM policy** is pre-created and ready to attach during containment (see [Part 3 — Contain](#part-3--contain))
- [ ] **Forensic account** is available for cross-account log analysis — isolated from production, with appropriate trust relationships pre-configured
- [ ] **IAM credential report** generation tested and accessible — confirm responders know how to generate and interpret it
- [ ] **Access to AWS Security Incident Response console** confirmed, if subscribed — verify case creation workflow before you need it

> 📖 **Reference:** [AWS Security Incident Response Guide — Preparation](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/preparation.html) — covers pre-provisioning access, establishing forensic accounts, and validating response capabilities.

### 1.3 Communication & Escalation

Clear communication paths reduce confusion during high-pressure incidents. Define who needs to be involved, at what severity threshold, and through which channel *before* you need them. The goal is to avoid spending incident time figuring out who to call.

> 📋 Do not include names in this playbook. Use roles only. Maintain a separate, access-controlled contact list (e.g., internal wiki, sealed envelope, or secure document) with current names, phone numbers, and escalation preferences.

| Role | Responsibility | When to Engage |
|---|---|---|
| IR Lead | Overall incident coordination, status updates, decision authority for containment actions | All severity levels — first notified |
| Account Owner | Business context, authorization for credential revocation, impact assessment | P1–P3, or when containment may disrupt services |
| Application Owner | Impact assessment of credential rotation on running services, identification of dependent systems | When the compromised credential is used by applications or automation |
| Legal / Compliance | Regulatory notification assessment, evidence preservation hold, breach counsel | P1–P2, or when regulated data may have been accessed |
| AWS Support / AWS CIRT | Technical assistance with scoping, containment guidance, threat intelligence | P1–P2 via AWS Support case (any support plan) or Security Incident Response service (if subscribed) |

**Escalation path:**

1. **Detection:** Automated alert (GuardDuty, secret scanning, SIEM) or human report triggers initial notification.
2. **Triage (IR Lead, < 15 min):** IR Lead assesses severity using [Section 2.3](#23-severity-determination). Determines if the credential is still active and whether unauthorized use is confirmed.
3. **Severity-based escalation:**
   - **P1/P2:** IR Lead notifies Account Owner and Legal/Compliance immediately. Opens AWS Support case (severity: Critical) requesting CIRT assistance. If AWS Security Incident Response service is enabled, creates a case there instead.
   - **P3/P4:** IR Lead manages internally with Application Owner. Escalates to P2 if investigation confirms unauthorized use.
4. **Status updates:** IR Lead provides updates to stakeholders every 30 minutes (P1), every 2 hours (P2), or at key milestones (P3/P4).

> 📖 **Reference:** [SEC10-BP01 Identify key personnel and external resources](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_identify_personnel.html) — recommends identifying and documenting internal and external resources and contact information ahead of time.

### 1.4 Game Day Guidance

Practicing incident response before a real incident occurs builds muscle memory, identifies gaps in tooling and access, and validates that escalation paths work. Teams that exercise regularly contain incidents faster.

Recommended testing cadence: **Semi-annually** (this is a P1-capable scenario).

Suggested tabletop scenario:
> *"A developer's long-term access key has been found in a public GitHub repository. The key has AdministratorAccess permissions in a production account. GitHub's secret scanning alert fired 4 hours ago. You don't know if anyone else has already used the key."*

**Practice resources (no paid service or support plan required):**

- [AWS CIRT Incident Response Workshops](https://aws.amazon.com/blogs/security/aws-cirt-announces-the-release-of-five-publicly-available-workshops/) — free, hands-on workshops covering credential compromise, S3 ransomware, and more. Deployable in any AWS account.
- [AWS Security Workshops catalog](https://workshops.aws/categories/Security) — broader collection of security-focused hands-on labs.

> 📖 **Reference:** [SEC10-BP04 Develop and test security incident response playbooks](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_playbooks.html) — recommends creating and regularly testing playbooks to verify response processes.

---

## Part 2 — Detect & Analyze

> **CSF 2.0 Functions:** Detect · Respond (Analyze)
> **Goal:** Determine whether the credential activity is authorized or unauthorized, understand the scope if it is unauthorized, and document the evidence needed to support containment and recovery decisions.

### 2.1 Initial Triage Questions

Not every alert is a confirmed compromise. The purpose of triage is to quickly determine whether you are dealing with a true positive (unauthorized use), a potential compromise requiring investigation, or a false positive that can be closed. Answer these questions to establish scope and urgency — each should take less than 2 minutes.

- [ ] What type of credential is involved? (Long-term access key, console password, session token, SAML assertion)
- [ ] How was the activity detected? (GuardDuty, secret scanning, user report, third-party notification)
- [ ] Is the activity confirmed unauthorized, or could it be legitimate but unusual? (New region, new service, off-hours access by an on-call engineer)
- [ ] What permissions does the principal have? (Check IAM policies — inline, attached, group-inherited, permission boundaries)
- [ ] Which accounts and regions could this principal access? (Check trust policies, resource policies, SCPs)
- [ ] Is the credential still active? (`aws iam get-access-key-last-used` or credential report)
- [ ] Is there evidence the credential has been used from an unfamiliar source? (Unusual IPs, user agents, geographic locations)
- [ ] Are production workloads or sensitive data accessible with this credential?
- [ ] Could persistence mechanisms have been created? (New access keys, roles, users, Lambda functions)

**If the credential has admin-level permissions AND evidence of unauthorized use → P1 immediately.**
**If the activity is anomalous but could be legitimate → investigate further before containment (avoid unnecessary disruption).**

### 2.2 Evidence Documentation

Whether the activity is confirmed malicious or still under investigation, document the current state of the credential and its usage. For IAM credential scenarios, the primary evidence source is AWS CloudTrail. The priority here is *documenting what you observe* rather than copying logs to a separate location.

> 📌 **Note on evidence storage:** If you have a dedicated forensic S3 bucket or SIEM, export findings there. If you don't, that's fine — CloudTrail logs, GuardDuty findings in the console, and notes in your IR ticket or documentation tool are sufficient for this scenario.

**Document the following:**

| What to Document | How | Notes |
|---|---|---|
| Credential details (key ID, user, creation date) | `aws iam list-access-keys --user-name USER` | Establishes which credential is under review |
| When the credential was last used | `aws iam get-access-key-last-used --access-key-id AKIA...` | Determines if credential is actively in use |
| IAM credential report (all users) | `aws iam generate-credential-report && aws iam get-credential-report` | Provides full picture of credential posture |
| Permissions attached to the principal | `aws iam list-attached-user-policies` / `list-user-policies` / `list-groups-for-user` | Determines scope of impact |
| Source IPs and user agents in CloudTrail | Athena query or CloudTrail console (see below) | Distinguishes legitimate vs. unfamiliar usage |
| GuardDuty findings for the principal | GuardDuty console → filter by resource | May provide additional context on the nature of the activity |
| IAM Access Analyzer findings | Security Hub or IAM Access Analyzer console | Shows if the principal has external or unused access |
| Resources created or modified by the principal | CloudTrail filtered by `userIdentity.accessKeyId` | Identifies potential persistence or damage |

**CloudTrail / Athena investigation queries:**

For detailed Athena queries to investigate credential usage (source IP analysis, persistence detection, data access events, cross-account role assumptions), see:

📁 [`resources/athena-queries-credential-compromise.sql`](resources/athena-queries-credential-compromise.sql)

**Quick CloudTrail Console approach (no Athena required):**

If Athena is not configured, you can investigate directly in the CloudTrail console:
1. Navigate to **CloudTrail → Event history**
2. Filter by **User name** = the IAM user under investigation
3. Review source IPs — compare against known corporate IP ranges
4. Look for API calls you don't expect from this user (e.g., `CreateAccessKey`, `AssumeRole` to unfamiliar accounts)
5. Check the time range — activity outside normal working hours from unfamiliar IPs is a strong indicator

### 2.3 Severity Determination

| Confirmed? | Priority Assignment |
|---|---|
| Admin credential used from unknown IP, resources created or data accessed | P1 |
| Credential confirmed used by unauthorized party, scope unclear | P2 |
| Credential exposed publicly but no evidence of unauthorized use yet | P2 |
| Anomalous behavior on principal, compromise not confirmed | P3 |
| Stale/unused credential found, no evidence of abuse | P4 |

### 2.4 Getting Help from AWS

For P1, P2, or P3 incidents, consider engaging AWS for support. AWS Support and AWS CIRT can help you determine whether activity is truly unauthorized, assist with scoping the impact, and advise on containment approaches — you do not need to be certain of a compromise before reaching out.

- **AWS Security Incident Response service** (if enabled): Sign into [AWS Security Incident Response](https://console.aws.amazon.com/security-ir/) via the console, choose **Create Case**, select **Resolve case with AWS**, and choose **Active Security Incident** for urgent support or **Investigations and Inquiries** for log analysis and secondary confirmation of findings.
- **AWS Support** (any support plan): Open a support case requesting assistance from the AWS Customer Incident Response Team (CIRT). Include the finding ID(s), the credential under investigation, and a summary of the anomalous behavior you have observed.

> 📌 You do not need the Security Incident Response service to get help experts. All AWS customers can request CIRT assistance through a support case, regardless of support plan level. For P3 (anomalous behavior, not yet confirmed), AWS CIRT can help you determine whether the activity is malicious or legitimate.

---

## Part 3 — Contain

> **CSF 2.0 Function:** Respond (Contain)
> **Goal:** Prevent further unauthorized API activity using the credential under investigation, while minimizing disruption to legitimate users and services. Containment should be deliberate — deactivate credentials rather than delete them, so you can observe what breaks and retain forensic value.

### 3.1 Containment Decision

The goal of containment is to disable the credential so it can no longer be used, while understanding the impact of that action. Deactivating (not deleting or revoking) is preferred because it allows you to: (1) observe if legitimate services or users are impacted, (2) retain the credential ID for CloudTrail investigation, and (3) reverse the action quickly if the alert turns out to be a false positive.

```
Has the credential been confirmed used by a threat actor?
│
├── YES (confirmed unauthorized use from unfamiliar source)
│     └── Proceed to 3.2 immediately — deactivate the credential
│
├── EXPOSED but no confirmed use yet (e.g., GitHub secret scan, paste site)
│     └── Proceed to 3.2 immediately — the threat actor may already have it
│         and is waiting to use it; time advantage matters
│
└── ANOMALOUS but unconfirmed (unusual IP or API pattern, could be legitimate)
      └── Investigate further (Part 2) before taking containment action
            ├── If confirmed unauthorized → Proceed to 3.2
            ├── If confirmed legitimate → Document and close
            └── If still unclear after 30 min → Consider engaging AWS CIRT (Section 2.4)
                  for help determining if the activity is malicious
```

### 3.2 Containment Actions

> `[IR Lead]` coordinates. `[Account Owner]` authorizes. `[Application Owner]` assesses service impact of credential deactivation.

The containment approach depends on the type of credential involved. In all cases, the immediate task is to disable the credential or restrict permissions associated with it, preventing further API activity.

#### If the credential is a long-term IAM user access key:

1. **Deactivate the access key** using the IAM console or CLI. Do not delete it — deactivation preserves the key ID for CloudTrail queries and can be reversed if needed.
2. **Monitor CloudTrail** for the next 30 minutes to confirm the credential is no longer being used. If you see continued activity from the same `accessKeyId`, the deactivation may not have propagated yet (allow a few minutes) or additional credentials may be in play.
3. **Note any service disruption** — if legitimate applications were using this key, they will begin failing. Document what breaks so you can address it during recovery.


#### If the credential is a console password:

1. **Attach an explicit deny-all inline policy** to the IAM user. This immediately blocks all API and console actions while preserving the user account for investigation.
2. **Consider deleting the login profile** (console password) if the threat actor may have changed the password or registered their own MFA device.
3. **Check for MFA devices** — if the threat actor registered an MFA device, deactivate it.

> 📌 There is no "deactivate" for console passwords. Attaching a deny-all inline policy is the fastest way to contain console access without destroying the user's configuration.

#### If the credential is a short-term STS token (associated with an IAM role):

Short-term credentials obtained via AWS STS are associated with an IAM role and will remain valid until they expire (default up to 1 hour, configurable up to 12 hours). There are several options to contain these:

1. **Revoke current role sessions** by attaching an inline policy with a `DateLessThan` condition on `aws:TokenIssueTime`. This invalidates all temporary credentials issued before the current timestamp. Note: if the threat actor can obtain new credentials (still has the ability to call `AssumeRole`), this alone will not solve the problem.

2. **If the threat actor continues to obtain new credentials**, it will be necessary to take additional action:
   - Remove or modify IAM policies attached to the role to block access
   - Modify the role's trust policy to prevent the threat actor from assuming the role
   - As a last resort, detach all policies from the role

3. **Important:** Modifying the trust policy prevents new sessions from being created, but any currently valid credentials will continue to work until they expire. The session revocation approach (step 1) is the only way to immediately invalidate existing sessions.

> ⚠️ Steps 1 and 2 will stop **all users** from using credentials obtained by assuming the role, including legitimate users and applications. Coordinate with the Application Owner before taking these actions.

#### For all credential types — verify containment:

After taking containment action, verify effectiveness by monitoring CloudTrail for the next 30 minutes for ongoing credential use. Filter by:
- The specific `accessKeyId` (for long-term keys)
- The IAM user name (for console access)
- The role name and session name (for STS credentials)

If activity continues from the same principal, the threat actor may have established persistence through additional credentials. Check for:
- Additional access keys created on the same or other users
- New IAM roles with trust policies allowing assumption from external accounts
- Lambda functions or other compute resources with attached roles

#### Lateral movement check:

If the credential had permissions to assume roles in other accounts (cross-account access), check CloudTrail for `AssumeRole` calls to other accounts. If confirmed, repeat containment steps in those accounts.


### 3.3 Document Containment Actions

Record all containment actions taken, including timestamps, who performed them, and what was affected. This documentation supports the post-incident timeline (Part 5) and is important for any regulatory inquiries.

- [ ] What credential was deactivated and when (timestamp, key ID or user, who performed the action)
- [ ] What services or applications were impacted by the deactivation
- [ ] Whether the deactivation was effective (did unauthorized activity stop?)
- [ ] Any additional containment actions taken (deny policies, trust policy modifications, role session revocation)
- [ ] Whether lateral movement to other accounts was identified and contained

---

## Part 4 — Eradicate & Recover

## Part 4 — Eradicate

> **CSF 2.0 Function:** Respond (Eradicate)
> **Goal:** Identify the root cause of the compromise, remove any persistence mechanisms the threat actor created, and confirm the environment is clean. Eradication often uncovers additional compromised resources — if new findings emerge during this phase, return to Part 3 (Contain) for any newly identified credentials or access paths before continuing.

### 4.1 Root Cause Identification

> `[IR Lead]` owns this step. Document findings in the IR ticket in real time.

Understanding how the credential was compromised is essential before issuing replacement credentials — if the root cause isn't resolved, new credentials will be compromised the same way.

Common root causes for IAM credential compromise:

- **Accidental exposure:** Access key committed to a public Git repository, pasted in a forum, included in a container image, or stored in plaintext in application configuration
- **Phishing / social engineering:** User tricked into providing credentials or approving an MFA push notification
- **Credential stuffing:** Console password reused from a breached third-party service (password reuse across sites)
- **Malware / infostealer:** Credential harvested from a developer workstation by malware or a browser extension
- **Overly permissive access:** The credential had far more permissions than needed, amplifying the scope of impact of the compromise
- **Lack of rotation:** Long-lived access key never rotated, increasing the window of exposure

Use the evidence documented in Part 2 to determine:
- Where did the threat actor access from? (Geolocation, VPN/proxy, known malicious infrastructure)
- When did unauthorized access begin? (First API call from the threat actor's IP)
- How did the threat actor obtain the credential? (Check for public exposure, `GetSecretValue` access, phishing reports)

### 4.2 Remove Credential-Based Persistence

> `[IR Lead]` coordinates. `[Account Owner]` approves changes to production resources.

When a credential is compromised, threat actors commonly create additional credentials or access paths that survive deactivation of the original credential. This section focuses on identifying and removing credential-based persistence. If the threat actor also created other resources (EC2 instances, Lambda functions, modified resource policies, etc.), refer to the eradication section of the relevant playbook for that resource type — for example, [IRP-EC2Compromise](IRP-EC2Compromise.md) (Coming Soon) for unauthorized compute resources.

**Identify and remove unauthorized credentials:**

- [ ] Additional access keys created on the compromised user (threat actors often create a second key before the first is deactivated)
- [ ] Access keys created on *other* legitimate users during the incident window
- [ ] Unauthorized IAM users created by the threat actor (check CloudTrail for `CreateUser` events)
- [ ] Unauthorized IAM roles with trust policies allowing assumption from external accounts or from the compromised principal
- [ ] Modified trust policies on existing roles (adding external principals the threat actor controls)
- [ ] Unauthorized IAM policies attached to existing users or roles (escalating permissions beyond what was originally granted)
- [ ] Modified permission boundaries or SCPs (weakening guardrails)

**Rotate accessed secrets:**

- [ ] Secrets accessed via Secrets Manager — rotate these immediately
- [ ] SSM Parameter Store values accessed — update with new values
- [ ] Any credentials stored in application configuration that the threat actor could have read (database passwords, API keys, etc.)

> ⚠️ **If you discover additional compromised credentials or access paths during eradication, return to Part 3 (Contain) and deactivate those credentials before continuing.** Eradication is iterative — it's common to cycle between containment and eradication multiple times.

> 📌 **Beyond credentials:** If CloudTrail shows the threat actor created compute resources, modified resource policies, or took other actions beyond credential manipulation, consult the relevant playbook for eradication guidance specific to those resource types. For a comprehensive reference of persistence techniques observed in AWS environments, see the [Threat Technique Catalog for AWS](https://aws-samples.github.io/threat-technique-catalog-for-aws/).

### 4.3 Eradication Validation

Before moving to recovery, confirm that the threat actor's access has been fully removed:

- [ ] All persistence mechanisms identified in 4.2 have been removed
- [ ] CloudTrail shows no continued unauthorized activity for at least 30 minutes after eradication actions
- [ ] All accessed secrets and credentials have been rotated
- [ ] No unauthorized resources remain in affected accounts
- [ ] SCPs, resource policies, and trust policies have been reviewed and confirmed unmodified (or reverted)
- [ ] GuardDuty shows no new findings related to the threat actor's activity

> 🤖 **Automation opportunity:** AWS Config rules with auto-remediation can detect and alert on unauthorized IAM changes. Consider rules like `iam-user-no-policies-check`, `iam-root-access-key-check`, and custom rules for trust policy modifications.

---

## Part 4b — Recover

> **CSF 2.0 Function:** Recover
> **Goal:** Restore legitimate access, remove containment controls, and harden the environment against recurrence. Recovery should only proceed once eradication is validated — restoring access prematurely can re-expose the environment if persistence mechanisms were missed.

### 4.4 Restore Legitimate Access

> ⚠️ Before issuing new credentials, confirm the root cause (Section 4.1) is resolved. For example, if the credential was exposed because it was hardcoded in an EC2 instance's environment variables or user data, storing the new credential the same way will result in the same exposure.

1. **Issue new credentials** for the legitimate user, appropriate to their use case:
   - If programmatic access is needed: create a new access key (or better, migrate to IAM Roles Anywhere or Identity Center)
   - If console access is needed: create a new login profile with a temporary password requiring reset on first use
   - Re-enable or re-register MFA for the user

2. **Remove containment controls** once you have confirmed eradication is complete:
   - Remove the deny-all inline or managed policy that was applied during containment
   - Remove the session revocation policy (if applied)
   - Restore security group configurations (if network isolation was applied to associated resources)

3. **Verify applications and services** that depended on the original credential are functioning with the new credential. Update any automation, CI/CD pipelines, or application configurations that referenced the old credential.

### 4.5 Harden Against Recurrence

Based on the root cause identified in Section 4.1, implement targeted hardening:

- [ ] **Reduce permissions to least privilege** — use IAM Access Analyzer unused access findings to scope down policies to only what is needed
- [ ] **Enforce MFA** for the affected user (and review org-wide MFA enforcement policy)
- [ ] **Migrate away from long-term access keys** where possible — consider IAM Roles Anywhere, Identity Center, or instance/task roles
- [ ] **Enable IMDSv2** requirement on EC2 instances if instance role credentials were involved
- [ ] **Implement credential rotation policy** — 90-day maximum for any remaining long-term access keys
- [ ] **Enable secret scanning** on all organization repositories (GitHub, GitLab, Bitbucket)
- [ ] **Address the specific root cause:**
  - If phishing: implement phishing-resistant MFA (FIDO2/WebAuthn), review security awareness training
  - If public repo exposure: audit all repositories for secrets, implement pre-commit hooks
  - If credential stuffing: enforce unique passwords, implement login anomaly detection
  - If malware: ensure endpoint protection, consider workstation re-imaging before re-issuing credentials

### 4.6 Recovery Validation

- [ ] Legitimate user can authenticate and perform their normal duties
- [ ] Applications and services that use the credential are functioning normally
- [ ] No unauthorized resources remain in affected accounts
- [ ] GuardDuty shows no new findings related to this incident
- [ ] All containment controls have been removed
- [ ] Monitoring and alerting confirmed operational for this principal
- [ ] AWS Security Incident Response case updated (if applicable)

---

## Part 5 — Post-Incident Activity

> **CSF 2.0 Function:** Identify (Improve) — continuous improvement, not a one-time activity
> **Goal:** Capture what happened, when, and why — then use those findings to improve detection, response, and prevention for next time. Post-incident activity is not a one-time report; it generates action items that feed back into Part 1 (Prepare) for this and other playbooks.

### 5.1 Timeline Reconstruction

Build a complete timeline of the incident from initial compromise through recovery. This should be completed within 24–48 hours while events are fresh and CloudTrail data is readily queryable. A clear timeline supports post-incident review, regulatory inquiries, and future detection tuning.

| Timestamp (UTC) | Event | Source / Evidence | Actor |
|---|---|---|---|
| | Initial credential compromise (estimated) | Root cause analysis | Threat actor |
| | First unauthorized API call | CloudTrail | Threat actor |
| | Detection alert fired | GuardDuty / secret scanning | AWS / tooling |
| | IR team notified | On-call alert | IR Lead |
| | Credential deactivated | CloudTrail | IR team |
| | Containment complete (deny policy applied) | CloudTrail | IR team |
| | Eradication complete (persistence removed) | IR ticket | IR team |
| | Recovery validated | IR ticket | IR Lead |

**Key metrics:**

These metrics help you measure response effectiveness over time and identify where investment would reduce future incident duration.

| Metric | Value | Why It Matters |
|---|---|---|
| Time to Detect (TTD) | *Time from first unauthorized use to detection alert* | Measures detection coverage |
| Time to Notify (TTN) | *Time from detection to IR team notified* | Measures alerting pipeline effectiveness |
| Time to Contain (TTC) | *Time from notification to credential deactivated* | Measures response readiness |
| Time to Recover (TTR) | *Time from containment to recovery validated* | Measures eradication thoroughness |
| Total Incident Duration | | End-to-end impact window |
| Affected Resources | *Count and type* | Blast radius |
| Data Impact | *Confirmed / Suspected / None* | Drives regulatory notification |
| Accounts Affected | *List account IDs* | Scope of cross-account spread |

### 5.2 Post-Incident Review

Conduct a blameless post-incident review within **5 business days** for P1/P2, **15 business days** for P3/P4. The goal is to identify systemic improvements, not assign blame. Include all stakeholders who participated in the response.

Discussion questions specific to credential compromise:

1. How was the credential exposed? Was this a preventable exposure with existing controls?
2. Why did this credential have the permissions it had? Was least privilege applied?
3. How long was the credential exposed before detection? What would have detected it sooner?
4. Did the threat actor create persistence? Did we find all of it, or did we discover more later?
5. Were there other credentials in the environment with similar exposure risk? (Audit all long-term access keys)
6. Should this workload migrate from long-term keys to short-lived credentials (roles, Identity Center, Roles Anywhere)?
7. Were our preparation steps (Part 1) adequate? Did we have the access, tools, and documentation we needed?
8. What single change would most reduce the likelihood of this happening again?

### 5.3 Detection Gap Analysis

For each gap identified during the incident — whether a detection that didn't fire, an alert that wasn't actioned, or a blind spot in coverage — document the root cause and assign an owner to fix it.

| Gap | Root Cause | Recommended Fix | Owner | Target Date |
|---|---|---|---|---|
| *(e.g., Key exposed for 3 days before detection)* | *(No secret scanning on private repos)* | *(Enable secret scanning org-wide)* | | |
| *(e.g., GuardDuty finding not actioned for 6 hours)* | *(Alert fatigue, finding lost in noise)* | *(Tune suppression rules, add PagerDuty integration)* | | |
| *(e.g., Threat actor created persistence undetected)* | *(No alerting on CreateUser/CreateAccessKey)* | *(Add EventBridge rule for IAM mutation events)* | | |

### 5.4 Playbook Update Checklist

Use this incident to improve this playbook. Do not wait for the next scheduled review — update immediately while the gaps are clear.

- [ ] Were triage questions (Part 2) sufficient? Add/remove as needed.
- [ ] Were evidence documentation steps accurate for this scenario?
- [ ] Were containment actions effective? Any unintended service disruption?
- [ ] Were any new persistence mechanisms observed that aren't listed in Section 4.2?
- [ ] Were automation opportunities identified? Add references to relevant sections.
- [ ] Were severity criteria accurate? Did this incident get classified at the right level?
- [ ] Update **Last Reviewed** date and increment **Playbook Version**.

---

## Appendix A — Investigation Resources

For detailed Athena queries, GuardDuty CLI commands, and IAM Access Analyzer investigation commands relevant to credential compromise investigations, see:

📁 [`resources/athena-queries-credential-compromise.sql`](resources/athena-queries-credential-compromise.sql)

These queries cover:
- All API activity for a specific access key
- Source IP and user agent analysis (distinguishing legitimate vs. unauthorized usage)
- Persistence detection (IAM mutations, role creation, policy changes)
- Data access events (S3, DynamoDB, Secrets Manager)
- Cross-account role assumptions
- Error events (reconnaissance and permission testing indicators)

---

## Appendix B — Regulatory & Compliance Considerations

> `[Legal / Compliance]` owns this section during an active incident.

See [Regulatory Context](../REGULATORY_CONTEXT.md) for the full notification obligation matrix.

**Quick reference for credential compromise:**

| Regulation | Trigger Condition | Timeframe |
|---|---|---|
| GDPR Art. 33 | Personal data confirmed accessed via compromised credential | 72 hours to supervisory authority |
| HIPAA | PHI accessed via compromised credential | 60 days to HHS |
| PCI-DSS 12.10 | Cardholder data environment accessed | Immediately to card brands |
| SOC 2 CC7.3 | Any confirmed security incident in scope environment | Document for auditor |

> ⚠️ The clock starts at **awareness**, not confirmation. If the compromised credential had access to regulated data and was used by a threat actor, assume notification is required and consult Legal immediately.

---

## Appendix C — Reference Links

- [NIST SP 800-61r3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html)
- [AWS Security Incident Response Service](https://docs.aws.amazon.com/security-ir/latest/userguide/what-is-security-ir.html)
- [AWS Well-Architected Framework — Security Pillar: Incident Response](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/incident-response.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [Revoking IAM Role Temporary Security Credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)
- [Amazon GuardDuty IAM Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
- [Amazon Detective Investigation Guide](https://docs.aws.amazon.com/detective/latest/userguide/investigation-about.html)
- [AWS CIRT Incident Response Workshops](https://aws.amazon.com/blogs/security/aws-cirt-announces-the-release-of-five-publicly-available-workshops/)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning)
- [Threat Technique Catalog for AWS](https://aws-samples.github.io/threat-technique-catalog-for-aws/)

---

## Revision History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | 2020-10-01 | AWS | Initial release |
| 2.0 | 2026-06-18 | AWS CIRT | Full rewrite: NIST r3 alignment, template standardization, added IAM Access Analyzer, Identity Center references, AWS Security IR service, separated eradication and recovery phases, moved Athena queries to resources folder |
