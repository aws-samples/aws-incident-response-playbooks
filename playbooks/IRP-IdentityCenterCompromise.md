# IRP-IdentityCenterCompromise: AWS Identity Center (SSO) Compromise

> **Playbook Version:** 2.0
> **Last Reviewed:** 2026-06-28
> **Status:** `Active`
> **NIST Framework:** SP 800-61r3 (CSF 2.0 Community Profile)
> **Related Playbooks:** [IRP-CredCompromise](IRP-CredCompromise.md) | [IRP-FederatedAccessAbuse](IRP-FederatedAccessAbuse.md) | [IRP-STSTokenAbuse](IRP-STSTokenAbuse.md)

---

> ⚠️ **Disclaimer:** This playbook is provided as a template only. It should be customized to suit your organization's specific needs, risks, available tools, and work processes. This guide is not official AWS documentation and is provided as-is. Security and Compliance is a shared responsibility between you and AWS. You are responsible for making your own independent assessment of the information in this document.

---

## Overview

AWS Identity Center (formerly AWS SSO) compromise occurs when an unauthorized party gains access to an Identity Center administrator or user account and leverages it to manipulate permission sets, account assignments, identity store users/groups, or active SSO sessions. Because Identity Center operates at the organization level — typically in the management account or a delegated administrator account — a compromise here can grant a threat actor broad access across all member accounts simultaneously. The scope of impact is potentially the entire AWS Organization. Threat actors who compromise an Identity Center admin can create new permission sets with elevated privileges, assign them to production accounts, create backdoor users in the identity store, and maintain persistent access that survives individual account-level credential rotations.

### Out of Scope

This playbook does **not** cover:

- **IAM credential compromise (access keys, console passwords)** — If the primary vector is stolen long-term IAM credentials without Identity Center involvement, see [IRP-CredCompromise](IRP-CredCompromise.md).
- **Federated identity provider compromise (Okta, Microsoft Entra ID, Ping)** — If the initial compromise is at the external IdP level and Identity Center is configured with an external identity source, see [IRP-FederatedAccessAbuse](IRP-FederatedAccessAbuse.md). If the threat actor compromised the IdP and is using it to access AWS via Identity Center, start with that playbook and pivot here for AWS-side containment.
- **STS token abuse via AssumeRole chains** — If the threat actor is abusing temporary credentials obtained through role chaining without modifying Identity Center configuration, see [IRP-STSTokenAbuse](IRP-STSTokenAbuse.md).
- **Service Control Policy (SCP) manipulation** — If the threat actor is modifying SCPs directly in AWS Organizations without Identity Center involvement, that is an Organizations-level incident (future playbook).

### Applicable Finding Types

| Source | Finding / Event Type | Severity |
|---|---|---|
| CloudTrail | `eventSource: sso.amazonaws.com`, `eventName: CreatePermissionSet` | HIGH |
| CloudTrail | `eventSource: sso.amazonaws.com`, `eventName: CreateAccountAssignment` | HIGH |
| CloudTrail | `eventSource: sso.amazonaws.com`, `eventName: AttachManagedPolicyToPermissionSet` | HIGH |
| CloudTrail | `eventSource: sso.amazonaws.com`, `eventName: PutInlinePolicyToPermissionSet` | HIGH |
| CloudTrail | `eventSource: identitystore.amazonaws.com`, `eventName: CreateUser` | HIGH |
| CloudTrail | `eventSource: identitystore.amazonaws.com`, `eventName: CreateGroup` | MEDIUM |
| CloudTrail | `eventSource: identitystore.amazonaws.com`, `eventName: CreateGroupMembership` | MEDIUM |
| CloudTrail | `eventSource: sso.amazonaws.com`, `eventName: RegisterDelegatedAdministrator` | CRITICAL |
| Amazon GuardDuty | `CredentialAccess:IAMUser/AnomalousBehavior` (on Identity Center admin) | MEDIUM |
| Amazon GuardDuty | `Persistence:IAMUser/AnomalousBehavior` (permission set changes) | MEDIUM |
| AWS Security Hub | Identity Center configuration findings | MEDIUM |
| Custom | Permission set changes outside approved change windows | HIGH |
| Custom | New MFA device registration for Identity Center users | MEDIUM |
| Custom | SSO authentication from unusual geographic locations or new devices | MEDIUM |

> 📌 GuardDuty finding types are updated regularly. See the [GuardDuty finding types reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) for the current list.

### Severity Classification

| Priority | Criteria |
|---|---|
| **P1 — Critical** | Confirmed unauthorized permission set creation/modification with account assignments to production accounts, OR new users created in identity store with elevated access, OR active SSO sessions from threat actor infrastructure |
| **P2 — High** | Confirmed unauthorized Identity Center administrative actions (permission set or account assignment changes) but scope of impact unclear, OR compromised Identity Center admin credential with no confirmed abuse yet |
| **P3 — Medium** | Anomalous Identity Center activity detected (unusual login time, new device, API calls from unexpected IP) but no confirmed unauthorized configuration changes |
| **P4 — Low** | Policy violation (e.g., permission set with overly broad permissions created through normal process, Identity Center configuration drift detected by Config rules) |

---

## Part 1 — Prepare

> **CSF 2.0 Functions:** Govern · Identify · Protect
> **Goal:** Ensure the right configurations, access, and processes are in place *before* this incident type occurs.

### 1.1 Recommended AWS Service Configurations

The following services each contribute to your ability to detect, investigate, and respond to an Identity Center compromise. None are strictly required, but each addresses a specific gap — the more you have enabled, the faster you can detect unauthorized changes and the more complete your forensic picture will be during an investigation.

- [ ] **Amazon GuardDuty** enabled in all regions (including the management account) with findings exported to Security Hub — provides continuous threat detection for IAM anomalies and credential abuse patterns on Identity Center admin accounts
- [ ] **AWS CloudTrail** enabled with organization trail capturing management events in all regions with integrity validation — the primary audit log for all Identity Center API activity; without it, investigation is severely limited
- [ ] **CloudTrail data events** enabled for Identity Center — captures SSO portal authentication events (`Authenticate`, `Federate`, `GetRoleCredentials`) which are not included in management events alone
- [ ] **AWS Config** enabled in the management account and delegated admin account with Identity Center-related rules — provides continuous compliance assessment and configuration change tracking
- [ ] **Amazon Detective** enabled — provides graph-based investigation of Identity Center activity, reducing time to understand relationships between users, permission sets, and accounts
- [ ] **AWS Security Hub** enabled with AWS Foundational Security Best Practices standard — aggregates and prioritizes findings across services into a single pane
- [ ] **CloudWatch alarms** configured for Identity Center administrative API calls outside change windows — provides near-real-time alerting when unexpected configuration changes occur
- [ ] **EventBridge rules** configured to alert on `CreatePermissionSet`, `CreateAccountAssignment`, `CreateUser`, and `CreateGroupMembership` events from `sso.amazonaws.com` and `identitystore.amazonaws.com` — enables automated response workflows
- [ ] **S3 bucket for CloudTrail logs** has Object Lock enabled — protects audit trail from tampering by threat actors who gain admin access
- [ ] **Identity Center audit logging** confirmed operational — verify CloudTrail is capturing `sso.amazonaws.com` events by checking recent log entries

> 🤖 **Automation opportunity:** Deploy EventBridge rules in the management account to trigger SNS notifications on any Identity Center administrative API call. Example rule pattern:
> ```json
> {
>   "source": ["aws.sso"],
>   "detail-type": ["AWS API Call via CloudTrail"],
>   "detail": {
>     "eventSource": ["sso.amazonaws.com"],
>     "eventName": ["CreatePermissionSet", "DeletePermissionSet", "CreateAccountAssignment",
>                   "DeleteAccountAssignment", "AttachManagedPolicyToPermissionSet",
>                   "PutInlinePolicyToPermissionSet", "UpdatePermissionSet"]
>   }
> }
> ```
>
> 📖 **Reference:** [SEC10-BP06 Pre-deploy tools](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_deploy_tools.html) — AWS Well-Architected Framework recommends pre-deploying investigation and response tooling so capabilities are available immediately when needed.

### 1.2 IAM & Access Prerequisites

Effective incident response depends on having the right access available *before* an incident occurs. For Identity Center compromise specifically, your IR team must have an access path that does not rely on Identity Center itself — if Identity Center is compromised, SSO-based access may be unreliable or threat-actor-controlled. The following recommendations align with [SEC10-BP05 Pre-provision access](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_provision_access.html) from the AWS Well-Architected Framework.

- [ ] **Break-glass IAM role** in the management account with permissions to: manage Identity Center configuration, disable users in identity store, delete account assignments, and query CloudTrail — pre-tested and documented
- [ ] **IR team members can assume the break-glass role** with MFA from a trusted account (this role MUST bypass Identity Center — use direct IAM federation or IAM user with MFA)
- [ ] **Access to AWS Security Incident Response console** confirmed (if subscribed) — verify case creation workflow before you need it
- [ ] **Forensic account** available for cross-account log analysis — isolated from production, with appropriate trust relationships pre-configured
- [ ] **Documented inventory** of all Identity Center permission sets, their policies, and account assignments (baseline for comparison during investigation)
- [ ] **Documented list** of authorized Identity Center administrators (for rapid identification of unauthorized changes)
- [ ] **Pre-created SCP** that can restrict Identity Center API access if needed (see containment section)

> ⚠️ **Critical:** The break-glass role for Identity Center incidents MUST NOT rely on Identity Center itself for access. If Identity Center is compromised, SSO-based access may be unreliable or threat-actor-controlled. Ensure an independent IAM-based access path exists — direct IAM federation to a separate IdP, or an IAM user with hardware MFA stored securely.
>
> 📖 **References:**
> - [SEC10-BP05 Pre-provision access](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_provision_access.html) — pre-provisioning IR access independent of the systems that may be compromised
> - [SEC10-BP06 Pre-deploy tools](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_deploy_tools.html) — having investigation tools ready before you need them

### 1.3 Communication & Escalation

Clear communication paths reduce confusion during high-pressure incidents. Identity Center compromise often requires coordination between the IR team, the management account owner, and the identity team — establish those communication channels before you need them.

> 📋 Do not include names in this playbook. Use roles only. Maintain a separate, access-controlled contact list (e.g., internal wiki, sealed envelope, or secure document) with current names, phone numbers, and escalation preferences.

| Role | Responsibility | When to Engage |
|---|---|---|
| IR Lead | Overall incident coordination, status updates, decision authority for containment actions | All severity levels — first notified |
| Management Account Owner | Authorization for Identity Center changes, SCP deployment, break-glass approval | All severity levels — engaged immediately after IR Lead |
| Identity Team Lead | Identity Center architecture context, baseline configuration knowledge, IdP coordination | All severity levels — for external identity source scenarios |
| Application Owners (affected accounts) | Impact assessment for account-level access changes | P1–P3, or when containment may disrupt services |
| Legal / Compliance | Regulatory notification if data accessed via unauthorized SSO sessions | P1–P2, or when regulated data may have been accessed |
| AWS Support / AWS CIRT | Technical assistance with scoping, containment guidance, threat intelligence | P1–P2 via AWS Support case (any support plan) or Security Incident Response service (if subscribed) |

**Escalation path:**

1. **Detection:** Automated alert (EventBridge, GuardDuty, SIEM) triggers initial notification.
2. **Triage (IR Lead + Management Account Owner, < 15 min):** IR Lead assesses severity. Management Account Owner confirms whether Identity Center changes were authorized.
3. **Severity-based escalation:**
   - **P1/P2:** IR Lead notifies Application Owners and Legal/Compliance immediately. Opens AWS Support case (severity: Critical) requesting CIRT assistance. If AWS Security Incident Response service is enabled, creates a case there instead.
   - **P3/P4:** IR Lead manages internally with Identity Team Lead. Escalates to P2 if investigation confirms unauthorized changes.
4. **Status updates:** IR Lead provides updates to stakeholders every 30 minutes (P1), every 2 hours (P2), or at key milestones (P3/P4).

> 📖 **Reference:** [SEC10-BP01 Identify key personnel and external resources](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_identify_personnel.html) — recommends identifying and documenting internal and external resources and contact information ahead of time.

### 1.4 Game Day Guidance

Practicing incident response before a real incident occurs builds muscle memory, identifies gaps in tooling and access, and validates that escalation paths work. For this scenario, testing the non-Identity-Center access path (break-glass role) and the speed of session revocation across member accounts is especially important.

Recommended testing cadence: **Semi-annually** (this is a P1-capable scenario with organization-wide impact potential).

Suggested tabletop scenario:
> *"A threat actor has compromised the credentials of an Identity Center administrator in your management account. Over the past 2 hours, they have created a new permission set called 'EmergencyAccess' with AdministratorAccess policy attached, assigned it to 3 production accounts, and created a new user called 'svc-backup-admin' in the Identity Center identity store. The new user has been added to the 'Platform-Admins' group. You received an EventBridge alert 15 minutes ago about the permission set creation. The threat actor may still have active sessions."*

**Practice resources (no paid service or support plan required):**

- [AWS CIRT Incident Response Workshops](https://aws.amazon.com/blogs/security/aws-cirt-announces-the-release-of-five-publicly-available-workshops/) — free, hands-on workshops covering credential compromise, S3 ransomware, and more. Deployable in any AWS account.
- [AWS Foundational Security, Identity and Governance Workshop](https://catalog.us-east-1.prod.workshops.aws/workshops/05554d54-07cc-483e-b810-d69f7d99b2ab/en-US) — covers IAM federation, identity governance, and security controls relevant to this scenario.
- [AWS Security Workshops catalog](https://workshops.aws/categories/Security) — broader collection of security-focused hands-on labs.

> 📖 **Reference:** [SEC10-BP04 Develop and test security incident response playbooks](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_playbooks.html) — recommends creating and regularly testing playbooks to verify response processes.

---

## Part 2 — Detect & Analyze

> **CSF 2.0 Functions:** Detect · Respond (Analyze)
> **Goal:** Confirm whether an incident has occurred, scope its impact, and gather evidence for containment and investigation.

### 2.1 Initial Triage Questions

- [ ] What Identity Center administrative actions were detected? (Permission set changes, account assignments, user/group modifications)
- [ ] Which Identity Center administrator account performed the actions? Is this a legitimate admin?
- [ ] Were the actions performed during an approved change window?
- [ ] What is the identity source configuration? (Identity Center directory, Active Directory, external IdP)
- [ ] Which AWS accounts have been affected by new or modified account assignments?
- [ ] Are production accounts or accounts with sensitive data involved?
- [ ] Were new users or groups created in the identity store?
- [ ] Are there active SSO sessions that may be threat-actor-controlled?
- [ ] Is the delegated administrator account involved (if one is configured)?
- [ ] Could the threat actor still be actively making changes?

**If permission sets with admin-level access have been assigned to production accounts AND the actor is unidentified → P1 immediately.**

### 2.2 Evidence Collection Checklist

> ⚠️ **Collect evidence BEFORE disabling users or removing assignments.** Document the current state of Identity Center configuration to understand the full scope of changes.

| Evidence Type | How to Collect | Where to Store |
|---|---|---|
| CloudTrail events for `sso.amazonaws.com` | Athena query (see resources) | Forensic S3 bucket |
| CloudTrail events for `identitystore.amazonaws.com` | Athena query (see resources) | Forensic S3 bucket |
| CloudTrail events for `sso-directory.amazonaws.com` | Athena query (see resources) | Forensic S3 bucket |
| Current permission set inventory | `aws sso-admin list-permission-sets` | IR ticket |
| Current account assignments | `aws sso-admin list-account-assignments` per permission set | IR ticket |
| Identity store user list | `aws identitystore list-users` | IR ticket |
| Identity store group memberships | `aws identitystore list-group-memberships` | IR ticket |
| GuardDuty findings | GuardDuty console → Export JSON | Forensic S3 bucket |
| SSO access portal authentication logs | CloudTrail (if data events enabled) | Forensic S3 bucket |
| Source IP and user agent analysis | Athena query on CloudTrail | IR ticket |

**CloudTrail / Athena investigation queries:**

For detailed Athena queries to investigate Identity Center compromise (permission set changes, account assignment analysis, identity store modifications, SSO session enumeration, delegated administrator changes), see:

📁 [`resources/athena-queries-identity-center-compromise.sql`](resources/athena-queries-identity-center-compromise.sql)

**Quick CloudTrail Console approach (no Athena required):**

If Athena is not configured, you can investigate directly in the CloudTrail console:

1. Navigate to **CloudTrail → Event history**
2. Filter by **Event source** = `sso.amazonaws.com` to see all Identity Center administrative actions
3. Look for `CreatePermissionSet`, `CreateAccountAssignment`, `AttachManagedPolicyToPermissionSet` — these are the highest-risk changes
4. Filter by **Event source** = `identitystore.amazonaws.com` to check for new users or group membership changes
5. Review source IPs on all events — compare against known administrator IPs
6. Check timing — Identity Center changes outside approved change windows from unfamiliar IPs are a strong indicator

### 2.3 Severity Determination

| Confirmed? | Priority Assignment |
|---|---|
| New permission sets with admin access assigned to production accounts, threat actor active | P1 |
| New users created in identity store with group memberships granting broad access | P1 |
| Confirmed unauthorized Identity Center admin actions, scope unclear | P2 |
| Identity Center admin credential compromised, no confirmed abuse of Identity Center yet | P2 |
| Anomalous Identity Center activity (unusual IP, time, or API pattern), not confirmed | P3 |
| Configuration drift detected (permission set broader than policy allows), no active threat | P4 |

### 2.4 Getting Help from AWS

If this incident is P1 or P2, consider engaging AWS for support:

- **If you have the AWS Security Incident Response service enabled:** Open a case via the [Security Incident Response console](https://console.aws.amazon.com/security-ir/), attach relevant findings, and grant AWS CIRT access to the affected account(s).
- **If you need assistance from AWS CIRT:** Open a support case with Critical severity and request assistance from the AWS Customer Incident Response Team (CIRT). Include relevant finding IDs and a summary of what you have observed.

> 📌 You do not need the Security Incident Response service to get help from AWS CIRT. All AWS customers can request CIRT assistance through a support case, regardless of support plan level.

> 🤖 **Automation opportunity:** Configure EventBridge rules to auto-create Security Incident Response cases when `CreatePermissionSet` or `CreateAccountAssignment` events occur outside approved change windows or from unexpected principals.

---

## Part 3 — Contain

> **CSF 2.0 Function:** Respond (Contain)
> **Goal:** Stop the spread of the incident and prevent further damage without destroying evidence.

### 3.1 Containment Decision

```text
Is the threat actor actively making Identity Center changes OR do they have active SSO sessions?
│
├── YES (active changes or sessions observed)
│     └── Proceed to 3.2 immediately — disable user and revoke sessions
│
├── CHANGES MADE but threat actor appears inactive now
│     └── Proceed to 3.2 — remove unauthorized access before threat actor returns
│
└── ANOMALOUS but unconfirmed
      └── Consult IR Lead: increase monitoring, review recent changes
            If confirmed → Proceed to 3.2
            If ruled out → Document and close
```

### 3.2 Containment Actions

> `[IR Lead]` coordinates. `[Management Account Owner]` authorizes. `[Identity Team Lead]` provides configuration context.

**Step 1: Disable the compromised user in the Identity Center identity store**

```bash
# Identify the user ID for the compromised admin
aws identitystore list-users \
  --identity-store-id d-1234567890 \
  --filters '[{"AttributePath":"UserName","AttributeValue":"compromised-admin"}]'

# Disable the user (prevents new SSO sessions)
aws identitystore update-user \
  --identity-store-id d-1234567890 \
  --user-id USER_ID_HERE \
  --operations '[{"AttributePath":"active","AttributeValue":"false"}]'
```

> ⚠️ **If using an external identity source (Active Directory, external IdP):** Disabling the user in the Identity Center identity store alone may not be sufficient. You must also disable the user at the identity source. Coordinate with the IdP team immediately.

**Step 2: Revoke active SSO sessions**

Identity Center sessions are backed by temporary role credentials in each member account. To revoke active sessions:

```bash
# List all account assignments for the compromised user to identify active sessions
aws sso-admin list-account-assignments-for-principal \
  --instance-arn arn:aws:sso:::instance/ssoins-1234567890abcdef \
  --principal-id USER_ID_HERE \
  --principal-type USER

# For each affected account, revoke the role session by attaching a deny policy
# to the Identity Center-created role in that account
# The role name follows the pattern: AWSReservedSSO_PermissionSetName_UniqueId

# In each affected member account:
aws iam put-role-policy \
  --role-name AWSReservedSSO_AdministratorAccess_abcdef1234567890 \
  --policy-name RevokeCompromisedSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "2026-06-28T12:00:00Z"
        }
      }
    }]
  }'
```

> 📌 Replace the timestamp with the current UTC time. This immediately invalidates all existing sessions while allowing new sessions (once the threat actor's access is removed). SSO session duration is configurable (default 1 hour, max 12 hours) — sessions will naturally expire, but this forces immediate revocation.

> ⚠️ **Impact:** This will terminate active sessions for ALL users of this role, including legitimate users. Coordinate with Application Owners.

**Step 3: Remove unauthorized permission set assignments**

```bash
# Delete the unauthorized account assignment
aws sso-admin delete-account-assignment \
  --instance-arn arn:aws:sso:::instance/ssoins-1234567890abcdef \
  --target-id 123456789012 \
  --target-type AWS_ACCOUNT \
  --permission-set-arn arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-abcdef1234567890 \
  --principal-type USER \
  --principal-id THREAT_ACTOR_USER_ID

# Verify the assignment was removed
aws sso-admin list-account-assignments \
  --instance-arn arn:aws:sso:::instance/ssoins-1234567890abcdef \
  --account-id 123456789012 \
  --permission-set-arn arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-abcdef1234567890
```

**Step 4: Remove unauthorized permission sets**

```bash
# First, delete all account assignments for the unauthorized permission set
# (A permission set cannot be deleted while it has active assignments)
aws sso-admin list-accounts-for-provisioned-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-1234567890abcdef \
  --permission-set-arn arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-THREAT_ACTOR_PS

# For each account returned, delete the assignment, then:
aws sso-admin delete-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-1234567890abcdef \
  --permission-set-arn arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-THREAT_ACTOR_PS
```

**Step 5: Disable delegated administrator (if compromised)**

If the threat actor compromised a delegated administrator account:

```bash
# Remove delegated administrator registration
aws organizations deregister-delegated-administrator \
  --account-id 111122223333 \
  --service-principal sso.amazonaws.com
```

> ⚠️ **Impact:** Removing delegated administrator access will prevent that account from managing Identity Center. Ensure you have management account access before taking this action.

**Step 6: Restrict Identity Center access via SCP (nuclear option for P1)**

If the threat actor is actively making changes faster than you can revert them, apply an SCP to block Identity Center administrative actions:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyIdentityCenterAdminActions",
    "Effect": "Deny",
    "Action": [
      "sso:CreatePermissionSet",
      "sso:DeletePermissionSet",
      "sso:UpdatePermissionSet",
      "sso:CreateAccountAssignment",
      "sso:DeleteAccountAssignment",
      "sso:AttachManagedPolicyToPermissionSet",
      "sso:PutInlinePolicyToPermissionSet",
      "identitystore:CreateUser",
      "identitystore:CreateGroup",
      "identitystore:CreateGroupMembership"
    ],
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "aws:PrincipalArn": "arn:aws:iam::MGMT_ACCOUNT_ID:role/BreakGlass-IR-Role"
      }
    }
  }]
}
```

> ⚠️ **This SCP blocks ALL Identity Center administrative changes except from the break-glass role.** Only apply this during active P1 incidents. Remove immediately after containment is confirmed.

> 🤖 **Automation opportunity:** AWS Systems Manager Automation document to disable an Identity Center user, revoke sessions across all assigned accounts, and send notification — executable in a single invocation.

### 3.3 Document Containment Actions

Record all containment actions taken, including timestamps, who performed them, and what was affected. This documentation supports the post-incident timeline (Part 5) and is important for any regulatory inquiries.

- [ ] All CloudTrail logs for the incident window exported to forensic S3 bucket (include `sso.amazonaws.com`, `identitystore.amazonaws.com`, and `sso-directory.amazonaws.com` events)
- [ ] Current Identity Center configuration snapshot saved (permission sets, assignments, users, groups)
- [ ] GuardDuty findings exported (full JSON)
- [ ] List of all permission sets created or modified during incident documented
- [ ] List of all account assignments created during incident documented
- [ ] List of all identity store users and group memberships created during incident documented
- [ ] What users were disabled and when (timestamp, user ID, who performed the action)
- [ ] What sessions were revoked and when
- [ ] Whether containment was effective (did unauthorized activity stop?)
- [ ] S3 Object Lock applied to forensic evidence bucket
- [ ] CloudTrail log integrity validation confirmed

---

## Part 4 — Eradicate

> **CSF 2.0 Function:** Respond (Eradicate)
> **Goal:** Identify the root cause of the compromise, remove any persistence mechanisms the threat actor created, and confirm the environment is clean. Eradication often uncovers additional compromised resources — if new findings emerge during this phase, return to Part 3 (Contain) for any newly identified access paths before continuing.

### 4.1 Root Cause Identification

> `[IR Lead]` owns this step. Document findings in the IR ticket in real time.

Understanding how the Identity Center admin was compromised is essential before restoring access — if the root cause is not resolved, the same access path will be exploited again.

Common root causes for Identity Center compromise:

- **Compromised admin credentials:** The Identity Center administrator's own credentials (IAM, SSO, or IdP) were phished, stolen via malware, or obtained through credential stuffing
- **Overly broad admin access:** Too many users had Identity Center administrative permissions, increasing the attack surface
- **Lack of MFA on admin accounts:** Identity Center admin accounts without enforced MFA allowed credential-only access
- **Compromised external IdP:** If using an external identity source, the IdP itself was compromised (pivot to IRP-FederatedAccessAbuse)
- **Delegated administrator over-provisioning:** Delegated admin account had broader permissions than necessary
- **Session hijacking:** Threat actor intercepted or stole an active SSO session token (e.g., via XSS on internal portal, browser extension malware)
- **Insider threat:** Authorized administrator performed unauthorized actions

Use the source IP and user agent analysis from Part 2 to determine:
- Where did the threat actor access from? (Geolocation, VPN/proxy, known malicious infrastructure)
- When did unauthorized access begin? (First unauthorized Identity Center API call)
- How did the threat actor obtain admin access? (Check for preceding credential compromise indicators)
- What was the threat actor's objective? (Persistence, lateral movement, data access)

### 4.2 Remove Persistence Mechanisms

> `[IR Lead]` coordinates. `[Management Account Owner]` approves changes.

When an Identity Center admin is compromised, threat actors commonly create additional access paths that survive session revocation and user disablement. This section focuses on identifying and removing those persistence mechanisms.

**Step 1: Remove all threat-actor-created identity store entities**

```bash
# Delete unauthorized users created by the threat actor
aws identitystore delete-user \
  --identity-store-id d-1234567890 \
  --user-id THREAT_ACTOR_CREATED_USER_ID

# Delete unauthorized groups
aws identitystore delete-group \
  --identity-store-id d-1234567890 \
  --group-id THREAT_ACTOR_CREATED_GROUP_ID

# Remove unauthorized group memberships added to existing groups
aws identitystore delete-group-membership \
  --identity-store-id d-1234567890 \
  --membership-id UNAUTHORIZED_MEMBERSHIP_ID
```

**Step 2: Remove all threat-actor-created or modified permission sets**

```bash
# For permission sets CREATED by the threat actor — delete entirely
# (First remove all account assignments, then delete)
aws sso-admin delete-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-1234567890abcdef \
  --permission-set-arn THREAT_ACTOR_PERMISSION_SET_ARN

# For permission sets MODIFIED by the threat actor — revert to known-good state
# Remove unauthorized managed policy attachments
aws sso-admin detach-managed-policy-from-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-1234567890abcdef \
  --permission-set-arn MODIFIED_PERMISSION_SET_ARN \
  --managed-policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Remove unauthorized inline policies
aws sso-admin delete-inline-policy-from-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-1234567890abcdef \
  --permission-set-arn MODIFIED_PERMISSION_SET_ARN

# Re-provision the permission set to push changes to all assigned accounts
aws sso-admin provision-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-1234567890abcdef \
  --permission-set-arn MODIFIED_PERMISSION_SET_ARN \
  --target-type ALL_PROVISIONED_ACCOUNTS
```

**Step 3: Check for persistence in member accounts**

The threat actor may have used their SSO access to create persistence mechanisms in member accounts:

```bash
# In each account the threat actor accessed, check for:
# - New IAM users, roles, or access keys
# - Modified trust policies on existing roles
# - New Lambda functions or EC2 instances
# - Modified resource policies (S3, KMS, SQS, etc.)

# Example: Find IAM entities created during the incident window in a member account
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole \
  --start-time 2026-06-27T00:00:00Z \
  --end-time 2026-06-28T23:59:59Z \
  --region us-east-1
```

**Step 4: Verify Identity Center configuration integrity**

```bash
# List all permission sets and compare against known-good baseline
aws sso-admin list-permission-sets \
  --instance-arn arn:aws:sso:::instance/ssoins-1234567890abcdef

# For each permission set, verify policies match baseline
aws sso-admin list-managed-policies-in-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-1234567890abcdef \
  --permission-set-arn PERMISSION_SET_ARN

aws sso-admin get-inline-policy-for-permission-set \
  --instance-arn arn:aws:sso:::instance/ssoins-1234567890abcdef \
  --permission-set-arn PERMISSION_SET_ARN

# List all users and groups, compare against baseline
aws identitystore list-users --identity-store-id d-1234567890
aws identitystore list-groups --identity-store-id d-1234567890
```

> ⚠️ **If you discover additional compromised credentials or access paths during eradication, return to Part 3 (Contain) and deactivate those credentials before continuing.** Eradication is iterative — it is common to cycle between containment and eradication multiple times.
>
> 📌 **Beyond Identity Center:** If CloudTrail shows the threat actor used SSO sessions to create compute resources, modify resource policies, or take other actions in member accounts, consult the relevant playbook for eradication guidance specific to those resource types. For a comprehensive reference of persistence techniques observed in AWS environments, see the [Threat Technique Catalog for AWS](https://aws-samples.github.io/threat-technique-catalog-for-aws/). Key techniques relevant to this playbook:
> - [T1484.002 — Trust Modification](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1484.002.html): Manipulating Identity Center configuration (permission sets, account assignments) to establish unauthorized access paths
> - [T1098.001 — Additional Cloud Credentials](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1098.001.html): Creating access keys, login profiles, or backdoor users in member accounts during SSO sessions to persist beyond session revocation
> - [T1098.003 — Additional Cloud Roles](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1098.003.html): Creating new permission sets or modifying existing ones to grant elevated privileges
> - [T1199.A002 — Role Assumption and Federated Access](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1199.A002.html): Abusing SSO sessions for lateral movement across member accounts

### 4.3 Eradication Validation

Before moving to recovery, confirm that the threat actor's access has been fully removed:

- [ ] All threat-actor-created users deleted from identity store
- [ ] All threat-actor-created groups deleted from identity store
- [ ] All unauthorized group memberships removed
- [ ] All threat-actor-created permission sets deleted
- [ ] All threat-actor-modified permission sets reverted and re-provisioned
- [ ] All unauthorized account assignments removed
- [ ] Persistence mechanisms in member accounts identified and removed
- [ ] Identity Center configuration matches known-good baseline
- [ ] No unauthorized delegated administrator registrations remain
- [ ] MFA devices registered by threat actor removed from compromised user
- [ ] CloudTrail shows no continued unauthorized activity for at least 30 minutes after eradication actions
- [ ] GuardDuty shows no new findings related to the threat actor's activity

> 🤖 **Automation opportunity:** Maintain Identity Center configuration as Infrastructure as Code (Terraform, CloudFormation, or AWS Control Tower). After eradication, re-deploy from the IaC source of truth to guarantee configuration matches the approved baseline.

---

## Part 4b — Recover

> **CSF 2.0 Function:** Recover
> **Goal:** Restore legitimate access, remove containment controls, and harden the environment against recurrence. Recovery should only proceed once eradication is validated — restoring access prematurely can re-expose the environment.

### 4.4 Restore Legitimate Access

> ⚠️ Before re-enabling the admin user, confirm: (1) the root cause is resolved (e.g., compromised workstation cleaned, phished credentials rotated at IdP), (2) MFA is enforced, and (3) the user's MFA devices are verified as legitimate.

**Step 1: Re-enable legitimate admin access**

```bash
# Re-enable the legitimate admin user (after confirming root cause is resolved)
aws identitystore update-user \
  --identity-store-id d-1234567890 \
  --user-id LEGITIMATE_ADMIN_USER_ID \
  --operations '[{"AttributePath":"active","AttributeValue":"true"}]'
```

**Step 2: Remove containment controls**

```bash
# Remove session revocation policies from Identity Center roles in member accounts
aws iam delete-role-policy \
  --role-name AWSReservedSSO_AdministratorAccess_abcdef1234567890 \
  --policy-name RevokeCompromisedSessions

# Remove the restrictive SCP (if applied during containment)
aws organizations detach-policy \
  --policy-id p-CONTAINMENT_SCP_ID \
  --target-id ou-ROOT_OR_ACCOUNT_ID
```

### 4.5 Harden Against Recurrence

Based on the root cause identified in Section 4.1, implement targeted hardening:

- [ ] **Enforce MFA** for all Identity Center users (especially administrators)
- [ ] **Reduce the number of Identity Center administrators** to the minimum necessary
- [ ] **Implement permission set change approval workflow** (e.g., require change ticket before modification)
- [ ] **Enable CloudTrail Insights** for anomaly detection on Identity Center API calls
- [ ] **Reduce SSO session duration** to the minimum acceptable for your organization (default 1 hour)
- [ ] **Implement EventBridge alerting** on all Identity Center administrative actions
- [ ] **Consider implementing permission boundaries** on permission sets to limit maximum privilege
- [ ] **Review and restrict delegated administrator permissions** if applicable
- [ ] **Deploy AWS Config rules** to detect permission set drift from approved baseline
- [ ] **Manage Identity Center configuration as IaC** (Terraform, CloudFormation, Control Tower) to enable rapid drift detection and recovery

### 4.6 Recovery Validation

- [ ] Legitimate administrators can access Identity Center and perform their duties
- [ ] All permission sets match the approved baseline configuration
- [ ] All account assignments match the approved baseline
- [ ] Identity store user and group inventory matches the approved baseline
- [ ] No unauthorized SSO sessions remain active
- [ ] GuardDuty shows no new findings related to this incident
- [ ] EventBridge alerting rules are operational for Identity Center events
- [ ] Application teams in affected accounts confirm normal operations
- [ ] All containment controls have been removed
- [ ] AWS Security Incident Response case updated (if applicable)

---

## Part 5 — Post-Incident Activity

> **CSF 2.0 Function:** Identify (Improve) — continuous improvement, not a one-time activity
> **Goal:** Capture what happened, when, and why — then use those findings to improve detection, response, and prevention for next time. Post-incident activity is not a one-time report; it generates action items that feed back into Part 1 (Prepare) for this and other playbooks.

### 5.1 Timeline Reconstruction

Build a complete timeline of the incident from initial compromise through recovery. This should be completed within 24–48 hours while events are fresh and CloudTrail data is readily queryable.

| Timestamp (UTC) | Event | Source / Evidence | Actor |
|---|---|---|---|
| | Initial admin credential compromise (estimated) | Root cause analysis | Threat actor |
| | First unauthorized Identity Center API call | CloudTrail (`sso.amazonaws.com`) | Threat actor |
| | Permission set created/modified | CloudTrail | Threat actor |
| | Account assignments created | CloudTrail | Threat actor |
| | Identity store users/groups created | CloudTrail (`identitystore.amazonaws.com`) | Threat actor |
| | Detection alert fired | EventBridge / GuardDuty | AWS / tooling |
| | IR team notified | On-call alert | IR Lead |
| | Compromised user disabled | CloudTrail | IR team |
| | Active sessions revoked | CloudTrail | IR team |
| | Unauthorized assignments removed | CloudTrail | IR team |
| | Eradication complete | IR ticket | IR team |
| | Recovery validated | IR ticket | IR Lead |

**Key metrics:**

| Metric | Value | Why It Matters |
|---|---|---|
| Time to Detect (TTD) | *Time from first unauthorized Identity Center action to detection alert* | Measures detection coverage for Identity Center abuse |
| Time to Notify (TTN) | *Time from detection to IR team notified* | Measures alerting pipeline effectiveness |
| Time to Contain (TTC) | *Time from notification to compromised user disabled and sessions revoked* | Measures response readiness and break-glass access availability |
| Time to Recover (TTR) | *Time from containment to recovery validated* | Measures eradication thoroughness and confidence in clean state |
| Total Incident Duration | | End-to-end impact window — drives urgency for detection improvements |
| Permission Sets Affected | *Count (created + modified)* | Indicates the scope of privilege escalation achieved |
| Accounts Affected | *Count of accounts with unauthorized assignments* | Defines the scope of potential lateral movement |
| Identity Store Entities Created | *Count of unauthorized users/groups* | Indicates persistence attempts at the identity layer |
| Data Impact | *Confirmed / Suspected / None* | Drives regulatory notification decisions |

### 5.2 Post-Incident Review

Conduct a blameless post-incident review within **5 business days** for P1/P2, **15 business days** for P3/P4. The goal is to identify systemic improvements, not assign blame.

Discussion questions specific to Identity Center compromise:

1. How did the threat actor obtain Identity Center admin access? Was this preventable?
2. Why did the compromised principal have Identity Center administrative permissions? Was least privilege applied?
3. How long were unauthorized permission sets and assignments active before detection? Could we detect faster?
4. Did the threat actor use their SSO access to create persistence in member accounts? Did we find all of it?
5. Was our break-glass access path (independent of Identity Center) functional and tested?
6. Should Identity Center administrative actions require additional approval workflows?
7. Is our Identity Center configuration managed as Infrastructure as Code? If not, should it be?
8. What single change would most reduce the scope of impact of a future Identity Center compromise?

### 5.3 Detection Gap Analysis

| Gap | Root Cause | Recommended Fix | Owner | Target Date |
|---|---|---|---|---|
| *(e.g., Permission set created 2 hours before alert)* | *(No real-time alerting on Identity Center admin actions)* | *(Deploy EventBridge rule for all sso.amazonaws.com write events)* | | |
| *(e.g., New user in identity store not detected)* | *(No monitoring on identitystore.amazonaws.com events)* | *(Add EventBridge rule for CreateUser, CreateGroup, CreateGroupMembership)* | | |
| *(e.g., Threat actor SSO sessions active for 4 hours)* | *(Session duration set to maximum 12 hours)* | *(Reduce session duration to 1 hour, implement anomaly detection)* | | |
| *(e.g., No alert on admin login from new country)* | *(No geo-based anomaly detection for SSO logins)* | *(Implement custom detection for SSO auth from unusual locations)* | | |

### 5.4 Playbook Update Checklist

- [ ] Were triage questions sufficient? Add/remove as needed.
- [ ] Were evidence collection steps accurate for this scenario?
- [ ] Were containment actions effective? Was session revocation fast enough?
- [ ] Were any new persistence mechanisms observed that aren't in this playbook?
- [ ] Were automation opportunities identified? Add stubs to relevant sections.
- [ ] Were severity criteria accurate? Were incidents under- or over-classified?
- [ ] Was the break-glass access path (independent of Identity Center) functional?
- [ ] Update **Last Reviewed** date and increment **Playbook Version**.

---

## Appendix A — Investigation Resources

For detailed Athena queries to investigate Identity Center compromise (permission set changes, account assignment analysis, identity store modifications, SSO session enumeration, delegated administrator changes), see:

📁 [`resources/athena-queries-identity-center-compromise.sql`](resources/athena-queries-identity-center-compromise.sql)

These queries cover:

- All Identity Center administrative actions in a time window
- Permission set creation and modification events
- Account assignment changes (who got access to which accounts)
- User and group membership changes in the identity store
- SSO authentication events from unusual source IPs
- All Identity Center actions by a specific principal
- Permission set policy attachment history
- Accounts accessed via SSO by a specific user
- High-volume Identity Center API calls (automated attack detection)
- Delegated administrator changes

### Identity Center Configuration Snapshot (CLI)

```bash
#!/bin/bash
# Script to capture current Identity Center configuration for baseline comparison
INSTANCE_ARN="arn:aws:sso:::instance/ssoins-1234567890abcdef"
IDENTITY_STORE_ID="d-1234567890"
OUTPUT_DIR="./ic-snapshot-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"

# Export permission sets
aws sso-admin list-permission-sets \
  --instance-arn "$INSTANCE_ARN" > "$OUTPUT_DIR/permission-sets.json"

# Export users
aws identitystore list-users \
  --identity-store-id "$IDENTITY_STORE_ID" > "$OUTPUT_DIR/users.json"

# Export groups
aws identitystore list-groups \
  --identity-store-id "$IDENTITY_STORE_ID" > "$OUTPUT_DIR/groups.json"

echo "Snapshot saved to $OUTPUT_DIR"
```

### GuardDuty Finding Export (CLI)

```bash
# List findings related to the management account (where Identity Center runs)
aws guardduty list-findings \
  --detector-id DETECTOR_ID \
  --finding-criteria '{
    "Criterion": {
      "severity": {"Gte": 5},
      "resource.accessKeyDetails.userName": {"Eq": ["SUSPECTED_ADMIN"]}
    }
  }' \
  --region us-east-1

# Get full finding details
aws guardduty get-findings \
  --detector-id DETECTOR_ID \
  --finding-ids FINDING_ID_1 FINDING_ID_2
```

---

## Appendix B — Automation Hooks

### EventBridge Rules for Identity Center Monitoring

**Rule 1: Permission set changes**

```json
{
  "source": ["aws.sso"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["sso.amazonaws.com"],
    "eventName": [
      "CreatePermissionSet",
      "DeletePermissionSet",
      "UpdatePermissionSet",
      "AttachManagedPolicyToPermissionSet",
      "DetachManagedPolicyFromPermissionSet",
      "PutInlinePolicyToPermissionSet",
      "DeleteInlinePolicyFromPermissionSet",
      "AttachCustomerManagedPolicyReferenceToPermissionSet",
      "PutPermissionsBoundaryToPermissionSet"
    ]
  }
}
```

**Rule 2: Account assignment changes**

```json
{
  "source": ["aws.sso"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["sso.amazonaws.com"],
    "eventName": [
      "CreateAccountAssignment",
      "DeleteAccountAssignment"
    ]
  }
}
```

**Rule 3: Identity store user and group changes**

```json
{
  "source": ["aws.identitystore"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["identitystore.amazonaws.com"],
    "eventName": [
      "CreateUser",
      "DeleteUser",
      "UpdateUser",
      "CreateGroup",
      "DeleteGroup",
      "CreateGroupMembership",
      "DeleteGroupMembership"
    ]
  }
}
```

**Target configuration:** Route all three rules to an SNS topic that triggers:
- PagerDuty / on-call notification (for out-of-window changes)
- Security Hub custom finding (for audit trail)
- Lambda function for automated validation against approved baseline (optional)

---

## Appendix C — Regulatory & Compliance Considerations

> `[Legal / Compliance]` owns this section during an active incident.

See [Regulatory Context](../REGULATORY_CONTEXT.md) for the full notification obligation matrix by regulation and incident type.

**Quick reference for this scenario:**

| Regulation | Trigger Condition | Timeframe |
|---|---|---|
| GDPR Art. 33 | Personal data confirmed accessed via unauthorized SSO session | 72 hours to supervisory authority |
| HIPAA Breach Notification | PHI accessed via unauthorized Identity Center access to healthcare accounts | 60 days to HHS (individual notification varies) |
| PCI DSS 12.10 | Cardholder data environment accessed via unauthorized SSO session | Immediately to acquirer and card brands |
| SOC 2 | Unauthorized access to systems in scope for SOC 2 report | Document in incident log, notify auditor at next review |
| SEC Regulation S-P | Customer financial data accessed via unauthorized access | As soon as reasonably practicable |

> ⚠️ The clock starts at **awareness**, not confirmation. When in doubt, assume notification is required and consult Legal immediately. Identity Center compromise has a high likelihood of triggering notification obligations due to the breadth of access it can provide across an entire AWS Organization.

---

## Appendix D — Reference Links

- [NIST SP 800-61r3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html)
- [AWS Security Incident Response Service Documentation](https://docs.aws.amazon.com/security-ir/latest/userguide/what-is-security-ir.html)
- [AWS IAM Identity Center User Guide](https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html)
- [AWS IAM Identity Center API Reference](https://docs.aws.amazon.com/singlesignon/latest/APIReference/welcome.html)
- [AWS Identity Store API Reference](https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/welcome.html)
- [AWS Well-Architected Framework — Security Pillar: Incident Response](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/incident-response.html)
- [Amazon GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [AWS CloudTrail Query Examples (Athena)](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)
- [AWS Organizations — Service Control Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [AWS Identity Center — Managing Permission Sets](https://docs.aws.amazon.com/singlesignon/latest/userguide/permissionsetsconcept.html)
- [AWS Identity Center — Delegated Administration](https://docs.aws.amazon.com/singlesignon/latest/userguide/delegated-admin.html)
- [AWS CIRT Incident Response Workshops](https://aws.amazon.com/blogs/security/aws-cirt-announces-the-release-of-five-publicly-available-workshops/)
- [AWS Foundational Security, Identity and Governance Workshop](https://catalog.us-east-1.prod.workshops.aws/workshops/05554d54-07cc-483e-b810-d69f7d99b2ab/en-US)
- [AWS Security Workshops catalog](https://workshops.aws/categories/Security)
- [Threat Technique Catalog for AWS](https://aws-samples.github.io/threat-technique-catalog-for-aws/)

---

## Revision History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | 2026-05-28 | AWS CIRT | Initial release |
| 2.0 | 2026-06-28 | AWS CIRT | Aligned to FederatedAccessAbuse conventions: added Well-Architected references (SEC10-BP01, BP04, BP05, BP06), separated Eradicate/Recover phases, added TTC technique references, extracted Athena queries to companion SQL file, added "Why It Matters" to metrics, added workshop links and game day resources |
