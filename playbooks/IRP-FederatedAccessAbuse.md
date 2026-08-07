# IRP-FederatedAccessAbuse: Federated Access Abuse (BEC / IdP Compromise)

> **Playbook Version:** 2.0
> **Last Reviewed:** 2026-06-25
> **Status:** `Active`
> **NIST Framework:** SP 800-61r3 (CSF 2.0 Community Profile)
> **Related Playbooks:** [IRP-CredCompromise](IRP-CredCompromise.md) | [IRP-IdentityCenterCompromise](IRP-IdentityCenterCompromise.md) | [IRP-STSTokenAbuse](IRP-STSTokenAbuse.md) | [IRP-Ransomware](IRP-Ransomware.md)

---

> ⚠️ **Disclaimer:** This playbook is provided as a template only. It should be customized to suit your organization's specific needs, risks, available tools, and work processes. This guide is not official AWS documentation and is provided as-is. Security and Compliance is a shared responsibility between you and AWS. You are responsible for making your own independent assessment of the information in this document.

---

## Overview

Federated access abuse occurs when an unauthorized party compromises an external identity provider (IdP) — such as Okta, Microsoft Entra ID, Google Workspace, or PingFederate — and leverages that access to pivot into AWS environments via SAML or OIDC federation. This includes Business Email Compromise (BEC) scenarios where stolen corporate credentials grant AWS console access through federated login, as well as advanced techniques like golden SAML where the threat actor forges assertions to assume any federated role. The scope of impact can be significant: a single compromised IdP administrator account may grant access to dozens of AWS accounts simultaneously. This playbook focuses exclusively on detecting and containing the **AWS-side impact** of an IdP compromise — the IdP investigation and remediation itself is owned by the identity team and is out of scope here.

### Out of Scope

This playbook does **not** cover:

- **Direct IAM credential compromise (access keys, console passwords)** — If the compromise involves stolen long-term AWS credentials rather than federated access, see [IRP-CredCompromise](IRP-CredCompromise.md).
- **AWS Identity Center (SSO) compromise** — If the compromise targets Identity Center permission sets or the Identity Center identity store directly, see [IRP-IdentityCenterCompromise](IRP-IdentityCenterCompromise.md).
- **STS token abuse without IdP compromise** — If the vector is AssumeRole chain abuse or session token manipulation without an upstream IdP compromise, see [IRP-STSTokenAbuse](IRP-STSTokenAbuse.md).
- **IdP platform investigation and remediation** — This playbook coordinates with the identity team but does not detail Okta/Entra ID/Google Workspace forensics or remediation. That is owned by the identity/IT security team.

### Applicable Finding Types

| Source | Finding / Event Type | Severity |
|---|---|---|
| Amazon GuardDuty | `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` | MEDIUM |
| Amazon GuardDuty | `InitialAccess:IAMUser/AnomalousBehavior` | MEDIUM |
| Amazon GuardDuty | `Persistence:IAMUser/AnomalousBehavior` | MEDIUM |
| CloudTrail | `eventName: AssumeRoleWithSAML` (unusual sourceIP or time) | — |
| CloudTrail | `eventName: AssumeRoleWithWebIdentity` (unusual sourceIP or time) | — |
| CloudTrail | `eventName: ConsoleLogin` with `additionalEventData.federatedProvider` | — |
| CloudTrail | `eventName: CreateSAMLProvider` | — |
| CloudTrail | `eventName: UpdateSAMLProvider` | — |
| CloudTrail | `eventName: DeleteSAMLProvider` | — |
| CloudTrail | `eventName: CreateOpenIDConnectProvider` | — |
| CloudTrail | `eventName: UpdateOpenIDConnectProviderThumbprint` | — |
| Custom / SIEM | Impossible travel on federated sessions | HIGH |
| Custom / SIEM | SAML assertions with unusual attribute values or new group claims | HIGH |
| Custom / SIEM | New SAML/OIDC provider creation in accounts without change tickets | CRITICAL |

> 📌 GuardDuty finding types are updated regularly. See the [GuardDuty finding types reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) for the current list.

### Severity Classification

| Priority | Criteria |
|---|---|
| **P1 — Critical** | Confirmed unauthorized federated access to production accounts, IdP admin compromise confirmed, golden SAML suspected, or new SAML provider created without authorization |
| **P2 — High** | Confirmed unauthorized federated console login or AssumeRoleWithSAML from unknown IP, multiple accounts potentially affected, or IdP compromise confirmed by identity team |
| **P3 — Medium** | Anomalous federated login patterns detected (impossible travel, unusual time), single account affected, no confirmed malicious actions yet |
| **P4 — Low** | Informational finding — e.g., federated login from new IP that may be legitimate, or stale SAML provider configuration identified during review |

---

## Part 1 — Prepare

> **CSF 2.0 Functions:** Govern · Identify · Protect
> **Goal:** Ensure the right configurations, access, and processes are in place *before* this incident type occurs.

### 1.1 Recommended AWS Service Configurations

The following services each contribute to your ability to detect, investigate, and respond to federated access abuse. None are strictly required, but each addresses a specific gap — the more you have enabled, the faster you can detect anomalous activity and the more complete your forensic picture will be during an investigation.

- [ ] **Amazon GuardDuty** enabled in all regions with findings exported to Security Hub — provides continuous threat detection for IAM anomalies, credential exfiltration, and reconnaissance patterns
- [ ] **AWS CloudTrail** enabled with multi-region trail, management events, and integrity validation — the primary audit log for all API activity; without it, investigation is severely limited
- [ ] **CloudTrail Insights** enabled — detects unusual API call volume (useful for sudden spikes in federated logins)
- [ ] **AWS Config** enabled with rules for IAM provider changes (`iam-no-inline-policy-check`, custom rules for SAML provider monitoring) — provides continuous compliance assessment
- [ ] **IAM Access Analyzer** enabled (external access analyzer to detect overly permissive role trust policies) — identifies roles that can be assumed from outside the organization
- [ ] **Amazon Detective** enabled — provides graph-based investigation of federated session activity, reducing time to scope an incident
- [ ] **AWS Security Hub** enabled with AWS Foundational Security Best Practices standard — aggregates and prioritizes findings across services
- [ ] **EventBridge rules** configured to alert on `CreateSAMLProvider`, `UpdateSAMLProvider`, `CreateOpenIDConnectProvider` API calls — provides near-real-time alerting on IdP trust changes
- [ ] **CloudWatch alarms** configured for federated console logins outside business hours or from unexpected geolocations
- [ ] **S3 bucket for CloudTrail logs** has Object Lock or versioning enabled — protects audit trail from tampering
- [ ] **Inventory of all SAML and OIDC providers** across all accounts maintained and reviewed quarterly

> 🤖 **Automation opportunity:** Deploy an EventBridge rule that triggers an SNS notification (or Security Hub custom finding) whenever `CreateSAMLProvider` or `UpdateSAMLProvider` is called in any account. See [Appendix D](#appendix-d--automation-hooks) for implementation.
>
> 📖 **Reference:** [SEC10-BP06 Pre-deploy tools](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_deploy_tools.html) — AWS Well-Architected Framework recommends pre-deploying investigation and response tooling so capabilities are available immediately when needed.

### 1.2 IAM & Access Prerequisites

Effective incident response depends on having the right access available *before* an incident occurs. For federated access abuse specifically, your IR team must have a non-federated access path to AWS — if the IdP is down or compromised, federated access is unavailable. The following recommendations align with [SEC10-BP05 Pre-provision access](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_pre_provision_access.html) from the AWS Well-Architected Framework.

- [ ] **Break-glass IAM role** exists with permissions to: modify role trust policies, delete/update SAML providers, attach deny policies, query CloudTrail, and manage SCPs — pre-tested and documented
- [ ] **IR team members can assume the break-glass role** with MFA from a trusted account (not via federation — must be direct IAM or Identity Center access)
- [ ] **Pre-created SCP** to block `CreateSAMLProvider` and `UpdateSAMLProvider` is ready to attach during incidents
- [ ] **Pre-created IAM policy** to deny all actions for sessions issued before a specific time (`aws:TokenIssueTime` condition) is documented and tested
- [ ] **Non-federated access path** confirmed — critical for this scenario; if the IdP is compromised, federated access is unavailable
- [ ] **Access to AWS Security Incident Response console** confirmed, if subscribed — verify case creation workflow before you need it
- [ ] **Forensic account** available for cross-account log analysis — isolated from production, with appropriate trust relationships pre-configured
- [ ] **Contact information for identity/IdP team** is current and accessible without relying on the potentially compromised IdP

> 📖 **Reference:** [AWS Security Incident Response Guide — Preparation](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/preparation.html) — covers pre-provisioning access, and validating response capabilities.

### 1.3 Communication & Escalation

Clear communication paths reduce confusion during high-pressure incidents. Federated access abuse often requires coordination between the IR team and the identity/IdP team — establish those communication channels before you need them.

> 📋 Do not include names in this playbook. Use roles only. Maintain a separate, access-controlled contact list (e.g., internal wiki, sealed envelope, or secure document) with current names, phone numbers, and escalation preferences.

| Role | Responsibility | When to Engage |
|---|---|---|
| IR Lead | Overall incident coordination, status updates, decision authority for containment actions | All severity levels — first notified |
| Identity / IdP Team Lead | IdP-side investigation, session revocation, IdP remediation | All severity levels — engaged immediately after IR Lead |
| Account Owner(s) | Business context, authorization for containment actions across affected accounts | P1–P3, or when containment may disrupt services |
| Application Owner(s) | Impact assessment of federation disruption on running services | When containment may disrupt federated applications |
| Legal / Compliance | Regulatory notification if data accessed via compromised sessions | P1–P2, or when regulated data may have been accessed |
| Communications | Internal messaging (especially if BEC affects broader organization) | P1–P2, or when broader workforce may be affected |
| AWS Support / AWS CIRT | Technical assistance with scoping, containment guidance, threat intelligence | P1–P2 via AWS Support case (any support plan) or Security Incident Response service (if subscribed) |

**Escalation path:**

1. **Detection:** Automated alert (GuardDuty, SIEM, identity team notification) triggers initial notification.
2. **Triage (IR Lead + Identity Team, < 15 min):** IR Lead assesses severity. Identity team confirms or denies IdP compromise.
3. **Severity-based escalation:**
   - **P1/P2:** IR Lead notifies Account Owners and Legal/Compliance immediately. Opens AWS Support case (severity: Critical) requesting CIRT assistance. If AWS Security Incident Response service is enabled, creates a case there instead.
   - **P3/P4:** IR Lead manages internally with identity team coordination. Escalates to P2 if investigation confirms unauthorized use.
4. **Status updates:** IR Lead provides updates to stakeholders every 30 minutes (P1), every 2 hours (P2), or at key milestones (P3/P4).

> 📖 **Reference:** [SEC10-BP01 Identify key personnel and external resources](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_identify_personnel.html) — recommends identifying and documenting internal and external resources and contact information ahead of time.

### 1.4 Game Day Guidance

Practicing incident response before a real incident occurs builds muscle memory, identifies gaps in tooling and access, and validates that escalation paths work. For this scenario, testing the non-federated access path and identity team coordination is especially important.

Recommended testing cadence: **Semi-annually** (this is a P1-capable scenario with multi-account impact potential).

Suggested tabletop scenario:
> *"A threat actor has compromised a corporate Okta admin account via phishing. They have modified the SAML assertion to include an admin group claim, which maps to an AWS role with AdministratorAccess in 5 production accounts. The identity team has confirmed the Okta compromise but has not yet revoked all sessions. You need to contain the AWS-side access immediately. You discover that the threat actor has already created a new IAM user with access keys in 2 of the 5 accounts."*

**Practice resources (no paid service or support plan required):**

- [AWS CIRT Incident Response Workshops](https://aws.amazon.com/blogs/security/aws-cirt-announces-the-release-of-five-publicly-available-workshops/) — free, hands-on workshops covering credential compromise, S3 ransomware, and more. Deployable in any AWS account.
- [AWS Foundational Security, Identity and Governance Workshop](https://catalog.us-east-1.prod.workshops.aws/workshops/05554d54-07cc-483e-b810-d69f7d99b2ab/en-US) — covers IAM federation, identity governance, and security controls relevant to this scenario.
- [AWS Security Workshops catalog](https://workshops.aws/categories/Security) — broader collection of security-focused hands-on labs.

> 📖 **Reference:** [SEC10-BP04 Develop and test security incident response playbooks](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_incident_response_playbooks.html) — recommends creating and regularly testing playbooks to verify response processes.

---

## Part 2 — Detect & Analyze

> **CSF 2.0 Functions:** Detect · Respond (Analyze)
> **Goal:** Determine whether federated access activity is authorized or unauthorized, understand the scope if it is unauthorized, and document the evidence needed to support containment and recovery decisions.

### 2.1 Initial Triage Questions

Not every alert is a confirmed compromise. The purpose of triage is to quickly determine whether you are dealing with a true positive (unauthorized federated access), a potential compromise requiring investigation, or a false positive that can be closed. Answer these questions to establish scope and urgency — each should take less than 2 minutes.

- [ ] What type of federation is involved? (SAML 2.0, OIDC, custom federation broker)
- [ ] Which IdP is the source? (Okta, Microsoft Entra ID, Google Workspace, PingFederate, other)
- [ ] Has the identity team confirmed an IdP compromise? (If yes, get scope — which users/groups affected)
- [ ] Which AWS accounts have SAML/OIDC providers configured for this IdP?
- [ ] Which IAM roles can be assumed via this federation? (Check role trust policies for `saml-provider` or `oidc-provider` conditions)
- [ ] What permissions do the federated roles have? (AdministratorAccess? ReadOnly? Custom?)
- [ ] Is there evidence of unauthorized federated sessions in CloudTrail? (Unusual IPs, times, or user agents on `AssumeRoleWithSAML`/`AssumeRoleWithWebIdentity`)
- [ ] Has the threat actor modified any SAML/OIDC provider configurations in AWS? (Check for `CreateSAMLProvider`, `UpdateSAMLProvider`)
- [ ] Are there signs of persistence beyond the federated session? (New IAM users, access keys, roles created during suspicious sessions)
- [ ] Can the IR team still access AWS without relying on the compromised IdP?

**If the IdP admin is compromised AND federated roles have admin permissions in production → P1 immediately.**
**If the activity is anomalous but could be legitimate → investigate further before containment (avoid unnecessary disruption).**

### 2.2 Evidence Collection Checklist

Whether the activity is confirmed malicious or still under investigation, document the current state of all federation configurations before taking any containment actions. For federated access scenarios, the primary evidence sources are CloudTrail and the IAM provider configurations.

> ⚠️ **Collect evidence BEFORE modifying SAML providers or role trust policies.** Document the current state of all federation configurations first.

| What to Document | How | Notes |
|---|---|---|
| SAML provider metadata (current) | `aws iam get-saml-provider --saml-provider-arn ...` | Preserves signing certificate and configuration |
| Role trust policies for federated roles | `aws iam get-role --role-name ...` (for each federated role) | Establishes what trust existed at time of compromise |
| All SAML/OIDC providers in account | `aws iam list-saml-providers` / `aws iam list-open-id-connect-providers` | Full federation inventory |
| CloudTrail events: AssumeRoleWithSAML | Athena query (see resources) | Identifies unauthorized federated sessions |
| CloudTrail events: ConsoleLogin (federated) | Athena query (see resources) | Source IP and timing analysis |
| CloudTrail events: SAML/OIDC provider changes | Athena query (see resources) | Detects trust manipulation |
| Actions performed during suspicious sessions | Athena query filtered by session issuer | Determines what the threat actor did |
| GuardDuty findings | GuardDuty console → filter by resource | Additional context on behavior |
| IdP audit logs | Request from identity team | Correlates IdP-side activity with AWS-side sessions |

**CloudTrail / Athena investigation queries:**

For detailed Athena queries to investigate federated access abuse (session enumeration, source IP analysis, provider modification detection, privilege escalation during sessions), see:

📁 [`resources/athena-queries-federated-access-abuse.sql`](resources/athena-queries-federated-access-abuse.sql)

**Quick CloudTrail Console approach (no Athena required):**

If Athena is not configured, you can investigate directly in the CloudTrail console:

1. Navigate to **CloudTrail → Event history**
2. Filter by **Event name** = `AssumeRoleWithSAML` or `AssumeRoleWithWebIdentity`
3. Review source IPs — compare against known corporate IP ranges
4. Check timing — federated logins outside business hours from unfamiliar IPs are a strong indicator
5. Filter by **Event name** = `CreateSAMLProvider` or `UpdateSAMLProvider` to check for trust manipulation

### 2.3 Severity Determination

Based on triage and initial evidence, assign a priority using the criteria in [Severity Classification](#severity-classification).

| Confirmed? | Priority Assignment |
|---|---|
| IdP admin compromised, federated roles have admin access to production, active sessions detected | P1 |
| Confirmed unauthorized federated login, scope unclear, or golden SAML suspected | P2 |
| IdP compromise confirmed by identity team but no evidence of AWS-side abuse yet | P2 |
| Anomalous federated login pattern (impossible travel, unusual time), not yet confirmed malicious | P3 |
| Stale SAML provider found, or federation misconfiguration identified during review | P4 |

### 2.4 Getting Help from AWS

For P1, P2, or P3 incidents, consider engaging AWS for support. AWS Support and AWS CIRT can help you determine whether activity is truly unauthorized, assist with scoping the impact, and advise on containment approaches — you do not need to be certain of a compromise before reaching out.

- **AWS Security Incident Response service** (if enabled): Sign into [AWS Security Incident Response](https://console.aws.amazon.com/security-ir/) via the console, choose **Create Case**, select **Resolve case with AWS**, and choose **Active Security Incident** for urgent support or **Investigations and Inquiries** for log analysis and secondary confirmation of findings.
- **AWS Support** (any support plan): Open a support case requesting assistance from the AWS Customer Incident Response Team (CIRT). Include the finding ID(s), the federated role(s) under investigation, and a summary of the anomalous behavior you have observed.

> 📌 You do not need the Security Incident Response service to get help from experts. All AWS customers can request CIRT assistance through a support case, regardless of support plan level. For P3 (anomalous behavior, not yet confirmed), AWS CIRT can help you determine whether the activity is malicious or legitimate.

---

## Part 3 — Contain

> **CSF 2.0 Function:** Respond (Contain)
> **Goal:** Prevent further unauthorized API activity via federated sessions, while minimizing disruption to legitimate users and services. Containment should be deliberate — revoke sessions and block federation trust rather than deleting providers outright, so you retain forensic value and can restore quickly.

### 3.1 Containment Decision

The goal of containment is to invalidate existing federated sessions and prevent new ones from being established. For federated access abuse, containment on the AWS side must proceed in parallel with (not wait for) IdP-side remediation by the identity team.

```text
Is the IdP compromise confirmed AND are federated sessions active in AWS?
│
├── YES (confirmed IdP compromise + active AWS sessions)
│     └── Proceed to 3.2 immediately — revoke all federated sessions
│           and block further federation until IdP is secured
│
├── IdP compromise confirmed but no AWS-side activity detected yet
│     └── Proceed to 3.2 proactively — block federation as a precaution
│         (race condition: threat actor may not have pivoted to AWS yet)
│
└── Anomalous federated login detected, IdP compromise NOT confirmed
      └── Investigate further (Part 2) before taking containment action
            ├── If confirmed unauthorized → Proceed to 3.2
            ├── If confirmed legitimate → Document and close
            └── If still unclear after 30 min → Consider engaging AWS CIRT (Section 2.4)
                  for help determining if the activity is malicious
```

### 3.2 Containment Actions

> `[IR Lead]` coordinates. `[Account Owner]` authorizes. `[Identity Team]` handles IdP-side containment in parallel.

> ⚠️ **Critical:** Containment actions here focus on the AWS side. The identity team must simultaneously revoke sessions and secure the IdP. Coordinate but do not wait for IdP remediation before securing AWS access.

**Step 1: Revoke all active federated sessions on affected roles**

Apply a deny policy to each affected role that invalidates all sessions issued before the current time:

```bash
# For each federated role that may have been compromised:
aws iam put-role-policy \
  --role-name FEDERATED_ROLE_NAME \
  --policy-name RevokeCompromisedFederatedSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "2026-06-25T15:00:00Z"
        }
      }
    }]
  }'
```

> 📌 Replace the timestamp with the current UTC time. This immediately invalidates all existing federated sessions while allowing new sessions (once the IdP is secured and federation is re-enabled).

> ⚠️ **Impact:** This will terminate active sessions for ALL users of this role, including legitimate users. Coordinate with Application Owners.

**Step 2: Modify role trust policies to temporarily block federation**

```bash
# First, save the current trust policy for evidence
aws iam get-role --role-name FEDERATED_ROLE_NAME \
  --query 'Role.AssumeRolePolicyDocument' > /tmp/original-trust-policy.json

# Replace with a trust policy that only allows the break-glass role
aws iam update-assume-role-policy \
  --role-name FEDERATED_ROLE_NAME \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::SECURITY_ACCOUNT_ID:role/BreakGlassRole"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "Bool": {"aws:MultiFactorAuthPresent": "true"}
      }
    }]
  }'
```

> ⚠️ **This completely blocks all federated access to this role.** Only do this if the IdP compromise is confirmed. This is the most effective containment but has the highest service impact.

**Step 3: Apply SCP to block SAML/OIDC provider modifications during the incident**

Prevent the threat actor from creating new federation trust or modifying existing providers:

```bash
# Attach the pre-created SCP to the organization root or affected OUs
aws organizations attach-policy \
  --policy-id p-EXAMPLE_SCP_ID \
  --target-id ou-AFFECTED_OU_ID
```

SCP content (pre-create and store in your SCP library):
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "BlockFederationChanges",
    "Effect": "Deny",
    "Action": [
      "iam:CreateSAMLProvider",
      "iam:UpdateSAMLProvider",
      "iam:DeleteSAMLProvider",
      "iam:CreateOpenIDConnectProvider",
      "iam:DeleteOpenIDConnectProvider",
      "iam:AddClientIDToOpenIDConnectProvider",
      "iam:UpdateOpenIDConnectProviderThumbprint"
    ],
    "Resource": "*",
    "Condition": {
      "StringNotLike": {
        "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassRole"
      }
    }
  }]
}
```

**Step 4: Address the SAML/OIDC provider based on scenario**

The appropriate action depends on whether the provider is legitimate infrastructure or was created by the threat actor. In most cases, **you do not need to delete a legitimate provider** — Steps 1–3 above already block all federated access at the role level.

```text
Was this SAML/OIDC provider created by the threat actor?
│
├── YES (unauthorized provider — e.g., threat actor ran CreateSAMLProvider
│        to establish trust to their own IdP)
│     └── Delete it immediately. It is unauthorized infrastructure.
│
└── NO (legitimate organizational provider — Okta, Entra ID, etc.)
      │
      ├── Was the provider metadata tampered with?
      │   (threat actor uploaded a modified signing certificate)
      │     └── Revert to known-good metadata from backup.
      │         Do NOT delete — the provider is legitimate, only the
      │         metadata was modified.
      │
      ├── IdP sessions compromised but metadata is intact?
      │   (BEC, stolen user creds, admin account hijacked)
      │     └── No action needed on the provider itself.
      │         Steps 1–3 already contain the AWS side.
      │         Identity team handles IdP-side remediation.
      │
      └── IdP is completely compromised and identity team cannot
          confirm they have regained control?
          (golden SAML, signing keys exfiltrated, full admin loss)
            └── Steps 1–2 (trust policy removal) are sufficient.
                Provider deletion is a last resort — only consider
                if trust policy modification fails or if the identity
                team explicitly requests it to guarantee severance.
```

**If the provider was created by the threat actor — delete it:**

```bash
# Delete unauthorized provider (threat-actor-created only)
aws iam delete-saml-provider \
  --saml-provider-arn arn:aws:iam::123456789012:saml-provider/UNAUTHORIZED_PROVIDER
```

**If a legitimate provider's metadata was tampered with — revert it:**

```bash
# Revert to known-good metadata (preserves the provider, fixes the trust)
aws iam update-saml-provider \
  --saml-provider-arn arn:aws:iam::123456789012:saml-provider/CorporateIdP \
  --saml-metadata-document file://known-good-metadata.xml
```

> 📌 For the vast majority of scenarios involving a legitimate IdP, the trust policy modification in Step 2 is the primary containment mechanism. Deleting a legitimate provider creates unnecessary recovery complexity and is rarely needed — modifying the role trust policy achieves the same isolation with a cleaner path back to normal operations.

**Step 5: Restrict console access to specific IP ranges (defense in depth)**

Apply an IAM policy condition to federated roles that limits access to known corporate IP ranges:

```bash
aws iam put-role-policy \
  --role-name FEDERATED_ROLE_NAME \
  --policy-name RestrictSourceIP \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "NotIpAddress": {
          "aws:SourceIp": ["203.0.113.0/24", "198.51.100.0/24"]
        },
        "Bool": {
          "aws:ViaAWSService": "false"
        }
      }
    }]
  }'
```

> 📌 Replace the CIDR ranges with your organization's known egress IPs. The `aws:ViaAWSService` condition prevents blocking AWS service-to-service calls.

**Step 6: Coordinate with identity team on IdP-side containment**

Communicate the following to the identity team (they own execution):
- [ ] Disable compromised IdP user accounts
- [ ] Revoke all active IdP sessions for affected users
- [ ] Rotate IdP signing certificates (if golden SAML is suspected)
- [ ] Review IdP audit logs for unauthorized configuration changes
- [ ] Confirm when IdP is secured and safe to re-enable federation

> 🤖 **Automation opportunity:** AWS Systems Manager Automation document to apply session revocation policies across multiple roles and accounts simultaneously. See [Appendix D](#appendix-d--automation-hooks) for implementation.

### 3.3 Document Containment Actions

Record all containment actions taken, including timestamps, who performed them, and what was affected. This documentation supports the post-incident timeline (Part 5) and is important for any regulatory inquiries.

- [ ] Original SAML provider metadata documents saved (before any updates/deletions)
- [ ] Original role trust policies saved for all affected roles
- [ ] What roles were contained and when (timestamp, role name, who performed the action)
- [ ] What services or applications were impacted by federation disruption
- [ ] Whether containment was effective (did unauthorized activity stop?)
- [ ] Whether lateral movement to other accounts was identified and contained
- [ ] All CloudTrail logs for the incident window exported to forensic S3 bucket
- [ ] GuardDuty findings exported (full JSON)
- [ ] S3 Object Lock applied to forensic evidence bucket
- [ ] CloudTrail log integrity validation confirmed
- [ ] IdP audit logs requested from identity team and preserved

---

## Part 4 — Eradicate

> **CSF 2.0 Function:** Respond (Eradicate)
> **Goal:** Identify the root cause of the compromise, remove any persistence mechanisms the threat actor created, and confirm the environment is clean. Eradication often uncovers additional compromised resources — if new findings emerge during this phase, return to Part 3 (Contain) for any newly identified credentials or access paths before continuing.

### 4.1 Root Cause Identification

> `[IR Lead]` owns this step. Document findings in the IR ticket in real time.

Understanding how the federation was abused is essential before re-enabling trust — if the root cause is not resolved, the same access path will be exploited again.

Common root causes for federated access abuse:

- **Business Email Compromise (BEC):** Threat actor phished a corporate user whose credentials grant AWS console access via federation — no IdP admin compromise, just a regular user's session
- **IdP admin account compromise:** Threat actor gained access to an IdP administrator account (via phishing, credential stuffing, or session hijacking) and modified SAML assertions or group memberships
- **Golden SAML:** Threat actor obtained the IdP signing certificate (from the IdP server or AD FS) and can forge arbitrary SAML assertions without needing ongoing IdP access
- **OIDC token theft:** Threat actor stole OIDC tokens from a compromised application or developer workstation and used them to call `AssumeRoleWithWebIdentity`
- **IdP misconfiguration exploitation:** Overly permissive SAML attribute mapping allowed the threat actor to escalate privileges by manipulating assertion attributes
- **Lack of federation session controls:** No IP restrictions, session duration too long, or no MFA requirement on federated roles amplified the scope of impact

Use the source IP analysis and session timeline from Part 2 to determine:

- When did the first unauthorized federated session begin?
- Which IdP user account was used? (Extract from SAML assertion subject in CloudTrail)
- Did the threat actor modify IdP configuration or just use existing access?
- What was the full scope of AWS accounts accessed?

### 4.2 Remove Persistence Mechanisms

> `[IR Lead]` coordinates. `[Account Owner]` approves changes to production resources. `[Identity Team]` confirms IdP is secured before re-enabling federation.

When a federated session is compromised, threat actors commonly create additional credentials or access paths that survive session revocation. This section focuses on identifying and removing those persistence mechanisms.

**Identify and remove unauthorized credentials and resources:**

- [ ] Additional access keys created on any IAM user during suspicious federated sessions
- [ ] Unauthorized IAM users created by the threat actor (check CloudTrail for `CreateUser` events during the incident window)
- [ ] Unauthorized IAM roles with trust policies allowing assumption from external accounts
- [ ] Modified trust policies on existing roles (adding external principals the threat actor controls)
- [ ] Unauthorized IAM policies attached to existing users or roles (escalating permissions beyond what was originally granted)
- [ ] Unauthorized Lambda functions, EC2 instances, or other compute resources
- [ ] Modified SCPs or resource policies (weakening guardrails)
- [ ] Unauthorized EventBridge rules (threat actor may disable alerting)
- [ ] Modified CloudTrail configurations (trails disabled, event selectors modified)

```bash
# Delete unauthorized IAM users created during compromised sessions
aws iam delete-user --user-name UNAUTHORIZED_USER

# Delete unauthorized access keys
aws iam delete-access-key \
  --user-name AFFECTED_USER \
  --access-key-id AKID_CREATED_BY_THREAT_ACTOR

# Delete unauthorized IAM roles (threat actor may create non-federated backdoor roles)
aws iam delete-role --role-name UNAUTHORIZED_BACKDOOR_ROLE

# Remove unauthorized policies attached during the incident
aws iam detach-role-policy \
  --role-name AFFECTED_ROLE \
  --policy-arn arn:aws:iam::123456789012:policy/UNAUTHORIZED_POLICY
aws iam delete-policy \
  --policy-arn arn:aws:iam::123456789012:policy/UNAUTHORIZED_POLICY
```

**Verify SAML/OIDC provider integrity:**

If the provider was modified during containment (metadata reverted or trust policy removed), verify the final state is correct. If the provider was not touched during containment (because Steps 1–3 were sufficient), verify it was not tampered with by the threat actor.

```bash
# Get current SAML provider metadata and compare to known-good backup
aws iam get-saml-provider \
  --saml-provider-arn arn:aws:iam::123456789012:saml-provider/CorporateIdP

# Verify the signing certificate in the metadata matches the legitimate IdP certificate
# Compare the X509Certificate element against your backup
# If the metadata was reverted during containment (Step 4), confirm the revert is correct

# List all OIDC providers and verify each is expected
aws iam list-open-id-connect-providers

# For each OIDC provider, verify thumbprint and client IDs
aws iam get-open-id-connect-provider \
  --open-id-connect-provider-arn arn:aws:iam::123456789012:oidc-provider/example.com

# Check for any NEW providers created by the threat actor during the incident
# (These should have been deleted during containment Step 4, but verify)
```

> 📌 If you discover a provider the threat actor created that was not caught during containment, delete it now. For legitimate providers, confirm the metadata is either the original untampered version or has been successfully reverted to known-good state.

**Verify role trust policies are clean:**

```bash
# For each federated role, verify the trust policy only references legitimate providers
aws iam get-role --role-name FEDERATED_ROLE_NAME \
  --query 'Role.AssumeRolePolicyDocument'

# Look for:
# - Unexpected SAML provider ARNs in the trust policy
# - Wildcard conditions or missing conditions on SAML:aud
# - New principals added to the trust policy during the incident
# - Removed conditions (e.g., threat actor removed IP restrictions)
```

**Rotate any secrets accessed during compromised sessions:**

- [ ] Secrets accessed via Secrets Manager — rotate immediately
- [ ] SSM Parameter Store values accessed — update with new values
- [ ] Any credentials stored in application configuration that the threat actor could have read (database passwords, API keys, etc.)
- [ ] KMS key rotation enabled for any keys used during suspicious sessions

> ⚠️ **If you discover additional compromised credentials or access paths during eradication, return to Part 3 (Contain) and deactivate those credentials before continuing.** Eradication is iterative — it is common to cycle between containment and eradication multiple times.
>
> 📌 **Beyond credentials:** If CloudTrail shows the threat actor created compute resources, modified resource policies, or took other actions beyond credential manipulation, consult the relevant playbook for eradication guidance specific to those resource types. For a comprehensive reference of persistence techniques observed in AWS environments, see the [Threat Technique Catalog for AWS](https://aws-samples.github.io/threat-technique-catalog-for-aws/). Key techniques relevant to this playbook:
> - [T1098.001 — Additional Cloud Credentials](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1098.001.html): Creating access keys, login profiles, or using `sts:GetFederationToken` to persist beyond session revocation
> - [T1484.002 — Trust Modification](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1484.002.html): Creating or modifying SAML/OIDC providers to establish unauthorized federation trust
> - [T1199.A002 — Role Assumption and Federated Access](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1199.A002.html): Using federated access or cross-account role assumption for lateral movement

### 4.3 Eradication Validation

Before moving to recovery, confirm that the threat actor's access has been fully removed:

- [ ] All unauthorized IAM users, roles, access keys, and policies removed
- [ ] All unauthorized resources (EC2, Lambda, ECS tasks, etc.) terminated
- [ ] Any threat-actor-created SAML/OIDC providers deleted
- [ ] Legitimate SAML/OIDC provider metadata verified (untampered or successfully reverted to known-good)
- [ ] All federated role trust policies verified clean (no unauthorized principals or weakened conditions)
- [ ] All accessed secrets rotated
- [ ] SCPs verified unmodified (or reverted)
- [ ] No unauthorized CloudTrail configurations (trails disabled, event selectors modified)
- [ ] No unauthorized EventBridge rules that could suppress alerts
- [ ] CloudTrail shows no continued unauthorized activity for at least 30 minutes after eradication actions
- [ ] GuardDuty shows no new findings related to the threat actor's activity
- [ ] Identity team confirms IdP is secured and signing certificates rotated (if golden SAML)

> 🤖 **Automation opportunity:** AWS Config rules with auto-remediation can detect unauthorized IAM changes. Custom Config rules can monitor SAML provider metadata for unexpected certificate changes.

---

## Part 4b — Recover

> **CSF 2.0 Function:** Recover
> **Goal:** Restore legitimate federated access, remove containment controls, and harden the environment against recurrence. Recovery should only proceed once eradication is validated and the identity team confirms the IdP is secured — restoring federation prematurely can re-expose the environment.

### 4.4 Restore Legitimate Access

> ⚠️ Before re-enabling federation, confirm the identity team has secured the IdP (Section 4.1 root cause resolved). If the IdP is not yet secured, restoring federation trust will reintroduce the same access path.

**Step 1: Re-establish federation with verified IdP**

The steps here depend on what containment actions were taken on the provider:

```text
Was the legitimate SAML provider deleted during containment?
│
├── NO (most common — trust policy was modified in Step 2 instead)
│     └── No action needed on the provider. Skip to Step 2.
│         The provider is intact; you only need to restore the trust policy.
│
├── Provider metadata was reverted to known-good during containment
│     └── Verify the metadata is still correct (should be from eradication).
│         Skip to Step 2.
│
└── YES (rare — provider was deleted as a last resort)
      └── Recreate with verified metadata from the identity team:
```

```bash
# Only needed if the provider was deleted during containment (rare)
aws iam create-saml-provider \
  --saml-metadata-document file://verified-idp-metadata.xml \
  --name CorporateIdP
```

> 📌 If you followed the containment guidance and used trust policy modification (Step 2) instead of provider deletion, the provider is already intact and you only need to restore the role trust policies in Step 2 below.

**Step 2: Restore role trust policies (with hardening improvements)**

```bash
aws iam update-assume-role-policy \
  --role-name FEDERATED_ROLE_NAME \
  --policy-document file://hardened-trust-policy.json
```

Hardened trust policy example (add conditions that were missing before):
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:saml-provider/CorporateIdP"
    },
    "Action": "sts:AssumeRoleWithSAML",
    "Condition": {
      "StringEquals": {
        "SAML:aud": "https://signin.aws.amazon.com/saml"
      },
      "IpAddress": {
        "aws:SourceIp": ["203.0.113.0/24", "198.51.100.0/24"]
      }
    }
  }]
}
```

**Step 3: Remove containment controls**

```bash
# Remove session revocation policy from affected roles
aws iam delete-role-policy \
  --role-name FEDERATED_ROLE_NAME \
  --policy-name RevokeCompromisedFederatedSessions

# Remove IP restriction policy (if now enforced in trust policy instead)
aws iam delete-role-policy \
  --role-name FEDERATED_ROLE_NAME \
  --policy-name RestrictSourceIP

# Detach the SCP blocking federation changes
aws organizations detach-policy \
  --policy-id p-EXAMPLE_SCP_ID \
  --target-id ou-AFFECTED_OU_ID
```

### 4.5 Harden Against Recurrence

Based on the root cause identified in Section 4.1, implement targeted hardening:

- [ ] **Add `aws:SourceIp` conditions** to all federated role trust policies (restrict to corporate egress IPs)
- [ ] **Reduce maximum session duration** on federated roles (from 12h default to 1–4h)
- [ ] **Implement `aws:MultiFactorAuthPresent` condition** where supported by the IdP
- [ ] **Enable CloudTrail Insights** to detect unusual spikes in `AssumeRoleWithSAML` calls
- [ ] **Deploy EventBridge rules** to alert on any SAML/OIDC provider changes (see Appendix D)
- [ ] **Review and minimize permissions** on federated roles (apply least privilege) — use IAM Access Analyzer unused access findings
- [ ] **Implement SAML assertion attribute conditions** (e.g., require specific group membership claims)
- [ ] **Establish a quarterly review cadence** for all SAML/OIDC provider configurations
- [ ] **Ensure IR team has a non-federated access path** (break-glass) that does not depend on the corporate IdP
- [ ] **Work with identity team** to implement phishing-resistant MFA (FIDO2/WebAuthn) for IdP access
- [ ] **Address the specific root cause:**
  - If BEC: implement phishing-resistant MFA, conditional access policies on the IdP
  - If IdP admin compromise: restrict IdP admin access, implement privileged access workstation requirements
  - If golden SAML: rotate IdP signing certificates, monitor for certificate access events
  - If OIDC token theft: restrict token audience, implement token binding where supported

### 4.6 Recovery Validation

- [ ] Legitimate users can authenticate via federation and access their normal resources
- [ ] Applications and services that depend on federated access are functioning normally
- [ ] No unauthorized resources remain in affected accounts
- [ ] SAML/OIDC provider metadata matches known-good configuration
- [ ] All federated role trust policies are hardened with appropriate conditions
- [ ] GuardDuty shows no new findings related to this incident
- [ ] Application health metrics are within normal range
- [ ] Monitoring and alerting for federation events confirmed operational
- [ ] Identity team confirms IdP is fully secured and monitoring is enhanced
- [ ] All containment controls have been removed
- [ ] AWS Security Incident Response case updated (if applicable)

---

## Part 5 — Post-Incident Activity

> **CSF 2.0 Function:** Identify (Improve) — continuous improvement, not a one-time activity
> **Goal:** Capture what happened, when, and why — then use those findings to improve detection, response, and prevention for next time. Post-incident activity is not a one-time report; it generates action items that feed back into Part 1 (Prepare) for this and other playbooks.

### 5.1 Timeline Reconstruction

Build a complete timeline of the incident from initial compromise through recovery. This should be completed within 24–48 hours while events are fresh and CloudTrail data is readily queryable. A clear timeline supports post-incident review, regulatory inquiries, and future detection tuning.

| Timestamp (UTC) | Event | Source / Evidence | Actor |
|---|---|---|---|
| | IdP compromise occurred (phishing, credential theft) | IdP audit logs | Threat actor |
| | First unauthorized federated session in AWS | CloudTrail: AssumeRoleWithSAML | Threat actor |
| | Reconnaissance activity (ListBuckets, DescribeInstances) | CloudTrail | Threat actor |
| | Persistence created (IAM user, access keys) | CloudTrail | Threat actor |
| | Detection: GuardDuty finding / SIEM alert / identity team notification | GuardDuty / SIEM | AWS / SOC |
| | IR team notified | On-call alert | IR Lead |
| | Federated sessions revoked (TokenIssueTime deny policy applied) | CloudTrail | IR team |
| | Role trust policies modified to block federation | CloudTrail | IR team |
| | Identity team confirmed IdP secured | Identity team communication | IdP Team |
| | Eradication complete — persistence removed | IR ticket | IR team |
| | Federation restored with hardened configuration | IR ticket | IR team |
| | Recovery validated | IR ticket | IR Lead |

**Key metrics:**

These metrics help you measure response effectiveness over time and identify where investment would reduce future incident duration.

| Metric | Value | Why It Matters |
|---|---|---|
| Time to Detect (TTD) | *Time from first unauthorized federated session to detection* | Measures detection coverage for federated abuse |
| Time to Notify (TTN) | *Time from detection to IR team notified* | Measures alerting pipeline effectiveness |
| Time to Contain (TTC) | *Time from notification to all federated sessions revoked* | Measures response readiness |
| Time to IdP Secured | *Time from notification to identity team confirming IdP secured* | Measures cross-team coordination |
| Time to Recover (TTR) | *Time from containment to federation restored and validated* | Measures eradication thoroughness |
| Total Incident Duration | | End-to-end impact window |
| Affected AWS Accounts | *Count* | Scope of multi-account spread |
| Affected Federated Roles | *Count and names* | Determines permissions exposed |
| Persistence Created | *Count and type* | Indicates threat actor sophistication |
| Data Impact | *Confirmed / Suspected / None* | Drives regulatory notification |

### 5.2 Post-Incident Review

Conduct a blameless post-incident review within **5 business days** for P1/P2, **15 business days** for P3/P4. The goal is to identify systemic improvements, not assign blame. Include all stakeholders who participated in the response — for this scenario, the identity team should participate.

Discussion questions specific to federated access abuse:

1. How was the IdP compromised? Could the initial access vector have been prevented? (Phishing-resistant MFA, conditional access policies)
2. How quickly was the AWS-side impact detected after the IdP compromise? What would have detected it faster?
3. Were federated role permissions appropriate (least privilege)? Could the scope of impact have been smaller with tighter permissions?
4. Did the IR team have non-federated access to AWS? Was there any delay caused by relying on the compromised IdP?
5. Was coordination with the identity team effective? Were communication channels clear and responsive?
6. Were containment actions (session revocation, trust policy modification) executed quickly enough?
7. Were there conditions on federated role trust policies (IP restrictions, session duration limits) that could have prevented or limited the abuse?
8. What single change would most reduce the likelihood or impact of a similar incident in future?

### 5.3 Detection Gap Analysis

For each gap identified during the incident — whether a detection that did not fire, an alert that was not actioned, or a blind spot in coverage — document the root cause and assign an owner to fix it.

| Gap | Root Cause | Recommended Fix | Owner | Target Date |
|---|---|---|---|---|
| No alert on federated login from unusual IP | No baseline for federated login source IPs | Implement impossible travel detection for federated sessions | | |
| SAML provider change not detected in real time | No EventBridge rule for IAM provider API calls | Deploy EventBridge rule (see Appendix D) | | |
| Multi-hour gap between IdP compromise and AWS detection | No integration between IdP alerts and AWS monitoring | Establish cross-team alerting: IdP compromise → immediate AWS IR notification | | |
| Federated role had AdministratorAccess | No periodic review of federated role permissions | Implement quarterly access review with IAM Access Analyzer | | |

### 5.4 Playbook Update Checklist

Use this incident to improve this playbook. Do not wait for the next scheduled review — update immediately while the gaps are clear.

- [ ] Were triage questions (Part 2) sufficient? Add/remove as needed.
- [ ] Were evidence collection steps accurate for this scenario?
- [ ] Were containment actions effective? Any unintended service disruption?
- [ ] Was coordination with the identity team smooth? Update communication procedures if not.
- [ ] Were any new persistence mechanisms observed that are not listed in Section 4.2?
- [ ] Were automation opportunities identified? Add references to relevant sections.
- [ ] Were severity criteria accurate? Did this incident get classified at the right level?
- [ ] Update **Last Reviewed** date and increment **Playbook Version**.

---

## Appendix A — Investigation Resources

For detailed Athena queries to investigate federated access abuse (session enumeration, source IP analysis, provider modification detection, privilege escalation during federated sessions), see:

📁 [`resources/athena-queries-federated-access-abuse.sql`](resources/athena-queries-federated-access-abuse.sql)

These queries cover:

- All federated role assumptions (SAML and OIDC) in a time window
- Console logins via federation with source IP analysis
- SAML and OIDC provider configuration changes
- All actions taken during suspicious federated sessions
- Organization-wide identity provider creation and modification
- Unique source IP analysis for anomaly identification
- Session-specific activity tracing
- Privilege escalation attempts during federated sessions
- Session duration and attribute pattern analysis

### Federation Provider Inventory (CLI)

```bash
# List all SAML providers in an account
aws iam list-saml-providers

# Get SAML provider details (including metadata with signing certificate)
aws iam get-saml-provider \
  --saml-provider-arn arn:aws:iam::123456789012:saml-provider/PROVIDER_NAME

# List all OIDC providers
aws iam list-open-id-connect-providers

# Get OIDC provider details
aws iam get-open-id-connect-provider \
  --open-id-connect-provider-arn arn:aws:iam::123456789012:oidc-provider/PROVIDER_URL

# Find all roles that trust a specific SAML provider
for role in $(aws iam list-roles --query 'Roles[].RoleName' --output text); do
  trust=$(aws iam get-role --role-name "$role" \
    --query 'Role.AssumeRolePolicyDocument' --output text 2>/dev/null)
  if echo "$trust" | grep -q "saml-provider/PROVIDER_NAME"; then
    echo "Role trusts SAML provider: $role"
  fi
done
```

### GuardDuty Finding Export (CLI)

```bash
# List findings related to unauthorized access and anomalous behavior
aws guardduty list-findings \
  --detector-id DETECTOR_ID \
  --finding-criteria '{
    "Criterion": {
      "type": {
        "Eq": [
          "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
          "InitialAccess:IAMUser/AnomalousBehavior",
          "Persistence:IAMUser/AnomalousBehavior"
        ]
      },
      "updatedAt": {"GreaterThanOrEqual": 1716854400000}
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

See [Regulatory Context](../REGULATORY_CONTEXT.md) for the full notification obligation matrix by regulation and incident type.

**Quick reference for federated access abuse:**

| Regulation | Trigger Condition | Timeframe |
|---|---|---|
| GDPR Art. 33 | Personal data confirmed accessed via compromised federated session | 72 hours to supervisory authority |
| HIPAA Breach Notification | PHI accessed via unauthorized federated session in healthcare workloads | 60 days to HHS (individual notification varies) |
| PCI DSS 4.0 (Req 12.10) | Cardholder data environment accessed via compromised federation | Immediately to acquirer and card brands |
| SEC Cybersecurity Rules | Material cybersecurity incident involving federated access to financial systems | 4 business days (Form 8-K) |
| SOC 2 (Trust Services) | Unauthorized access to systems in scope via federation compromise | Report to auditor; include in management assertion |

> ⚠️ The clock starts at **awareness**, not confirmation. If the compromised federated session had access to regulated data and was used by a threat actor, assume notification is required and consult Legal immediately. Federated access incidents often affect multiple systems simultaneously — assess each regulated workload independently.

---

## Appendix C — Reference Links

- [NIST SP 800-61r3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html)
- [AWS Security Incident Response Service Documentation](https://docs.aws.amazon.com/security-ir/latest/userguide/what-is-security-ir.html)
- [AWS Well-Architected Framework — Security Pillar: Incident Response](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/incident-response.html)
- [Amazon GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [AWS CloudTrail Query Examples (Athena)](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)
- [AWS IAM: Creating IAM SAML Identity Providers](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml.html)
- [AWS IAM: Creating OpenID Connect (OIDC) Identity Providers](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)
- [AWS IAM: Available Keys for SAML-Based Federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html#condition-keys-saml)
- [AWS IAM: Revoking IAM Role Temporary Security Credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)
- [AWS Organizations: Service Control Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [Amazon Detective Investigation Guide](https://docs.aws.amazon.com/detective/latest/userguide/investigation-about.html)
- [AWS CIRT Incident Response Workshops](https://aws.amazon.com/blogs/security/aws-cirt-announces-the-release-of-five-publicly-available-workshops/)
- [AWS Foundational Security, Identity and Governance Workshop](https://catalog.us-east-1.prod.workshops.aws/workshops/05554d54-07cc-483e-b810-d69f7d99b2ab/en-US)
- [AWS Security Workshops catalog](https://workshops.aws/categories/Security)
- [Threat Technique Catalog for AWS](https://aws-samples.github.io/threat-technique-catalog-for-aws/)
- [CISA Advisory: Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a) *(Golden SAML context)*

---

## Appendix D — Automation Hooks

### EventBridge Rule: Alert on SAML/OIDC Provider Changes

Deploy this rule in every account (or via organization-wide CloudTrail + centralized EventBridge):

```json
{
  "Source": ["aws.iam"],
  "DetailType": ["AWS API Call via CloudTrail"],
  "Detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": [
      "CreateSAMLProvider",
      "UpdateSAMLProvider",
      "DeleteSAMLProvider",
      "CreateOpenIDConnectProvider",
      "DeleteOpenIDConnectProvider",
      "AddClientIDToOpenIDConnectProvider",
      "UpdateOpenIDConnectProviderThumbprint"
    ]
  }
}
```

**Target:** SNS topic → Security team notification + Security Hub custom finding import.

### EventBridge Rule: Alert on Unusual Federated Login Patterns

```json
{
  "Source": ["aws.signin"],
  "DetailType": ["AWS Console Sign In via CloudTrail"],
  "Detail": {
    "eventName": ["ConsoleLogin"],
    "additionalEventData": {
      "SamlProviderArn": [{"exists": true}]
    }
  }
}
```

**Target:** Lambda function that checks source IP against known corporate ranges and alerts if outside expected networks.

### Systems Manager Automation: Bulk Session Revocation

```yaml
# SSM Automation document to revoke federated sessions across multiple roles
description: Revoke all federated sessions for specified roles
schemaVersion: '0.3'
parameters:
  RoleNames:
    type: StringList
    description: List of IAM role names to revoke sessions for
  Timestamp:
    type: String
    description: UTC timestamp - sessions before this time will be denied
mainSteps:
  - name: RevokeSessions
    action: aws:executeScript
    inputs:
      Runtime: python3.11
      Handler: handler
      Script: |
        import boto3
        import json
        
        def handler(event, context):
            iam = boto3.client('iam')
            role_names = event['RoleNames']
            timestamp = event['Timestamp']
            
            policy_doc = json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "DateLessThan": {
                            "aws:TokenIssueTime": timestamp
                        }
                    }
                }]
            })
            
            results = []
            for role_name in role_names:
                try:
                    iam.put_role_policy(
                        RoleName=role_name,
                        PolicyName='RevokeCompromisedFederatedSessions',
                        PolicyDocument=policy_doc
                    )
                    results.append(f"SUCCESS: {role_name}")
                except Exception as e:
                    results.append(f"FAILED: {role_name} - {str(e)}")
            
            return {'results': results}
      InputPayload:
        RoleNames: '{{RoleNames}}'
        Timestamp: '{{Timestamp}}'
```

---

## Appendix E — Federation Architecture Quick Reference

### SAML 2.0 Federation Flow (Normal)

```
User → Corporate IdP (Okta/Entra ID) → SAML Assertion → AWS STS (AssumeRoleWithSAML) → Temporary Credentials → AWS Console/API
```

**Key CloudTrail fields for SAML federation:**
- `eventName`: `AssumeRoleWithSAML`
- `requestParameters.roleArn`: The IAM role being assumed
- `requestParameters.principalArn`: The SAML provider ARN
- `requestParameters.SAMLAssertion`: (not logged — only metadata)
- `responseElements.credentials.accessKeyId`: The temporary credential issued
- `responseElements.assumedRoleUser.arn`: The resulting session ARN

### OIDC Federation Flow (Normal)

```
Application → OIDC IdP → ID Token → AWS STS (AssumeRoleWithWebIdentity) → Temporary Credentials → AWS API
```

**Key CloudTrail fields for OIDC federation:**
- `eventName`: `AssumeRoleWithWebIdentity`
- `requestParameters.roleArn`: The IAM role being assumed
- `requestParameters.webIdentityToken`: (not logged)
- `responseElements.credentials.accessKeyId`: The temporary credential issued
- `responseElements.provider`: The OIDC provider URL

### Common Techniques

| Technique | TTC ID | Description | Detection Signal |
|---|---|---|---|
| BEC → Federated Login | [T1199.A002](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1199.A002.html) | Threat actor phishes corporate credentials, logs into AWS console via normal federation | ConsoleLogin from unusual IP/time |
| IdP Admin Compromise | [T1484.002](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1484.002.html) | Threat actor gains IdP admin, modifies group claims in SAML assertions | AssumeRoleWithSAML to roles the user should not access |
| Golden SAML | [T1484.002](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1484.002.html) | Threat actor steals IdP signing certificate, forges arbitrary assertions offline | AssumeRoleWithSAML from IPs that never hit the IdP |
| OIDC Token Theft | [T1199.A002](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1199.A002.html) | Threat actor steals OIDC tokens from compromised app/workstation | AssumeRoleWithWebIdentity from unusual source |
| Provider Manipulation | [T1484.002](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1484.002.html) | Threat actor creates/modifies SAML provider in AWS to trust their own IdP | CreateSAMLProvider / UpdateSAMLProvider events |
| Credential Persistence via Federation | [T1098.001](https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1098.001.html) | Threat actor uses `sts:GetFederationToken` to create credentials that survive key deactivation | GetFederationToken from compromised principal |

---

## Revision History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | 2026-05-28 | AWS CIRT | Initial release |
| 2.0 | 2026-06-25 | AWS CIRT | Full rewrite: aligned with PR2 template conventions, American spelling, separated eradicate/recover phases, moved Athena queries to resources folder, added workshop references and TTC metrics, added Well-Architected references, removed FUD language |
