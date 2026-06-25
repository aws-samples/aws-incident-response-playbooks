# IRP-AgentCoreIdentityCompromise: Amazon Bedrock AgentCore Identity & Credential Compromise

> **Playbook Version:** 1.0
> **Last Reviewed:** 2026-06-20
> **Status:** `Draft`
> **NIST Framework:** SP 800-61r3 (CSF 2.0 Community Profile)
> **Related Playbooks:** [IRP-AgentCoreAuthorizationBypass](IRP-AgentCoreAuthorizationBypass.md) | [IRP-AgentCoreAgentIntegrity](IRP-AgentCoreAgentIntegrity.md) | [IRP-AgentCoreToolAbuse](IRP-AgentCoreToolAbuse.md) | [IRP-AgentCoreObservabilityTampering](IRP-AgentCoreObservabilityTampering.md)

---

> ⚠️ **Disclaimer:** This playbook is provided as a template only. It should be customized to suit your organization's specific needs, risks, available tools, and work processes. This guide is not official AWS documentation and is provided as-is. Security and Compliance is a shared responsibility between you and AWS. You are responsible for making your own independent assessment of the information in this document.

---

## Overview

Amazon Bedrock AgentCore Identity & Credential Compromise covers the theft or misuse of any identity that grants access to AgentCore resources: a stolen Amazon Cognito JWT, a stolen confidential Cognito User-Pool App Client secret (the "machine client" used in the OAuth2 client-credentials flow), a hijacked AgentCore workload-identity session, or theft of credentials held in the AgentCore Token Vault (OAuth2 access and refresh tokens, or API keys vended through credential providers). In AWS environments it typically manifests as AgentCore API calls (`bedrock-agentcore.amazonaws.com`) from an unexpected principal, IP, or user agent; a spike in token-vending calls (`GetResourceOauth2Token`, `GetResourceApiKey`, `GetWorkloadAccessToken*`); Cognito authentication anomalies; or a third-party OAuth provider reporting anomalous API use by a client tied to an AgentCore credential provider. It matters because agents act autonomously — a single compromised credential lets an attacker mint additional persistent credentials, harvest secrets from the Token Vault, and act against external services using tokens that remain valid at those services even after the AgentCore-side credential is revoked.

### Out of Scope

This playbook does **not** cover:

- IAM access-key or console-credential theft with **no** AgentCore resource in the blast radius — use your general credential-compromise playbook.
- STS `AssumeRole` chain abuse with no AgentCore principal involved — use your STS / role-abuse playbook.
- Authorization bypass that does **not** begin with credential theft (for example, a Cedar `ENFORCE` → `LOG_ONLY` flip or a rogue Gateway target by an already-authorized insider) — see [IRP-AgentCoreAuthorizationBypass](IRP-AgentCoreAuthorizationBypass.md).
- A compromise that began here but has pivoted to cloud-native ransomware (EBS/S3/KMS) — contain credentials here first, then pivot to your ransomware playbook.

### Applicable Finding Types

List the detection signals that should route a responder to this playbook.

| Source | Finding / Event Type | Severity |
|---|---|---|
| Amazon GuardDuty | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` referencing an AgentCore execution role / workload identity | HIGH |
| Amazon GuardDuty | `CredentialAccess:IAMUser/AnomalousBehavior`, `Discovery:IAMUser/AnomalousBehavior`, `Impact:IAMUser/AnomalousBehavior` on an AgentCore principal | HIGH |
| AWS Security Hub | Aggregated finding referencing an AgentCore workload-identity or credential-provider resource ARN | CRITICAL / HIGH |
| CloudTrail | `CreateWorkloadIdentity`, `CreateOauth2CredentialProvider`, `CreateApiKeyCredentialProvider`, or `SetTokenVaultCMK` from an unexpected principal | — |
| CloudTrail | `InitiateAuth` / `AdminInitiateAuth` / `RespondToAuthChallenge` from an unexpected source IP; `AdminSetUserPassword`, `ConfirmForgotPassword` during an incident window | — |
| CloudWatch | Alarm on `GetResourceOauth2Token` / `GetResourceApiKey` / `GetWorkloadAccessToken*` volume deviation per principal | — |
| Custom / Third-Party | External OAuth provider (GitHub, Salesforce, Slack, Okta, Microsoft Entra) reports anomalous API use by the client tied to an AgentCore credential provider | — |

> 📌 GuardDuty finding types are updated regularly. See the [GuardDuty finding types reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) for the current list. GuardDuty does not currently emit AgentCore-specific findings; the IAM findings above frequently correlate with AgentCore credential compromise.

### Severity Classification

Use this table to determine incident priority at time of detection. Escalate immediately if P1 criteria are met.

| Priority | Criteria |
|---|---|
| **P1 — Critical** (≤15 min) | Token Vault contents accessed or re-keyed (`SetTokenVaultCMK`); active exfiltration via tokens vended from the Token Vault; confirmed use of stolen credentials against external services; cross-account role assumption via an injected trust policy |
| **P2 — High** (≤1 hr) | Confirmed credential theft but blast radius contained; rogue workload identity or credential provider created; unusual but bounded OAuth2 / API-key token retrieval |
| **P3 — Medium** (≤4 hr) | Anomalous authentication or token-vending activity, no confirmed impact yet; failed-authentication spikes (possible credential stuffing) |
| **P4 — Low** (≤1 day) | Identity-configuration drift without exploitation; policy violation with no active threat |

> **P1 override:** regardless of the matrix, treat as P1 if Token Vault contents were accessed or re-keyed via `SetTokenVaultCMK`, or if a resource-based policy granting access outside your AWS Organization was added during the window.

---

## Part 1 — Prepare

> **CSF 2.0 Functions:** Govern · Identify · Protect
> **Goal:** Ensure the right configurations, access, and processes are in place *before* this incident type occurs.

Responding to AgentCore identity compromise requires preparation that anticipates autonomous, machine-to-machine credential use. Controls that assume a human in the loop (IP allow-lists, MFA at each action) do not map cleanly to workload identities and machine clients, so detection and revocation paths must be pre-built and tested before an incident.

### 1.1 Required AWS Service Configurations

Confirm the following are enabled and configured in all accounts and regions where AgentCore is deployed before an incident occurs.

- [ ] AWS CloudTrail enabled with a multi-region trail, log-file validation, delivered to an S3 bucket in a dedicated security account whose bucket policy prevents the workload account from deleting log files
- [ ] Amazon GuardDuty enabled (with Runtime Monitoring) and findings exported to AWS Security Hub
- [ ] AWS Security Hub enabled with the Foundational Security Best Practices standard
- [ ] AWS Config enabled with a delivery channel and rules for IAM, KMS, and CloudTrail compliance
- [ ] CloudWatch alarms on token-vending volume per principal (`GetResourceOauth2Token`, `GetResourceApiKey`, `GetWorkloadAccessToken`, `GetWorkloadAccessTokenForJWT`, `GetWorkloadAccessTokenForUserId`) and on high-risk identity APIs (`CreateWorkloadIdentity`, `CreateOauth2CredentialProvider`, `CreateApiKeyCredentialProvider`, `SetTokenVaultCMK`); SNS subscriptions confirmed
- [ ] Cognito advanced security features enabled (adaptive authentication, compromised-credentials detection) on user pools fronting AgentCore
- [ ] A maintained, diffable baseline inventory of every workload identity, OAuth2 / API-key credential provider, Cognito App Client, and the Token Vault CMK ARN, so drift is detectable
- [ ] S3 Versioning plus S3 Object Lock (COMPLIANCE mode) on the forensic bucket used to preserve evidence

> 🤖 **Automation opportunity:** Use AWS Config conformance packs or Security Hub standards to continuously validate these prerequisites, and an EventBridge rule on `SetTokenVaultCMK` that pages the security team on any CMK change. [Link TBD]

### 1.2 IAM & Access Prerequisites

Ensure the following access is pre-provisioned and tested — *do not provision break-glass access during an active incident*.

- [ ] Break-glass IAM role with least-privilege IR permissions (Cognito disable/sign-out, `bedrock-agentcore:Delete*` and `bedrock-agentcore:List*`, KMS key management, CloudTrail read) exists and is documented
- [ ] IR team members can assume the break-glass role with MFA
- [ ] Access to the AWS Security Incident Response console (if subscribed) is confirmed
- [ ] Forensic account (isolated) is available for evidence preservation
- [ ] IAM Permissions Boundaries applied to any team that creates or modifies AgentCore identity resources; every AgentCore execution-role trust policy carries `aws:SourceAccount` and `aws:SourceArn` confused-deputy guards
- [ ] Cognito authenticated roles scoped to specific runtime ARNs rather than wildcards; `iam:PassRole` scoped to `arn:aws:iam::*:role/agentcore-runtime-*` with `iam:PassedToService == bedrock-agentcore.amazonaws.com`

### 1.3 Communication & Escalation

> 📋 Do not include names. Use roles only. Maintain a separate, access-controlled contact list.

| Role | Responsibility |
|---|---|
| IR Lead | Overall incident coordination, status updates |
| Account / Agent Owner | Business context, authorization for containment that may disrupt the agent |
| AI/ML Platform team | AgentCore Identity configuration, IaC known-good baseline, redeploy |
| Legal / Compliance | Regulatory notification obligations, evidence hold |
| Communications | Internal and external messaging |
| External Provider Liaison | Files token-revocation and audit-log requests at external OAuth providers (GitHub, Okta, Entra, Google Workspace, Salesforce, Slack) |
| AWS CIRT | Engage via AWS Support case or Security Incident Response service (P1/P2, if available) |

**Escalation path:**
Detection → IR Lead notified → Severity assessed → P1/P2: AWS CIRT engaged, Legal notified, external-provider revocation initiated → P3/P4: IR Lead manages internally

### 1.4 Game Day Guidance

This playbook should be exercised before it is needed. Recommended testing cadence: **annually at minimum, semi-annually for P1 scenarios.**

Suggested tabletop scenario for this incident type:
> "At 02:00 UTC a workload identity that did not exist an hour ago begins issuing a burst of `GetResourceOauth2Token` calls from a single external IP, and a confidential Cognito App Client shows a rising rate of `RespondToAuthChallenge`. Walk the team from detection, through distinguishing a stolen JWT from a machine-client secret compromise, to Token-Vault and external-provider revocation — including who files the GitHub/Okta audit-log request and how the credential chain is walked to closure."

Reference: [AWS Security Incident Response Game Days](https://docs.aws.amazon.com/security-ir/latest/userguide/game-days.html)

---

## Part 2 — Detect & Analyze

> **CSF 2.0 Functions:** Detect · Respond (Analyze)
> **Goal:** Confirm whether an incident has occurred, scope its impact, and gather evidence for containment and investigation.

### 2.1 Initial Triage Questions

Answer these quickly to determine scope and priority. Each question should take < 2 minutes to answer.

- [ ] Is this a confirmed incident or an anomalous finding requiring investigation?
- [ ] Which AWS accounts and regions are potentially affected?
- [ ] Are production agents or sensitive Token-Vault / Memory data involved?
- [ ] Is the threat actor potentially still active (new principals appearing, token-vending continuing)?
- [ ] Have tokens vended from the Token Vault been used against external services (data may have left the environment)?
- [ ] Which compromise vector is in play — IAM key, Cognito JWT, machine-client secret, workload-identity session, or external OAuth2/API-key token? (Each has a different revocation path.)
- [ ] Are there downstream customers, partners, or regulatory implications?

**If 3 or more questions are answered YES → escalate to P1 immediately** and proceed to evidence preservation before completing full analysis.

### 2.2 Evidence Collection Checklist

Collect and preserve the following **before taking any containment actions**. Evidence collected after containment may be incomplete or altered.

> ⚠️ **Do not delete workload identities, credential providers, or Cognito App Clients before snapshotting their configuration and capturing the CloudTrail window — once deleted, the AgentCore-side state is unrecoverable for forensics.**

| Evidence Type | How to Collect | Where to Store |
|---|---|---|
| CloudTrail logs (incident window) | AWS Console / Athena / Logs Insights / CLI; copy before any selector tampering | Forensic S3 bucket (Object Lock) |
| GuardDuty / Security Hub finding JSON | Console → Export | Forensic S3 bucket |
| Workload-identity / credential-provider config snapshots | `aws bedrock-agentcore-control get-workload-identity` / `get-oauth2-credential-provider` / `get-api-key-credential-provider` | Forensic S3 bucket |
| Token Vault CMK configuration | `aws bedrock-agentcore-control get-token-vault --token-vault-id default` | Forensic S3 bucket |
| IAM credential last-used data | `aws iam generate-credential-report` first (run once; wait ~5s for `COMPLETE`), then `aws iam get-credential-report` — calling `get` before a report exists returns `ReportNotPresent` | IR ticket / notes |
| External OAuth provider audit logs | Provider admin portal / API (see Appendix A table) | Forensic S3 bucket |

**Investigation and scoping steps for this scenario:**

1. **Build the primary timeline.** Pull every AgentCore API call made by the suspect principal during the incident window — the blast radius of a credential compromise is bounded by what that principal's credentials can reach. Preserve the output to the forensic bucket; it seeds the credential-chain analysis. (See Appendix A for the literal-ARN caveat — Logs Insights does not interpolate shell variables.)

2. **Identify credential-issuance operations.** An attacker who compromises one credential typically uses it to create additional persistent credentials — a new IAM role/key, a new workload identity, a new OAuth2 or API-key credential provider, or a Token Vault re-key. Each created credential is a separate investigation thread; do not assume that revoking the initial credential stops the attacker. The relevant event names are `CreateAccessKey`, `CreateRole`, `CreateUser`, `AssumeRole`, `GetFederationToken`, `CreateWorkloadIdentity`, `CreateOauth2CredentialProvider`, `CreateApiKeyCredentialProvider`, and `SetTokenVaultCMK` (Appendix A query).

3. **Hunt token-vending anomalies.** Spikes in `GetWorkloadAccessToken*`, `GetResourceOauth2Token`, or `GetResourceApiKey` volume, unexpected source IPs, or calls against credential providers the principal does not normally use indicate a compromised credential harvesting secondary credentials from the Token Vault. Treat unusual `GetResourceOauth2Token` / `GetResourceApiKey` volume as evidence that external services may already be compromised through tokens vended before you discovered the incident.

4. **Analyze Cognito authentication.** A stolen JWT replay shows as `REFRESH_TOKEN_AUTH` calls with no preceding `InitiateAuth`. A machine-client secret compromise shows as a high-rate `InitiateAuth` / `RespondToAuthChallenge` pair (client-credentials flow) against a single confidential App Client. Credential stuffing shows as many `InitiateAuth` calls returning `UserNotFoundException` / `NotAuthorizedException` across many usernames from one IP. Also pull `ForgotPassword`, `ConfirmForgotPassword`, `AdminSetUserPassword`, `SignUp`, `ConfirmSignUp`, `AdminRespondToAuthChallenge`, `AdminAddUserToGroup`, `CreateUserPoolClient`, and `UpdateUserPoolClient` during the window — each is a distinct persistence mechanism that survives JWT revocation and global sign-out (Appendix A queries).

5. **Review GuardDuty IAM findings** for the suspect principal — `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`, `CredentialAccess:IAMUser/AnomalousBehavior`, `Discovery:IAMUser/AnomalousBehavior`, or `Impact:IAMUser/AnomalousBehavior` frequently correlate with AgentCore credential compromise. Filter by resource ARNs containing `bedrock-agentcore` or by the suspect principal ARN.

6. **Extract the compromised identity.** From the CloudTrail events, pull `userIdentity.type`, `userIdentity.arn`, `userIdentity.accessKeyId`, `userIdentity.sessionContext.sessionIssuer.arn`, and `sourceIPAddress`. These five fields determine the revocation path, which downstream IAM trust relationships may be affected, and whether the compromise originated inside or outside AWS. Record them in the incident ticket before containment.

7. **Determine the compromise vector**, because the revocation path differs by vector:
   - IAM long-term key → revoked at IAM
   - Cognito JWT → `admin-user-global-sign-out`
   - Machine-client secret → delete the confidential Cognito App Client
   - Workload-identity session → delete the workload identity
   - External OAuth2 token → revoked at the external provider itself
   Confirm the vector by checking, for each candidate, whether the `userIdentity.accessKeyId` or source IP matches a known-good team member or automated process; if not, that vector is the likely entry point.

8. **Build the credential chain.** For every credential-issuance event from step 2, re-run the full CloudTrail timeline against the newly created principal. Iterate until no new principals appear. The resulting tree is your eradication checklist — any node left untouched is a re-entry path. A worked example:

   ```text
   CompromisedPrincipal
   ├── CreateWorkloadIdentity → wi-attacker
   │     └── GetWorkloadAccessToken (used from <IP>)
   ├── CreateOauth2CredentialProvider → provider-exfil
   │     └── GetResourceOauth2Token → <external auth server URL>
   ├── SetTokenVaultCMK → attacker-controlled KMS key
   └── AssumeRole → RuntimeExecutionRole (via modified trust policy)
   ```

9. **Scope the external blast radius.** List every Token Vault secret retrievable by the compromised principal (from the `GetResourceOauth2Token` / `GetResourceApiKey` calls), then for each credential provider look up its `authorizationServerUrl` — that is the external service where tokens are active and remain active until revoked there. Enumerate cross-account resources reachable via any assumed roles in the chain; a cross-account path means a second IR process may need to start in the other account. Request the provider-side audit log for each compromised provider (Appendix A table) — it is the only source of truth for what was read, written, or escalated at the external service during the exposure window.

10. **Assess impersonation flows and non-OAuth credential types.** AgentCore Identity supports an impersonation pattern where agents act on behalf of users via the SDK's `@requires_access_token` and `@requires_api_key` annotations. When the impersonated user is compromised, every agent calling such a function acts with that user's identity at the resource server — the blast radius includes every downstream service accessed through decorated code during the window. AgentCore Identity also supports client certificates, SAML assertions, and custom tokens in credential providers; SAML requires IdP-side session revocation and client certificates require CA-level revocation (CRL/OCSP). Enumerate every credential provider's type and route each to the correct revocation path.

### 2.3 Severity Determination

Based on triage and initial evidence, assign a priority using the criteria in [Severity Classification](#severity-classification), and apply the P1 override.

| Confirmed? | Priority Assignment |
|---|---|
| Token Vault accessed/re-keyed, or active threat actor minting credentials / using external tokens | P1 |
| Confirmed credential theft, blast radius contained, actor no longer active | P2 |
| Suspicious authentication or token-vending activity, scope unclear | P3 |
| Identity-configuration drift, no active threat | P4 |

### 2.4 Getting Help from AWS

For P1 or P2 incidents, consider engaging AWS for additional support:

- **AWS Security Incident Response service** (if enabled): Open a case via the [Security Incident Response console](https://console.aws.amazon.com/security-ir/), attach relevant findings, and grant AWS CIRT access to the affected account(s).
- **AWS Support** (any AWS Support plan): Open a support case with severity "Critical" or "Urgent" and request assistance from the AWS Customer Incident Response Team (CIRT).
- **AWS Trust & Safety** (for abuse reports): If AgentCore resources are being used to attack others, report via the [AWS abuse form](https://support.aws.amazon.com/#/contacts/report-abuse).

> 📌 You do not need the AWS Security Incident Response service to get help. All AWS customers can request CIRT assistance through a support case, regardless of support plan level. The Security Incident Response service provides additional automation, case management, and proactive triage capabilities.

---

## Part 3 — Contain

> **CSF 2.0 Function:** Respond (Contain)
> **Goal:** Stop the spread of the incident and prevent further damage without destroying evidence.

### 3.1 Containment Decision

Before acting, consider the tradeoff:

```text
Is containment action required immediately?
│
├── YES (active token-vending / external token use / credential minting)
│     └── Proceed to 3.2 — accept potential agent disruption
│
└── NO (threat appears inactive)
      └── Consult Account/Agent Owner and IR Lead before proceeding
            Can we contain without disrupting a production agent?
            ├── YES → Proceed to 3.2
            └── NO  → Document business impact, obtain authorization, then proceed
```

### 3.2 Containment Actions

> `[IR Lead]` coordinates. `[Account/Agent Owner]` authorizes actions that may cause service disruption.

**Step-by-step containment for this incident type:**

1. **Revoke active IAM sessions for the compromised principal.**
   Attach an inline deny policy conditioned on `aws:TokenIssueTime` less than the current timestamp. This invalidates every session issued before now without affecting future sessions, so legitimate automation can resume cleanly after credentials are rotated.

   ```bash
   REVOKE_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
   cat > /tmp/revoke-sessions.json <<EOF
   {"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",
    "Condition":{"DateLessThan":{"aws:TokenIssueTime":"$REVOKE_TIME"}}}]}
   EOF
   aws iam put-role-policy --role-name <ROLE_NAME> \
     --policy-name RevokeOldSessions-<INCIDENT_ID> \
     --policy-document file:///tmp/revoke-sessions.json
   ```

2. **Disable the compromised Cognito user and force a global sign-out.**
   Disabling prevents future authentication; the global sign-out invalidates existing refresh tokens so the attacker cannot obtain a new access token after the current one expires.

   ```bash
   aws cognito-idp admin-disable-user --user-pool-id <USER_POOL_ID> --username <user>
   aws cognito-idp admin-user-global-sign-out --user-pool-id <USER_POOL_ID> --username <user>
   # Verify containment landed (expect Enabled=false):
   aws cognito-idp admin-get-user --user-pool-id <USER_POOL_ID> --username <user> \
     --query '{Username:Username,Enabled:Enabled,Status:UserStatus}' --output table
   ```

   If Part 2 step 4 surfaced a `CreateUserPoolClient`/`UpdateUserPoolClient` or an injected **pre/post-authentication Lambda trigger** during the window, detach the trigger now — disabling the user and global sign-out do **not** stop a malicious trigger from minting tokens or exfiltrating auth events on subsequent logins by other users. Snapshot the current `LambdaConfig` to the forensic bucket first (it is evidence), then clear the suspect trigger(s); full removal/forensics of the Lambda itself happens in eradication (§4.2).

   ```bash
   aws cognito-idp describe-user-pool --user-pool-id <USER_POOL_ID> --query 'UserPool.LambdaConfig' > forensic/cognito-lambda-config.json
   aws cognito-idp update-user-pool --user-pool-id <USER_POOL_ID> --lambda-config '{}'  # or re-submit with only the known-good triggers
   ```

3. **Rotate a compromised machine client by deleting the confidential Cognito App Client.**
   AgentCore has no standalone machine-client API — what AgentCore literature calls a "machine client" is a confidential Cognito User-Pool App Client (one with a `ClientSecret`) used in the OAuth2 `client_credentials` flow. Deleting it immediately invalidates every token issued with it. Redeploy the client from IaC to recreate it with a fresh secret.

   ```bash
   aws cognito-idp list-user-pool-clients --user-pool-id <USER_POOL_ID> --max-results 60
   aws cognito-idp delete-user-pool-client --user-pool-id <USER_POOL_ID> --client-id <CID>
   ```

4. **Delete every rogue workload identity created by the suspect principal.**
   Workload identities vend scoped credentials to agents and MCP servers, so an attacker-created workload identity is an ongoing credential-minting path that must be removed even after the parent credential is revoked. The delete parameter is `--name`, not `--workload-identity-id`.

   > **Paginate.** The `list-*` commands in this step (and `list-user-pool-clients` above) cap each page at `--max-results`; an account with more resources than the page size returns a `nextToken` you must follow, or you will miss attacker-created identities. Loop until the token is empty, e.g.: `T=""; while :; do OUT=$(aws bedrock-agentcore-control list-workload-identities --max-results 20 ${T:+--next-token "$T"}); echo "$OUT" | jq -r '.workloadIdentities[].name'; T=$(echo "$OUT" | jq -r '.nextToken // empty'); [ -z "$T" ] && break; done`

   ```bash
   aws bedrock-agentcore-control list-workload-identities --max-results 20
   aws bedrock-agentcore-control delete-workload-identity --name <WORKLOAD_IDENTITY_NAME>
   ```

5. **Delete compromised OAuth2 and API-key credential providers.**
   These are two separate APIs — OAuth2 providers hold access/refresh tokens for external services; API-key providers hold static keys — and both are identified by a `--name` string, not an ARN. Deletion invalidates the AgentCore-side credential store so subsequent `GetResourceOauth2Token` / `GetResourceApiKey` calls fail.

   ```bash
   aws bedrock-agentcore-control list-oauth2-credential-providers --max-results 20
   aws bedrock-agentcore-control delete-oauth2-credential-provider --name <OAUTH_PROVIDER_NAME>

   aws bedrock-agentcore-control list-api-key-credential-providers --max-results 20
   aws bedrock-agentcore-control delete-api-key-credential-provider --name <name>
   ```

6. **Revoke tokens at every external OAuth provider whose credential provider was compromised.**
   AgentCore deletions only affect the AgentCore-side copy. Tokens already issued to external services (GitHub, Salesforce, Slack, Splunk, Google Workspace, Okta, Microsoft Entra) remain valid at those services until they expire naturally — typically one to twenty-four hours, longer if the attacker captured refresh tokens. This is a manual step at each provider's admin console; the revocation surfaces are listed in Appendix A.

7. **Block the malicious source IP at the WAF (if the data plane is fronted by one).**
   Blocking at the WAF stops further authentication attempts from the same source without affecting legitimate users.

   ```bash
   aws wafv2 create-ip-set --name "AgentCore-IR-Block-<INCIDENT_ID>" \
     --scope REGIONAL --ip-address-version IPV4 \
     --addresses "<SUSPECT_IP>/32"
   ```

8. **Escalate to broader containment if scope widens (kill-switch option).**
   If new principals keep appearing during your investigation, new workload identities are created after you start revoking, or Token Vault activity predates your earliest timeline entry, the attacker likely retains the ability to re-create credentials. The AgentCore emergency kill switch severs every authorization path across six sequential phases — (1) block new API calls via an emergency SCP denying `bedrock-agentcore:*` (the single AgentCore IAM prefix, covering control and data plane) plus a deny-all-except-CloudWatch-Logs permissions boundary on every `agentcore` IAM role; (2) sever authentication by disabling all Cognito users, global sign-out, deleting confidential App Clients, workload identities, and all credential providers; (3) sever authorization by forcing every Gateway to Cedar `ENFORCE` and applying a deny-all policy; (4) sever tool access by deleting Gateway targets and resource-based policies; (5) sever network and active sessions; (6) prevent recreation by neutralizing `agentcore` SSM parameters and EventBridge rules. It terminates all agentic workflows — legitimate and compromised — so obtain explicit written authorization and run a pre-execution blast-radius assessment first. As a less drastic alternative, apply an emergency Organizations SCP scoping `bedrock-agentcore:CreateWorkloadIdentity`, `CreateOauth2CredentialProvider`, `CreateApiKeyCredentialProvider`, and `SetTokenVaultCMK` to the IR role only.

> 🤖 **Automation opportunity:** AWS Systems Manager Automation runbook for Cognito user disablement + global sign-out, keyed on a security-team playbook invocation; EventBridge rule on `SetTokenVaultCMK` that pages the security team. [Link TBD]

### 3.3 Evidence Preservation Reminders

After containment begins, ensure the following before modifying or terminating any resources:

- [ ] Workload-identity, credential-provider, and Token Vault CMK configurations snapshotted **before** deletion or re-key
- [ ] **Old Token Vault CMK left enabled (not disabled or scheduled for deletion) until forensic analysis of any captured Token Vault ciphertext completes.** If the attacker exfiltrated Token Vault contents during the window, the old CMK is the only key that decrypts that ciphertext — do not disable/schedule-delete it in eradication (§4.2 step 4) until §5.1 timeline reconstruction confirms no further decryption is needed
- [ ] All relevant CloudTrail logs exported to the forensic S3 bucket and integrity-validated
- [ ] External OAuth provider audit-log requests filed for the exposure window
- [ ] S3 Object Lock or legal hold applied to the forensic bucket
- [ ] CloudTrail integrity validation confirmed on exported logs

---

## Part 4 — Eradicate & Recover

> **CSF 2.0 Function:** Respond (Eradicate) · Recover
> **Goal:** Remove the root cause, validate the environment is clean, and restore normal operations.

### 4.1 Root Cause Identification

> `[IR Lead]` owns this step. Document findings in the IR ticket in real time.

Determine the root cause before beginning eradication. Common root causes for this incident type:

- Hard-coded credentials (an IAM key, a Cognito App Client secret, or an OAuth client secret) committed to a public or shared code repository
- Phishing of a developer who held a credential, or a stolen developer laptop / browser session
- Exposed CI/CD secrets (pipeline variables, build logs) holding an App Client secret or workload-identity bootstrap material
- Server-side request forgery from a Code Interpreter or Browser session harvesting instance-metadata credentials
- An over-broad execution or developer IAM role, scoped-too-broadly `iam:PassRole`, or a missing `aws:SourceAccount` / `aws:SourceArn` confused-deputy guard on an AgentCore trust policy

Use evidence collected in Part 2 to trace the initial access vector and full attack path.

### 4.2 Eradication Actions

> `[IR Lead]` coordinates. `[Account/Agent Owner]` approves changes to production resources.

1. **Walk every node in the credential chain from Part 2** and confirm each credential is deleted or rotated. Do not assume initial containment covered the whole tree — a missed workload identity or OAuth provider is a persistence path.

2. **Audit every AgentCore execution-role trust policy for injected principals.**
   An attacker who adds their own account as a trusted assumer keeps access even after the initial credential is revoked. Compare each trust policy against the IaC baseline; any principal not in the baseline is suspect.

   ```bash
   for ROLE in $(aws iam list-roles \
     --query "Roles[?contains(RoleName,'agentcore') || contains(RoleName,'AgentCore')].RoleName" \
     --output text); do
     aws iam get-role --role-name "$ROLE" --query "Role.AssumeRolePolicyDocument" --output json \
       > /tmp/ir/<INCIDENT_ID>/trust-$ROLE.json
   done
   ```

3. **Remove inline IAM policies added to AgentCore roles during the window.**
   Inline policies are a common persistence mechanism because they attach directly to the role and survive an audit that only checks attached managed policies.

   ```bash
   aws iam list-role-policies --role-name <ROLE>
   aws iam delete-role-policy --role-name <ROLE> --policy-name <PlantedPolicy>
   ```

4. **Rotate the Token Vault CMK if the encryption material may be exposed.**
   Point the Token Vault at a new CMK with `SetTokenVaultCMK`, then disable (do not yet delete) the old CMK. Do not schedule deletion of the old CMK until every OAuth2 / API-key token encrypted under it has been re-encrypted or rotated externally — otherwise old tokens become undecryptable and may be needed for forensics. There is one Token Vault per account per region, identified as `default`.

   ```bash
   aws bedrock-agentcore-control get-token-vault --token-vault-id default

   NEW_KEY_ARN=$(aws kms create-key \
     --description "AgentCore Token Vault CMK - IR rotation <INCIDENT_ID>" \
     --query "KeyMetadata.Arn" --output text)

   aws bedrock-agentcore-control set-token-vault-cmk \
     --token-vault-id default \
     --kms-configuration "{\"keyType\":\"CustomerManagedKey\",\"kmsKeyArn\":\"$NEW_KEY_ARN\"}"

   aws kms disable-key --key-id <OLD_KEY_ARN>
   aws kms schedule-key-deletion --key-id <OLD_KEY_ARN> --pending-window-in-days 7
   ```

5. **Remove attacker persistence mechanisms.** Check for and remove:
   - [ ] Unauthorized IAM users, roles, or access keys created during the incident (delete with `aws iam delete-access-key` / `aws iam delete-user`)
   - [ ] Unauthorized workload identities, OAuth2 / API-key credential providers, or Cognito App Clients not in the baseline
   - [ ] Modified SCPs, resource-based policies, or trust relationships granting cross-account access
   - [ ] Cognito pre/post-authentication Lambda triggers added to the user pool, and attacker-created users left in the pool
   - [ ] EventBridge rules wired to re-create deleted identity resources, or SSM/Step Functions automation tied to AgentCore lifecycle events

> 🤖 **Automation opportunity:** AWS Config auto-remediation can flag and revert AgentCore trust policies missing `aws:SourceAccount` / `aws:SourceArn` guards. [Link TBD]

### 4.3 Recovery Actions

1. **Restore from known-good state.**
   Redeploy Cognito user pools, App Clients, workload identities, and credential providers from the last known-good IaC commit. Pin to the commit hash rather than the latest branch tip so you restore a version that predates the compromise.

2. **Re-enable services and access.**
   - [ ] Re-configure every external OAuth provider with new client secrets from the redeployed stack (the mirror of containment step 6 — containment revoked old tokens, recovery issues new ones)
   - [ ] Re-issue OAuth2 / API-key credentials at the external providers so agents can resume work with external services
   - [ ] Re-enable disabled Cognito users individually after confirming each account is legitimate (bulk re-enablement risks restoring an attacker-created account)
   - [ ] Validate application functionality with end-to-end smoke tests on each affected runtime and gateway

3. **Harden against recurrence.**
   - [ ] Add SCP guardrails denying `bedrock-agentcore:CreateWorkloadIdentity`, `CreateOauth2CredentialProvider`, `CreateApiKeyCredentialProvider`, and `SetTokenVaultCMK` to everyone except specific CI/CD or security-admin roles
   - [ ] Add a CloudWatch alarm on `GetResourceOauth2Token` / `GetResourceApiKey` volume deviation per principal, with thresholds based on each principal's observed baseline
   - [ ] Add an AWS Config rule flagging any AgentCore execution-role trust policy missing `aws:SourceAccount` / `aws:SourceArn` confused-deputy conditions
   - [ ] Move every credential out of code/CI into Secrets Manager or Parameter Store and rotate on a schedule

### 4.4 Recovery Validation

Confirm the environment is clean before declaring the incident resolved.

- [ ] No unauthorized workload identities, credential providers, Cognito App Clients, IAM principals, or resource policies remain
- [ ] All credentials created or used by the attacker have been revoked; Token Vault CMK rotated if exposed
- [ ] All external OAuth provider tokens for compromised providers revoked and re-issued
- [ ] GuardDuty / Security Hub show no active findings related to this incident
- [ ] CloudTrail monitored for 48 hours post-recovery shows no `InitiateAuth`, `AdminInitiateAuth`, `GetWorkloadAccessToken*`, `GetResourceOauth2Token`, `GetResourceApiKey`, or `SetTokenVaultCMK` from unexpected IPs or principals
- [ ] Agent health metrics and application functionality within normal range
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
| YYYY-MM-DD HH:MM | Credential leaked / earliest anomalous authentication | CloudTrail / GuardDuty `eventFirstSeen` | Threat actor |
| YYYY-MM-DD HH:MM | Token-vending or credential-minting anomaly detected | CloudWatch alarm / GuardDuty | AWS / monitoring |
| YYYY-MM-DD HH:MM | IR team notified | On-call alert | IR Lead |
| YYYY-MM-DD HH:MM | Credentials revoked / containment completed | IR ticket | IR Lead |
| YYYY-MM-DD HH:MM | Recovery validated | IR ticket | IR Lead |

**Key metrics to capture:**

| Metric | Value |
|---|---|
| Time to Detect (TTD) | *HH:MM from initial event to detection* |
| Time to Notify (TTN) | *HH:MM from detection to IR team notified* |
| Time to Contain (TTC) | *HH:MM from notification to containment* |
| Time to Recover (TTR) | *HH:MM from containment to recovery validated* |
| Total Incident Duration | *HH:MM* |
| Affected Resources | *Count and type (workload identities, providers, App Clients, external services)* |
| Data Impact | *Confirmed / Suspected / None* |

### 5.2 Post-Incident Review

Conduct a blameless post-incident review within **5 business days** for P1/P2, **15 business days** for P3/P4.

Discussion questions:

1. What was the initial access vector? Could it have been prevented with existing controls (secret scanning, short-lived credentials)?
2. How was the incident detected? Was token-vending anomaly detection fast enough?
3. Were the right people notified at the right time, including the external-provider liaison?
4. Did containment actions work as expected? Did revocation at AWS and at the external providers both complete?
5. Were there gaps in runbooks, automation, or tooling that slowed the credential-chain walk?
6. What would have reduced the blast radius (tighter `iam:PassRole`, SCPs on identity-creation APIs, per-principal vending baselines)?
7. What single change would most improve our response to this scenario in future?

### 5.3 Detection Gap Analysis

For each detection source that *did not* catch this incident early, document why and what would have:

| Gap | Root Cause | Recommended Fix | Owner | Target Date |
|---|---|---|---|---|
| Token Vault access not baselined | No per-principal alarm on `GetResourceOauth2Token` / `GetResourceApiKey` | Add CloudWatch anomaly alarm per principal | | |
| Rogue workload identity not alerted | No EventBridge rule on `CreateWorkloadIdentity` | Add rule paging the security team | | |
| Token Vault re-key undetected | No alarm on `SetTokenVaultCMK` | Add EventBridge rule + auto-page | | |

### 5.4 Playbook Update Checklist

Review and update this playbook based on what you learned. Do not wait for the next scheduled review.

- [ ] Were triage questions sufficient (especially the vector-identification question)? Add/remove as needed.
- [ ] Were evidence collection steps accurate for this scenario (config snapshots before deletion)?
- [ ] Were containment actions effective per vector? Update steps if not.
- [ ] Were external-provider revocation paths current? Update the Appendix A table if a provider changed its audit surface.
- [ ] Were severity criteria accurate? Adjust if incidents were under- or over-classified.
- [ ] Update **Last Reviewed** date and increment **Playbook Version**.

---

## Appendix A — Useful Queries

> **Before running any Logs Insights query below:** replace `$SUSPECT_PRINCIPAL_ARN`, `$SUSPECT_IP`, and `$USER_POOL_ID` with literal values. CloudWatch Logs Insights does **not** interpolate shell variables — a query containing `$SUSPECT_PRINCIPAL_ARN` matches that literal string and returns zero results.

### CloudTrail (Athena)

```sql
-- All AgentCore API activity by a suspect principal in the incident window
SELECT eventTime, eventName, awsRegion, sourceIPAddress, userAgent,
       errorCode, errorMessage
FROM cloudtrail_logs
WHERE userIdentity.arn = 'arn:aws:iam::123456789012:role/SUSPECTED_PRINCIPAL'
  AND eventSource = 'bedrock-agentcore.amazonaws.com'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
```

```sql
-- Token-vending volume by principal, source IP, and operation (anomaly hunt)
SELECT userIdentity.arn, sourceIPAddress, eventName, COUNT(*) AS calls
FROM cloudtrail_logs
WHERE eventName IN ('GetWorkloadAccessToken','GetWorkloadAccessTokenForJWT',
       'GetWorkloadAccessTokenForUserId','GetResourceOauth2Token','GetResourceApiKey')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
GROUP BY userIdentity.arn, sourceIPAddress, eventName
ORDER BY calls DESC;
```

### CloudWatch Logs Insights — credential-issuance (persistence) hunt

```text
fields @timestamp, eventName, userIdentity.arn, responseElements
| filter eventName in [
    "CreateAccessKey","CreateRole","CreateUser","AssumeRole","GetFederationToken",
    "CreateWorkloadIdentity","DeleteWorkloadIdentity",
    "CreateOauth2CredentialProvider","UpdateOauth2CredentialProvider","DeleteOauth2CredentialProvider",
    "CreateApiKeyCredentialProvider","UpdateApiKeyCredentialProvider","DeleteApiKeyCredentialProvider",
    "SetTokenVaultCMK"
  ]
| filter userIdentity.arn like /SUSPECTED_PRINCIPAL/
| sort @timestamp asc
```

### CloudWatch Logs Insights — Cognito authentication anomaly + persistence

```text
fields @timestamp, eventName, sourceIPAddress, userAgent, errorCode, errorMessage,
       requestParameters.authFlow, requestParameters.clientId, requestParameters.userPoolId,
       responseElements.challengeName, userIdentity.arn
| filter eventSource = "cognito-idp.amazonaws.com"
| filter sourceIPAddress = "SUSPECT_IP" or requestParameters.userPoolId = "USER_POOL_ID"
| sort @timestamp asc
```

```text
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress,
       requestParameters.username, requestParameters.userPoolId, requestParameters.clientId
| filter eventSource = "cognito-idp.amazonaws.com"
| filter eventName in [
    "ForgotPassword","ConfirmForgotPassword","AdminSetUserPassword","SignUp","ConfirmSignUp",
    "AdminRespondToAuthChallenge","AdminCreateUser","AdminAddUserToGroup",
    "CreateUserPoolClient","UpdateUserPoolClient","CreateIdentityProvider","UpdateIdentityProvider"
  ]
| sort @timestamp asc
```

> Auth-flow interpretation: a stolen-JWT replay shows as `REFRESH_TOKEN_AUTH` with no preceding `InitiateAuth`; a machine-client secret compromise shows as high-rate `InitiateAuth`/`RespondToAuthChallenge` (client-credentials) against one confidential App Client; credential stuffing shows as many `InitiateAuth` calls with `UserNotFoundException` / `NotAuthorizedException` across many usernames from one IP.

### Bedrock model-abuse hunt (multi-region)

An attacker who controls an AgentCore principal can call Bedrock models directly (bypassing the Gateway) for a denial-of-wallet attack, training-data extraction, or system-prompt leak. `InvokeModel`, `InvokeModelWithResponseStream`, `Converse`, and `ConverseStream` log as CloudTrail **management events** (no data-event opt-in needed). If the workload uses Cross-Region Inference (CRIS), inference routes to destination Regions within a geographic boundary, so the responder must query CloudTrail in **every** Region the profile can reach — not just the resource's home Region. Determine the routing scope first:

```bash
aws bedrock list-inference-profiles --type-equals SYSTEM_DEFINED --region "$AWS_REGION" \
  --output json \
  | jq '.inferenceProfileSummaries[] | {name: .inferenceProfileName, models: [.models[].modelArn]}'
```

Then run the `InvokeModel`-by-suspect-principal CloudTrail/Athena query (below) against each Region in the profile's routing scope.

### GuardDuty Finding Export (CLI)

```bash
# List IAM findings for a detector filtered by severity
aws guardduty list-findings \
  --detector-id DETECTOR_ID \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}' \
  --region us-east-1

# Get full finding details
aws guardduty get-findings \
  --detector-id DETECTOR_ID \
  --finding-ids FINDING_ID_1 FINDING_ID_2
```

### External OAuth provider audit-log / token-revocation surfaces

Revocation of the AgentCore-side credential does not tell you what tokens already vended did at the provider. Request the provider audit log for the window `[initial-compromise-time, now]`, scoped to the OAuth application / service-account ID AgentCore uses at the provider.

| Provider | Audit product | Scoping parameters |
|---|---|---|
| GitHub / GitHub Enterprise | Organization audit log + REST API `/orgs/{org}/audit-log` | `actor` (OAuth app slug / installation ID), `created` range |
| Okta | System Log + API `/api/v1/logs` | `actor.id` (OAuth client ID), `published` range |
| Microsoft Entra ID | Sign-in + Audit logs + Graph `auditLogs/signIns`, `auditLogs/directoryAudits` | `appId` (OAuth client ID), `activityDateTime` range |
| Google Workspace | Admin audit log + Reports API `activities.list` | `applicationName = login`/`token`, `actor.email` / `oauth_client_id`, range |
| Slack | Audit Logs API (Enterprise Grid) `/audit/v1/logs` | `actor` user/app ID, `action`, `date_range` |
| Salesforce | Setup Audit Trail + Event Monitoring | `LogFile.LogDate`, user ID / Connected App ID |
| Splunk | Internal `_audit` / `_internal` indexes | `user`, `action`, time range |
| Atlassian | Organization audit log + REST API `/admin/v1/orgs/{orgId}/events` | principal filter, `from`/`to` range |
| Custom OAuth2 provider | Provider's own audit surface (request/response, token-refresh, resource-access logs) | scoped to the compromised OAuth client ID |

---

## Appendix B — Regulatory & Compliance Considerations

> `[Legal / Compliance]` owns this section during an active incident.

See [Regulatory Context](../REGULATORY_CONTEXT.md) for the full notification obligation matrix by regulation and incident type.

**Quick reference for this scenario:** Identity & credential compromise frequently exposes Token Vault credentials for external services and may give the attacker access to Memory records (conversation content, PII) and customer-facing agent output — any of which can trigger notification obligations.

| Regulation | Trigger Condition | Timeframe |
|---|---|---|
| GDPR Art. 33 | Personal data (Memory records, conversation content) confirmed accessed via stolen credentials | 72 hours to supervisory authority from awareness |
| HIPAA Breach Notification Rule | Protected health information in Memory or downstream services accessed | Without unreasonable delay, ≤ 60 days |
| PCI-DSS | Cardholder data reachable via a compromised credential provider / external service | Per acquirer / card-brand timelines; notify immediately |
| State / sector breach-notification laws | Personal data of residents accessed; sector-specific AI-governance regimes | Jurisdiction-specific |

> ⚠️ The clock starts at **awareness**, not confirmation. When in doubt, assume notification is required and consult Legal immediately.

---

## Appendix C — Reference Links

- [NIST SP 800-61r3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html)
- [AWS Security Incident Response Service Documentation](https://docs.aws.amazon.com/security-ir/latest/userguide/what-is-security-ir.html)
- [AWS Well-Architected Framework — Security Pillar: Incident Response](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/incident-response.html)
- [Amazon Bedrock AgentCore Developer Guide](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/)
- [AWS Prescriptive Guidance — Securing generative-AI agents](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture-generative-ai/gen-auto-agents.html)
- [Amazon Cognito — Revoking Tokens](https://docs.aws.amazon.com/cognito/latest/developerguide/token-revocation.html)
- [Amazon GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [AWS CloudTrail Query Examples (Athena)](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)

---

## Revision History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | 2026-06-20 | AWS | Initial draft |
