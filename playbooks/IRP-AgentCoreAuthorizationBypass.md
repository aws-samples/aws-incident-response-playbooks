# IRP-AgentCoreAuthorizationBypass: Amazon Bedrock AgentCore Authorization Bypass (Cedar Policy Engine)

> **Playbook Version:** 1.0
> **Last Reviewed:** 2026-06-20
> **Status:** `Draft`
> **NIST Framework:** SP 800-61r3 (CSF 2.0 Community Profile)
> **Related Playbooks:** [IRP-AgentCoreIdentityCompromise](IRP-AgentCoreIdentityCompromise.md) | [IRP-AgentCoreAgentIntegrity](IRP-AgentCoreAgentIntegrity.md) | [IRP-AgentCoreToolAbuse](IRP-AgentCoreToolAbuse.md) | [IRP-AgentCoreObservabilityTampering](IRP-AgentCoreObservabilityTampering.md)

---

> ⚠️ **Disclaimer:** This playbook is provided as a template only. It should be customized to suit your organization's specific needs, risks, available tools, and work processes. This guide is not official AWS documentation and is provided as-is. Security and Compliance is a shared responsibility between you and AWS. You are responsible for making your own independent assessment of the information in this document.

---

## Overview

An **authorization bypass** in Amazon Bedrock AgentCore is the silent disabling or subversion of the Cedar Policy Engine that is supposed to authorize every agent tool call at the Gateway boundary. The signature attack is a single `UpdateGateway` call that flips the Gateway's enforcement mode from `ENFORCE` to `LOG_ONLY` — authorization decisions are still computed and logged, but no longer enforced, so every tool call is permitted while the policy infrastructure appears completely intact. Adjacent variants achieve the same effect by inserting a `permit` Cedar policy, deleting a `forbid` policy, registering a rogue Gateway target that routes tool calls to an external MCP server or a cross-account Lambda, adding a resource-based policy that grants cross-account invocation, or flipping the Gateway authorizer type to widen inbound access. This matters because AgentCore agents act autonomously: once authorization is off, a single compromised inbound identity or prompt-injection path can reach every tool, every Memory record, and every external credential the agent can touch, and the blast radius expands with each subsequent tool call until enforcement is restored.

### Out of Scope

This playbook does **not** cover:

- Theft or hijack of an inbound identity (stolen Cognito JWT, machine-client secret, or workload-identity session) where no Gateway, policy, or resource-policy object was modified — use **[IRP-AgentCoreIdentityCompromise](IRP-AgentCoreIdentityCompromise.md)**.
- Abuse of a *legitimately authorized* tool (data exfiltration through an approved Gateway target, Code Interpreter or Browser misuse) with the Policy Engine still enforcing — use **[IRP-AgentCoreToolAbuse](IRP-AgentCoreToolAbuse.md)**.
- Tampering with logging, tracing, or KMS that *hides* an authorization bypass (`StopLogging`, `DeleteLogGroup`, X-Ray sampling zeroed) — contain the authorization bypass here first, then pivot to **[IRP-AgentCoreObservabilityTampering](IRP-AgentCoreObservabilityTampering.md)** to restore visibility.
- Poisoned Runtime artifacts (S3 ZIP or ECR image) loaded at the next cold start — use **[IRP-AgentCoreAgentIntegrity](IRP-AgentCoreAgentIntegrity.md)**.
- A compromise that has pivoted to cloud-native ransomware (EBS/S3/KMS) — contain here first, then pivot to your ransomware playbook.

### Applicable Finding Types

List the detection signals that should route a responder to this playbook. GuardDuty finding types are updated regularly — re-verify against the current reference.

| Source | Finding / Event Type | Severity |
|---|---|---|
| CloudTrail | `UpdateGateway` with `requestParameters.policyEngineConfiguration.mode = LOG_ONLY` on a production gateway | — (treat as P1) |
| CloudTrail | `CreateGatewayTarget` / `UpdateGatewayTarget` to a non-account Lambda ARN or a non-`*.amazonaws.com` URL | — |
| CloudTrail | `PutResourcePolicy` referencing an AWS account outside your Organization, on a Runtime / Endpoint / Gateway / Memory | — (treat as P1) |
| CloudTrail | `UpdateGateway` with a changed `authorizerType` (for example `CUSTOM_JWT` → `AWS_IAM`) | — |
| CloudTrail | `CreatePolicy` whose `requestParameters.definition` Cedar statement begins with `permit(`, or `DeletePolicy` on a known `forbid` policy | — |
| Amazon GuardDuty | `Discovery:IAMUser/AnomalousBehavior`, `CredentialAccess:IAMUser/AnomalousBehavior` on a principal that holds `bedrock-agentcore:*` | HIGH |
| AWS Security Hub | Aggregated finding referencing an AgentCore Gateway or policy-engine resource ARN | CRITICAL/HIGH |
| Custom / Third-Party | AWS Config rule flags a Gateway in `LOG_ONLY` mode or a resource policy with an external-account principal | — |

> 📌 GuardDuty finding types are updated regularly. See the [GuardDuty finding types reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) for the current list.

### Severity Classification

Use this table to determine incident priority at time of detection. Escalate immediately if P1 criteria are met.

| Priority | Criteria (any one) |
|---|---|
| **P1 — Critical** (≤15 min) | Cedar `ENFORCE` → `LOG_ONLY` flip via `UpdateGateway` on a production gateway; resource-based policy granting access outside your AWS Organization; cross-account or external-URL Gateway target with confirmed tool traffic; active exfiltration through a rogue target |
| **P2 — High** (≤1 hr) | Rogue Gateway target created but no confirmed tool traffic; suspicious `permit` Cedar policy inserted but still under `ENFORCE`; authorizer type flipped with blast radius unclear |
| **P3 — Medium** (≤4 hr) | Anomalous-but-consistent policy or target activity; authorization-DENY spikes suggesting probing; configuration drift detected by Config with no confirmed exploitation |
| **P4 — Low** (≤1 day) | Policy or authorizer drift from IaC baseline with no active threat; informational finding |

> **P1 override:** Regardless of the matrix, treat as **P1** if Cedar enforcement mode was flipped to `LOG_ONLY` via `UpdateGateway` on a production gateway, or if a resource-based policy granting access outside your AWS Organization was added. An `UpdateGateway` event whose `requestParameters.policyEngineConfiguration.mode` equals `LOG_ONLY` on a production gateway is P1 **regardless of the calling principal or any other signal** — a mode flip disables authorization on the affected Gateway without removing any policy, so the policy infrastructure looks intact in post-compromise review even though no decision was actually enforced during the LOG_ONLY window.

---

## Part 1 — Prepare

> **CSF 2.0 Functions:** Govern · Identify · Protect
> **Goal:** Ensure the right configurations, access, and processes are in place *before* an AgentCore authorization-bypass incident occurs.

Responding to an authorization bypass depends almost entirely on preparation: the attack is silent by design, so without the right detective controls in place beforehand a `LOG_ONLY` flip can persist for hours with no alert. Agents act autonomously across many AWS services and external destinations, so detection and response controls that assume human-in-the-loop behavior (IP allow-list authentication, MFA at each action) do not apply. The points below cover the key preparation steps specific to this incident type.

### 1.1 Required AWS Service Configurations

Confirm the following are enabled and configured in all accounts and Regions where AgentCore Gateways and Policy Engines are deployed, *before* an incident occurs.

- [ ] AWS CloudTrail multi-region trail with log-file validation, delivered to an S3 bucket in a dedicated security account with a bucket policy that prevents the workload account from deleting log files; CloudTrail data events enabled for `AWS::BedrockAgentCore::Gateway` where `InvokeGateway` visibility is needed
- [ ] Amazon GuardDuty enabled with findings exported to AWS Security Hub
- [ ] AWS Config enabled with a delivery channel, plus a rule that flags any Gateway in `LOG_ONLY` mode and any resource-based policy on a Runtime / Gateway / Memory that references an account outside your AWS Organization
- [ ] AWS Security Hub with the Foundational Security Best Practices standard
- [ ] VPC Flow Logs enabled for every VPC hosting VPC-mode Runtime / Code Interpreter / Browser ENIs (rogue cross-account targets can create egress not otherwise visible)
- [ ] CloudWatch alarm wired to an EventBridge rule on `UpdateGateway` where `requestParameters.policyEngineConfiguration.mode = LOG_ONLY`, with SNS subscriptions to the security team confirmed
- [ ] CloudWatch alarms on `CreateGatewayTarget`, `UpdateGatewayTarget`, `PutResourcePolicy`, and `UpdateGateway` authorizer-type changes
- [ ] Cedar Policy Engine evaluation logs (policy-decision logs) shipped to a CloudWatch Log Group so that `ALLOW`/`DENY` decisions during any `LOG_ONLY` window are auditable after the fact
- [ ] All IaC (Cedar policies, Gateway/target definitions, resource policies, authorizer configuration) stored in Git with tagged commit hashes corresponding to deployed versions, so a known-good baseline is always diffable

> 🤖 **Automation opportunity:** An EventBridge rule on `UpdateGateway` with `policyEngineConfiguration.mode = LOG_ONLY` that invokes a Lambda to re-submit the Gateway with `mode = "ENFORCE"` and pages the security team shrinks the LOG_ONLY window from hours to seconds. Use AWS Config conformance packs to continuously validate the prerequisites above. (See 5.4 for the post-incident automation checklist.)

### 1.2 IAM & Access Prerequisites

Ensure the following access is pre-provisioned and tested — *do not provision break-glass access during an active incident*.

- [ ] Break-glass IAM role with least-privilege IR permissions exists and is documented; IR team members can assume it with MFA. The role needs `bedrock-agentcore:GetGateway`, `UpdateGateway`, `ListGateways`, `ListGatewayTargets`, `DeleteGatewayTarget`, `CreatePolicy`, `DeletePolicy`, `ListPolicies`, `GetResourcePolicy`, `DeleteResourcePolicy`, and `ListPolicyEngines`
- [ ] IR team can reach the AWS Security Incident Response console (if subscribed) and confirm the path to open a CIRT support case
- [ ] Isolated forensic account is available for evidence preservation, with an S3 forensic bucket using Object Lock in COMPLIANCE mode and KMS encryption
- [ ] IAM Permissions Boundaries applied to any team that creates or modifies AgentCore Gateways, targets, or policies; `aws:SourceAccount` / `aws:SourceArn` confused-deputy guards on every AgentCore trust policy
- [ ] A documented, approved baseline of every Gateway's `(mode, attached PolicyEngine ARN, authorizerType)` triple and every Gateway target's destination, so containment can distinguish attacker objects from legitimate ones
- [ ] An SCP scaffold ready to deny `bedrock-agentcore:UpdateGateway`, `CreateGatewayTarget`, and `PutResourcePolicy` to all principals except the security-admin role, ready to apply if scope widens

### 1.3 Communication & Escalation

> 📋 Do not include names. Use roles only. Maintain a separate, access-controlled contact list.

| Role | Responsibility |
|---|---|
| IR Lead | Overall incident coordination, status updates |
| Account / Agent Owner | Business context, authorization for containment that may disrupt the agent |
| AI/ML Platform team | AgentCore Gateway / Policy Engine configuration, IaC known-good baseline, redeploy |
| Legal / Compliance | Regulatory notification obligations, evidence hold |
| Communications | Internal and external messaging |
| AWS CIRT | Engage via AWS Support case or Security Incident Response service (P1/P2, if available) |

**Escalation path:**
Detection → IR Lead notified → Severity assessed → P1/P2 (Cedar mode flip, cross-account resource policy, or external-URL target confirmed): AWS CIRT engaged, Legal notified, IR bridge opened → P3/P4: IR Lead manages internally.

### 1.4 Game Day Guidance

This playbook should be exercised before it is needed. Recommended testing cadence: **annually at minimum, semi-annually for P1 scenarios.**

Suggested tabletop scenario for this incident type:

> A production Gateway shows an `UpdateGateway` event at 02:00 UTC flipping `policyEngineConfiguration.mode` from `ENFORCE` to `LOG_ONLY`, followed thirty seconds later by a `CreateGatewayTarget` call registering an MCP target whose URL is on a domain outside `*.amazonaws.com`, and then a burst of tool calls. Walk the team from detection (was the EventBridge auto-revert rule armed?), through forcing `ENFORCE` and applying the emergency deny-all Cedar policy, deleting the rogue target, auditing the `ALLOW` decisions logged during the LOG_ONLY window, to recovery and the post-incident SCP that restricts `UpdateGateway`.

Reference: [AWS Security Incident Response Game Days](https://docs.aws.amazon.com/security-ir/latest/userguide/game-days.html)

---

## Part 2 — Detect & Analyze

> **CSF 2.0 Functions:** Detect · Respond (Analyze)
> **Goal:** Confirm whether an authorization bypass has occurred, scope its impact, and gather evidence for containment and investigation.

### 2.1 Initial Triage Questions

Answer these quickly to determine scope and priority. Each question should take < 2 minutes to answer.

- [ ] Is this a confirmed incident or an anomalous finding requiring investigation?
- [ ] Which AWS accounts, Regions, and AgentCore Gateways / Policy Engines are potentially affected?
- [ ] Are production agents or sensitive Memory / Token-Vault data reachable through the affected Gateway?
- [ ] **Was authorization disabled — is any production Gateway currently in `LOG_ONLY` mode (`gateway.policyEngineConfiguration.mode`)?**
- [ ] Was a Gateway target created or updated to point at a cross-account Lambda or an external (non-`*.amazonaws.com`) URL?
- [ ] Was a resource-based policy added that references an AWS account outside your Organization?
- [ ] Is the threat actor potentially still active (new policies or targets reappearing after removal)?
- [ ] Are there downstream customers, partners, or regulatory implications from data reached during the bypass window?

**If 3 or more questions are answered YES → escalate to P1 immediately.** A single YES on the `LOG_ONLY` question or the external-account resource-policy question is itself a P1 override (see Severity Classification) — escalate and proceed to evidence preservation before completing full analysis.

### 2.2 Evidence Collection Checklist

Collect and preserve the following **before taking any containment actions**. Evidence collected after containment may be incomplete or altered.

> ⚠️ **Do not force Gateways back to `ENFORCE`, delete targets, or delete resource policies before exporting the relevant CloudTrail events and Cedar policy-decision logs.** The `ALLOW` decisions logged during a `LOG_ONLY` window are the only record of what the bypass permitted, and they are needed to scope downstream impact.

| Evidence Type | How to Collect | Where to Store |
|---|---|---|
| CloudTrail logs (incident window) | Athena / CloudWatch Logs Insights / CLI; copy before any `PutEventSelectors` tampering | Forensic S3 (Object Lock) |
| `UpdateGateway` events (mode + authorizer changes) | CloudTrail query (below) | Forensic S3 |
| Gateway target CRUD events | CloudTrail query (below) | Forensic S3 |
| Resource-based policy CRUD events | CloudTrail query (below) | Forensic S3 |
| Cedar policy-decision logs for the LOG_ONLY window | CloudWatch Logs Insights export | Forensic S3 |
| Current Gateway state `(mode, PE ARN, authorizerType)` per Gateway | `get-gateway` enumeration (below) | IR ticket / notes |
| GuardDuty / Security Hub finding JSON | Console export | Forensic S3 |

**The single most important query — surface Cedar enforcement-mode flips.** This is the highest-impact defense-evasion action in AgentCore and it is easy to miss: mode flips appear as `UpdateGateway` events carrying a `policyEngineConfiguration.mode` of `LOG_ONLY`, **not** as a dedicated policy API. The mode lives on the **Gateway** (`gateway.policyEngineConfiguration.mode`), not on the PolicyEngine, and `UpdatePolicyEngine` only changes the engine's description — it never appears here. Treat every match as a P1 indicator regardless of the calling principal.

```text
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress,
       requestParameters.gatewayIdentifier,
       requestParameters.policyEngineConfiguration.mode,
       requestParameters.policyEngineConfiguration.arn
| filter eventSource = "bedrock-agentcore.amazonaws.com"
| filter eventName = "UpdateGateway"
| filter requestParameters.policyEngineConfiguration.mode = "LOG_ONLY"
| sort @timestamp desc
```

The exact-equality filter on `LOG_ONLY` surfaces only the flips that disabled enforcement — not legitimate `ENFORCE` re-applications from recovery. To reconstruct the attacker pattern of "flip to `LOG_ONLY` → activity → flip back to `ENFORCE`," and to determine the precise start and end of the LOG_ONLY window, use the windowed query in **Appendix A**.

**Confirm the current enforcement mode on every Gateway.** If any Gateway is in `LOG_ONLY`, authorization was not enforced during the window since it flipped. Record each Gateway's `(mode, attached PolicyEngine ARN, inbound authorizerType)` triple — this triple is the authorization state for the Gateway and must match the IaC baseline after recovery.

```bash
for GW in $(aws bedrock-agentcore-control list-gateways --query "items[].gatewayId" --output text); do
  echo "=== Gateway: $GW ==="
  aws bedrock-agentcore-control get-gateway --gateway-identifier "$GW" \
    --query "{gateway:name, pe:policyEngineConfiguration.arn, mode:policyEngineConfiguration.mode, auth:authorizerType}" \
    --output table
done
aws bedrock-agentcore-control list-policy-engines

# Enumerate the Cedar policies attached to the suspect Policy Engine — a newly
# inserted permit(...) or a deleted forbid(...) is the bypass.
aws bedrock-agentcore-control list-policies --policy-engine-id "$POLICY_ENGINE_ID"
```

**Additional evidence to collect** (full queries in **Appendix A**):

- [ ] **PolicyEngine lifecycle events** (`CreatePolicyEngine`, `UpdatePolicyEngine`, `DeletePolicyEngine`). These never change mode, but if a PolicyEngine was **deleted** during the window, any Gateway that referenced it lost its authorization attachment entirely — confirm every Gateway's `policyEngineConfiguration` is intact.
- [ ] **Cedar policy CRUD** (`CreatePolicy`, `UpdatePolicy`, `DeletePolicy`) plus natural-language authoring (`GeneratePolicy*`). Review `requestParameters.definition` on every match — a newly inserted policy whose Cedar statement starts with `permit(` is a candidate attacker-created bypass, and a deleted policy may be the `forbid` that blocked the action the attacker needed. AgentCore can translate plain-English descriptions into Cedar, so an attacker can author a bypass without knowing Cedar syntax.
- [ ] **Gateway target changes** (`CreateGatewayTarget`, `UpdateGatewayTarget`, `DeleteGatewayTarget`). A target pointing at a cross-account Lambda (account ID not yours) or an external attacker-controlled URL is an exfiltration path that bypasses every downstream control. Inspect `requestParameters.targetConfiguration`.
- [ ] **Resource-based policy changes** (`PutResourcePolicy`, `DeleteResourcePolicy`) on every Runtime, Runtime Endpoint, Gateway, and Memory. Resource-based policies grant access independently of customer IAM — flag any `PutResourcePolicy` whose document references an account ARN outside your Organization.
- [ ] **Gateway authorizer changes.** Flipping `authorizerType` from `CUSTOM_JWT` to `AWS_IAM` widens inbound access to any IAM principal holding `bedrock-agentcore:InvokeGateway`, because `AWS_IAM` defers to standard IAM evaluation rather than JWT claim validation; flipping the other way may indicate the attacker loaded an OIDC discovery URL they control. Either direction warrants investigation.
- [ ] **`iam:PassRole` privilege-escalation pattern.** An attacker holding `bedrock-agentcore:CreateAgentRuntime` plus broad `iam:PassRole` can create a runtime that assumes an over-privileged role. Look for `CreateAgentRuntime` followed by `UpdateAgentRuntime` with a `roleArn` outside the approved set.
- [ ] **Enumerate every Gateway target and every resource-based policy** to build the removal list for containment:

```bash
for GW in $(aws bedrock-agentcore-control list-gateways --query "items[].gatewayId" --output text); do
  aws bedrock-agentcore-control get-gateway --gateway-identifier "$GW"
  aws bedrock-agentcore-control list-gateway-targets --gateway-identifier "$GW"
  aws bedrock-agentcore-control get-resource-policy \
    --resource-arn "arn:aws:bedrock-agentcore:$AWS_REGION:$ACCOUNT_ID:gateway/$GW" 2>/dev/null
done
```

> *(See [CloudTrail query examples](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html) and Appendix A for the full scenario-specific query set.)*

### 2.3 Severity Determination

Based on triage and initial evidence, assign a priority using the criteria in [Severity Classification](#severity-classification), applying the P1 override for any confirmed `LOG_ONLY` flip or external-account resource policy.

| Confirmed? | Priority Assignment |
|---|---|
| Cedar `LOG_ONLY` flip on production gateway, OR resource policy granting access outside the Organization | P1 (override) |
| Active threat actor in environment; rogue external-URL target with confirmed tool traffic | P1 |
| Rogue target or `permit` policy created, no confirmed traffic, actor no longer active | P2 |
| Suspicious policy / authorizer activity, scope unclear | P3 |
| Configuration drift, no active threat | P4 |

### 2.4 Getting Help from AWS

For P1 or P2 incidents, consider engaging AWS for additional support:

- **AWS Security Incident Response service** (if enabled): Open a case via the [Security Incident Response console](https://console.aws.amazon.com/security-ir/), attach relevant findings (the `UpdateGateway` mode-flip event and any rogue-target / resource-policy events), and grant AWS CIRT access to the affected account(s).
- **AWS Support** (any AWS Support plan): Open a support case with severity "Critical" or "Urgent" and request assistance from the AWS Customer Incident Response Team (CIRT).
- **AWS Trust & Safety** (for abuse reports): If a rogue Gateway target is being used to attack others, report via the [AWS abuse form](https://support.aws.amazon.com/#/contacts/report-abuse).

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
├── YES (Gateway in LOG_ONLY / active tool calls through a rogue target / live cross-account path)
│     └── Proceed to 3.2 — accept potential agent disruption
│
└── NO (threat appears inactive)
      └── Consult Agent Owner and IR Lead before proceeding
            Can we contain without disrupting a production agent?
            ├── YES → Proceed to 3.2
            └── NO  → Document business impact, obtain authorization, then proceed
```

A Gateway in `LOG_ONLY` is an active-threat condition by definition — authorization is off right now — so the answer to the first branch is YES whenever the mode-flip query in 2.2 returns a current match.

### 3.2 Containment Actions

> `[IR Lead]` coordinates. `[Account / Agent Owner]` authorizes actions that may disrupt a production agent.

**Step-by-step containment for this incident type:**

1. **Force every Gateway back to `ENFORCE` mode.**
   This is the single most urgent action — it re-enables authorization on every affected Gateway. Because `UpdateGateway` is a PUT, you must fetch the current configuration first and pass back every required field with only the mode changed to `ENFORCE`. Omit optional fields (`--authorizer-configuration`, `--protocol-configuration`) entirely when the source config does not have them — do not pass literal `null`.

   ```bash
   for GW in $(aws bedrock-agentcore-control list-gateways --query "items[].gatewayId" --output text); do
     CONFIG=$(aws bedrock-agentcore-control get-gateway --gateway-identifier "$GW" --output json)
     PE_ARN=$(echo "$CONFIG" | jq -r '.policyEngineConfiguration.arn')
     if [ "$PE_ARN" = "null" ] || [ -z "$PE_ARN" ]; then continue; fi
     ARGS=(
       --gateway-identifier "$GW"
       --name "$(echo "$CONFIG" | jq -r '.name')"
       --role-arn "$(echo "$CONFIG" | jq -r '.roleArn')"
       --protocol-type "$(echo "$CONFIG" | jq -r '.protocolType')"
       --authorizer-type "$(echo "$CONFIG" | jq -r '.authorizerType')"
       --policy-engine-configuration "{\"mode\":\"ENFORCE\",\"arn\":\"$PE_ARN\"}"
     )
     if [ "$(echo "$CONFIG" | jq -r '.authorizerConfiguration')" != "null" ]; then
       ARGS+=(--authorizer-configuration "$(echo "$CONFIG" | jq -c '.authorizerConfiguration')")
     fi
     if [ "$(echo "$CONFIG" | jq -r '.protocolConfiguration')" != "null" ]; then
       ARGS+=(--protocol-configuration "$(echo "$CONFIG" | jq -c '.protocolConfiguration')")
     fi
     aws bedrock-agentcore-control update-gateway "${ARGS[@]}"
   done
   ```

2. **Apply an emergency deny-all Cedar policy to every PolicyEngine.**
   This denies every tool call at the Gateway boundary for the duration of the investigation, in case the attacker also inserted a `permit` policy you have not yet identified. The statement **must** be scoped to the `AgentCore::Gateway` resource type — AgentCore rejects unconstrained wildcard-resource statements with `ValidationException: a wildcard resource was detected ... please constrain the resource ... to the AgentCore::Gateway resource type.` The policy `--name` must match `^[A-Za-z][A-Za-z0-9_]*$` (hyphens rejected), so sanitize any incident ID by replacing hyphens with underscores. Remove this policy **only** after the baseline policy set has been redeployed from IaC and verified to restore legitimate traffic.

   ```bash
   POLICY_NAME_SAFE="ir_deny_all_${INCIDENT_ID//-/_}"
   aws bedrock-agentcore-control create-policy \
     --policy-engine-id "$POLICY_ENGINE_ID" \
     --name "$POLICY_NAME_SAFE" \
     --description "IR emergency deny-all" \
     --definition '{"cedar":{"statement":"forbid(principal, action, resource is AgentCore::Gateway);"}}'
   ```

3. **Delete every rogue Gateway target.**
   Deregistration removes the target from the Gateway's routing table so new tool calls cannot reach it. For Lambda targets pointing to attacker-controlled functions in **cross-account** destinations, you must **also** have the target account's security team revoke the Lambda resource policy — deregistration here does not remove trust on the target side. For external MCP-server targets, an existing WebSocket / HTTP/2 connection may persist until broken at the network layer; block at the VPC NACL (stateless) in addition to deregistration.

   ```bash
   aws bedrock-agentcore-control delete-gateway-target \
     --gateway-identifier "$GATEWAY_ID" --target-id "$GATEWAY_TARGET_ID"
   ```

4. **Delete every unauthorized resource-based policy.**
   Cross-account Runtime access requires resource-based policies on **both** the runtime and the endpoint — delete both, or the surviving one keeps the access path open.

   ```bash
   aws bedrock-agentcore-control delete-resource-policy \
     --resource-arn "arn:aws:bedrock-agentcore:$AWS_REGION:$ACCOUNT_ID:runtime/<id>"
   aws bedrock-agentcore-control delete-resource-policy \
     --resource-arn "arn:aws:bedrock-agentcore:$AWS_REGION:$ACCOUNT_ID:runtime/<id>/runtime-endpoint/<endpoint-name>"
   aws bedrock-agentcore-control delete-resource-policy \
     --resource-arn "arn:aws:bedrock-agentcore:$AWS_REGION:$ACCOUNT_ID:gateway/<gid>"
   ```

5. **Revert any flipped Gateway authorizer.**
   Pull the IaC-known-good authorizer configuration from Git and re-submit the Gateway so JWT or IAM validation resumes as specified in the baseline. `UpdateGateway` is a PUT, so resend every required field using the same argv-array idiom as step 1 and only swap in the known-good authorizer configuration.

6. **Apply a `PassRole` scope-down to prevent re-escalation.**
   Attach an identity-based policy to every developer role denying `iam:PassRole` except for AgentCore-prefixed runtime roles. Without this, an attacker who retains `CreateAgentRuntime` can re-escalate the moment an over-permissioned role becomes passable again. The condition must key off `iam:PassedToService` (the action name `iam:PassRole` is **not** a valid condition key):

   ```json
   {
     "Effect": "Deny",
     "Action": "iam:PassRole",
     "Resource": "arn:aws:iam::*:role/*",
     "Condition": {
       "StringNotEquals": { "iam:PassedToService": "bedrock-agentcore.amazonaws.com" }
     }
   }
   ```

7. **Escalate to broad containment if scope widens.**
   Signs that scope is widening: new policies appearing after you apply the deny-all overlay, new Gateway targets appearing after you delete them, or resource-based policies being re-added. All indicate the attacker retains `bedrock-agentcore` control-plane access — apply the pre-staged SCP from 1.2 denying `UpdateGateway` / `CreateGatewayTarget` / `PutResourcePolicy` to all but the security-admin role, then pivot to **[IRP-AgentCoreIdentityCompromise](IRP-AgentCoreIdentityCompromise.md)** to eradicate the credential chain. If the compromise spans multiple components or the Incident Commander directs a full shutdown, invoke the AgentCore emergency kill switch (see below).

> 🤖 **Automation opportunity:** An AWS Systems Manager Automation runbook can perform step 1 (force `ENFORCE` across all Gateways) and step 2 (apply deny-all) as a single keyed invocation, reducing time-to-contain on a confirmed mode flip.

**Emergency kill switch (summary).** If scope is unclear or spans multiple components, the AgentCore kill switch severs every authorization path across **six sequential phases** and terminates all agentic workflows in the account — legitimate and compromised — so obtain explicit written authorization and run a blast-radius impact assessment first. The phases are: **(1)** block new API calls via an emergency SCP denying `bedrock-agentcore:*` plus `bedrock:InvokeModel*` except for the responder role; **(2)** sever authentication (disable Cognito users, global sign-out, delete confidential app clients, delete workload identities and credential providers); **(3)** sever authorization (force `ENFORCE` on every Gateway and apply the `forbid(principal, action, resource is AgentCore::Gateway);` deny-all to every PolicyEngine); **(4)** sever tool access (delete every Gateway target and every resource-based policy on runtimes, endpoints, and gateways); **(5)** sever network and active sessions (stop Code Interpreter / Browser sessions, delete runtime endpoints to close WebSocket/AGUI streams, isolate VPC-mode ENIs); and **(6)** prevent recreation (invalidate `agentcore`-named SSM parameters, disable `agentcore`/`bedrock` EventBridge rules). After execution, revoke tokens at external OAuth providers, block C2 IPs at the NACL, and monitor CloudTrail for 48 hours for any residual AgentCore activity.

### 3.3 Evidence Preservation Reminders

After containment begins, ensure the following before modifying or terminating any further resources:

- [ ] CloudTrail events for the window exported to the forensic S3 bucket and integrity-validated
- [ ] Cedar policy-decision logs for the entire `LOG_ONLY` window exported (these are the only record of what the bypass permitted)
- [ ] Pre-deletion snapshot recorded of every Gateway target's `targetConfiguration` and every resource-based policy document
- [ ] Each Gateway's pre-containment `(mode, PE ARN, authorizerType)` triple recorded in the IR ticket
- [ ] S3 Object Lock or legal hold applied to the forensic bucket

---

## Part 4 — Eradicate & Recover

> **CSF 2.0 Function:** Respond (Eradicate) · Recover
> **Goal:** Remove the root cause, validate the environment is clean, and restore normal operations.

### 4.1 Root Cause Identification

> `[IR Lead]` owns this step. Document findings in the IR ticket in real time.

The central question is how the attacker obtained the control-plane permission used: `bedrock-agentcore:UpdateGateway` (to flip mode or authorizer), `bedrock-agentcore:CreateGatewayTarget` (to register an exfiltration endpoint), `bedrock-agentcore:PutResourcePolicy` (to grant cross-account access), or `bedrock-agentcore:CreatePolicy` / `DeletePolicy` (to insert a `permit` or delete a `forbid`). Common root causes for this incident type:

- An overly-broad developer role holding `bedrock-agentcore:*` (note: there is no `bedrock-agentcore-control:*` IAM prefix — all AgentCore actions live under the single `bedrock-agentcore:*` prefix; the `-control` suffix exists only in CLI/SDK module names and API endpoint hostnames).
- A CI/CD deployment role scoped too broadly, allowing Gateway and policy mutation beyond what the pipeline needs.
- A missing SCP at the OU level that would have denied `UpdateGateway` to all but the security-admin role.
- A scoped-too-broadly `iam:PassRole` combined with `CreateAgentRuntime`, enabling a privilege-escalation path to an over-privileged execution role.
- A compromised inbound identity (stolen JWT / machine-client secret) that itself held the control-plane permission — if so, complete eradication here, then continue in **[IRP-AgentCoreIdentityCompromise](IRP-AgentCoreIdentityCompromise.md)**.

Use the evidence collected in Part 2 to trace the initial access vector and the full attack path.

### 4.2 Eradication Actions

> `[IR Lead]` coordinates. `[Account / Agent Owner]` approves changes to production resources.

1. **Remove every object written during the compromise window.**
   Work from the CloudTrail queries in 2.2 / Appendix A. For each Cedar policy ID, Gateway target ID, and resource-policy ARN created or modified during the window, delete it and confirm it is gone with a follow-up list call.

   ```bash
   aws bedrock-agentcore-control delete-policy --policy-engine-id "$POLICY_ENGINE_ID" --policy-id "<rogue-policy-id>"
   ```

2. **Restore the Cedar policy set from IaC**, then remove the emergency deny-all from containment step 2 (otherwise legitimate traffic stays blocked).

   ```bash
   cd /path/to/iac
   git checkout <known-good-commit>
   npm run build
   AWS_PROFILE=$AWS_PROFILE npx cdk deploy <PolicyStackName> --require-approval never
   ```

3. **Audit every `ALLOW` decision logged during the `LOG_ONLY` window.**
   Each `ALLOW` logged during LOG_ONLY is an action that was permitted **without enforcement**. Compare each against the restored policy set: any action that is `ALLOW` under LOG_ONLY but would be `DENY` under `ENFORCE` is a confirmed bypass and must be investigated individually — what data was read, what tool was invoked, what downstream system was reached.

   ```text
   fields @timestamp, principalId, actionId, resourceId, decision
   | filter decision = "ALLOW"
   | filter @timestamp >= <logOnly_start> and @timestamp <= <logOnly_end>
   ```

4. **Audit every Gateway target Lambda for planted code.**
   For each Lambda created or updated during the window, pull the function code and recent invocation logs; review for exfiltration logic, reverse shells, credential harvesting, or response-rewriting functions.

5. **Remove attacker persistence mechanisms.**
   Check for and remove:
   - [ ] Unauthorized Cedar policies (`permit` statements) inserted during the window, or legitimate `forbid` policies that were deleted and not yet restored
   - [ ] Unauthorized Gateway targets pointing to cross-account Lambdas or external URLs
   - [ ] Resource-based policies on Runtimes, Endpoints, Gateways, or Memory granting access outside the Organization
   - [ ] Unauthorized runtimes created with an over-privileged `roleArn` via the `iam:PassRole` path
   - [ ] EventBridge rules that re-create deleted targets or re-flip Gateway mode on a `DeleteGatewayTarget` / `UpdateGateway` trigger
   - [ ] Modified trust policies on legitimate Gateway / runtime roles that now trust an external account

6. **Re-validate the restored Cedar policy set against the Gateway schema** using AgentCore's automated-reasoning validation flow, which detects overly-permissive policies, overly-restrictive policies, and unsatisfiable conditions before they reach production traffic.

> 🤖 **Automation opportunity:** AWS Config auto-remediation can revert a Gateway found in `LOG_ONLY` back to `ENFORCE` and detach any resource policy that references an external account.

### 4.3 Recovery Actions

1. **Restore from known-good state.**
   Redeploy the PolicyEngine and Cedar policies, Gateway targets, and resource-based policies from the last known-good IaC commit, pinned to the commit hash rather than branch tip. Do not restore any target or policy that was created during the incident window — only the approved baseline.

2. **Re-enable services and access.**
   - [ ] Confirm `ENFORCE` mode on every production Gateway (mode is per-Gateway, so enumerate and confirm each):

     ```bash
     for GW in $(aws bedrock-agentcore-control list-gateways --query "items[].gatewayId" --output text); do
       MODE=$(aws bedrock-agentcore-control get-gateway --gateway-identifier "$GW" \
         --query "policyEngineConfiguration.mode" --output text)
       echo "$GW : $MODE"
     done
     ```

   - [ ] Confirm each Gateway's `authorizerType` and `authorizerConfiguration` match the IaC baseline
   - [ ] Restore IAM access for legitimate principals with new credentials if any were rotated
   - [ ] Validate agent functionality end-to-end through the restored Gateways

3. **Harden against recurrence.**
   - [ ] Apply an SCP denying `bedrock-agentcore:UpdateGateway` to all principals except the security-admin role
   - [ ] Scope `iam:PassRole` to `arn:aws:iam::*:role/agentcore-runtime-*` with the `iam:PassedToService == bedrock-agentcore.amazonaws.com` condition
   - [ ] Arm the EventBridge auto-revert rule on `UpdateGateway` mode flips to `LOG_ONLY`
   - [ ] Run positive and negative test cases against the restored policy set: known-good actions from allowed principals receive `ALLOW`; known-bad actions receive `DENY` (not just logged); cross-agent tool-access restrictions are enforced

### 4.4 Recovery Validation

Confirm the environment is clean before declaring the incident resolved.

- [ ] No unauthorized Cedar policies, Gateway targets, or resource-based policies remain in any affected account
- [ ] Every production Gateway confirmed in `ENFORCE` mode with its IaC-baseline authorizer type and attached PolicyEngine
- [ ] The emergency deny-all Cedar policy has been removed and legitimate traffic is restored
- [ ] All credentials created or used by the attacker have been revoked
- [ ] GuardDuty / Security Hub show no active findings related to this incident
- [ ] Agent health metrics (`InvokeAgentRuntime` error rate, tool-call fan-out, Bedrock cost) within normal range
- [ ] Cedar policy-decision logs monitored for 48 hours show no unexpected `ALLOW` decisions and no spike in `DENY` from unauthenticated paths
- [ ] CloudTrail logging and log-file validation confirmed operational
- [ ] AWS Security Incident Response case updated / closed (if applicable)

---

## Part 5 — Post-Incident Activity

> **CSF 2.0 Function:** Identify (Improve) — continuous improvement, not a one-time activity
> **Goal:** Learn from this incident to reduce the likelihood and impact of future occurrences.

### 5.1 Timeline Reconstruction

Document the full incident timeline. Complete this within 24–48 hours while memory is fresh. For an authorization bypass, the `LOG_ONLY` window start and end are the anchor events — every `ALLOW` decision between them is in scope.

| Timestamp (UTC) | Event | Source / Evidence | Actor |
|---|---|---|---|
| YYYY-MM-DD HH:MM | Initial access / control-plane permission obtained | CloudTrail | Threat actor |
| YYYY-MM-DD HH:MM | `UpdateGateway` flips mode to `LOG_ONLY` (window start) | CloudTrail | Threat actor |
| YYYY-MM-DD HH:MM | Rogue target / resource policy created; tool calls begin | CloudTrail / decision logs | Threat actor |
| YYYY-MM-DD HH:MM | Detection signal fired | EventBridge / CloudWatch alarm | AWS / monitoring |
| YYYY-MM-DD HH:MM | IR team notified | On-call alert | IR Lead |
| YYYY-MM-DD HH:MM | `ENFORCE` restored, deny-all applied (window end) | IR ticket | IR Lead |
| YYYY-MM-DD HH:MM | Containment completed | IR ticket | IR Lead |
| YYYY-MM-DD HH:MM | Recovery validated | IR ticket | IR Lead |

**Key metrics to capture:**

| Metric | Value |
|---|---|
| Time to Detect (TTD) | *HH:MM from mode flip to detection* |
| Time to Notify (TTN) | *HH:MM from detection to IR team notified* |
| Time to Contain (TTC) | *HH:MM from notification to `ENFORCE` restored* |
| Time to Recover (TTR) | *HH:MM from containment to recovery validated* |
| LOG_ONLY window duration | *HH:MM enforcement was disabled* |
| Total Incident Duration | *HH:MM* |
| Affected AgentCore resources | *Count and type (gateways, targets, policies)* |
| Data Impact | *Confirmed / Suspected / None* |

### 5.2 Post-Incident Review

Conduct a blameless post-incident review within **5 business days** for P1/P2, **15 business days** for P3/P4.

Discussion questions:

1. How did the attacker obtain the control-plane permission (`UpdateGateway` / `CreateGatewayTarget` / `PutResourcePolicy` / `CreatePolicy`)? Could an SCP or tighter role have prevented it?
2. How long was the Gateway in `LOG_ONLY`? Was the EventBridge auto-revert rule armed, and if not, why?
3. How was the bypass detected? Was detection fast enough given that the attack is silent by design?
4. Were the right people notified at the right time?
5. Did forcing `ENFORCE` and applying the deny-all work as expected? Were there unintended side effects on legitimate traffic?
6. Could we fully enumerate what the bypass permitted from the Cedar decision logs, or were those logs missing or under-retained?
7. What single change would most improve our response to this scenario in future?

### 5.3 Detection Gap Analysis

For each detection source that *did not* catch this incident early, document why and what would have:

| Gap | Root Cause | Recommended Fix | Owner | Target Date |
|---|---|---|---|---|
| Cedar `LOG_ONLY` flip not alarmed | No EventBridge rule on `UpdateGateway` mode change | Add rule + Lambda auto-revert to `ENFORCE` and page security | | |
| Rogue cross-account target not flagged | No rule inspecting `targetConfiguration` for non-account ARN / non-`*.amazonaws.com` URL | Add EventBridge rule on `CreateGatewayTarget` | | |
| External-account resource policy not caught | No AWS Config rule on cross-Organization principals | Add Config rule flagging external-account resource policies | | |
| Bypass scope unknowable | Cedar policy-decision logs not retained | Ship decision logs to CloudWatch with adequate retention | | |

### 5.4 Playbook Update Checklist

Review and update this playbook based on what you learned. Do not wait for the next scheduled review.

- [ ] Were triage questions sufficient? Add/remove as needed (especially the `LOG_ONLY` and external-account resource-policy questions).
- [ ] Were evidence collection steps accurate — did the mode-flip and windowed queries return what was expected?
- [ ] Were containment actions effective? Did the force-`ENFORCE` loop and deny-all behave as written (PUT semantics, name regex, wildcard-resource constraint)?
- [ ] Were any automation opportunities identified? Add EventBridge / Config / SSM stubs to the relevant sections.
- [ ] Were severity criteria accurate? Adjust if incidents were under- or over-classified.
- [ ] Add the prevent-recurrence controls if not yet deployed: EventBridge auto-revert for mode flips; EventBridge auto-delete for rogue targets; AWS Config rule for external-account resource policies; SCP denying `UpdateGateway` except to security-admin; `iam:PassRole` scope-down with `iam:PassedToService`.
- [ ] Update **Last Reviewed** date and increment **Playbook Version**.

---

## Appendix A — Useful Queries

### CloudTrail (Athena)

```sql
-- All control-plane activity in a time window for a specific principal
SELECT eventTime, eventName, awsRegion, sourceIPAddress, userAgent,
       errorCode, errorMessage
FROM cloudtrail_logs
WHERE userIdentity.arn = 'arn:aws:iam::111111111111:role/SUSPECTED_ROLE'
  AND eventSource = 'bedrock-agentcore.amazonaws.com'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
```

### CloudWatch Logs Insights — scenario-specific

```text
-- Cedar enforcement-mode flips to LOG_ONLY (the signature attack; P1 on every match)
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress,
       requestParameters.gatewayIdentifier,
       requestParameters.policyEngineConfiguration.mode,
       requestParameters.policyEngineConfiguration.arn
| filter eventSource = "bedrock-agentcore.amazonaws.com"
| filter eventName = "UpdateGateway"
| filter requestParameters.policyEngineConfiguration.mode = "LOG_ONLY"
| sort @timestamp desc
```

```text
-- Windowed view: reconstruct "flip to LOG_ONLY -> activity -> flip back to ENFORCE"
-- to determine the precise LOG_ONLY window per gateway
fields @timestamp, requestParameters.gatewayIdentifier as gw,
       requestParameters.policyEngineConfiguration.mode as mode, userIdentity.arn
| filter eventSource = "bedrock-agentcore.amazonaws.com"
| filter eventName = "UpdateGateway"
| filter ispresent(requestParameters.policyEngineConfiguration.mode)
| sort gw asc, @timestamp asc
```

```text
-- Cedar policy CRUD: inspect definition for attacker-inserted permit / deleted forbid
fields @timestamp, eventName, userIdentity.arn,
       requestParameters.policyEngineId, requestParameters.policyId,
       requestParameters.definition
| filter eventSource = "bedrock-agentcore.amazonaws.com"
| filter eventName in ["CreatePolicy","UpdatePolicy","DeletePolicy"]
| sort @timestamp asc
```

```text
-- Gateway target CRUD: rogue cross-account Lambda or external MCP URL
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress,
       requestParameters.gatewayIdentifier, requestParameters.name,
       requestParameters.targetConfiguration
| filter eventSource = "bedrock-agentcore.amazonaws.com"
| filter eventName in ["CreateGatewayTarget","UpdateGatewayTarget","DeleteGatewayTarget"]
| sort @timestamp desc
```

```text
-- Resource-based policy changes (cross-account grants)
fields @timestamp, eventName, userIdentity.arn,
       requestParameters.resourceArn, requestParameters.policy
| filter eventSource = "bedrock-agentcore.amazonaws.com"
| filter eventName in ["PutResourcePolicy","DeleteResourcePolicy"]
| sort @timestamp desc
```

```text
-- Gateway authorizer-type changes (CUSTOM_JWT <-> AWS_IAM)
fields @timestamp, eventName, userIdentity.arn,
       requestParameters.gatewayIdentifier, requestParameters.authorizerType
| filter eventSource = "bedrock-agentcore.amazonaws.com"
| filter eventName = "UpdateGateway"
| filter requestParameters.authorizerType like /./
| sort @timestamp desc
```

```text
-- Cedar ALLOW decisions during a known LOG_ONLY window (confirmed-bypass candidates)
fields @timestamp, principalId, actionId, resourceId, decision
| filter decision = "ALLOW"
| filter @timestamp >= <logOnly_start> and @timestamp <= <logOnly_end>
```

> **Contributors:** The queries above are tailored to authorization bypass. Memory data-plane APIs (`DeleteEvent`, `BatchDeleteMemoryRecords`, `StartMemoryExtractionJob`) do **not** emit CloudTrail events — query OTel spans / Memory structured logs instead. See [CloudTrail query examples](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html).

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

An authorization bypass is especially significant for notification analysis because, during the `LOG_ONLY` window, an agent may have read Memory records (conversation content, PII), retrieved Token Vault credentials, or reached customer-facing tools with no enforcement — any of which can trigger obligations. Determine data-subject impact early (Part 2, by auditing the `ALLOW` decisions logged during the window), since that determines which regulations apply.

**Quick reference for this scenario:**

| Regulation | Trigger Condition | Timeframe |
|---|---|---|
| GDPR Art. 33 | Personal data in Memory confirmed accessed during the bypass window | 72 hours to supervisory authority |
| HIPAA Breach Notification Rule | PHI reachable through an agent tool was accessed without enforcement | Without unreasonable delay, ≤ 60 days |
| PCI-DSS | Cardholder data reachable via an affected Gateway target | Per acquirer / card-brand agreement, promptly |
| US state breach-notification laws | Resident PII confirmed accessed | Varies by state (often "without unreasonable delay") |
| Sector-specific AI-governance regimes | AI-system security incident affecting a regulated decision path | Per regime |

> ⚠️ The clock starts at **awareness**, not confirmation. When in doubt, assume notification is required and consult Legal immediately.

---

## Appendix C — Reference Links

- [NIST SP 800-61r3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [Amazon Bedrock AgentCore Developer Guide](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [AWS Security Incident Response Service Documentation](https://docs.aws.amazon.com/security-ir/latest/userguide/what-is-security-ir.html)
- [AWS Prescriptive Guidance — Providing secure access, usage, and implementation of generative AI agents](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture-generative-ai/gen-auto-agents.html)
- [AWS Well-Architected Framework — Security Pillar: Incident Response](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/incident-response.html)
- [Cedar Policy Language Reference](https://docs.cedarpolicy.com/)
- [Amazon GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [AWS CloudTrail Query Examples (Athena)](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)

---

## Revision History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | 2026-06-20 | AWS | Initial draft |
