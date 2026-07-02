# IRP-AgentCoreObservabilityTampering: Amazon Bedrock AgentCore Observability Tampering

> **Playbook Version:** 1.0
> **Last Reviewed:** 2026-06-20
> **Status:** `Draft`
> **NIST Framework:** SP 800-61r3 (CSF 2.0 Community Profile)
> **Related Playbooks:** [IRP-AgentCoreIdentityCompromise](IRP-AgentCoreIdentityCompromise.md) | [IRP-AgentCoreAgentIntegrity](IRP-AgentCoreAgentIntegrity.md) | [IRP-AgentCoreAuthorizationBypass](IRP-AgentCoreAuthorizationBypass.md) | [IRP-AgentCoreToolAbuse](IRP-AgentCoreToolAbuse.md)

---

> ⚠️ **Disclaimer:** This playbook is provided as a template only. It should be customized to suit your organization's specific needs, risks, available tools, and work processes. This guide is not official AWS documentation and is provided as-is. Security and Compliance is a shared responsibility between you and AWS. You are responsible for making your own independent assessment of the information in this document.

---

## Overview

Observability tampering is the deliberate degradation or destruction of the telemetry that an incident responder depends on to investigate an Amazon Bedrock AgentCore environment. The observability surface — AWS CloudTrail configuration, CloudWatch Log Groups (including the `aws/spans` Transaction Search group and AgentCore vended `APPLICATION_LOGS` groups), X-Ray sampling and trace-segment destination, the KMS keys that encrypt all of the above, and the customer-provided IAM role used by AgentCore Evaluations) is simultaneously the investigator's primary evidence source and a high-value attacker target. Tampering manifests as `StopLogging` / `DeleteTrail` / `PutEventSelectors` / `UpdateTrail` on a trail covering your AgentCore accounts, Log Group deletion or retention reduction, X-Ray sampling reduced to zero, a KMS key disabled or scheduled for deletion, or the Evaluations IAM role assumed from an unexpected source to mine agent trace spans. Because every action an attacker takes after disabling logging happens in a blindspot, observability tampering is a defense-evasion event that should be treated as **P1** — and the signature containment move is to **re-enable logging first**, before any other containment, or every subsequent investigation step is unreliable.

### Out of Scope

This playbook does **not** cover:

- Authorization bypass without an observability nexus — a Cedar `ENFORCE` → `LOG_ONLY` flip, a rogue `CreateGatewayTarget`, or a cross-account resource-based policy. Use [IRP-AgentCoreAuthorizationBypass](IRP-AgentCoreAuthorizationBypass.md). (A `LOG_ONLY` flip is an *authorization* change; it is distinct from tampering with the telemetry pipeline.)
- Stolen inbound identity (Cognito JWT, confidential App Client secret, hijacked workload identity) where logging is intact — use [IRP-AgentCoreIdentityCompromise](IRP-AgentCoreIdentityCompromise.md).
- Sandbox or tool abuse (Code Interpreter exfiltration, Browser SSRF, repeated tool-call fan-out) where the observability surface itself was not modified — use [IRP-AgentCoreToolAbuse](IRP-AgentCoreToolAbuse.md).
- Runtime artifact tampering (poisoned S3 ZIP or ECR image) without telemetry impairment — use [IRP-AgentCoreAgentIntegrity](IRP-AgentCoreAgentIntegrity.md).
- A compromise that began with observability tampering but has pivoted to account-wide credential abuse — contain the observability surface here first (re-enable logging), then pivot to your general credential-compromise playbook.

### Applicable Finding Types

List the detection signals that should route a responder to this playbook.

| Source | Finding / Event Type | Severity |
|---|---|---|
| Amazon GuardDuty | `Stealth:IAMUser/CloudTrailLoggingDisabled` | HIGH |
| Amazon GuardDuty | `Stealth:IAMUser/LoggingConfigurationModified`, `Impact:IAMUser/AnomalousBehavior` on a logging/KMS principal | HIGH |
| AWS Security Hub | `CloudTrail.1` / `CloudTrail.2` / `CloudWatch.*` controls reporting a trail or log-group regression on an AgentCore account | CRITICAL/HIGH |
| CloudTrail | `eventName: StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors` on a trail covering AgentCore accounts | — (treat as P1) |
| CloudTrail | `eventName: DeleteLogGroup`, `PutRetentionPolicy`, `DisassociateKmsKey`, `PutSubscriptionFilter`, `DeleteDelivery` on a `bedrock-agentcore` / `aws/spans` / `aws/vendedlogs/bedrock-agentcore` group | — |
| CloudTrail | `eventName: ScheduleKeyDeletion`, `DisableKey`, `RevokeGrant` on a KMS key encrypting AgentCore logs/Memory/Token Vault | — (treat as P1) |
| CloudTrail | `eventName: UpdateTraceSegmentDestination`, `UpdateSamplingRule`/`DeleteSamplingRule` zeroing X-Ray sampling | — |
| CloudTrail | `eventName: AssumeRole` on the Evaluations IAM role from an unexpected source; `CreateEvaluator`/`UpdateEvaluator` with a non-baseline prompt | — |
| Custom / Third-Party | AWS Config `cloudtrail-enabled` / `cloudwatch-log-group-encrypted` non-compliant on an AgentCore account | — |

> 📌 GuardDuty finding types are updated regularly. See the [GuardDuty finding types reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) for the current list.

### Severity Classification

Use this table to determine incident priority at time of detection. Escalate immediately if P1 criteria are met.

| Priority | Criteria |
|---|---|
| **P1 — Critical** (≤15 min) | CloudTrail logging disabled, deleted, or redirected on a trail covering AgentCore accounts; a KMS key encrypting AgentCore logs/Memory/Token Vault disabled or scheduled for deletion; an attacker-installed subscription filter actively exfiltrating live log events; tampering occurring concurrently with other active malicious activity. |
| **P2 — High** | Confirmed observability change (retention reduction, sampling zeroed, vended-delivery deleted) but the actor appears no longer active, or the blindspot window is bounded and short. |
| **P3 — Medium** | Anomalous observability configuration change detected, intent unclear, no confirmed downstream impact. |
| **P4 — Low** | Observability configuration drift (e.g., a non-security log group's retention reduced) with no evidence of malicious intent. |

> **P1 override:** regardless of the matrix, treat as P1 whenever CloudTrail capture was halted/redirected for any account hosting AgentCore resources, or whenever a KMS key protecting AgentCore evidence was disabled or scheduled for deletion — these destroy the evidence base for everything that follows.

---

## Part 1 — Prepare

> **CSF 2.0 Functions:** Govern · Identify · Protect
> **Goal:** Ensure the right configurations, access, and processes are in place *before* this incident type occurs.

### 1.1 Required AWS Service Configurations

Confirm the following are enabled and configured in all applicable accounts and regions before an incident occurs.

- [ ] AWS CloudTrail enabled with a **multi-region** trail, **log-file validation** enabled, delivered to an S3 bucket in a **dedicated security account** with cross-account bucket policies that deny the workload account `s3:DeleteObject` on log files
- [ ] CloudTrail data events enabled for `AWS::BedrockAgentCore::Gateway` on the trails that need `InvokeGateway` visibility (Gateway data events are opt-in)
- [ ] Amazon GuardDuty enabled with findings exported to Security Hub; alerting on `Stealth:IAMUser/CloudTrailLoggingDisabled`
- [ ] AWS Config enabled with delivery channel configured and the rules `cloudtrail-enabled`, `cloudtrail-s3-dataevents-enabled`, `multi-region-cloudtrail-enabled`, and `cloudwatch-log-group-encrypted`
- [ ] CloudWatch **Transaction Search** enabled in every account hosting AgentCore resources (the ingestion pipeline for `aws/spans`); the `TransactionSearchXRayAccess` resource policy present on the `aws/spans` and `aws/application-signals/data` log groups
- [ ] AgentCore vended logs enabled where investigation requires them: Runtime `USAGE_LOGS` **and** `APPLICATION_LOGS`, and Gateway `APPLICATION_LOGS` (`/aws/vendedlogs/bedrock-agentcore/gateway/APPLICATION_LOGS/{gateway_id}`) — these are the only AWS-side source of unredacted `tools/call` request/response bodies
- [ ] Security-relevant log groups KMS-encrypted with a customer-managed key whose key policy denies disable/schedule-deletion to all but a break-glass admin; retention set to ≥365 days
- [ ] EventBridge auto-remediation rules on `StopLogging`, `DeleteTrail`, `DeleteLogGroup`, and `UpdateTraceSegmentDestination` that page the security team and re-enable the tampered component
- [ ] Evaluations IAM role scoped to *only* the designated trace-span log group, with `aws:SourceAccount`/`aws:SourceArn` confused-deputy guards on its trust policy
- [ ] VPC Lattice access logs enabled for any Gateway target using a **private endpoint**. Such targets flow through a Resource Gateway via VPC Lattice — not through customer-managed VPC ENIs — so VPC Flow Logs do **not** capture the Gateway → private-target traffic. VPC Lattice emits two distinct access-log types: `VpcLatticeAccessLogs` (service networks and services) and `VpcLatticeResourceAccessLogs` (resource configurations). A Resource Gateway is a **resource configuration**, so the responder needs `VpcLatticeResourceAccessLogs` — not the more commonly documented service-network log; enable both if you also operate service networks. These logs are only an evidence source if enabled *before* the incident. The `x-amzn-requestid` header is propagated to targets and included in the access log, giving a correlation key back to the Gateway OTel `aws/spans` span (`aws.request.id`) that initiated the private-target call.

  ```bash
  aws vpc-lattice create-access-log-subscription \
    --resource-identifier <resource-config-arn> \
    --destination-arn <cw-log-group-or-s3-or-firehose-arn>
  ```

> 🤖 **Automation opportunity:** Use AWS Config conformance packs (Operational Best Practices for CloudTrail / CloudWatch) plus an EventBridge → Lambda re-enable function to continuously validate and self-heal these prerequisites, shrinking any future blindspot window from hours to seconds.

### 1.2 IAM & Access Prerequisites

Ensure the following access is pre-provisioned and tested — *do not provision break-glass access during an active incident*.

- [ ] Break-glass IAM role with least-privilege IR permissions exists and is documented (must include `cloudtrail:StartLogging`, `cloudtrail:PutEventSelectors`, `logs:CreateLogGroup`/`logs:AssociateKmsKey`/`logs:PutRetentionPolicy`, `kms:CancelKeyDeletion`/`kms:EnableKey`, `xray:UpdateSamplingRule`)
- [ ] IR team members can assume the break-glass role with MFA
- [ ] Access to the AWS Security Incident Response console (if subscribed) is confirmed
- [ ] Forensic account (isolated) is available for evidence preservation, with an Object-Lock (COMPLIANCE) forensic S3 bucket
- [ ] An IaC-managed, version-controlled **known-good** export of: CloudTrail advanced event selectors, the `TransactionSearchXRayAccess` resource policy, the default X-Ray sampling rule, and log-group retention/KMS configuration — so containment restores from a trusted source rather than guesswork
- [ ] An enumerated inventory of every principal holding `cloudtrail:StopLogging`, `logs:DeleteLogGroup`, `xray:UpdateTraceSegmentDestination`, or `kms:ScheduleKeyDeletion`

### 1.3 Communication & Escalation

> 📋 Do not include names. Use roles only. Maintain a separate, access-controlled contact list.

| Role | Responsibility |
|---|---|
| IR Lead | Overall incident coordination, status updates |
| Account / Agent Owner | Business context, authorization for containment actions |
| AI/ML Platform team | AgentCore observability configuration, IaC known-good baseline, redeploy |
| Legal / Compliance | Regulatory notification obligations, evidence hold |
| Communications | Internal and external messaging |
| AWS CIRT | Engage via AWS Support case or Security Incident Response service (P1/P2, if available) |

**Escalation path:**
Detection → IR Lead notified → Severity assessed → P1/P2: AWS CIRT engaged, Legal notified, IR bridge opened → P3/P4: IR Lead manages internally

### 1.4 Game Day Guidance

This playbook should be exercised before it is needed. Recommended testing cadence: **annually at minimum, semi-annually for P1 scenarios.**

Suggested tabletop scenario for this incident type:
> A monitoring alert shows a `StopLogging` event on the organization trail at 02:14 UTC, followed eight minutes later by a `PutRetentionPolicy` reducing the `aws/spans` log group from 365 days to 1 day, and a `ScheduleKeyDeletion` on the CMK that encrypts the AgentCore log groups. Walk the team from detection through the "re-enable logging first" containment ordering, blindspot-window scoping, and KMS key-deletion cancellation — then decide whether the concurrent activity warrants escalation to a full account kill switch.

Reference: [AWS Security Incident Response Game Days](https://docs.aws.amazon.com/security-ir/latest/userguide/game-days.html)

---

## Part 2 — Detect & Analyze

> **CSF 2.0 Functions:** Detect · Respond (Analyze)
> **Goal:** Confirm whether an incident has occurred, scope its impact, and gather evidence for containment and investigation.

### 2.1 Initial Triage Questions

Answer these quickly to determine scope and priority. Each question should take < 2 minutes to answer.

- [ ] Is this a confirmed incident or an anomalous finding requiring investigation?
- [ ] Which AWS accounts and regions are potentially affected, and do they host AgentCore resources?
- [ ] Is CloudTrail capture currently halted, deleted, or redirected for any of those accounts (is the primary evidence source live *right now*)?
- [ ] Was a KMS key that encrypts AgentCore logs, Memory, or the Token Vault disabled or scheduled for deletion?
- [ ] Is the tampering still in progress, or is the actor still active in the environment?
- [ ] Has any data left the AWS environment (e.g., an attacker-installed subscription filter or a redirected `UpdateTrail` S3 destination)?
- [ ] What is the blindspot window — the time between the first tampering action and now — and what activity is unaccounted for within it?

**If 3 or more questions are answered YES → escalate to P1 immediately** and proceed to evidence preservation before completing full analysis.

### 2.2 Evidence Collection Checklist

Collect and preserve the following **before taking any containment actions**. Evidence collected after containment may be incomplete or altered.

> ⚠️ **Do not modify or delete the tampered resource before snapshotting its current (tampered) configuration — the tampered state is itself evidence.** Capture `get-trail-status`, `describe-trails`, `get-event-selectors`, `describe-log-groups`, the current X-Ray sampling rules, and the KMS key state into the forensic bucket first.

| Evidence Type | How to Collect | Where to Store |
|---|---|---|
| CloudTrail config + status (current, tampered state) | `aws cloudtrail describe-trails`, `get-trail-status`, `get-event-selectors` | Forensic S3 (Object Lock) |
| CloudTrail logs for the incident window | Athena / Logs Insights / CLI — copy **before** any `PutEventSelectors` reversal | Forensic S3 |
| GuardDuty / Security Hub finding JSON | Console export | Forensic S3 |
| Log Group state (retention, KMS, subscription filters, deliveries) | `aws logs describe-log-groups`, `describe-subscription-filters`, `describe-deliveries` | Forensic S3 |
| X-Ray config (sampling rules, trace-segment destination) | `aws xray get-sampling-rules`, `get-trace-segment-destination` | Forensic S3 |
| KMS key state + grants | `aws kms describe-key`, `list-grants` | IR ticket / Forensic S3 |
| Evaluations IAM role policy + AssumeRole history | `aws iam get-role`, CloudTrail `AssumeRole` query | IR ticket / Forensic S3 |
| CloudWatch metric values (persist even when logs tampered) | `aws cloudwatch get-metric-statistics` | Forensic S3 |

> 📌 **Memory data-plane APIs do not emit CloudTrail events** (`DeleteEvent`, `BatchDeleteMemoryRecords`, `StartMemoryExtractionJob`, etc. are observability-only). When tampering targets the observability surface, you cannot fall back to CloudTrail to reconstruct Memory write/delete activity — that activity is visible *only* via OTel spans or Memory structured logs, which makes any tampering against those span/log sources especially destructive. Capture Memory spans/logs early.

**Enumerating the AgentCore observability sources.** The AgentCore service namespace is `AWS/Bedrock-AgentCore` (hyphen between `Bedrock` and `AgentCore`). To discover which metrics and dimension combinations the service is actually emitting in the affected account — the starting point for selecting an evidence source:

```bash
aws cloudwatch list-metrics --namespace "AWS/Bedrock-AgentCore" \
  --output json | jq -r '.Metrics[] | "\(.MetricName) | \(.Dimensions | map("\(.Name)=\(.Value)") | join(","))"' \
  | sort -u
```

Runtime/Gateway `APPLICATION_LOGS` and `USAGE_LOGS` are emitted through the CloudWatch Logs vended-log delivery pipeline, not by direct `PutLogEvents`. Verify a delivery exists (and is not the target of vended-delivery tampering) by enumerating the delivery sources and deliveries that reference an AgentCore resource ARN:

```bash
aws logs describe-delivery-sources --output json \
  | jq -r '.deliverySources[] | select(.resourceArns[]? | contains("bedrock-agentcore")) | .name'
aws logs describe-deliveries --output json \
  | jq -r '.deliveries[] | select(.deliverySourceName | contains("bedrock-agentcore"))'
```

If a delivery exists but a downstream query still returns zero rows, the issue is "no activity in window" rather than missing data — distinguish these before concluding evidence is gone.

**X-Ray trace investigation.** When the affected runtime is instrumented, X-Ray ties together the Runtime invocation, Gateway target invocations, downstream target executions, and Bedrock model invocations as a single parent-child trace — the evidence needed to confirm a Gateway target was used as an exfiltration path. Pull the trace summaries for the runtime under investigation:

```bash
aws xray get-trace-summaries --start-time "$LOOKBACK_24H" --end-time "$NOW_UTC" \
  --filter-expression 'service("bedrock-agentcore") AND annotation.AgentRuntimeId = "'$AGENT_RUNTIME_ID'"' \
  --output json > /tmp/ir/$INCIDENT_ID/xray-summaries.json
```

Then retrieve segment detail for specific traces — for example, to surface sessions that hit external (non-AWS) destinations via the Gateway, which appear in trace segments even when CloudTrail data events are not enabled:

```bash
aws xray batch-get-traces --trace-ids <trace-id-list> \
  --output json | jq '.Traces[].Segments[].Document | fromjson | select(.http.request.url | test("amazonaws\\.com") | not)'
```

**Useful CloudTrail / Logs Insights queries for this scenario:**

```sql
-- Find CloudTrail lifecycle/selector tampering in the incident window
-- (StopLogging halts capture; PutEventSelectors can silently drop AgentCore
--  events while the trail still appears healthy; UpdateTrail can redirect
--  delivery to an attacker bucket)
SELECT eventTime, eventName, userIdentity.arn AS principal,
       sourceIPAddress, requestParameters
FROM cloudtrail_logs
WHERE eventSource = 'cloudtrail.amazonaws.com'
  AND eventName IN ('StopLogging','StartLogging','UpdateTrail','DeleteTrail',
                    'PutEventSelectors','PutInsightSelectors')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime DESC;
```

```sql
-- Find KMS key tampering that would render AgentCore logs / Memory / Token Vault
-- unreadable (ScheduleKeyDeletion and DisableKey are evidence-destruction, not
-- exfiltration, vectors)
SELECT eventTime, eventName, userIdentity.arn AS principal,
       requestParameters.keyId AS key_id
FROM cloudtrail_logs
WHERE eventSource = 'kms.amazonaws.com'
  AND eventName IN ('ScheduleKeyDeletion','DisableKey','PutKeyPolicy',
                    'RetireGrant','RevokeGrant')
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime DESC;
```

> *(Additional scenario-specific Logs Insights queries — CloudWatch Logs tampering, vended-delivery tampering, X-Ray sampling changes, and Evaluations role abuse — are in [Appendix A](#appendix-a--useful-queries).)*

### 2.3 Severity Determination

Based on triage and initial evidence, assign a priority using the criteria in [Severity Classification](#severity-classification).

| Confirmed? | Priority Assignment |
|---|---|
| CloudTrail halted/redirected on an AgentCore account, or KMS key disabled/scheduled-for-deletion, or active exfiltration via subscription filter | P1 |
| Confirmed observability change, actor no longer active, blindspot bounded | P2 |
| Anomalous observability change, scope/intent unclear | P3 |
| Observability drift on a non-security resource, no active threat | P4 |

After confirming the tampering, run the scope analysis:

1. **Identify the tampered signal.** For CloudTrail, note which trail, which selectors changed, and during what window. For CloudWatch Logs, note which log group, what retention was set, and whether a subscription filter was added (which would indicate exfiltration rather than destruction). For Transaction Search / X-Ray, note whether sampling was reduced to zero or the destination changed. For the Evaluations role, note whether it was assumed cross-account and whether new custom evaluators were created.
2. **Assess the evidence gap.** The blindspot window is the time between the first tampering action and detection. Within it, treat activity as unknown. Document the window bounds in the incident ticket so subsequent investigation can cross-reference sources that survive log tampering — CloudWatch metric values, billing/Cost Explorer deltas, VPC Flow Logs, agent application logs in untampered groups, and external-system logs.
3. **Validate CloudTrail log-file integrity.** If log-file validation was enabled, validate digest files to detect tampering of the log files themselves (distinct from tampering of the trail configuration). Any file that fails validation during the blindspot window is inadmissible and must be treated as unreliable.

   ```bash
   aws cloudtrail validate-logs --trail-arn "$TRAIL_ARN" \
     --start-time "$LOOKBACK_7D" --end-time "$NOW_UTC"
   ```

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

Before acting, consider the tradeoff — but note the inversion specific to this scenario: for observability tampering, the **first** containment action is always to restore visibility, because every other decision below depends on having a live evidence source. You cannot reliably assess whether the threat is "active" or "inactive" while CloudTrail is disabled — so re-enable logging first, *then* evaluate the rest of the tree.

```text
Is containment action required immediately?
│
├── YES (logging disabled/redirected, KMS key pending deletion, live subscription-filter exfiltration)
│     └── Proceed to 3.2 immediately — re-enable logging FIRST, accept potential service disruption
│
└── NO (single bounded change, actor appears inactive)
      └── Consult Account Owner and IR Lead before proceeding
            Can we restore observability without service disruption?
            ├── YES → Proceed to 3.2 (still restore logging first)
            └── NO  → Document business impact, obtain authorization, then proceed
```

### 3.2 Containment Actions

> `[IR Lead]` coordinates. `[Account / Agent Owner]` authorizes actions that may cause service disruption. **The ordering below is deliberate: restore the evidence sources before anything else, or you work blind.** Restore each component from the IaC-known-good source rather than guessing at the prior configuration.

1. **Re-enable CloudTrail logging and restore selectors — before any other containment.**
   Additional investigation and containment steps are unreliable while CloudTrail is disabled or its selectors are still narrowed. Start logging, then restore the advanced event selectors from the IaC known-good file, then verify. If `UpdateTrail` redirected delivery to an attacker bucket, also re-point the S3 destination to the trusted security-account bucket.

   ```bash
   aws cloudtrail start-logging --name "$TRAIL_NAME"
   aws cloudtrail put-event-selectors --trail-name "$TRAIL_NAME" \
     --advanced-event-selectors file:///path/to/iac-known-good-selectors.json
   aws cloudtrail get-event-selectors --trail-name "$TRAIL_NAME"
   ```

2. **Restore the CloudWatch Transaction Search pipeline if it was tampered with.**
   The `aws/spans` and `aws/application-signals/data` log groups must exist, must be KMS-encrypted, and must carry the `TransactionSearchXRayAccess` resource policy that grants X-Ray permission to write spans. Without this, every span-based query returns zero rows.

   ```bash
   aws logs put-resource-policy --policy-name TransactionSearchXRayAccess \
     --policy-document file:///path/to/iac-known-good-xray-trust.json
   aws xray update-trace-segment-destination --destination CloudWatchLogs
   ```

3. **Restore Log Group state.**
   If the log group was deleted, recreate it with KMS encryption and the IaC-documented retention. If retention was reduced, restore it. If a subscription filter was added by the attacker, delete it immediately — an attacker-installed subscription filter is a **live exfiltration channel** that keeps leaking log events until removed. Pay special attention to AgentCore observability groups: `aws/spans`, `aws/application-signals/data`, agent-specific application log groups, and the Gateway vended group `/aws/vendedlogs/bedrock-agentcore/gateway/APPLICATION_LOGS/{gateway_id}`.

   ```bash
   aws logs create-log-group --log-group-name "$LOG_GROUP_NAME" --kms-key-id "$KMS_KEY_ARN"
   aws logs put-retention-policy --log-group-name "$LOG_GROUP_NAME" --retention-in-days 365
   aws logs associate-kms-key --log-group-name "$LOG_GROUP_NAME" --kms-key-id "$KMS_KEY_ARN"
   aws logs delete-subscription-filter --log-group-name "$LOG_GROUP_NAME" \
     --filter-name "<attacker-filter-name>"
   ```

   Also check for **vended-log delivery** tampering: an attacker with `logs:DeleteDelivery` or `logs:DeleteDeliverySource` can disable Gateway/Runtime `APPLICATION_LOGS` delivery without touching the log group, producing an instant blindspot for request/response content with no retention or subscription-filter change to alert on. Restore the delivery from IaC.

4. **Cancel KMS key deletion and re-enable any disabled keys.**
   Scheduled key deletions have a pending window (minimum 7 days); cancel during that window to preserve the key — encrypted log groups, Memory, and the Token Vault are all readable only through KMS, so a deleted key destroys access to everything encrypted under it. Then recreate any grants that were revoked.

   ```bash
   aws kms cancel-key-deletion --key-id "$KMS_KEY_ARN"
   aws kms enable-key --key-id "$KMS_KEY_ARN"
   ```

5. **Restore X-Ray sampling.**
   Deploy the IaC-known-good sampling rule so new invocations produce traces again. Historical traces not sampled during the tampering window are lost, but future traces resume.

   ```bash
   aws xray update-sampling-rule \
     --sampling-rule-update file:///path/to/iac-default-sampling.json
   ```

6. **Revoke the Evaluations IAM role session and tighten its scope.**
   Attach an inline deny policy conditioned on `aws:TokenIssueTime` earlier than now to invalidate every session issued before the revocation timestamp. If new evaluators or evaluation configs were created during the incident, delete them — they may reference attacker-controlled prompts or models that leak sampled agent responses. (`$EVAL_IAM_ROLE_NAME` is the unqualified role name used by `put-role-policy`; CloudTrail filters and `iam simulate-principal-policy --policy-source-arn` take the full ARN instead — do not conflate them.)

   ```bash
   REVOKE_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
   cat > /tmp/revoke-eval.json <<EOF
   {"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",
    "Condition":{"DateLessThan":{"aws:TokenIssueTime":"$REVOKE_TIME"}}}]}
   EOF
   aws iam put-role-policy --role-name "$EVAL_IAM_ROLE_NAME" \
     --policy-name "IR-RevokeSessions-$INCIDENT_ID" \
     --policy-document file:///tmp/revoke-eval.json
   ```

7. **If the scope is unclear or the attacker retains broad permissions, escalate to the AgentCore emergency kill switch.**
   The kill switch severs every AgentCore authorization path across six sequential phases — (1) block new API calls via an emergency SCP denying `bedrock-agentcore:*`, `bedrock:InvokeModel`, and stack-mutation actions except the responder role; (2) sever authentication by disabling Cognito users, deleting confidential App Clients, workload identities, and credential providers; (3) sever authorization by forcing every Gateway to `ENFORCE` and applying a deny-all Cedar policy; (4) sever tool access by deleting Gateway targets and resource policies; (5) sever network and active sessions by stopping sandbox sessions and isolating ENIs; and (6) prevent recreation by neutralizing SSM parameters and AgentCore EventBridge rules. It terminates *all* agentic workflows in the account — legitimate and compromised — so obtain explicit written authorization and run a blast-radius impact assessment first.

8. **Apply an SCP guardrail against recurrence.**
   Deploy at the OU level after recovery. Use `ArnNotLike` (not `StringNotEquals`/`StringNotLike`) for the `aws:PrincipalArn` exemption: `StringNotEquals` treats `*` as a literal character, so a wildcard in the exempted ARN's account segment would never match and the deny would apply universally — including to the security admin meant to be exempted.

   ```json
   {
     "Sid": "DenyObservabilityTampering",
     "Effect": "Deny",
     "Action": [
       "cloudtrail:StopLogging","cloudtrail:DeleteTrail","cloudtrail:UpdateTrail",
       "cloudtrail:PutEventSelectors",
       "logs:DeleteLogGroup","logs:PutRetentionPolicy","logs:DeleteRetentionPolicy",
       "logs:DisassociateKmsKey","logs:DeleteSubscriptionFilter","logs:PutResourcePolicy",
       "logs:DeleteDelivery","logs:DeleteDeliverySource",
       "xray:UpdateSamplingRule","xray:DeleteSamplingRule",
       "xray:UpdateTraceSegmentDestination","xray:UpdateIndexingRule",
       "kms:ScheduleKeyDeletion","kms:DisableKey","kms:RetireGrant","kms:RevokeGrant"
     ],
     "Resource": "*",
     "Condition": { "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/SecurityAdminRole" } }
   }
   ```

> 🤖 **Automation opportunity:** An EventBridge rule on `StopLogging` / `DeleteTrail` / `DeleteLogGroup` / `UpdateTraceSegmentDestination` targeting a Lambda that re-enables the tampered component shrinks the blindspot window from hours to seconds. [Link TBD]

### 3.3 Evidence Preservation Reminders

After containment begins, ensure the following before modifying or terminating any further resources:

- [ ] The tampered configuration state (trail status, selectors, log-group retention/KMS, sampling rules, KMS key state) was snapshotted to the forensic bucket **before** restoration overwrote it
- [ ] CloudTrail events for the window exported to the forensic bucket and integrity-validated (`aws cloudtrail validate-logs`)
- [ ] Memory OTel spans / structured logs captured (Memory data-plane activity is not in CloudTrail)
- [ ] S3 Object Lock / legal hold applied to the forensic bucket
- [ ] Blindspot-window bounds (first tampering action → detection) documented in the IR ticket
- [ ] KMS grant/key-policy state recorded before any grant is recreated

---

## Part 4 — Eradicate & Recover

> **CSF 2.0 Function:** Respond (Eradicate) · Recover
> **Goal:** Remove the root cause, validate the environment is clean, and restore normal operations.

### 4.1 Root Cause Identification

> `[IR Lead]` owns this step. Document findings in the IR ticket in real time.

Determine the root cause before beginning eradication. Common root causes for this incident type:

- An over-broad IAM or developer role holding `cloudtrail:StopLogging`, `logs:DeleteLogGroup`, `xray:UpdateTraceSegmentDestination`, or `kms:ScheduleKeyDeletion` with no business need.
- A compromised credential (key, Cognito session, or workload identity) escalated to logging-modification permissions.
- A missing organization-level SCP guardrail allowing any workload-account principal to mutate trail or log-group configuration.
- An over-privileged Evaluations IAM role granting read access to log groups beyond the designated trace-span group, used to mine spans containing PII or system prompts.
- A KMS key policy that permitted `ScheduleKeyDeletion` / `DisableKey` to a non-break-glass principal.

Use evidence collected in Part 2 to trace the initial access vector and full attack path. Because CloudTrail was impaired during the blindspot window, reconstruct activity from sources that survive log tampering (see 4.2 step 1).

### 4.2 Eradication Actions

> `[IR Lead]` coordinates. `[Account / Agent Owner]` approves changes to production resources.

1. **Reconstruct the blindspot window from untampered sources.**
   CloudTrail was impaired during the window, so rely on: CloudWatch metric values (which persist even when log sources are tampered with); billing and Cost Explorer deltas (activity bills even when not logged); VPC Flow Logs if applicable; agent application logs if emitted to a log group other than the tampered one; and logs from external systems (OAuth providers, third-party tools, downstream APIs). Each gives a partial reconstruction; together they narrow the unknowns. Note that AgentCore Memory long-term extraction, Policy Engine evaluators, and Evaluations can invoke Bedrock models via cross-region inference (CRIS) — so for model-invocation reconstruction, query CloudTrail in every region AgentCore might route to, not just the originating region.

2. **Audit every principal with observability-modification permissions.**
   Use IAM Access Analyzer to enumerate principals holding `cloudtrail:StopLogging`, `logs:DeleteLogGroup`, `xray:UpdateTraceSegmentDestination`, or `kms:ScheduleKeyDeletion` — each is a potential attacker foothold that could repeat the tampering. Scope each role to the minimum needed for legitimate operation, and remove the permission entirely from any role that has no business need.

3. **Review Evaluations Log Group access.**
   Evaluations reads trace spans from a customer-specified log group; spans may contain PII or system prompts the Evaluations output was never supposed to expose. Use IAM policy simulation to confirm the Evaluations role has access only to the designated group and not to any other log source.

   ```bash
   aws iam simulate-principal-policy --policy-source-arn "$EVAL_IAM_ROLE_ARN" \
     --action-names logs:GetLogEvents \
     --resource-arns "arn:aws:logs:$AWS_REGION:$ACCOUNT_ID:log-group:*"
   ```

4. **Remove attacker persistence mechanisms.**
   Check for and remove:
   - [ ] Unauthorized IAM users, roles, or access keys created during the incident (especially any granting logging-modification or KMS permissions)
   - [ ] Attacker-installed CloudWatch Logs subscription filters or redirected vended-log deliveries
   - [ ] Redirected CloudTrail S3 destinations (`UpdateTrail`) pointing at attacker-controlled buckets
   - [ ] Modified KMS key policies or grants that retain attacker access
   - [ ] EventBridge rules that re-disable logging or re-schedule key deletion after recovery
   - [ ] Unauthorized custom Evaluators (`CreateEvaluator`/`UpdateEvaluator`) referencing non-baseline prompts or models

> 🤖 **Automation opportunity:** AWS Config auto-remediation rules (`cloudtrail-enabled`, `cloudwatch-log-group-encrypted`) can detect and revert some of these configuration changes automatically. [Link TBD]

### 4.3 Recovery Actions

1. **Restore from known-good state.**
   Redeploy the trail, log groups, KMS grants, X-Ray sampling rules, Transaction Search configuration, and AgentCore observability configuration from IaC, pinned to the last known-good commit. For stateless observability configuration this is the restore point; historical telemetry lost during the blindspot window cannot be recovered, so document the gap in the incident record.

2. **Re-enable services and access.**
   - [ ] Confirm the trail is *actively logging and delivering* — a trail can exist but not deliver files; verify both with `aws cloudtrail get-trail-status --name "$TRAIL_NAME"`
   - [ ] Restore IAM access for legitimate principals with newly scoped (least-privilege) policies
   - [ ] Re-enable any observability components suspended during containment
   - [ ] Confirm every AgentCore log group has KMS encryption, ≥365-day retention for security-relevant groups, and no unauthorized subscription filters

3. **Harden against recurrence.**
   - [ ] Apply the observability-tampering SCP from § 3.2 permanently at the OU level
   - [ ] Move CloudTrail log storage to a dedicated security account with cross-account bucket policies denying the workload account delete permissions
   - [ ] Enable CloudTrail log-file validation on every trail (required for forensic admissibility)
   - [ ] Generate a diagnostic `InvokeAgentRuntime` call and confirm it appears in CloudWatch Logs, CloudTrail, CloudWatch GenAI Observability, and X-Ray within five minutes — if any of the four sources does not show it, recovery is incomplete

### 4.4 Recovery Validation

Confirm the environment is clean before declaring the incident resolved.

- [ ] No unauthorized resources, subscription filters, redirected deliveries, or KMS grants remain in affected accounts
- [ ] All credentials created or used by the attacker have been revoked; the Evaluations role scope is least-privilege
- [ ] GuardDuty / Security Hub show no active findings related to this incident
- [ ] A diagnostic invocation is visible across all four observability sources within five minutes
- [ ] Monitoring and alerting confirmed operational; EventBridge re-enable automation tested
- [ ] No repeat tampering observed over a 48-hour monitoring window (an attacker who retains credentials may try again once attention moves on)
- [ ] AWS Security Incident Response case updated / closed (if applicable)

---

## Part 5 — Post-Incident Activity

> **CSF 2.0 Function:** Identify (Improve) — continuous improvement, not a one-time activity
> **Goal:** Learn from this incident to reduce the likelihood and impact of future occurrences.

### 5.1 Timeline Reconstruction

Document the full incident timeline. Complete this within 24–48 hours while memory is fresh.

| Timestamp (UTC) | Event | Source / Evidence | Actor |
|---|---|---|---|
| YYYY-MM-DD HH:MM | First tampering action (e.g., `StopLogging`) — start of blindspot window | CloudTrail (pre-tampering) / GuardDuty `eventFirstSeen` | Threat actor |
| YYYY-MM-DD HH:MM | Detection signal fired (e.g., `Stealth:IAMUser/CloudTrailLoggingDisabled`) | GuardDuty / CloudWatch alarm | AWS / monitoring |
| YYYY-MM-DD HH:MM | IR team notified | On-call alert | IR Lead |
| YYYY-MM-DD HH:MM | Logging re-enabled (end of blindspot window) | IR ticket | IR Lead |
| YYYY-MM-DD HH:MM | Containment completed | IR ticket | IR Lead |
| YYYY-MM-DD HH:MM | Recovery validated | IR ticket | IR Lead |

**Key metrics to capture:**

| Metric | Value |
|---|---|
| Time to Detect (TTD) | *HH:MM from first tampering action to detection* |
| Time to Notify (TTN) | *HH:MM from detection to IR team notified* |
| Time to Contain (TTC) | *HH:MM from notification to logging re-enabled* |
| Time to Recover (TTR) | *HH:MM from containment to recovery validated* |
| Blindspot Window Duration | *HH:MM — first tampering action to logging restored* |
| Total Incident Duration | *HH:MM* |
| Affected Resources | *Count and type (trails, log groups, KMS keys, roles)* |
| Data Impact | *Confirmed / Suspected / None* |

### 5.2 Post-Incident Review

Conduct a blameless post-incident review within **5 business days** for P1/P2, **15 business days** for P3/P4.

Discussion questions:

1. What was the initial access vector for the logging-modification permissions? Could an SCP have prevented it?
2. How was the tampering detected, and how long was the blindspot window? Was detection fast enough?
3. Were the right people notified at the right time?
4. Did the "re-enable logging first" containment ordering work as expected? Were there unintended side effects?
5. Were there gaps in runbooks, automation, or IaC known-good exports that slowed restoration?
6. Which untampered sources (metrics, billing, external logs) proved most valuable for reconstructing the blindspot window? What would have made reconstruction easier?
7. What single change would most improve our response to this scenario in future — e.g., EventBridge auto-remediation, log storage in a separate security account, or tighter KMS key policies?

### 5.3 Detection Gap Analysis

For each detection source that *did not* catch this incident early, document why and what would have.

| Gap | Root Cause | Recommended Fix | Owner | Target Date |
|---|---|---|---|---|
| *(e.g., `StopLogging` not alarmed)* | *(No EventBridge rule on CloudTrail lifecycle events)* | *(Add rule + auto re-enable Lambda)* | | |
| *(e.g., Retention reduction undetected)* | *(No AWS Config rule on log-group retention)* | *(Add Config rule + alarm)* | | |
| *(e.g., KMS schedule-deletion not paged)* | *(No alarm on `ScheduleKeyDeletion` for AgentCore keys)* | *(Add CloudWatch alarm; tighten key policy)* | | |
| *(e.g., Evaluations span-mining invisible)* | *(No baseline on Evaluations-role `AssumeRole` source)* | *(Alarm on unexpected AssumeRole source)* | | |

### 5.4 Playbook Update Checklist

Review and update this playbook based on what you learned. Do not wait for the next scheduled review.

- [ ] Were triage questions sufficient (especially the blindspot-window and KMS questions)? Add/remove as needed.
- [ ] Were evidence collection steps accurate — was the tampered config snapshotted before restoration?
- [ ] Was the "re-enable logging first" ordering effective? Update steps if not.
- [ ] Were automation opportunities identified (EventBridge auto-remediation, Config rules)? Add stubs to relevant sections.
- [ ] Were severity criteria accurate? Adjust if incidents were under- or over-classified.
- [ ] Update **Last Reviewed** date and increment **Playbook Version**.

---

## Appendix A — Useful Queries

### CloudTrail (Athena)

```sql
-- Template query: All API activity in a time window for a specific principal
-- (use to investigate the principal that performed the tampering)
SELECT eventTime, eventName, awsRegion, sourceIPAddress, userAgent,
       errorCode, errorMessage
FROM cloudtrail_logs
WHERE userIdentity.arn = 'arn:aws:iam::111122223333:role/SUSPECTED_ROLE'
  AND eventTime BETWEEN 'START_TIME' AND 'END_TIME'
ORDER BY eventTime ASC;
```

```sql
-- Scenario query: every AssumeRole on the Evaluations IAM role
-- (an assume from an unexpected source indicates the role is being
--  misappropriated to mine agent trace spans rather than produce evaluations)
SELECT eventTime, sourceIPAddress, userIdentity.arn AS assuming_principal
FROM cloudtrail_logs
WHERE eventSource = 'sts.amazonaws.com'
  AND eventName = 'AssumeRole'
  AND requestParameters.roleArn = 'EVAL_IAM_ROLE_ARN'
ORDER BY eventTime ASC;
```

### CloudWatch Logs / vended-delivery tampering (Logs Insights)

```text
# CloudWatch Log Group tampering against AgentCore observability groups
# (DeleteLogGroup destroys evidence; PutRetentionPolicy ages it out early;
#  PutSubscriptionFilter is a live exfiltration channel)
fields @timestamp, eventName, userIdentity.arn,
       requestParameters.logGroupName, requestParameters.retentionInDays
| filter eventSource = "logs.amazonaws.com"
| filter eventName in [
    "DeleteLogGroup","PutRetentionPolicy","DeleteRetentionPolicy",
    "AssociateKmsKey","DisassociateKmsKey","PutSubscriptionFilter","DeleteSubscriptionFilter"
  ]
| filter (requestParameters.logGroupName like /bedrock-agentcore/
          or requestParameters.logGroupName like /aws\/spans/
          or requestParameters.logGroupName like /application-signals/
          or requestParameters.logGroupName like /aws\/vendedlogs\/bedrock-agentcore/)
| sort @timestamp desc
```

```text
# Vended-log delivery tampering — disables Gateway/Runtime APPLICATION_LOGS
# without touching the log group (no retention/subscription change to alert on)
fields @timestamp, eventName, userIdentity.arn,
       requestParameters.name, requestParameters.resourceArns
| filter eventSource = "logs.amazonaws.com"
| filter eventName in [
    "DeleteDelivery","DeleteDeliverySource","DeleteDeliveryDestination",
    "UpdateDeliveryConfiguration"
  ]
| filter @message like /bedrock-agentcore/
| sort @timestamp desc
```

### X-Ray / Transaction Search tampering (Logs Insights)

```text
# Transaction Search / X-Ray configuration changes — disabling Transaction Search
# or zeroing sampling cuts off every span-based investigation path
fields @timestamp, eventName, userIdentity.arn, requestParameters
| filter eventSource = "xray.amazonaws.com"
| filter eventName in ["UpdateTraceSegmentDestination","UpdateIndexingRule",
                       "CreateSamplingRule","UpdateSamplingRule","DeleteSamplingRule"]
| sort @timestamp desc
```

### Custom Evaluator tampering (Logs Insights)

```text
# Custom LLM-as-Judge evaluators invoke a customer-specified Bedrock model and see
# every response they evaluate — an attacker-created evaluator can leak sampled output
fields @timestamp, eventName, userIdentity.arn, requestParameters.definition
| filter eventSource = "bedrock-agentcore.amazonaws.com"
| filter eventName in ["CreateEvaluator","UpdateEvaluator","DeleteEvaluator",
                       "CreateOnlineEvaluationConfig","UpdateOnlineEvaluationConfig"]
| sort @timestamp desc
```

### CloudTrail log-file integrity validation (CLI)

```bash
# Validate digest files to detect tampering of the log files themselves
# (distinct from tampering of the trail configuration). A file that fails
# validation during the blindspot window is inadmissible as evidence.
aws cloudtrail validate-logs --trail-arn "$TRAIL_ARN" \
  --start-time "$LOOKBACK_7D" --end-time "$NOW_UTC"
```

> **Contributors:** The queries above are tailored to observability tampering. Adjust the log-group name patterns and the `eventSource` filters to match your account's actual AgentCore log-group naming. See [CloudTrail query examples](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html).

---

## Appendix B — Regulatory & Compliance Considerations

> `[Legal / Compliance]` owns this section during an active incident.

See [Regulatory Context](../../REGULATORY_CONTEXT.md) for the full notification obligation matrix by regulation and incident type.

Observability tampering carries a distinctive regulatory posture: because the evidence base was deliberately degraded, you may be **unable to prove** that personal data was *not* accessed during the blindspot window. Many regimes treat an inability to rule out access — combined with confirmed defense evasion — as sufficient to trigger notification. Determine the data classification of records reachable during the blindspot window (Memory conversation content/PII, Token Vault credentials, Evaluations spans that may contain sampled response content) early, and consult Legal before concluding "no notifiable impact."

**Quick reference for this scenario:**

| Regulation | Trigger Condition | Timeframe |
|---|---|---|
| GDPR Art. 33 | Personal data confirmed — *or cannot be ruled out as* — accessed during the blindspot window | 72 hours to supervisory authority from awareness |
| HIPAA Breach Notification Rule | PHI in Memory/spans potentially accessed and access cannot be excluded | Without unreasonable delay; ≤60 days |
| PCI-DSS | Cardholder data environment telemetry tampered (Req. 10 logging integrity) | Per acquirer/brand agreement; notify promptly |
| State breach-notification laws | Resident personal data potentially exposed during blindspot | Varies by state (often "without unreasonable delay") |
| Sector-specific AI-governance regimes | Agent-system security incident affecting a regulated workload | Per applicable regime |

> ⚠️ The clock starts at **awareness**, not confirmation. When in doubt — and an impaired evidence base means doubt is the default for this scenario — assume notification is required and consult Legal immediately.

---

## Appendix C — Reference Links

- [NIST SP 800-61r3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html)
- [AWS Security Incident Response Service Documentation](https://docs.aws.amazon.com/security-ir/latest/userguide/what-is-security-ir.html)
- [AWS Well-Architected Framework — Security Pillar: Incident Response](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/incident-response.html)
- [Amazon GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [AWS CloudTrail Query Examples (Athena)](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)
- [Amazon Bedrock AgentCore Developer Guide](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/)
- [Amazon Bedrock AgentCore — Observability](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability.html)
- [AWS CloudTrail — Validating CloudTrail log file integrity](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)
- [Using CloudWatch Logs with CloudWatch Transaction Search](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Application-Signals-transaction-search.html)
- [AWS KMS — Deleting AWS KMS keys (and cancelling deletion)](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html)

---

## Revision History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | 2026-06-20 | AWS | Initial draft |
