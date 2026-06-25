# IRP-AgentCoreAgentIntegrity: Amazon Bedrock AgentCore Agent Integrity (Prompt Injection & Memory Poisoning)

> **Playbook Version:** 1.0
> **Last Reviewed:** 2026-06-20
> **Status:** `Draft`
> **NIST Framework:** SP 800-61r3 (CSF 2.0 Community Profile)
> **Related Playbooks:** [IRP-AgentCoreIdentityCompromise](IRP-AgentCoreIdentityCompromise.md) | [IRP-AgentCoreAuthorizationBypass](IRP-AgentCoreAuthorizationBypass.md) | [IRP-AgentCoreToolAbuse](IRP-AgentCoreToolAbuse.md) | [IRP-AgentCoreObservabilityTampering](IRP-AgentCoreObservabilityTampering.md)

---

> ⚠️ **Disclaimer:** This playbook is provided as a template only. It should be customized to suit your organization's specific needs, risks, available tools, and work processes. This guide is not official AWS documentation and is provided as-is. Security and Compliance is a shared responsibility between you and AWS. You are responsible for making your own independent assessment of the information in this document.

---

## Overview

Agent integrity compromise occurs when an attacker manipulates what an Amazon Bedrock AgentCore agent reasons about or executes, rather than stealing a credential outright. It manifests as prompt injection (an untrusted input steers a single session's behavior), memory poisoning (unauthorized `CreateEvent` or `BatchCreateMemoryRecords` calls insert false context that influences *future* sessions), Runtime artifact tampering (a poisoned S3 ZIP archive or ECR container image that loads at the next cold start), AgentCore Registry supply-chain compromise (a malicious record approved into the centralized catalog that downstream consumers trust without re-review), or Memory Record Streaming exfiltration (the memory's streaming destination repointed to an attacker-controlled Amazon Kinesis stream). It matters because agents act autonomously — once their reasoning is corrupted, the blast radius expands with every tool call and persists across sessions until the poisoned state is purged and the writer is blocked.

### Out of Scope

This playbook does **not** cover:

- Theft or misuse of an AgentCore inbound identity (stolen Cognito JWT, machine-client secret, hijacked workload-identity session) with no memory/artifact/Registry integrity impact — see [IRP-AgentCoreIdentityCompromise](IRP-AgentCoreIdentityCompromise.md).
- Authorization-control failures such as a Cedar `ENFORCE` → `LOG_ONLY` flip via `UpdateGateway`, a rogue `CreateGatewayTarget`, or a cross-account resource-based policy — see [IRP-AgentCoreAuthorizationBypass](IRP-AgentCoreAuthorizationBypass.md).
- Sandbox abuse (Code Interpreter reconnaissance/exfiltration, Browser SSRF, saved-Profile cookie persistence) and Gateway tool misuse where the agent itself was not integrity-compromised — see [IRP-AgentCoreToolAbuse](IRP-AgentCoreToolAbuse.md).
- Tampering with logging/telemetry (`StopLogging`, log-group deletion, KMS disable, X-Ray sampling zeroed) — see [IRP-AgentCoreObservabilityTampering](IRP-AgentCoreObservabilityTampering.md). Note that because Memory data-plane activity is observability-only (see 2.2), an observability-tampering incident can blind this playbook — investigate the two together when both signals appear.

### Applicable Finding Types

List the detection signals that should route a responder to this playbook.

| Source | Finding / Event Type | Severity |
|---|---|---|
| Amazon GuardDuty | `Impact:IAMUser/AnomalousBehavior` or `CredentialAccess:IAMUser/AnomalousBehavior` on an AgentCore execution role / workload identity | HIGH |
| AWS Security Hub | Aggregated finding referencing an AgentCore Memory, Runtime, or Registry resource ARN | CRITICAL/HIGH |
| CloudTrail | `UpdateMemory` altering `streamDeliveryResources.resources[].kinesis.dataStreamArn` to a Kinesis ARN outside your organization | — (treat as P1) |
| CloudTrail | `PutObject` / `CopyObject` / `PutObjectAcl` on the Runtime artifact bucket, or `PutImage` to the Runtime ECR repo, by a principal outside the CI/CD allow-list | — |
| CloudTrail | `CreateRegistryRecord` / `UpdateRegistryRecord` / `UpdateRegistryRecordStatus` outside the IaC approval process | — |
| Observability (NOT CloudTrail) | OTel span or Memory structured-log spike in `CreateEvent` / `BatchCreateMemoryRecords` / `StartMemoryExtractionJob` volume per memory resource | — |
| Custom / Third-Party | Analyst reports manipulated agent output, or a threat actor references exfiltrated conversation/memory content | — |

> 📌 GuardDuty finding types are updated regularly. See the [GuardDuty finding types reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) for the current list.

### Severity Classification

Use this table to determine incident priority at time of detection. Escalate immediately if P1 criteria are met.

| Priority | Criteria |
|---|---|
| **P1 — Critical** (≤15 min) | Confirmed memory exfiltration via repointed Kinesis stream; confirmed Runtime artifact tampering on a production agent; poisoned Registry record reached `APPROVED` and is being consumed; active poisoning of memory that production sessions are reading now |
| **P2 — High** (≤1 hr) | Unauthorized memory writes confirmed but blast radius unclear; tampered artifact found but not yet loaded at cold start; suspicious Registry record in `PENDING_APPROVAL` |
| **P3 — Medium** (≤4 hr) | Anomalous memory write volume or branch activity, no confirmed impact yet; single-session prompt injection with no persistent state change |
| **P4 — Low** (≤1 day) | Configuration drift (e.g., unexpected `memoryStrategies` change) without evidence of exploitation; informational finding |

> **P1 override:** treat as P1 regardless of the matrix if Memory Record Streaming was repointed to a Kinesis destination outside your AWS Organization, or if a tampered Runtime artifact is confirmed and the Runtime has not yet been pinned to a known-good version.

---

## Part 1 — Prepare

> **CSF 2.0 Functions:** Govern · Identify · Protect
> **Goal:** Ensure the right configurations, access, and processes are in place *before* this incident type occurs.

### 1.1 Required AWS Service Configurations

Confirm the following are enabled and configured in all accounts and Regions where AgentCore is deployed before an incident occurs.

- [ ] Amazon GuardDuty (with Runtime Monitoring) enabled, findings exported to AWS Security Hub
- [ ] AWS CloudTrail multi-region trail with log-file validation, delivered to an S3 bucket in a dedicated security account
- [ ] AWS Config enabled with a delivery channel; `AWS::BedrockAgentCore::Memory` is a Config-recorded resource type — its configuration history is the authoritative source for recovering a pre-attack `streamDeliveryResources` value
- [ ] **AgentCore Memory observability enabled** — either Transaction Search (emits Memory OTel spans to the `aws/spans` CloudWatch Log Group) or Memory structured logging. **Both are opt-in. Without one of them enabled before the incident, there is no retrospective detection path for memory writes** (see 2.2). ⚠️ **Account-level Transaction Search is necessary but NOT sufficient** — the **Memory resource itself** must have observability/log delivery configured. A Memory created without per-resource observability emits zero `aws/spans` even when account Transaction Search is on, so the detection queries in 2.2 return nothing. Verify per-resource with `aws bedrock-agentcore-control get-memory --memory-id "$MEMORY_ID"` and confirm an `observabilityConfiguration` / log-delivery is present. To enable: turn on account-wide CloudWatch **Transaction Search** (Console → CloudWatch → Application Signals → Transaction search → *Ingest spans as structured logs*), **then** configure log/trace delivery on each Memory resource. SDK path in the [AgentCore observability-configure docs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-configure.html).
- [ ] OpenTelemetry (ADOT) instrumentation on agents so per-session reasoning, tool calls, and model invocations land in CloudWatch and X-Ray — the only reliable source of agent decision-making evidence after a microVM is destroyed
- [ ] S3 Versioning **and** S3 Object Lock (COMPLIANCE mode) on the Runtime artifact bucket; S3 data events (`GetObject`, `PutObject`) enabled on that bucket — management-only logging misses the attacker's reads of the tampered artifact
- [ ] ECR image immutability enabled on Runtime container repositories; ECR image scanning (Amazon Inspector) on push
- [ ] Two-approver workflow enforced on AgentCore Registry writes so no single principal can drive a record to `APPROVED`. AgentCore has no built-in dual-control primitive, so enforce it externally: deny `bedrock-agentcore:UpdateRegistryRecordStatus` (transition to `APPROVED`) in the day-to-day developer role, and gate the transition behind an approval workflow that requires a second principal — e.g. an EventBridge rule on `CreateRegistryRecord`/`UpdateRegistryRecord` that routes to a Step Functions/manual-approval task, or a CI/CD pipeline whose approval stage runs as a separate role. Separation-of-duty via an IAM condition keyed on the requester vs. approver identity is not reliably expressible on a single API call — prefer the workflow/pipeline gate.

> 🤖 **Automation opportunity:** Use AWS Config conformance packs or Security Hub standards to continuously validate S3 Object Lock, ECR immutability, and Memory-observability prerequisites. [Link TBD]

### 1.2 IAM & Access Prerequisites

Ensure the following access is pre-provisioned and tested — *do not provision break-glass access during an active incident*.

- [ ] Break-glass IAM role with least-privilege IR permissions exists and is documented
- [ ] IR team members can assume the break-glass role with MFA
- [ ] Isolated forensic account is available for evidence preservation, with an S3 bucket using Object Lock (COMPLIANCE) and KMS encryption
- [ ] CI/CD principal allow-list for the Runtime artifact bucket and ECR repository is documented and diffable, so "who legitimately writes artifacts" is answerable in seconds during triage
- [ ] A shared IR permissions boundary exists that can deny `bedrock-agentcore:CreateEvent`, `bedrock-agentcore:BatchCreateMemoryRecords`, and `bedrock-agentcore:StartMemoryExtractionJob` on a compromised execution role without redeploying it
- [ ] Known-good baseline of Memory configuration (`streamDeliveryResources`, `memoryStrategies`) and the IaC commit hash for every Runtime artifact is recorded and diffable

### 1.3 Communication & Escalation

> 📋 Do not include names. Use roles only. Maintain a separate, access-controlled contact list.

| Role | Responsibility |
|---|---|
| IR Lead | Overall incident coordination, status updates |
| Account / Agent Owner | Business context, authorization for containment that may disrupt the agent |
| AI/ML Platform team | AgentCore configuration, IaC known-good baseline, memory/artifact redeploy |
| Legal / Compliance | Regulatory notification obligations, evidence hold |
| Communications | Internal and external messaging |
| AWS CIRT | Engage via AWS Support case or Security Incident Response service (P1/P2, if available) |

**Escalation path:**
Detection → IR Lead notified → Severity assessed → P1/P2: AWS CIRT engaged, Legal notified, IR bridge opened → P3/P4: IR Lead manages internally

### 1.4 Game Day Guidance

This playbook should be exercised before it is needed. Recommended testing cadence: **annually at minimum, semi-annually for P1 scenarios.**

Suggested tabletop scenario for this incident type:
> "At 02:00 UTC, OTel spans show a burst of `BatchCreateMemoryRecords` against a production memory resource from an execution role that normally only reads. Two hours later, an `UpdateMemory` event repoints `streamDeliveryResources` to a Kinesis ARN in an unrecognized account. Walk the team from detection — through the fact that the memory writes left no CloudTrail trail — to purging poisoned records (including hidden branches), reverting the stream destination from AWS Config history, and estimating exfiltration volume from producer-side evidence."

Reference: [AWS Security Incident Response Game Days](https://docs.aws.amazon.com/security-ir/latest/userguide/game-days.html)

---

## Part 2 — Detect & Analyze

> **CSF 2.0 Functions:** Detect · Respond (Analyze)
> **Goal:** Confirm whether an incident has occurred, scope its impact, and gather evidence for containment and investigation.

### 2.1 Initial Triage Questions

Answer these quickly to determine scope and priority. Each question should take < 2 minutes to answer.

- [ ] Is this a confirmed incident or an anomalous finding requiring investigation?
- [ ] Which AWS accounts, Regions, and AgentCore resources (memory IDs, runtimes, artifact bucket, ECR repo, registries) are potentially affected?
- [ ] Are production agents or sensitive Memory contents (conversation history, PII) involved?
- [ ] Is the threat actor — or a poisoned agent — still active (rising `InvokeAgentRuntime` errors, ongoing tool calls, new memory writes)?
- [ ] Has data left the environment (Memory Record Streaming repointed to a foreign Kinesis stream)?
- [ ] Was a Runtime artifact (S3 ZIP / ECR image) modified, or a Registry record approved outside the IaC process?
- [ ] Which integrity class is this — prompt injection (session-scoped), memory poisoning (persistent), artifact injection (loads at cold start), Registry compromise (supply-chain), or stream exfiltration?

**If 3 or more questions are answered YES → escalate to P1 immediately.**

Before you begin, set the incident-scoping variables you will reuse throughout this playbook:

```bash
export INCIDENT_ID="<your IR ticket ID>"
export MEMORY_ID=""               # memory resource identifier
export AGENT_RUNTIME_ID=""        # e.g. output of list-agent-runtimes
export ARTIFACT_BUCKET=""         # S3 bucket holding Runtime ZIPs
export ARTIFACT_KEY=""            # key path
export ECR_REPO=""                # ECR repo used by Runtime
export SUSPECT_PRINCIPAL_ARN=""
export AWS_REGION="us-east-1"
export ACCOUNT_ID="111122223333"  # placeholder — use your account ID
```

### 2.2 Evidence Collection Checklist

Collect and preserve the following **before taking any containment actions**. Evidence collected after containment may be incomplete or altered.

> ⚠️ **Do not delete poisoned memory records, terminate Runtime sessions, or overwrite tampered artifacts before capturing them. The payload of a poisoned record is the evidence of what the attacker injected and is required for root-cause analysis.**

| Evidence Type | How to Collect | Where to Store |
|---|---|---|
| Memory write/delete activity | **OTel spans (`aws/spans`) or Memory structured logs — NOT CloudTrail** (see note below) | Forensic S3 (Object Lock) |
| Poisoned record payloads | `get-event` / `get-memory-record` per identified ID, before deletion | Forensic S3 |
| Memory config changes (`UpdateMemory`) | CloudTrail (control-plane lifecycle only) | Forensic S3 |
| Runtime artifact object versions | `s3api list-object-versions`, copy with SHA256 | Forensic S3 |
| ECR image digests / scan findings | `ecr describe-images` / `describe-image-scan-findings` | Forensic S3 |
| Registry record history | CloudTrail `*RegistryRecord*` events + record export | Forensic S3 |
| X-Ray traces (incident window) | `xray get-trace-summaries` | Forensic S3 |

> ⚠️ **Critical scenario fact — Memory data-plane APIs do NOT emit CloudTrail events.** `CreateEvent`, `DeleteEvent`, `BatchCreateMemoryRecords`, `BatchUpdateMemoryRecords`, `BatchDeleteMemoryRecords`, `DeleteMemoryRecord`, `GetMemoryRecord`, `ListEvents`, `RetrieveMemoryRecords`, `StartMemoryExtractionJob`, and `GetEvent` are all **observability-only**. Only the control-plane lifecycle APIs — `CreateMemory`, `UpdateMemory`, `DeleteMemory` — are CloudTrail-visible. The memory attack surface is visible only in (a) AgentCore Memory OTel spans in the `aws/spans` CloudWatch Log Group when Transaction Search is enabled, and (b) AgentCore Memory structured logs in the runtime application log group when observability is enabled on the Memory resource. Which source you use depends on which was enabled *before* the incident — both are opt-in. **If neither was enabled, you have no retrospective detection path for memory writes** — document this gap in the ticket and add "enable Memory observability" to the post-incident preparation list.

**Useful queries for this scenario (run against the source you have enabled):**

```text
-- Memory write/delete activity (CloudWatch Logs Insights against aws/spans, Transaction Search enabled)
fields @timestamp, attributes.aws.bedrock_agentcore.memory.id,
       attributes.aws.bedrock_agentcore.actor.id,
       attributes.aws.bedrock_agentcore.session.id,
       attributes.aws.bedrock_agentcore.branch.name, name
| filter name in ["CreateEvent","DeleteEvent","BatchCreateMemoryRecords",
    "BatchUpdateMemoryRecords","BatchDeleteMemoryRecords","DeleteMemoryRecord",
    "StartMemoryExtractionJob"]
| stats count() as ops by attributes.aws.bedrock_agentcore.memory.id, name,
    attributes.aws.bedrock_agentcore.branch.name
| sort ops desc
```

> 🔎 **Branch-hiding caveat:** Memory branching (`branch.name`, `branch.rootEventId`) is an attacker-hiding mechanism — events can be written to a named branch rather than the main conversation line, and a reviewer inspecting only the main branch will miss the poisoned events. `list-events` **requires** `--memory-id`, `--actor-id`, and `--session-id` (all three are mandatory — there is no "list all events for a memory" call and no `--branch-name` flag), so you must first discover the actors and sessions before you can enumerate their branches:
>
> ```bash
> # 1. Discover actors, then each actor's sessions, then walk events per session.
> aws bedrock-agentcore list-actors --memory-id "$MEMORY_ID" \
>   --query 'actorSummaries[].actorId' --output text
> aws bedrock-agentcore list-sessions --memory-id "$MEMORY_ID" --actor-id "$ACTOR_ID" \
>   --query 'sessionSummaries[].sessionId' --output text
> # 2. List events for the actor/session (omit --filter to see the main line;
> #    add it to scope to a specific branch). branch scoping is via --filter JSON.
> aws bedrock-agentcore list-events --memory-id "$MEMORY_ID" --actor-id "$ACTOR_ID" --session-id "$SESSION_ID"
> aws bedrock-agentcore list-events --memory-id "$MEMORY_ID" --actor-id "$ACTOR_ID" --session-id "$SESSION_ID" \
>   --filter '{"branch":{"name":"<name>"}}'
> ```
>
> To inspect long-term records (semantic memory) rather than raw events, `list-memory-records` requires `--namespace` or `--namespace-path` (not just `--memory-id`), and `retrieve-memory-records` takes `--search-criteria` (not `--query-input`). Attribute names in the OTel spans follow the semantic conventions AgentCore emits; if your ADOT SDK version differs, inspect a sample span with `fields @message | limit 1` and map names before running the aggregation.

```text
-- Memory configuration changes (CloudWatch Logs Insights against the CloudTrail log group)
fields @timestamp, eventName, userIdentity.arn,
       requestParameters.streamDeliveryResources, requestParameters.memoryStrategies
| filter eventSource = "bedrock-agentcore.amazonaws.com"
| filter eventName in ["CreateMemory","UpdateMemory","DeleteMemory"]
| sort @timestamp desc
```

> Memory Record Streaming pushes record lifecycle events to a Kinesis Data Stream via `streamDeliveryResources` (structure: `streamDeliveryResources.resources[].kinesis.dataStreamArn`, plus optional `contentConfigurations`), a top-level field on `CreateMemory`/`UpdateMemory`. Attackers who repoint streaming change `dataStreamArn` — flag any Kinesis ARN belonging to an account outside your organization. `memoryStrategies` controls short-term→long-term extraction and is a separate field worth reviewing for drift, but it is not the streaming exfil channel.

```text
-- Artifact-bucket writes (CloudWatch Logs Insights — replace the literal bucket name; Insights does NOT interpolate shell variables)
fields @timestamp, eventName, userIdentity.arn, requestParameters.bucketName, requestParameters.key
| filter eventSource = "s3.amazonaws.com"
| filter requestParameters.bucketName = "REPLACE_WITH_ARTIFACT_BUCKET_NAME"
| filter eventName in ["PutObject","CopyObject","DeleteObject","PutObjectAcl"]
| sort @timestamp desc
```

```bash
# Runtime artifact object versions — any unexpected new version is a tampering candidate
aws s3api list-object-versions --bucket "$ARTIFACT_BUCKET" --prefix "$ARTIFACT_KEY" \
  --output json | jq '.Versions[] | {Key, VersionId, LastModified, Size, ETag}'

# Container-mode Runtimes: audit ECR for unexpected tags/digests and review scan findings
aws ecr describe-images --repository-name "$ECR_REPO" --output table
aws ecr describe-image-scan-findings --repository-name "$ECR_REPO" --image-id imageTag=<tag>

# X-Ray traces for affected runtimes — flag downstream Lambda ARNs / URLs not on the approved list
aws xray get-trace-summaries --start-time "<lookback UTC>" --end-time "<now UTC>" \
  --filter-expression 'service("bedrock-agentcore")' --output json \
  > /tmp/ir/$INCIDENT_ID/xray-summaries.json
```

> 📌 The Registry is a centralized catalog of approved agents, tools, and MCP servers; a malicious record approved into it becomes a trusted resource downstream consumers use without further review. Query `CreateRegistryRecord`, `UpdateRegistryRecord`, `SubmitRegistryRecordForApproval`, and `UpdateRegistryRecordStatus` (all on `eventSource = "bedrock-agentcore.amazonaws.com"`) for any activity outside the IaC-driven approval process and investigate before any consumer deploys the affected record.

Additional analysis steps:

- **Classify the integrity attack** — containment differs sharply by class. *Prompt injection alone* (a single session steered without persistent state change) is contained at the session. *Memory poisoning* requires purging affected records and blocking the writer. *Artifact injection* requires restoring the artifact and preventing restart until verified. *Registry compromise* requires rejecting the record and freezing Registry writes. *Stream exfiltration* requires reverting the streaming config and investigating the attacker's Kinesis consumer.
- **For memory poisoning**, extract the specific `actorId`, `sessionId`, `eventId`, and `memoryRecordId` values written during the incident window from the span query above, and capture each record's payload to the forensic bucket *before* deletion.
- **For artifact injection**, compute the SHA256 of the current artifact (S3 object) or ECR manifest digest and compare against the CI/CD-produced known-good hash. If no known-good hash exists, use S3 Versioning history or ECR image tags to locate the most recent version predating the incident window and treat that as the baseline.
- **For prompt injection**, invoke the agent with a diagnostic prompt via `InvokeAgentRuntime` and review the response for system-prompt-override artifacts, encoded-instruction execution, or unexpected tool calls. Capture the full response (including X-Ray tool-call traces) to the forensic bucket but **do not share externally** — it may contain PII, prompts, or sensitive system instructions.
- **If a poisoned record steered the agent into Gateway tool calls**, X-Ray gives the call graph and timing but not request arguments or response content. Join Gateway and Runtime application logs on `trace_id` to reconstruct what data the poisoned agent actually retrieved or exfiltrated through tools — CloudTrail `InvokeGateway` data events redact arguments and response content.

### 2.3 Severity Determination

Based on triage and initial evidence, assign a priority using the criteria in [Severity Classification](#severity-classification).

| Confirmed? | Priority Assignment |
|---|---|
| Active memory exfiltration via foreign Kinesis stream, or tampered artifact unpinned on production | P1 |
| Confirmed unauthorized memory writes or tampered artifact, writer no longer active | P2 |
| Anomalous memory write/branch activity, scope unclear | P3 |
| Configuration drift (`memoryStrategies`/config), no exploitation | P4 |

### 2.4 Getting Help from AWS

For P1 or P2 incidents, consider engaging AWS for additional support:

- **AWS Security Incident Response service** (if enabled): Open a case via the [Security Incident Response console](https://console.aws.amazon.com/security-ir/), attach relevant findings, and grant AWS CIRT access to the affected account(s).
- **AWS Support** (any AWS Support plan): Open a support case with severity "Critical" or "Urgent" and request assistance from the AWS Customer Incident Response Team (CIRT).
- **AWS Trust & Safety** (for abuse reports): If the incident involves AgentCore resources being used to attack others, report via the [AWS abuse form](https://support.aws.amazon.com/#/contacts/report-abuse).

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
├── YES (active stream exfiltration / poisoned memory being read now / tampered artifact about to load)
│     └── Proceed to 3.2 — accept potential agent disruption
│
└── NO (writer appears inactive, artifact not yet loaded)
      └── Consult Agent Owner and IR Lead before proceeding
            Can we contain without disrupting a production agent?
            ├── YES → Proceed to 3.2
            └── NO  → Document business impact, obtain authorization, then proceed
```

### 3.2 Containment Actions

> `[IR Lead]` coordinates. `[Account / Agent Owner]` authorizes actions that may disrupt a production agent. Containment differs by attack class.

**Step-by-step containment for this incident type:**

1. **Purge poisoned memory records**
   Short-term events are deleted individually; long-term records individually or in batches. If the contamination scope is unclear or the writer had broad access, delete and recreate the memory resource from IaC rather than cleaning record-by-record. **Delete poisoned *branches* explicitly** — deleting only main-branch events leaves branch contents intact.

   ```bash
   aws bedrock-agentcore delete-event --memory-id "$MEMORY_ID" \
     --actor-id <actorId> --session-id <sessionId> --event-id <eventId>

   aws bedrock-agentcore delete-memory-record --memory-id "$MEMORY_ID" \
     --memory-record-id <recId>

   aws bedrock-agentcore batch-delete-memory-records --memory-id "$MEMORY_ID" \
     --records '[{"memoryRecordId":"<id1>"},{"memoryRecordId":"<id2>"}]'
   ```

2. **Revert a repointed Memory Record Streaming destination**
   If streaming was repointed to an attacker Kinesis destination, revert `streamDeliveryResources` to the known-good ARN to stop further exfiltration. **Recover the known-good ARN from AWS Config resource history, not from IaC** — if the attacker had IaC write access or the stream was configured out-of-band, IaC is not authoritative. `AWS::BedrockAgentCore::Memory` is Config-recorded, so the pre-attack snapshot is available **when AWS Config is enabled and recording that resource type**. If Config is not enabled in the account (verify with `aws configservice describe-configuration-recorders` — an empty result or a recorder excluding `AWS::BedrockAgentCore::Memory` means no history exists), the `get-resource-config-history` call below returns nothing. Fall back, in order: (a) the IaC source of record if you can confirm it was not attacker-modified during the window; (b) the CloudTrail `UpdateMemory` event itself — its `requestParameters`/`responseElements` capture both the new (malicious) and, on the *prior* legitimate `CreateMemory`/`UpdateMemory`, the known-good `streamDeliveryResources`; (c) the application/Memory owner. Whatever the source, set the reverted ARN explicitly below.

   ```bash
   aws configservice get-resource-config-history \
     --resource-type AWS::BedrockAgentCore::Memory --resource-id "$MEMORY_ID" \
     --later-time "<pre-attack UTC>" --limit 1 --output json \
     | jq -r '.configurationItems[0].configuration' | jq '.streamDeliveryResources'

   aws bedrock-agentcore-control update-memory --memory-id "$MEMORY_ID" \
     --stream-delivery-resources '{
       "resources": [
         {
           "kinesis": {
             "dataStreamArn": "<known-good Kinesis ARN from Config history>",
             "contentConfigurations": [{"type":"MEMORY_RECORDS","level":"METADATA_ONLY"}]
           }
         }
       ]
     }'
   ```

   > `update-memory` uses delta semantics for `memoryStrategies` (`addMemoryStrategies`/`modifyMemoryStrategies`/`deleteMemoryStrategies`) — that field is *not* the streaming destination. `streamDeliveryResources` replaces the prior configuration when passed.

   **Estimate exfiltration volume.** If the stream is *in your account*, query producer-side stream metrics — `IncomingBytes`/`IncomingRecords` give the upper bound on what Memory Record Streaming wrote:

   ```bash
   aws cloudwatch get-metric-statistics --namespace AWS/Kinesis \
     --metric-name IncomingBytes \
     --dimensions Name=StreamName,Value=<redirected-stream-name> \
     --start-time "<attack start UTC>" --end-time "<containment UTC>" \
     --period 60 --statistics Sum --output table
   ```

   If the stream is *cross-account*, you cannot read its CloudWatch metrics. Instead read CloudTrail `PutRecord`/`PutRecords` events emitted from the caller's perspective in your own trail (these are Kinesis **data events** requiring trail opt-in; if not recorded, the volume figure is unavailable). Record the resulting approximate-bytes value in the ticket — it feeds blast-radius and breach-notification assessment.

3. **Restore a tampered Runtime artifact and block further writes**
   Apply a temporary deny-all bucket policy so the attacker cannot overwrite again, then copy the pre-incident version back via S3 Versioning. For ECR, batch-delete the tampered tag and re-tag the known-good digest; the Runtime picks up the clean artifact on the next endpoint update or version publish.

   ```bash
   aws s3api put-bucket-policy --bucket "$ARTIFACT_BUCKET" --policy file:///tmp/deny-writes.json

   aws s3api copy-object --bucket "$ARTIFACT_BUCKET" --key "$ARTIFACT_KEY" \
     --copy-source "$ARTIFACT_BUCKET/$ARTIFACT_KEY?versionId=<KNOWN_GOOD_VID>"
   ```

4. **Roll back a Registry supply-chain compromise**
   Mark each compromised record `REJECTED` so polling consumers stop treating it as approved, then delete it. Lock down Registry writes via SCP/IAM during review. Valid statuses: `DRAFT`, `PENDING_APPROVAL`, `APPROVED`, `REJECTED`, `DEPRECATED`. CLI params are `--registry-id` and `--record-id`; `--status-reason` is required.

   ```bash
   aws bedrock-agentcore-control update-registry-record-status \
     --registry-id <reg-id> --record-id <rec> \
     --status REJECTED --status-reason "IR-$INCIDENT_ID: supply-chain compromise"
   aws bedrock-agentcore-control delete-registry-record --registry-id <reg-id> --record-id <rec>
   ```

5. **Stop a session actively reading poisoned memory**
   This terminates the microVM hosting the session and forces a fresh start on the next invocation after records are purged. CLI param is `--runtime-session-id` (not `--session-id`).

   ```bash
   aws bedrock-agentcore stop-runtime-session \
     --agent-runtime-arn "arn:aws:bedrock-agentcore:$AWS_REGION:$ACCOUNT_ID:runtime/$AGENT_RUNTIME_ID" \
     --runtime-session-id <sid>
   ```

6. **(Full shutdown only) AgentCore emergency kill switch**
   If scope is unclear or spans multiple components and the Incident Commander directs a full shutdown, invoke the AgentCore kill switch. It severs every AgentCore authorization path across **six sequential phases** — (1) block new API calls via emergency SCP on `bedrock-agentcore:*`; (2) sever authentication by disabling Cognito users and deleting workload identities and credential providers; (3) sever authorization by forcing every Gateway to `ENFORCE` and applying a deny-all Cedar policy; (4) sever tool access by deleting Gateway targets and resource-based policies; (5) sever network and active sessions by stopping sandbox sessions and deleting Runtime endpoints; (6) prevent recreation by neutralizing SSM parameters and disabling EventBridge rules. It terminates all agentic workflows — legitimate and compromised — so obtain explicit written authorization and run a blast-radius assessment first. Be aware of residual risk: in-flight Gateway Lambda invocations run to completion (up to 15 min), IAM temporary credentials remain valid for their session duration, and an already-running memory extraction job continues briefly until its batch-write APIs are blocked by the Phase 1 SCP.

> 🤖 **Automation opportunity:** AWS Systems Manager Automation runbook to revert `streamDeliveryResources` from AWS Config history and apply the artifact-bucket deny-writes policy in one keyed invocation. [Link TBD]

### 3.3 Evidence Preservation Reminders

After containment begins, ensure the following before modifying or terminating any resources:

- [ ] Poisoned memory record payloads captured to the forensic bucket **before** deletion (including hidden branches)
- [ ] Runtime artifact object versions copied with SHA256 before the deny-writes policy and restore
- [ ] Kinesis exfiltration-volume evidence (producer-side metrics or `PutRecord`/`PutRecords` CloudTrail) recorded in the ticket
- [ ] All relevant logs (OTel spans, Memory structured logs, CloudTrail) exported to forensic S3 bucket
- [ ] S3 Object Lock or legal hold applied to the forensic bucket; CloudTrail log-file integrity validation confirmed

---

## Part 4 — Eradicate & Recover

> **CSF 2.0 Function:** Respond (Eradicate) · Recover
> **Goal:** Remove the root cause, validate the environment is clean, and restore normal operations.

### 4.1 Root Cause Identification

> `[IR Lead]` owns this step. Document findings in the IR ticket in real time.

Determine the root cause before beginning eradication. Common root causes for this incident type:

- A prompt-injection surface — a tool input, a memory record, or an external RAG source that an untrusted party can influence.
- An artifact-delivery pipeline that accepts writes from too broad a principal set (no CI/CD allow-list, no S3 Object Lock / ECR immutability).
- A Registry approval gap that let a single principal mark records `APPROVED` without independent review.
- An over-broad execution role that permitted `CreateEvent` / `BatchCreateMemoryRecords` from a principal that should only read.
- A missing `aws:SourceAccount` / `aws:SourceArn` confused-deputy guard on an AgentCore trust policy.

Use evidence collected in Part 2 to trace the initial access vector and full attack path.

### 4.2 Eradication Actions

> `[IR Lead]` coordinates. `[Account / Agent Owner]` approves changes to production resources.

1. **Cancel in-flight memory extraction jobs**
   `StartMemoryExtractionJob` launches background processing that converts short-term events into long-term records; a job started before containment keeps running until it finishes unless cancelled. Cancelling prevents poisoned events from reaching long-term storage.

   ```bash
   aws bedrock-agentcore list-memory-extraction-jobs --memory-id "$MEMORY_ID" \
     --output json | jq '.jobs[]? | select(.status == "RUNNING")'
   ```

2. **Rebuild memory summaries and embeddings from clean data**
   Generated summaries and embeddings derived from poisoned records persist and keep influencing reasoning even after individual records are deleted. The safe path is to delete the memory resource and recreate it from IaC, then re-run extraction against a validated clean event set only.

3. **Revert the artifact to a signed known-good version and lock the bucket**
   Apply S3 Object Lock (COMPLIANCE mode) for the incident window, pin the image digest or ZIP SHA256 in CDK, and redeploy the Runtime stack so the pinned version loads at the next cold start.

4. **Audit the Registry for other anomalous records from the same principal**
   Re-run the Registry query for every record created by the compromised principal and reject/delete each individually. Enable the two-approver workflow on Registry writes so no malicious record can reach `APPROVED` without independent sign-off.

5. **Close the writer's credential path**
   Deny `bedrock-agentcore:CreateEvent`, `bedrock-agentcore:BatchCreateMemoryRecords`, and `bedrock-agentcore:StartMemoryExtractionJob` on the compromised execution role via an inline policy or the shared IR permissions boundary, preventing continued poisoning by any residual session.

6. **Remove attacker persistence mechanisms**
   Check for and remove:
   - [ ] Unauthorized IAM users, roles, or access keys created during the incident
   - [ ] EventBridge rules that re-create deleted AgentCore resources or re-trigger extraction
   - [ ] Modified trust policies on legitimate AgentCore roles now trusting an external account
   - [ ] S3 bucket-notification configurations forwarding artifact-bucket objects to attacker destinations
   - [ ] Poisoned memory *branches* not on the main conversation line, and background extraction jobs still running

> 🤖 **Automation opportunity:** AWS Config auto-remediation to flag any Memory whose `streamDeliveryResources` points outside the organization and any artifact-bucket write by a non-CI/CD principal. [Link TBD]

### 4.3 Recovery Actions

1. **Restore from known-good state**
   Redeploy the Runtime from the last known-good IaC commit with the container image digest or ZIP SHA256 pinned; restart it to force a clean cold start. Recreate the memory resource from IaC — replay a clean backup of records if one exists, otherwise accept and document the data loss.

2. **Re-enable services and access**
   - [ ] Re-enable Memory Record Streaming to the correct Kinesis destination; confirm the consumer in that account is receiving records before declaring recovery complete
   - [ ] Approve only allow-listed Registry records; keep the Registry write-lock in place until supply-chain review passes on every affected record
   - [ ] Validate agent functionality with diagnostic prompts

3. **Harden against recurrence**
   - [ ] Monitor agent behavior with diagnostic prompts for **24 hours** post-recovery — residual prompt-injection payloads may remain cached in a RAG source, vector store, or external knowledge base even after memory and artifact are clean
   - [ ] Confirm S3 Object Lock + ECR immutability on artifact stores, and the two-approver Registry workflow, are enforced
   - [ ] Scope the writer's execution role to least privilege based on observed API usage

### 4.4 Recovery Validation

Confirm the environment is clean before declaring the incident resolved.

- [ ] No unauthorized memory records, branches, Runtime artifacts, or Registry records remain
- [ ] All credentials created or used by the attacker have been revoked; the writer role is least-privileged
- [ ] Memory Record Streaming points only to the known-good Kinesis ARN; no extraction jobs against poisoned events remain
- [ ] GuardDuty / Security Hub show no active findings related to this incident
- [ ] Agent health metrics (`InvokeAgentRuntime` error rate, tool-call fan-out, Bedrock cost) are within normal range
- [ ] Memory observability (OTel spans / structured logs) confirmed operational
- [ ] AWS Security Incident Response case updated / closed (if applicable)

---

## Part 5 — Post-Incident Activity

> **CSF 2.0 Function:** Identify (Improve) — continuous improvement, not a one-time activity
> **Goal:** Learn from this incident to reduce the likelihood and impact of future occurrences.

### 5.1 Timeline Reconstruction

Document the full incident timeline. Complete this within 24–48 hours while memory is fresh.

| Timestamp (UTC) | Event | Source / Evidence | Actor |
|---|---|---|---|
| YYYY-MM-DD HH:MM | Initial poisoning write / artifact tamper | OTel span / Memory structured log / S3 version | Threat actor |
| YYYY-MM-DD HH:MM | Detection signal fired | GuardDuty / CloudWatch alarm | AWS / monitoring |
| YYYY-MM-DD HH:MM | IR team notified | On-call alert | IR Lead |
| YYYY-MM-DD HH:MM | Containment completed (records purged / stream reverted / artifact restored) | IR ticket | IR Lead |
| YYYY-MM-DD HH:MM | Recovery validated | IR ticket | IR Lead |

**Key metrics to capture:**

| Metric | Value |
|---|---|
| Time to Detect (TTD) | *HH:MM from initial event to detection* |
| Time to Notify (TTN) | *HH:MM from detection to IR team notified* |
| Time to Contain (TTC) | *HH:MM from notification to containment* |
| Time to Recover (TTR) | *HH:MM from containment to recovery validated* |
| Total Incident Duration | *HH:MM* |
| Affected Resources | *Memory IDs, runtimes, artifacts, Registry records — count and type* |
| Data Impact | *Confirmed / Suspected / None (approx. exfiltrated bytes if streamed)* |

### 5.2 Post-Incident Review

Conduct a blameless post-incident review within **5 business days** for P1/P2, **15 business days** for P3/P4.

Discussion questions:

1. What was the initial access vector — a prompt-injection surface, an over-broad artifact-write principal, or a Registry approval gap? Could existing controls have prevented it?
2. How was the incident detected? Was Memory observability enabled, or did we discover the writes only after impact?
3. Were the right people notified at the right time?
4. Did containment actions work? Did we catch hidden memory branches and cancel in-flight extraction jobs?
5. Were there gaps in runbooks, automation, or tooling (e.g., no AWS Config history to recover the known-good stream ARN)?
6. What would have reduced the blast radius — earlier session termination, tighter writer-role scope, faster stream revert?
7. What single change would most improve our response to this scenario next time?

### 5.3 Detection Gap Analysis

For each detection source that *did not* catch this incident early, document why and what would have:

| Gap | Root Cause | Recommended Fix | Owner | Target Date |
|---|---|---|---|---|
| Memory write activity invisible | Relies on CloudTrail; Memory data-plane is observability-only | Enable Memory OTel spans / structured logs | | |
| Artifact tamper not alarmed | No alarm on artifact-bucket `PutObject` by non-CI/CD principal | Add CloudWatch alarm + S3 Object Lock | | |
| Stream repoint not alarmed | No alarm on `UpdateMemory` `streamDeliveryResources` change | Add EventBridge rule on `UpdateMemory` to a foreign Kinesis ARN | | |
| Registry abuse not alarmed | No alert on `UpdateRegistryRecordStatus` outside approval flow | Add EventBridge rule + two-approver workflow | | |

### 5.4 Playbook Update Checklist

Review and update this playbook based on what you learned. Do not wait for the next scheduled review.

- [ ] Were triage questions sufficient (especially attack-class classification)? Add/remove as needed.
- [ ] Were evidence collection steps accurate — particularly the Memory observability-only caveat and branch enumeration?
- [ ] Were containment actions effective per attack class (purge, stream revert, artifact restore, Registry rollback, session stop)? Update if not.
- [ ] Were any automation opportunities identified? Add EventBridge/Config stubs to the relevant sections.
- [ ] Were severity criteria accurate? Adjust if incidents were under- or over-classified.
- [ ] Update **Last Reviewed** date and increment **Playbook Version**.

---

## Appendix A — Useful Queries

### Memory write/delete activity (CloudWatch Logs Insights — `aws/spans`, Transaction Search enabled)

```text
fields @timestamp, attributes.gen_ai.conversation.id, attributes.gen_ai.agent.name,
       attributes.aws.bedrock_agentcore.memory.id,
       attributes.aws.bedrock_agentcore.actor.id,
       attributes.aws.bedrock_agentcore.session.id,
       attributes.aws.bedrock_agentcore.branch.name, name
| filter name in ["CreateEvent","DeleteEvent","BatchCreateMemoryRecords",
    "BatchUpdateMemoryRecords","BatchDeleteMemoryRecords","DeleteMemoryRecord",
    "StartMemoryExtractionJob"]
| stats count() as ops by attributes.aws.bedrock_agentcore.memory.id, name,
    attributes.aws.bedrock_agentcore.branch.name
| sort ops desc
```

> Memory data-plane APIs do **not** emit CloudTrail events. If Transaction Search was not enabled, query Memory structured logs in the runtime application log group instead. If neither was enabled before the incident, there is no retrospective detection path for memory writes.

### Memory configuration changes and Registry activity (CloudTrail log group)

```text
fields @timestamp, eventName, userIdentity.arn,
       requestParameters.streamDeliveryResources, requestParameters.memoryStrategies, requestParameters
| filter eventSource = "bedrock-agentcore.amazonaws.com"
| filter eventName in ["CreateMemory","UpdateMemory","DeleteMemory",
    "CreateRegistryRecord","UpdateRegistryRecord","DeleteRegistryRecord",
    "SubmitRegistryRecordForApproval","UpdateRegistryRecordStatus"]
| sort @timestamp desc
```

### Artifact-bucket and ECR writes (CloudTrail log group)

```text
fields @timestamp, eventName, userIdentity.arn, requestParameters.bucketName,
       requestParameters.key, requestParameters.repositoryName
| filter (eventSource = "s3.amazonaws.com"
          and requestParameters.bucketName = "REPLACE_WITH_ARTIFACT_BUCKET_NAME"
          and eventName in ["PutObject","CopyObject","DeleteObject","PutObjectAcl"])
       or (eventSource = "ecr.amazonaws.com"
          and eventName in ["PutImage","BatchDeleteImage","InitiateLayerUpload"])
| sort @timestamp desc
```

> CloudWatch Logs Insights does **not** interpolate shell variables — replace the bucket name literal before running.

### Kinesis exfiltration volume — cross-account stream (CloudTrail data events, opt-in)

```text
fields @timestamp, eventName, userIdentity.arn, requestParameters.streamName, requestParameters.streamARN
| filter eventSource = "kinesis.amazonaws.com"
| filter eventName in ["PutRecord","PutRecords"]
| filter requestParameters.streamARN like /<attacker Kinesis ARN or account segment>/
| stats count() as writes, sum(requestParameters.data_size) as approx_bytes by requestParameters.streamARN
```

### GuardDuty Finding Export (CLI)

```bash
aws guardduty list-findings \
  --detector-id DETECTOR_ID \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}' \
  --region us-east-1

aws guardduty get-findings \
  --detector-id DETECTOR_ID \
  --finding-ids FINDING_ID_1 FINDING_ID_2
```

---

## Appendix B — Regulatory & Compliance Considerations

> `[Legal / Compliance]` owns this section during an active incident.

See [Regulatory Context](../REGULATORY_CONTEXT.md) for the full notification obligation matrix by regulation and incident type.

Agent-integrity incidents frequently involve Memory records (conversation content, PII), manipulated agent output returned to end users, and — in the stream-exfiltration case — bulk transfer of memory contents to an attacker-controlled destination. Any of these can trigger notification obligations. Determine data-subject impact early (Part 2): are conversation histories or Memory records associated with identifiable users, and did the agent return manipulated responses to users during the incident window?

**Quick reference for this scenario:**

| Regulation | Trigger Condition | Timeframe |
|---|---|---|
| GDPR Art. 33 | Personal data in Memory records confirmed accessed or exfiltrated via the repointed stream | 72 hours to supervisory authority from awareness |
| HIPAA Breach Notification Rule | PHI in conversation/Memory content confirmed disclosed | Without unreasonable delay, no later than 60 days |
| US state breach-notification laws | Resident PII in Memory confirmed acquired by an unauthorized party | Per applicable state statute (often "without unreasonable delay") |
| Sector-specific AI-governance regimes | Manipulated agent output affected a regulated decision or customer | Per applicable regime |

> ⚠️ The clock starts at **awareness**, not confirmation. When in doubt, assume notification is required and consult Legal immediately.

---

## Appendix C — Reference Links

- [NIST SP 800-61r3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [Amazon Bedrock AgentCore Developer Guide](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/)
- [AWS Prescriptive Guidance — Providing secure access, usage, and implementation of generative AI agents](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture-generative-ai/gen-auto-agents.html)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html)
- [AWS Security Incident Response Service Documentation](https://docs.aws.amazon.com/security-ir/latest/userguide/what-is-security-ir.html)
- [AWS Well-Architected Framework — Security Pillar: Incident Response](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/incident-response.html)
- [Amazon GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [AWS CloudTrail Query Examples (Athena)](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)
- [Amazon Kinesis Data Streams — Monitoring with Amazon CloudWatch](https://docs.aws.amazon.com/streams/latest/dev/monitoring-with-cloudwatch.html)

---

## Revision History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | 2026-06-20 | AWS | Initial draft |
