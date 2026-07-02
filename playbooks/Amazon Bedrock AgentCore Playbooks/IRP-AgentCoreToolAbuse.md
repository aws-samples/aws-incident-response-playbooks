# IRP-AgentCoreToolAbuse: Amazon Bedrock AgentCore Tool Abuse (Code Interpreter & Browser)

> **Playbook Version:** 1.0
> **Last Reviewed:** 2026-06-20
> **Status:** `Draft`
> **NIST Framework:** SP 800-61r3 (CSF 2.0 Community Profile)
> **Related Playbooks:** [IRP-AgentCoreIdentityCompromise](IRP-AgentCoreIdentityCompromise.md) | [IRP-AgentCoreAgentIntegrity](IRP-AgentCoreAgentIntegrity.md) | [IRP-AgentCoreAuthorizationBypass](IRP-AgentCoreAuthorizationBypass.md) | [IRP-AgentCoreObservabilityTampering](IRP-AgentCoreObservabilityTampering.md)

---

> ⚠️ **Disclaimer:** This playbook is provided as a template only. It should be customized to suit your organization's specific needs, risks, available tools, and work processes. This guide is not official AWS documentation and is provided as-is. Security and Compliance is a shared responsibility between you and AWS. You are responsible for making your own independent assessment of the information in this document.

---

## Overview

Amazon Bedrock AgentCore Tool Abuse occurs when an attacker — often by way of prompt injection or a compromised inbound identity — drives an agent's sandboxed tools (Code Interpreter and Browser) to act against your environment rather than on the user's behalf. Code Interpreter runs sandboxed Python/TypeScript/JavaScript inside an ephemeral Firecracker microVM and can be abused for server-side request forgery (SSRF) against internal endpoints, reconnaissance of the execution environment, or exfiltration over HTTP or DNS. Browser is headless Chromium automation and can be abused for SSRF to internal URLs, for saved-Profile cookie persistence that survives session termination, and for Web Bot Auth signing-key misuse against external WAFs. Both tools enforce **zero data retention** — the moment a session stops, the microVM is destroyed and its contents are unrecoverable — so evidence of what the attacker did inside a session must be captured *live* before any stop action. This scenario also covers persistent WebSocket/AGUI streaming connections that outlive API-level containment, and network-mode drift to PUBLIC that quietly removes egress restrictions (Code Interpreter SANDBOX/VPC → PUBLIC; Browser VPC → PUBLIC — Browser has no SANDBOX mode).

### Out of Scope

This playbook does **not** cover:

- Theft or hijack of the inbound identity (Cognito JWT, confidential machine-client secret, workload-identity session) that *enabled* the tool calls — when the nexus is the credential itself, use [IRP-AgentCoreIdentityCompromise](IRP-AgentCoreIdentityCompromise.md) and return here for tool-level containment.
- Cedar enforcement-mode flips (`ENFORCE` → `LOG_ONLY`), rogue Gateway targets, or rogue resource-based policies — route to [IRP-AgentCoreAuthorizationBypass](IRP-AgentCoreAuthorizationBypass.md).
- Tampering with CloudTrail, log groups, KMS keys, or X-Ray sampling to hide the abuse — route to [IRP-AgentCoreObservabilityTampering](IRP-AgentCoreObservabilityTampering.md), then return here once visibility is restored.
- Memory poisoning or exfiltration, or Runtime artifact tampering (poisoned S3 ZIP / ECR image) — route to [IRP-AgentCoreAgentIntegrity](IRP-AgentCoreAgentIntegrity.md).
- A tool-abuse compromise that has pivoted to cloud-native ransomware (EBS/S3/KMS) — contain here first, then pivot to your ransomware playbook.

### Applicable Finding Types

List the detection signals that should route a responder to this playbook.

| Source | Finding / Event Type | Severity |
|---|---|---|
| Amazon GuardDuty | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` referencing a Code Interpreter / Browser execution role | HIGH |
| Amazon GuardDuty | `Discovery:IAMUser/AnomalousBehavior` or `Impact:IAMUser/AnomalousBehavior` on a sandbox execution role | HIGH |
| AWS Security Hub | Aggregated finding referencing a Code Interpreter or Browser resource ARN | CRITICAL/HIGH |
| CloudTrail | `DeleteCodeInterpreter`/`DeleteBrowser` followed by `CreateCodeInterpreter`/`CreateBrowser` whose `networkConfiguration.networkMode` differs from the IaC baseline (network-mode drift) | — (treat as P1) |
| CloudTrail | `SaveBrowserSessionProfile` from an unexpected principal; change to Browser `browserSigning` (Web Bot Auth) configuration | — |
| CloudWatch | Anomalous `InvokeCodeInterpreter` volume; `ConnectBrowserAutomationStream` spike; VPC egress anomaly from CI/Browser ENIs; elevated `OutboundStreamingBytesProcessed` | — |
| Custom / Third-Party | External WAF (Cloudflare, HUMAN, Akamai) reports a signed bot identity behaving anomalously; Route 53 Resolver DNS logs show queries to a newly-registered or dynamic-DNS domain | — |

> 📌 GuardDuty finding types are updated regularly. See the [GuardDuty finding types reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html) for the current list.

### Severity Classification

Use this table to determine incident priority at time of detection. Escalate immediately if P1 criteria are met.

| Priority | Criteria (any one) |
|---|---|
| **P1 — Critical** (≤15 min) | Active exfiltration from a sandbox confirmed (HTTP/DNS to attacker infrastructure, outbound byte volume on a long session); network-mode drift to PUBLIC on a production resource; Web Bot Auth signing key confirmed misused at an external WAF; an established WebSocket/AGUI stream is exfiltrating live |
| **P2 — High** (≤1 hr) | Suspicious sandbox activity confirmed but blast radius unclear; saved Browser Profile created during the window (authenticated-session persistence); over-privileged execution-role credentials harvested via MMDS but downstream use not yet confirmed |
| **P3 — Medium** (≤4 hr) | Anomalous-but-consistent `InvokeCodeInterpreter` / `ConnectBrowserAutomationStream` volume; sandbox reconnaissance signatures with no confirmed egress |
| **P4 — Low** (≤1 day) | Configuration drift (a PUBLIC-mode resource detected) without evidence of exploitation; policy violation, informational finding |

> **P1 override:** regardless of the matrix, treat as P1 if any sandbox or Runtime resource was moved to PUBLIC network mode in production, if a Web Bot Auth signing key was used to bypass an external WAF, or if exfiltration to a destination outside your AWS environment is confirmed.

---

## Part 1 — Prepare

> **CSF 2.0 Functions:** Govern · Identify · Protect
> **Goal:** Ensure the right configurations, access, and processes are in place *before* this incident type occurs.

Sandbox tools expand an agent's reach into code execution and web navigation, so preparation centers on two things that are otherwise unrecoverable after the fact: forensic *capture paths* for ephemeral sessions (zero data retention means there is no post-hoc recovery), and *egress visibility* (PUBLIC and SANDBOX network modes produce no VPC Flow Logs at all). Get both in place before an incident, or accept that a future tool-abuse investigation will have metadata only.

### 1.1 Required AWS Service Configurations

Confirm the following are enabled and configured in all applicable accounts and regions before an incident occurs.

- [ ] Amazon GuardDuty (with Runtime Monitoring) enabled with findings exported to Security Hub
- [ ] AWS CloudTrail enabled with a multi-region trail, log-file validation, delivered to an S3 bucket in a dedicated security account
- [ ] AWS Config enabled with a delivery channel configured, plus a rule that flags any Code Interpreter or Browser resource with `networkMode = "PUBLIC"` as non-compliant for production
- [ ] VPC Flow Logs enabled for every VPC hosting VPC-mode Code Interpreter / Browser / Runtime ENIs
- [ ] **Browser Live View and Session Replay enabled with a destination S3 bucket in your account** — these are the only forensic capture paths for sandbox sessions given zero data retention
- [ ] **Route 53 Resolver DNS query logging enabled** for every VPC hosting AgentCore resources — SANDBOX mode permits DNS, so DNS logs are the only exfiltration signal in that mode
- [ ] Runtime and Gateway OpenTelemetry (ADOT) instrumentation enabled so OTel spans record the reasoning step that invoked a tool (distinguishes prompt-injection-driven tool calls from legitimate behavior)
- [ ] CloudWatch alarms on `InvokeCodeInterpreter` volume, `ConnectBrowserAutomationStream` volume, `OutboundStreamingBytesProcessed`, and VPC egress anomalies from CI/Browser ENIs; SNS subscriptions confirmed
- [ ] An EventBridge rule on `DeleteCodeInterpreter`/`DeleteBrowser` followed by a `CreateCodeInterpreter`/`CreateBrowser` with a different `networkMode`, auto-paging the security team (network mode is immutable — delete+recreate is the only way to change it, so this sequence *is* the drift signal)

> 🤖 **Automation opportunity:** Use AWS Config conformance packs to continuously validate the PUBLIC-mode-is-non-compliant rule and the presence of Browser Live View / Session Replay destinations across all accounts. [Link TBD]

### 1.2 IAM & Access Prerequisites

Ensure the following access is pre-provisioned and tested — *do not provision break-glass access during an active incident*.

- [ ] Break-glass IAM role with least-privilege IR permissions exists and is documented; IR team members can assume it with MFA
- [ ] Access to the AWS Security Incident Response console (if subscribed) is confirmed
- [ ] Forensic account (isolated) is available for evidence preservation, with an S3 bucket configured for Object Lock (COMPLIANCE) and KMS encryption
- [ ] Every sandbox execution role is scoped to least privilege and carries an IAM permissions boundary that caps the maximum permissions reachable by code running inside the microVM via the MicroVM Metadata Service (MMDS)
- [ ] Sandbox execution roles do **not** carry broad Secrets Manager or S3 access, and do not carry `bedrock:InvokeModel*` unless the agent specifically needs model access from inside the sandbox
- [ ] A baseline inventory of every Code Interpreter, Browser, and Browser Profile is maintained and diffable against IaC (so drift and rogue profiles are detectable)

### 1.3 Communication & Escalation

> 📋 Do not include names. Use roles only. Maintain a separate, access-controlled contact list.

| Role | Responsibility |
|---|---|
| IR Lead | Overall incident coordination, status updates |
| Account / Agent Owner | Business context, authorization for containment that may disrupt the agent |
| AI/ML Platform team | AgentCore configuration, IaC known-good baseline, redeploy of sandbox tools |
| Legal / Compliance | Regulatory notification obligations, evidence hold |
| Communications | Internal and external messaging |
| AWS CIRT | Engage via AWS Support case or Security Incident Response service (P1/P2, if available) |

**Escalation path:**
Detection → IR Lead notified → Severity assessed → P1/P2: AWS CIRT engaged, Legal notified, IR bridge opened → P3/P4: IR Lead manages internally.

### 1.4 Game Day Guidance

This playbook should be exercised before it is needed. Recommended testing cadence: **annually at minimum, semi-annually for P1 scenarios.**

Suggested tabletop scenario for this incident type:
> "A CloudWatch alarm fires on a spike in `InvokeCodeInterpreter` from a single agent session at 02:00 UTC. Route 53 Resolver DNS logs show a cluster of queries to a newly-registered domain, and the session is still active. Walk the team from detection through the decision to capture Browser Live View / OTel evidence *before* stopping the session (zero data retention), through execution-role audit, network-mode-drift check, and an SCP block on new sandbox sessions."

Reference: [AWS Security Incident Response Game Days](https://docs.aws.amazon.com/security-ir/latest/userguide/game-days.html)

---

## Part 2 — Detect & Analyze

> **CSF 2.0 Functions:** Detect · Respond (Analyze)
> **Goal:** Confirm whether an incident has occurred, scope its impact, and gather evidence for containment and investigation.

### 2.1 Initial Triage Questions

Answer these quickly to determine scope and priority. Each question should take < 2 minutes to answer.

- [ ] Is this a confirmed incident or an anomalous finding requiring investigation?
- [ ] Which AWS accounts, regions, and Code Interpreter / Browser resources are potentially affected?
- [ ] Are production agents or sensitive data involved?
- [ ] Is a Code Interpreter or Browser session **still active** right now? (If yes, evidence capture is time-critical — see 2.2.)
- [ ] Has data left the AWS environment — HTTP/DNS exfiltration from a sandbox, an established WebSocket/AGUI stream, or egress to a non-RFC1918 destination from a VPC-mode ENI?
- [ ] Was any Code Interpreter or Browser resource moved to PUBLIC network mode, or was a Browser Profile saved, during the window?
- [ ] Was a Web Bot Auth signing configuration changed during the window?

**If 3 or more questions are answered YES → escalate to P1 immediately** and proceed to evidence preservation before completing full analysis.

### 2.2 Evidence Collection Checklist

Collect and preserve the following **before taking any containment actions**. Evidence collected after containment may be incomplete or altered.

> ⚠️ **ZERO DATA RETENTION — capture first, stop second.** Code Interpreter and Browser microVMs do **not** persist customer code, data files, or execution output past session termination — the microVM is destroyed and its contents are unrecoverable. If a session is active and you need forensic evidence of what the attacker did inside it, you **must** capture it *before* you call `stop-code-interpreter-session` or `stop-browser-session`. The only live capture paths are: **Browser Live View** streaming (if the destination S3 bucket was pre-configured), **Browser Session Replay** (DOM mutations, same precondition), **Runtime application logs** (if the agent was OpenTelemetry-instrumented), and **X-Ray spans** (invocation metadata). If none of these were pre-configured, the session content is lost the instant you stop it — document the gap in the incident ticket.

| Evidence Type | How to Collect | Where to Store |
|---|---|---|
| **Active sandbox session content** | Browser Live View / Session Replay / OTel spans — **capture before any stop** | Customer S3 |
| List of active sessions | `aws bedrock-agentcore list-code-interpreter-sessions` / `list-browser-sessions` | IR ticket / notes |
| CloudTrail logs (incident window) | Athena / Logs Insights / CLI; copy before any log tampering | Forensic S3 (Object Lock) |
| GuardDuty / Security Hub finding JSON | Console → Export | Forensic S3 |
| VPC Flow Logs (VPC-mode resources only) | CloudWatch Logs / S3 | Forensic S3 |
| Route 53 Resolver DNS query logs | CloudWatch Logs | Forensic S3 |
| Sandbox execution-role CloudTrail timeline | `aws cloudtrail lookup-events` / Logs Insights (see Appendix A) | Forensic S3 |
| Built-in tool metrics + `OutboundStreamingBytesProcessed` | CloudWatch | IR ticket / notes |

Save all evidence to the forensic S3 bucket with Object Lock in COMPLIANCE mode and KMS encryption, recording each artifact's SHA256 with its acquisition timestamp.

**Detection sources and scoping steps — useful queries for this scenario** (the full scenario-specific query set lives in [Appendix A](#appendix-a--useful-queries)):

- **Code Interpreter activity.** The data-plane event for code execution is `InvokeCodeInterpreter` (action and session live in `requestParameters`); lifecycle events are `StartCodeInterpreterSession` / `StopCodeInterpreterSession`. An invocation spike from one principal, sessions that outlast their normal duration, or invocations from never-before-seen IPs all indicate the sandbox is being used for reconnaissance or exfiltration rather than legitimate reasoning.
- **Browser activity and streaming connections.** Browser interaction spans three data-plane actions. `ConnectBrowserAutomationStream` establishes the Chrome DevTools Protocol (CDP) automation stream — page navigation runs over this stream, with the target URL passed inside the call rather than as a separate event name. `InvokeBrowser` is a **separate, standalone action** that performs OS-level browser actions (mouse clicks, keyboard input, screenshots, and dialogs that CDP cannot reach, such as print and JavaScript-alert dialogs) against an active session identified by `browserIdentifier` + `sessionId` — do not assume browser activity is visible only through the automation stream. `ConnectBrowserLiveViewStream` is the live-view stream. All three can establish or drive sessions that outlive the client's view. `SaveBrowserSessionProfile` captures cookies, localStorage, and sessionStorage into a Browser Profile (also creatable via the control-plane `CreateBrowserProfile`) that persists across sessions — saving a profile after authenticating to an external service establishes authenticated-session persistence that survives the session's termination.
- **Persistent WebSocket / AGUI streams.** `InvokeAgentRuntimeWithWebSocketStream` (and its on-behalf-of-user variant `InvokeAgentRuntimeWithWebSocketStreamForUser`) establishes bidirectional WebSocket connections that persist after an SCP or IAM block until the underlying TCP connection closes — API-level denial does **not** immediately terminate the stream. When a call carries the `X-Amzn-Bedrock-AgentCore-Runtime-User-Id` header, AgentCore requires **both** `bedrock-agentcore:InvokeAgentRuntime` **and** the separate `bedrock-agentcore:InvokeAgentRuntimeForUser` action — a deny that omits `InvokeAgentRuntimeForUser` leaves the on-behalf-of-user invocation path open, so any deny set must include it.
- **Interactive command shell.** `InvokeAgentRuntimeCommand` and `InvokeAgentRuntimeCommandShell` invoke commands / an interactive command shell on a Runtime endpoint (the shell runs over a WebSocket stream). This is the most direct hands-on-keyboard execution surface in AgentCore — like the WebSocket streams, an established shell survives API-level denial until the TCP connection closes, so containment requires endpoint deletion plus a VPC NACL deny, not just an SCP. Hunt for these actions and include them in the §3.2 deny set.
- **Network-mode drift.** Code Interpreter supports three network modes: PUBLIC (unrestricted outbound), SANDBOX (S3 and DNS only), and VPC (customer-controlled). The mode is **immutable** once created — there is no `UpdateCodeInterpreter` or `UpdateBrowser` API — so an attacker downgrading SANDBOX/VPC to PUBLIC must `Delete` then `Create`. A `DeleteCodeInterpreter` followed by a `CreateCodeInterpreter` whose `networkConfiguration.networkMode` differs from the IaC baseline (apply the same pattern to `DeleteBrowser`/`CreateBrowser`) must be investigated before containment.
- **VPC egress (VPC-mode only).** Enumerate the relevant ENIs (`aws ec2 describe-network-interfaces --filters Name=description,Values="*bedrock-agentcore*"`), then query Flow Logs for ACCEPT entries to non-RFC1918 destinations. **PUBLIC-mode and SANDBOX-mode resources produce no flow-log visibility at all** — for those modes detection relies on Route 53 Resolver DNS query logs and application-layer logs only.
- **DNS exfiltration.** Query Route 53 Resolver DNS logs for queries to non-AWS domains. SANDBOX mode permits DNS resolution (so agents can reach S3 via DNS), which makes DNS a working exfiltration channel. A cluster of queries to a newly-registered domain, a dynamic-DNS provider, or a domain matching no allowlisted service is evidence of DNS-encoded exfiltration.
- **Web Bot Auth.** AgentCore Browser can cryptographically sign HTTP requests to bypass allowlist checks at external WAFs (Cloudflare, HUMAN, Akamai). A compromised signing configuration lets the agent impersonate an allowlisted bot identity at the edge. Any change to Browser signing configuration (`requestParameters.browserSigning`) during the window is a high-severity indicator.

**Classify the abuse pattern — each class requires different containment:**

1. **Code Interpreter reconnaissance** — sandbox Python queries the MicroVM Metadata Service (MMDS), internal APIs, or DNS to enumerate the execution environment.
2. **Code Interpreter exfiltration** — sandbox makes HTTP POST or DNS queries to attacker infrastructure.
3. **Browser SSRF** — headless browser navigates to internal URLs (IMDS, cluster API, internal admin endpoints) it should not reach.
4. **Browser session persistence** — `SaveBrowserSessionProfile` caches cookies and localStorage that survive session stop.
5. **WebSocket / AGUI persistence** — a long-lived streaming connection held open to bypass API-level containment.
6. **Web Bot Auth abuse** — compromised signing keys bypass external WAFs.
7. **Network-mode drift** — a SANDBOX/VPC resource recreated as PUBLIC to remove egress restrictions, frequently a reconnaissance/exfiltration precursor.

**Audit the execution role before you go further.** Sandbox code runs inside the Firecracker microVM using the resource's execution role, and the microVM exposes that role's credentials via MMDS to code running inside the sandbox. Over-privileged execution roles are the most common root cause of sandbox abuse. Review *both* attached and inline policies, **and pull every CloudTrail call made by the execution role during the window** — policy review tells you what the role *could* do; the CloudTrail timeline tells you what it *did*. If MMDS credentials were harvested and used from outside the microVM, the only evidence is anomalous `sourceIPAddress` or cross-region activity in the role's CloudTrail history.

```bash
aws iam list-attached-role-policies --role-name <ci-or-browser-exec-role>
aws iam list-role-policies --role-name <ci-or-browser-exec-role>
```

**Pull agent-level observability before termination.** Built-in tool metrics (session count, session duration, invocation volume per tool) let you flag sessions at the upper bound of `sessionTimeoutSeconds` — a common reconnaissance signature — and Runtime `OutboundStreamingBytesProcessed` correlates long sessions with outbound byte volume to confirm exfiltration. Runtime OTel spans (if ADOT-instrumented) record the reasoning step that invoked the tool, which tells you whether the call was the result of a prompt-injection payload or legitimate agent behavior.

### 2.3 Severity Determination

Based on triage and initial evidence, assign a priority using the criteria in [Severity Classification](#severity-classification).

| Confirmed state | Priority |
|---|---|
| Active exfiltration / live stream; network-mode drift to PUBLIC in production; Web Bot Auth misuse confirmed | P1 |
| Confirmed sandbox abuse, actor no longer active; saved Browser Profile created during window | P2 |
| Suspicious sandbox activity, scope unclear | P3 |
| PUBLIC-mode drift with no exploitation; policy violation, no active threat | P4 |

### 2.4 Getting Help from AWS

For P1 or P2 incidents, consider engaging AWS for additional support:

- **AWS Security Incident Response service** (if enabled): Open a case via the [Security Incident Response console](https://console.aws.amazon.com/security-ir/), attach relevant findings, and grant AWS CIRT access to the affected account(s).
- **AWS Support** (any AWS Support plan): Open a support case with severity "Critical" or "Urgent" and request assistance from the AWS Customer Incident Response Team (CIRT).
- **AWS Trust & Safety** (for abuse reports): If the sandbox is being used to attack others (for example, SSRF or scanning against third-party infrastructure), report via the [AWS abuse form](https://support.aws.amazon.com/#/contacts/report-abuse).

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
├── YES (active exfiltration / live stream / lateral tool-calls)
│     └── Capture sandbox session evidence first (zero data retention), then proceed to 3.2 — accept potential agent disruption
│
└── NO (threat appears inactive)
      └── Consult Agent Owner and IR Lead before proceeding
            Can we contain without disrupting a production agent?
            ├── YES → Proceed to 3.2
            └── NO  → Document business impact, obtain authorization, then proceed
```

### 3.2 Containment Actions

> `[IR Lead]` coordinates. `[Account / Agent Owner]` authorizes actions that may disrupt a production agent.

**Step-by-step containment for this incident type:**

1. **Terminate active Code Interpreter and Browser sessions**
   This destroys the microVM hosting the session and prevents further in-session activity. **Session content is lost at this point — capture forensic evidence first (see 2.2 and 3.3) if you have not already.**

   ```bash
   aws bedrock-agentcore stop-code-interpreter-session \
     --code-interpreter-identifier "$CODE_INTERPRETER_ID" --session-id "$SESSION_ID"

   aws bedrock-agentcore stop-browser-session \
     --browser-identifier "$BROWSER_ID" --session-id "$SESSION_ID"
   ```

2. **Delete every saved Browser Profile**
   Profiles cache cookies, localStorage, and sessionStorage, so an attacker who saved a profile after authenticating at an external service has a persistent authenticated session that survives individual Browser session stops. The profile must be deleted to invalidate that persistence.

   ```bash
   aws bedrock-agentcore-control list-browser-profiles
   aws bedrock-agentcore-control delete-browser-profile --profile-id <pid>
   ```

   > **IAM prerequisite:** `delete-browser-profile` requires `bedrock-agentcore:DeleteBrowserProfile`, which a read-only investigator role will not have. Confirm the IR/containment role carries it (and `bedrock-agentcore:ListBrowserProfiles`) before you reach this step, or the deletion fails with `AccessDenied` mid-incident.

3. **Block new sandbox-session API calls (if abuse continues or scope is unclear)**
   Apply an SCP that denies every new sandbox-session API call across the account except for the incident-responder role. This prevents the attacker from starting new sandbox sessions while you investigate.

   ```json
   {
     "Effect": "Deny",
     "Action": [
       "bedrock-agentcore:StartCodeInterpreterSession",
       "bedrock-agentcore:StartBrowserSession",
       "bedrock-agentcore:InvokeAgentRuntime",
       "bedrock-agentcore:InvokeAgentRuntimeForUser",
       "bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStream",
       "bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStreamForUser",
       "bedrock-agentcore:InvokeAgentRuntimeCommand",
       "bedrock-agentcore:InvokeAgentRuntimeCommandShell",
       "bedrock-agentcore:ConnectBrowserAutomationStream",
       "bedrock-agentcore:ConnectBrowserLiveViewStream",
       "bedrock-agentcore:InvokeBrowser"
     ],
     "Resource": "*",
     "Condition": { "StringNotEquals": { "aws:PrincipalArn": "<IR role ARN>" } }
   }
   ```

   > **Action-coverage notes.** `InvokeAgentRuntimeCommand` / `InvokeAgentRuntimeCommandShell` are the interactive command / command-shell surfaces (the shell runs over a WebSocket stream) — without them in the deny set an attacker keeps a hands-on-keyboard execution path after the block; `InvokeAgentRuntimeWithWebSocketStreamForUser` is the on-behalf-of-user variant of the WebSocket stream and must be denied alongside `InvokeAgentRuntimeWithWebSocketStream`. `InvokeBrowser` is a confirmed live operation but, as of 2026-06, is not yet enumerated in the IAM service-authorization reference — verify the `bedrock-agentcore:InvokeBrowser` action string resolves in your account before relying on this deny to block it (if it does not yet, scope containment via `StartBrowserSession`/session-stop instead).

4. **Break established WebSocket and AGUI streams at the network layer**
   SCP-based denial only blocks *new* API calls — existing TCP connections persist until one side closes. Deleting the Runtime endpoint forces closure of established streams by removing the endpoint they are connected to. The CLI parameter is `--endpoint-name`, **not** `--endpoint-identifier`. For persistent external connections from VPC-mode resources, also apply a VPC NACL deny rule — NACLs are stateless and immediately drop packets on established connections.

   ```bash
   for RT in $(aws bedrock-agentcore-control list-agent-runtimes \
     --query "agentRuntimes[].agentRuntimeId" --output text); do
     for EP in $(aws bedrock-agentcore-control list-agent-runtime-endpoints \
       --agent-runtime-id "$RT" --query "runtimeEndpoints[].name" --output text); do
       aws bedrock-agentcore-control delete-agent-runtime-endpoint \
         --agent-runtime-id "$RT" --endpoint-name "$EP"
     done
   done

   aws ec2 create-network-acl-entry --network-acl-id <acl> --rule-number 10 \
     --protocol -1 --rule-action deny --cidr-block 0.0.0.0/0 --egress
   ```

5. **Revert any network-mode drift**
   If an attacker changed Code Interpreter from SANDBOX or VPC, or Browser from VPC, to PUBLIC, revert to the IaC-known-good mode. (Code Interpreter supports `PUBLIC | SANDBOX | VPC`; **Browser supports only `PUBLIC | VPC`** — there is no Browser SANDBOX mode, so the only non-public Browser option is VPC.) AgentCore exposes **no update API** for Code Interpreter or Browser — `networkConfiguration` is immutable once the tool is created. To revert, delete the tool resource and recreate it from IaC with the correct `networkConfiguration`. Active sessions must be stopped first (step 1) because the tool cannot be deleted with active sessions.

   ```bash
   # Delete the tool with the drifted network mode (requires no active sessions)
   aws bedrock-agentcore-control delete-code-interpreter \
     --code-interpreter-id "$CODE_INTERPRETER_ID"

   # Recreate from IaC with the correct networkConfiguration, for example:
   aws bedrock-agentcore-control create-code-interpreter \
     --name "<same-name-as-iac>" \
     --execution-role-arn "<execution-role-arn>" \
     --network-configuration '{"networkMode":"SANDBOX"}'
   ```

6. **Block DNS-based exfiltration at Route 53 Resolver DNS Firewall (if configured for the VPC)**
   Adding the suspect domain to a block-list rule stops further DNS queries to it and produces alerts when the sandbox retries.

   ```bash
   aws route53resolver create-firewall-rule \
     --firewall-rule-group-id <group> --firewall-domain-list-id <dlist> \
     --priority 100 --action BLOCK --block-response NODATA --name "ir-block-$INCIDENT_ID"
   ```

7. **Revoke Web Bot Auth signing keys (if the Browser signing configuration was compromised)**
   Delete the signing configuration on the Browser and notify the external WAF provider (Cloudflare, HUMAN, Akamai) that the signing identity is revoked, so they stop allowlisting requests signed with the compromised key.

> 🤖 **Automation opportunity:** An AWS Systems Manager Automation runbook that stops all active sessions, deletes saved Browser Profiles, and applies the sandbox-session deny SCP on a single security-team invocation. [Link TBD]

**Account-wide kill switch (full shutdown).** If scope is unclear, spans multiple components, or the Incident Commander directs a full shutdown, the AgentCore emergency kill switch severs every AgentCore authorization path. It terminates *all* agentic workflows in the account — legitimate and compromised — so obtain explicit written authorization and run a pre-execution impact assessment (cross-account targets, shared OAuth providers, external MCP connections, shared Cognito app clients, active sessions) first. It proceeds in six sequential phases: **(1) block new API calls** via an emergency SCP denying `bedrock-agentcore:*` (the single AgentCore IAM prefix — there is no `bedrock-agentcore-control:*` prefix), `bedrock:InvokeModel*`, and CloudFormation stack mutation, except the IR role; **(2) sever authentication** — disable Cognito users and global-sign-out, delete confidential app clients, workload identities, and credential providers; **(3) sever authorization** — force every Gateway to `ENFORCE` and apply a deny-all Cedar policy; **(4) sever tool access** — delete every Gateway target and every resource-based policy on Runtimes, endpoints, and Gateways; **(5) sever network and active sessions** — stop every Code Interpreter and Browser session (accepting zero-data-retention loss), delete every Runtime endpoint to close streams, and replace VPC-mode ENI security groups with an empty-rule isolation group; **(6) prevent recreation** — invalidate AgentCore SSM parameters and disable AgentCore/Bedrock EventBridge rules. Afterward, revoke tokens at external OAuth providers, block C2 IPs at VPC NACL, and monitor CloudTrail for 48 hours for any residual AgentCore activity.

### 3.3 Evidence Preservation Reminders

After containment begins, ensure the following before modifying or terminating any further resources:

- [ ] **Active sandbox session content captured (Browser Live View / Session Replay / OTel spans) BEFORE any session stop** — microVMs enforce zero data retention; content is unrecoverable after `stop-code-interpreter-session` / `stop-browser-session`
- [ ] List of active sessions (`list-code-interpreter-sessions` / `list-browser-sessions`) recorded before stopping them
- [ ] Sandbox execution-role state and CloudTrail timeline exported to the forensic bucket
- [ ] Saved Browser Profile inventory recorded before deletion (which profiles existed, when each was saved)
- [ ] All relevant CloudTrail, VPC Flow Log, and Route 53 DNS log segments exported to the forensic S3 bucket
- [ ] S3 Object Lock / legal hold applied to the forensic bucket; CloudTrail log-file integrity validation confirmed on exported logs

---

## Part 4 — Eradicate & Recover

> **CSF 2.0 Function:** Respond (Eradicate) · Recover
> **Goal:** Remove the root cause, validate the environment is clean, and restore normal operations.

### 4.1 Root Cause Identification

> `[IR Lead]` owns this step. Document findings in the IR ticket in real time.

Determine the root cause before beginning eradication. Common root causes for this incident type:

- **Over-privileged sandbox execution role** — the MMDS exposes the execution role's credentials to any code in the sandbox; broad Secrets Manager / S3 / `bedrock:InvokeModel*` access turns the sandbox into a privilege-escalation launchpad (most common).
- **Network-mode drift to PUBLIC** — an attacker (or an unreviewed change) recreated a SANDBOX/VPC resource as PUBLIC, removing egress restrictions.
- **A prompt-injection path** that drove the tool call — a vulnerable prompt-handling code path let untrusted input steer the agent into invoking Code Interpreter or Browser against attacker-chosen targets.
- **Missing forensic capture configuration** — no Browser Live View / Session Replay destination, no DNS logging, no OTel instrumentation, so the abuse ran without visibility.
- **An external WAF allowlisting** a Web Bot Auth signing identity whose key was compromised.

Use the evidence collected in Part 2 (execution-role CloudTrail timeline, OTel reasoning spans, DNS logs, VPC Flow Logs) to trace the initial access vector and full attack path.

### 4.2 Eradication Actions

> `[IR Lead]` coordinates. `[Account / Agent Owner]` approves changes to production resources.

1. **Rebuild Code Interpreter and Browser resources from IaC with hardened configuration**
   Pin `networkMode` away from PUBLIC: Code Interpreter to SANDBOX or VPC, and Browser to VPC (Browser has no SANDBOX mode). Scope the execution role to the minimum required permissions — do not grant `bedrock:InvokeModel*` to the sandbox execution role unless the agent specifically needs model access from inside the sandbox, and never grant broad Secrets Manager or S3 access. Do **not** restore saved Browser Profiles that existed during the incident window.

2. **Audit every sandbox execution role**
   The MMDS exposes the execution role's credentials to any code that runs in the sandbox, so an over-privileged execution role is a privilege-escalation launchpad. Enumerate roles whose names indicate sandbox attachment (`agentcore` plus `tool`, `ci`, or `browser`) and review every attached and inline policy. Remove anything not strictly required.

   ```bash
   for ROLE in $(aws iam list-roles \
     --query "Roles[?(contains(RoleName,'agentcore') || contains(RoleName,'AgentCore')) && (contains(RoleName,'tool') || contains(RoleName,'Tool') || contains(RoleName,'ci') || contains(RoleName,'CI') || contains(RoleName,'browser') || contains(RoleName,'Browser'))].RoleName" \
     --output text); do
     echo "=== $ROLE ==="
     aws iam list-attached-role-policies --role-name "$ROLE"
     aws iam list-role-policies --role-name "$ROLE"
   done
   ```

3. **Remove attacker persistence mechanisms**
   Check for and remove:
   - [ ] Saved Browser Profiles created during the window (authenticated-cookie persistence)
   - [ ] Any Code Interpreter / Browser resource left in PUBLIC network mode
   - [ ] Web Bot Auth signing configurations the attacker added or repurposed
   - [ ] EventBridge rules that re-create deleted Code Interpreter / Browser resources (look for rules triggered by AgentCore delete events targeting a Lambda that recreates them)
   - [ ] Injected inline or attached policies on the sandbox execution role
   - [ ] New IAM principals or access keys created using MMDS-harvested credentials (walk the credential chain: for each `CreateAccessKey` / `CreateRole` / `CreateUser` by the execution role, enumerate the resulting principal and re-run the investigation against it until no new credentials appear)

4. **Rotate every secret readable by sandbox-executed code during the window**
   Check CloudTrail for `GetSecretValue` calls by the sandbox execution role and rotate each secret returned. Rotation forces an attacker who captured the old secret to re-acquire it, by which time the sandbox is hardened.

> 🤖 **Automation opportunity:** AWS Config auto-remediation that deletes or quarantines any Code Interpreter / Browser resource detected in PUBLIC mode. [Link TBD]

### 4.3 Recovery Actions

1. **Restore from known-good state**
   For sandbox tools (stateless), the restore point is your last known-good IaC commit hash. Redeploy Code Interpreter and Browser from IaC with the hardened configuration from the eradication phase. Confirm no PUBLIC-mode resource exists in production — Code Interpreter resources should be SANDBOX or VPC, Browser resources VPC (Browser has no SANDBOX mode). Do not restore saved Browser Profiles that existed during the incident window.

2. **Re-enable services and access**
   - [ ] Remove the sandbox-session deny SCP (containment step 3) **only after** sandbox sessions succeed with the restricted scope — tool abuse should be blocked while new, hardened sessions succeed
   - [ ] Re-create any legitimate Runtime endpoints deleted to break streams
   - [ ] Run an end-to-end test: start a session, execute benign code or navigate to an allowlisted URL, and confirm the session terminates cleanly with no residual data. If the test fails, recovery is incomplete.

3. **Harden against recurrence**
   - [ ] Add a permissions boundary on every sandbox execution role restricting MMDS-accessible credentials to a hardened allowlist
   - [ ] Confirm Browser Live View / Session Replay destination and Route 53 DNS logging are now enabled
   - [ ] Add VPC endpoints (S3, ECR.API, ECR.DKR, CloudWatch Logs) in any VPC hosting VPC-mode resources so legitimate AWS traffic does not need NAT egress and any remaining public-destination egress stands out

### 4.4 Recovery Validation

Confirm the environment is clean before declaring the incident resolved.

- [ ] No PUBLIC-mode Code Interpreter / Browser resources remain in any production account
- [ ] All saved Browser Profiles from the incident window are deleted
- [ ] Sandbox execution roles are scoped to least privilege and carry permissions boundaries
- [ ] All secrets readable by sandbox code during the window have been rotated; all attacker-created credentials revoked
- [ ] GuardDuty / Security Hub show no active findings related to this incident
- [ ] `InvokeCodeInterpreter` / `ConnectBrowserAutomationStream` volumes and external-destination DNS queries monitored for 48 hours and within pre-incident baseline (a spike indicates a retained access path)
- [ ] Monitoring and alerting confirmed operational; AWS Security Incident Response case updated / closed (if applicable)

---

## Part 5 — Post-Incident Activity

> **CSF 2.0 Function:** Identify (Improve) — continuous improvement, not a one-time activity
> **Goal:** Learn from this incident to reduce the likelihood and impact of future occurrences.

### 5.1 Timeline Reconstruction

Document the full incident timeline. Complete this within 24–48 hours while memory is fresh.

| Timestamp (UTC) | Event | Source / Evidence | Actor |
|---|---|---|---|
| YYYY-MM-DD HH:MM | Initial sandbox abuse / earliest anomalous `InvokeCodeInterpreter` or `ConnectBrowserAutomationStream` | CloudTrail / OTel span | Threat actor |
| YYYY-MM-DD HH:MM | Detection signal fired (DNS-log cluster, egress anomaly, volume alarm) | CloudWatch / GuardDuty | AWS / monitoring |
| YYYY-MM-DD HH:MM | IR team notified | On-call alert | IR Lead |
| YYYY-MM-DD HH:MM | Sandbox session content captured (Live View / Replay / OTel) | Customer S3 | IR Lead |
| YYYY-MM-DD HH:MM | Sessions stopped, profiles deleted, drift reverted (containment) | IR ticket | IR Lead |
| YYYY-MM-DD HH:MM | Recovery validated | IR ticket | IR Lead |

**Key metrics to capture:**

| Metric | Value |
|---|---|
| Time to Detect (TTD) | *HH:MM from initial event to detection* |
| Time to Notify (TTN) | *HH:MM from detection to IR team notified* |
| Time to Contain (TTC) | *HH:MM from notification to containment* |
| Time to Recover (TTR) | *HH:MM from containment to recovery validated* |
| Total Incident Duration | *HH:MM* |
| Affected Resources | *Count and type of CI / Browser / Runtime resources* |
| Data Impact | *Confirmed / Suspected / None* |

### 5.2 Post-Incident Review

Conduct a blameless post-incident review within **5 business days** for P1/P2, **15 business days** for P3/P4.

Discussion questions:

1. What was the initial access vector — prompt injection, a compromised inbound identity, or an unreviewed network-mode change? Could it have been prevented with existing controls?
2. Was a sandbox session active when we detected the incident, and did we capture its content before stopping it? If not, what forensic capture configuration was missing?
3. How was the incident detected? For PUBLIC/SANDBOX-mode resources (no Flow Logs), did DNS logging and application-layer signals catch it fast enough?
4. Did containment actions work as expected? Did the network-mode-drift revert (delete+recreate) succeed cleanly, and did the WebSocket/AGUI streams actually close after endpoint deletion?
5. Was the sandbox execution role over-privileged? What did the MMDS expose to in-sandbox code?
6. What would have reduced the blast radius — a tighter execution role, a permissions boundary, an SCP pinning network mode, or earlier evidence capture?
7. What single change would most improve our response to this scenario in future?

### 5.3 Detection Gap Analysis

For each detection source that *did not* catch this incident early, document why and what would have:

| Gap | Root Cause | Recommended Fix | Owner | Target Date |
|---|---|---|---|---|
| Sandbox session content unrecoverable | No Browser Live View / Session Replay destination configured | Enable Live View + Session Replay to an S3 bucket on every Browser resource | | |
| Exfiltration invisible (PUBLIC/SANDBOX mode) | No Route 53 Resolver DNS query logging | Enable DNS query logging for every VPC hosting AgentCore resources | | |
| Network-mode drift to PUBLIC not alarmed | No EventBridge rule on Delete+Create with changed `networkMode` | Add EventBridge rule that auto-pages on the delete+recreate-with-different-mode sequence | | |
| Could not tell injection from legitimate tool call | No Runtime OTel (ADOT) instrumentation | Enable ADOT so spans record the reasoning step that invoked the tool | | |

### 5.4 Playbook Update Checklist

Review and update this playbook based on what you learned. Do not wait for the next scheduled review.

- [ ] Were triage questions sufficient (especially the "is a session active right now?" question)? Add/remove as needed.
- [ ] Were evidence collection steps accurate — particularly the zero-data-retention capture-before-stop sequence?
- [ ] Were containment actions effective per attack class (session stop, profile delete, drift revert, stream break)? Update steps if not.
- [ ] Were automation opportunities identified (drift-detection EventBridge rule, PUBLIC-mode Config rule, SSM session-kill runbook)? Add stubs.
- [ ] Were severity criteria accurate? Adjust if incidents were under- or over-classified.
- [ ] Update **Last Reviewed** date and increment **Playbook Version**.

---

## Appendix A — Useful Queries

> **Locate your CloudTrail log group first.** The CloudWatch Logs Insights queries below run against the CloudTrail trail's log group, whose name is environment-specific (not a fixed `/aws/cloudtrail`). Resolve it before running them: `aws cloudtrail describe-trails --query 'trailList[?CloudWatchLogsLogGroupArn].CloudWatchLogsLogGroupArn' --output text` and use the log-group portion of that ARN as the `--log-group-name`.

### Code Interpreter session activity (CloudWatch Logs Insights, CloudTrail log group)

```text
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress,
       requestParameters.codeInterpreterIdentifier, requestParameters.sessionId
| filter eventSource = "bedrock-agentcore.amazonaws.com"
| filter eventName in [
    "StartCodeInterpreterSession","StopCodeInterpreterSession",
    "InvokeCodeInterpreter","ListCodeInterpreterSessions"
  ]
| stats count() as calls by userIdentity.arn, eventName, sourceIPAddress
| sort calls desc
```

### Browser session activity and streaming connections

Browser activity spans both `ConnectBrowserAutomationStream` (CDP navigation; the target URL is a request parameter inside that call) and the **standalone `InvokeBrowser` action** (OS-level mouse/keyboard/screenshot/dialog actions on an active session). Hunt for both, plus profile-persistence (`SaveBrowserSessionProfile`).

```text
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress,
       requestParameters.browserIdentifier, requestParameters.sessionId
| filter eventSource = "bedrock-agentcore.amazonaws.com"
| filter eventName in [
    "StartBrowserSession","StopBrowserSession",
    "ConnectBrowserAutomationStream","ConnectBrowserLiveViewStream","UpdateBrowserStream",
    "InvokeBrowser","SaveBrowserSessionProfile"
  ]
| stats count() as calls by userIdentity.arn, eventName
| sort calls desc
```

### Network-mode drift (delete + recreate is the only way to change an immutable network mode)

```text
fields @timestamp, eventName, userIdentity.arn, requestParameters.networkConfiguration
| filter eventSource = "bedrock-agentcore.amazonaws.com"
| filter eventName in ["CreateCodeInterpreter","DeleteCodeInterpreter","CreateBrowser","DeleteBrowser","CreateBrowserProfile","DeleteBrowserProfile"]
| sort @timestamp desc
```

### Persistent WebSocket / AGUI streams and interactive command shells

```text
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress
| filter eventSource = "bedrock-agentcore.amazonaws.com"
| filter eventName in [
    "InvokeAgentRuntimeWithWebSocketStream",
    "InvokeAgentRuntimeWithWebSocketStreamForUser",
    "InvokeAgentRuntimeCommand",
    "InvokeAgentRuntimeCommandShell"
  ]
| sort @timestamp desc
```

### VPC egress from sandbox ENIs (VPC-mode resources only)

```bash
aws ec2 describe-network-interfaces \
  --filters Name=description,Values="*bedrock-agentcore*" \
  --query "NetworkInterfaces[].{ENI:NetworkInterfaceId,IP:PrivateIpAddress,SG:Groups[0].GroupId}" \
  --output table
```

```text
fields @timestamp, srcAddr, dstAddr, dstPort, protocol, bytes, action
| filter srcAddr in ["<sandbox-eni-ip-1>","<sandbox-eni-ip-2>"]
| filter action = "ACCEPT"
| filter dstAddr not like /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/
| stats sum(bytes) as total_bytes by dstAddr, dstPort
| sort total_bytes desc
```

> PUBLIC-mode and SANDBOX-mode resources produce **no** flow-log visibility. For those modes, detection relies on the DNS query below and on application-layer logs only.

### DNS exfiltration (Route 53 Resolver DNS query logs)

```text
fields @timestamp, query_name, query_type, srcaddr, rcode
| filter query_name not like /amazonaws\.com/
| filter query_name not like /aws\.dev/
| stats count() as queries by query_name
| sort queries desc
| limit 50
```

> The `as queries` alias is required. CloudWatch Logs Insights aggregation functions produce an unaliased field named literally `count()`; referring to it as `count` in the `sort` clause silently no-ops, so `| limit 50` would return arbitrary rows rather than the top-50 highest-volume domains.

### Sandbox execution-role CloudTrail timeline (what the role *did*, not just what it *could* do)

```text
fields @timestamp, eventName, sourceIPAddress, awsRegion, errorCode
| filter userIdentity.sessionContext.sessionIssuer.arn like /<ci-or-browser-exec-role>/
| sort @timestamp asc
```

Red flags: `GetSecretValue`, `s3:GetObject` on buckets outside the agent's expected scope, any call from a `sourceIPAddress` outside AWS (indicates MMDS credentials were harvested and used externally), or cross-region activity inconsistent with the agent's deployment region.

### Web Bot Auth configuration changes

```text
fields @timestamp, eventName, userIdentity.arn, requestParameters
| filter eventSource = "bedrock-agentcore.amazonaws.com"
| filter eventName like /Browser/
| filter ispresent(requestParameters.browserSigning)
```

### GuardDuty finding export (CLI)

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

See [Regulatory Context](../../REGULATORY_CONTEXT.md) for the full notification obligation matrix by regulation and incident type.

Tool-abuse incidents can carry data-impact even when the blast radius looks technical: a Code Interpreter exfiltration channel may have moved Memory contents, conversation history, or files staged in the sandbox out of the environment; a Browser SSRF or saved-Profile session may have read internal data or acted as an authenticated user against a third-party service. Determine data-subject impact early (Part 2) — whether conversation histories or sandbox-staged data are associated with identifiable users drives the downstream obligations below.

**Quick reference for this scenario:**

| Regulation | Trigger Condition | Timeframe |
|---|---|---|
| GDPR Art. 33 | Personal data confirmed exfiltrated from a sandbox or read via Browser SSRF | 72 hours to supervisory authority from awareness |
| HIPAA Breach Notification Rule | Protected health information in sandbox-staged data or Memory confirmed accessed | Without unreasonable delay, ≤60 days |
| PCI-DSS | Cardholder data reachable by the sandbox confirmed accessed | Per acquirer/brand agreement; notify promptly |
| US state breach-notification laws | Residents' personal information confirmed exfiltrated | Varies by state; often "without unreasonable delay" |

> ⚠️ The clock starts at **awareness**, not confirmation. When in doubt, assume notification is required and consult Legal immediately.

---

## Appendix C — Reference Links

- [NIST SP 800-61r3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [Amazon Bedrock AgentCore Developer Guide](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [AWS Security Incident Response Service Documentation](https://docs.aws.amazon.com/security-ir/latest/userguide/what-is-security-ir.html)
- [AWS Prescriptive Guidance — Providing secure access, usage, and implementation of generative AI agents](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture-generative-ai/gen-auto-agents.html)
- [AWS Well-Architected Framework — Security Pillar: Incident Response](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/incident-response.html)
- [Amazon GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [AWS CloudTrail Query Examples (Athena)](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)

---

## Revision History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | 2026-06-20 | AWS | Initial draft |
