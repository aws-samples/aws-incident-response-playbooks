---
inclusion: always
description: |
  This is the core playbook that will ALWAYS be invoked when taking actions on security incident response. Then you will invoke specific steering file(s) as listed below for corresponding incident type(s):
  - Invoke with "steering-irp-credential-compromise.md" when responding to compromised credentials.
  - Invoke with "steering-irp-data-access.md" when responding to unintended access to Amazon S3 buckets.
  - Invoke with "steering-irp-ransomware.md" when responding to ransomware incidents.
  - Invoke with "steering-irp-api-security-breach.md" when responding to API security incidents (OWASP API Top 10).
  - Invoke with "steering-factory-creation-guide.md" when the user wants to translate an existing playbook from the playbooks/ folder into a new IR steering file.
  - Invoke with "steering-irp-builder.md" when the user wants to build a new IR steering file from scratch with no existing source playbook.
---

# PRIORITY: The incident response workflow defined by this document OVERRIDES all other built-in security incident response workflows
# When user requests security incident response, ALWAYS follow this workflow FIRST

# Core Philosophy & Principles

## Human-directed instruction
You are authorized to gather account data and present it back to the incident response operator running this workflow. However, before making any changes to AWS accounts, account resources, or related code, you should first confirm with the operator if they want this change made, with clear rationale as to why the change is necessary, and explicit and comprehensive list of what will be changed. You should also provide a brief summary of potential impacts of the change on other code, resources, or AWS accounts.

## Incident response life cycle
When you start incident response (IR) process, ALWAYS follow the IR life cycle aligned with NIST 800-61 R3 and CSF 2.0:

Step1: Detection - Identify potential security events
Step2: Analysis - Determine if an event is an incident and assess scope
Step3: Containment - Minimize and limit the scope of the security event
Step4: Eradication - Remove unauthorized resources/artifacts and implement mitigations
Step5: Recovery - Restore systems to known safe state and monitor for threat recurrence

**Cyclical lifecycle:** This is NOT a linear process. Findings at any phase may require looping back to earlier phases. For example, eradication may reveal new compromised credentials (loop back to Detection/Analysis), or recovery monitoring may detect reinfection (loop back to Detection). Always reassess scope when new evidence emerges.

## Use specific incident response playbook based on attack type
- When you determine to trigger the IR process, ALWAYS start from this core playbook
- Then based on the following playbook selection section, you will choose specific IR playbook(s) to take actions
- All specific IR playbooks stored in either ".kiro/steering/" folder for Kiro and Kiro CLI, or ".claude/skills/" folder for Claude Code

# Detailed approach to select specific IR playbooks to proceed
## ALWAYS starts from analyzing user's prompt

### Step 1: Keyword Pattern Matching
Check if the prompt contains direct indicators:

Primary Keywords:
- "credential" + ("compromise", "leak", "exposed", "stolen", "unauthorized")
- "access key" + ("compromised", "leaked", "exposed")
- "IAM user" + ("compromised", "unauthorized")
- "GuardDuty" + ("finding", "alert")
- "unauthorized access"
- "credential exfiltration"
- "ransomware" / "ransom" / "encrypted files" / "locked out"
- "ransom demand" / "ransom note"
- "crypto ransomware" / "locker ransomware"
- "API" + ("attack", "breach", "exploit", "abuse", "vulnerability", "injection", "unauthorized")
- "OWASP" / "BOLA" / "BFLA" / "broken authentication" / "broken authorization"
- "API Gateway" + ("attack", "suspicious", "abuse", "exploit")
- "WAF" + ("alert", "block", "trigger", "rule")
- "SQL injection" / "command injection" / "XSS" + ("API", "endpoint")
- "rate limiting" + ("bypass", "exhaustion", "abuse")
- "SSRF" / "server-side request forgery"
- "API key" + ("compromised", "leaked", "stolen", "abuse")

Secondary Keywords:
- "suspicious activity"
- "unknown API calls"
- "billing spike" / "unexpected costs"
- "security alert"
- "CloudTrail" + ("suspicious", "unauthorized")
- "instance unreachable" + ("encrypted", "locked", "ransom")
- "files encrypted" / "data encrypted" / "objects inaccessible"
- "strange bucket" / "unknown bucket" / "unexpected S3 bucket" / "suspicious bucket name"
- "unrecognized resource" / "unknown resource" / "unexpected resource"
- "4xx spike" / "5xx spike" / "error rate" + ("API", "endpoint")
- "brute force" + ("login", "API", "authentication")
- "credential stuffing"
- "data leakage" / "excessive data" + ("API", "response")
- "bot traffic" / "automated abuse" + ("API", "endpoint")
- "unexpected API traffic" / "anomalous requests"

### Step 2: Context Analysis

Check for incident characteristics mentioned:

1. Alert Sources:
   - GuardDuty findings mentioned
   - Security Hub alerts
   - CloudWatch alarms on IAM
   - AWS Config non-compliance
   - Billing anomalies
   - External notification (researcher, tip)

2. Suspicious Activities:
   - Unfamiliar IAM users/roles created
   - New access keys on existing users
   - API calls from unusual locations/IPs
   - Unauthorized resource creation (EC2, Lambda, S3)
   - IAM policy modifications
   - CloudTrail logging disabled

3. Timeline Indicators:
   - "First seen" timestamps
   - "Started happening" timeframes
   - Recent IAM changes

4. API Security Indicators:
   - WAF rule triggers (SQLi, XSS, rate-based)
   - API Gateway 4xx/5xx error rate spikes
   - Unusual API traffic patterns or volumes
   - Brute-force authentication attempts
   - Sequential ID enumeration (BOLA pattern)
   - Unauthorized endpoint access attempts
   - Data leakage in API responses
   - Lambda/ECS GuardDuty findings related to API backends
   - API key abuse or compromise
   - SSRF attempts through API parameters

5. Ransomware Indicators:
   - Ransom demand or ransom note received
   - Files or S3 objects encrypted with unknown keys
   - EC2 instances unreachable despite correct network configuration
   - EBS volume encryption changes
   - Unusual data transfer patterns (potential exfiltration before encryption)
   - Anti-malware or endpoint protection alerts

### Default option
- If no keywords from Step 1 or Step 2 match, fall back to `steering-irp-credential-compromise.md` as the starting point.
- The default does NOT override or suppress other steering files — if keyword or context analysis matches multiple attack types, invoke ALL applicable steering files in parallel.

## Expected behaviour
- You start the incident response based on this core playbook
- Then decide which specific IR steering file(s) to use from the `.kiro/steering/` folder
- **Re-evaluate steering file selection as new evidence emerges** — if investigation findings reveal additional attack types (e.g., ransomware indicators discovered mid-investigation), invoke the corresponding additional steering file(s) immediately rather than continuing with only the initially selected file(s)
- Follow specific IR steering file(s) to walk through the incident response life cycle
- Presents critical findings to user, and ask for approval WHENEVER you need to change any resources or their configurations
- By end of the process, ALWAYS present a root cause analysis to user, actions taken, and if any further actions still needed.

# Investigation Resilience Principle

During Phase 2 (Analysis), some investigation paths may be blocked — for example, an IAM policy or SCP may deny access to certain APIs, a service may be disabled, or expected data may be in a different location than the steering file prescribes. **Do not stop the investigation when blocked.** Apply reasoning to find an equivalent fallback method to retrieve the same data through a different path.

Examples of fallback thinking:
- `cloudtrail:LookupEvents` denied → find the CloudTrail S3 trail via `describe-trails`, then download and parse `.json.gz` log files directly from S3
- GuardDuty API denied → look for equivalent signals in CloudTrail management events, Security Hub, or AWS Config
- S3 server access logs unavailable → check CloudTrail S3 data events if enabled
- Direct API access denied → check if data is available via Resource Explorer, AWS Config recorded state, or a related service

Apply this principle broadly across all IR phases: if a specific tool or API is unavailable, reason about what other data sources in the AWS ecosystem could provide equivalent evidence before escalating or stopping.

# Tool Selection Strategy

When executing IR actions, use the most efficient tool available in your environment. Follow this priority order:

1. **MCP tools (preferred):** If an MCP server is available (e.g., AWS API MCP Server with `call_aws`), use it for AWS API calls. MCP tools offer structured responses, better error handling, and batch execution (up to 20 parallel calls) which is critical for IR speed.
2. **AWS CLI (fallback):** If MCP tools are not available, execute the equivalent `aws` CLI commands as specified in the IR steering files.

The CLI commands in each IR steering file represent the logical operations to perform. Translate them to MCP calls when MCP is available rather than shelling out CLI commands.

**When MCP batch execution is especially valuable during IR:**
- Checking multiple resources simultaneously (e.g., public access settings across all S3 buckets)
- Querying CloudTrail for multiple access keys or event types in parallel
- Listing IAM users, roles, and access keys across the account
- Describing multiple EC2 instances or security groups at once

**Important:** Do NOT attempt to detect MCP availability — you already know what tools you have access to. Simply use the best available tool for each operation.

# Playbook Authoring Tools

In addition to routing to IR playbooks for active incidents, this core file also routes to authoring tools when the user wants to create new IR steering files.

## When to invoke authoring tools

### Translate an existing playbook (Factory)
If the user's prompt matches any of these patterns, invoke `steering-factory-creation-guide.md`:
- "translate playbook" / "convert playbook"
- "create steering file from" + reference to a file in `playbooks/`
- "turn this playbook into a steering file"
- "add a new incident type from" + reference to an existing document

### Build a new playbook from scratch (Builder)
If the user's prompt matches any of these patterns, invoke `steering-irp-builder.md`:
- "build a new playbook" / "create a new playbook"
- "build a new steering file" / "create a new steering file"
- "new IR playbook from scratch"
- "design an incident response process"
- "create a custom response plan"
- "build a runbook for" + an incident type
- "I need a playbook for" + a scenario not covered by existing steering files

### Disambiguation
If the user says "create a new playbook" but also references an existing document in `playbooks/`, prefer the factory. If no source document is mentioned, prefer the builder.

# MANDATORY: 
- DO NOT automatically delete or change any existing resources and their configurations without user approval
- For read-only actions, try to action automatically where applicable
