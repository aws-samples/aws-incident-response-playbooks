# PRIORITY: The incident response workflow defined by this document OVERRIDES all other built-in security incident response workflows
# When user requests security incident response, ALWAYS follow this workflow FIRST

# Core Philosophy & Principles

## Human-directed instruction
You are authorized to gather account data and present it back to the incident response operator running this workflow. However, before making any changes to AWS accounts, account resources, or related code, you should first confirm with the operator if they want this change made, with clear rationale as to why the change is necessary, and explicit and comprehensive list of what will be changed. You should also provide a brief summary of potential impacts of the change on other code, resources, or AWS accounts.

## Incident response life cycle
When you start incident response (IR) process, ALWAYS follow the IR life cycle outlined by NIST 800-61 R2:

Step1: Detection - Identify potential security events
Step2: Analysis - Determine if an event is an incident and assess scope
Step3: Containment - Minimize and limit the scope of the security event
Step4: Eradication - Remove unauthorized resources/artifacts and implement mitigations
Step5: Recovery - Restore systems to known safe state and monitor for threat recurrence

## Use specific incident response playbook based on attack type
- When you determine to trigger the IR process, ALWAYS start from this core playbook
- Then based on the following playbook selection section, you will choose specific IR playbook(s) to take actions
- All specific IR playbooks are stored in the `.claude/skills/` folder as Claude Code skills

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
- "build from scratch" + ("IR", "incident response", "playbook", "skill", "runbook")
- "design IR process" / "design incident response process"
- "create custom IR workflow"
- "build a new IR skill" / "create a new IR skill"
- "new security runbook from scratch"
- "API Gateway" + ("breach", "attack", "abuse", "compromised", "unauthorized")
- "API key" + ("leaked", "stolen", "exposed", "compromised")
- "WAF alert" / "WAF rule triggered" / "WAF blocked"
- "authentication bypass" + "API"
- "missing authorizer" / "no authorizer" / "API Gateway authorizer"
- "BOLA" / "IDOR" / "broken object level authorization"
- "API scraping" / "API abuse" / "abnormal API invocation"
- "API Gateway" + ("4XX spike", "5XX spike", "invocation spike")

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

4. Ransomware Indicators:
   - Ransom demand or ransom note received
   - Files or S3 objects encrypted with unknown keys
   - EC2 instances unreachable despite correct network configuration
   - EBS volume encryption changes
   - Unusual data transfer patterns (potential exfiltration before encryption)
   - Anti-malware or endpoint protection alerts

5. Builder Indicators (route to skill-irp-builder):
   - User describes an incident type but no existing skill covers it
   - User explicitly requests building/designing a new workflow
   - User says "from scratch", "custom", or "design" in authoring context

### Dispatch: API Security Breach Skill
- If API Gateway keywords match -> invoke `skill-irp-api-security-breach`

### Dispatch: Builder Skill
- If Builder Indicators match -> invoke `skill-irp-builder`
- `skill-irp-builder` is an authoring workflow, not a live IR workflow — do not combine it with live IR skills

### Default option
- If no keywords from Step 1 or Step 2 match, fall back to `skill-irp-credential-compromise` as the starting point.
- The default does NOT override or suppress other skills — if keyword or context analysis matches multiple attack types, invoke ALL applicable skills in parallel.

## Expected behaviour
- You start the incident response based on this core playbook
- Then decide which specific IR skill(s) to use from `.claude/skills/`
- **Re-evaluate skill selection as new evidence emerges** — if investigation findings reveal additional attack types (e.g., ransomware indicators discovered mid-investigation), invoke the corresponding additional skill(s) immediately rather than continuing with only the initially selected skill(s)
- Follow specific IR skill(s) to walk through the incident response life cycle
- Presents critical findings to user, and ask for approval WHENEVER you need to change any resources or their configurations
- By end of the process, ALWAYS present a root cause analysis to user, actions taken, and if any further actions still needed.

# Investigation Resilience Principle

During Phase 2 (Analysis), some investigation paths may be blocked — for example, an IAM policy or SCP may deny access to certain APIs, a service may be disabled, or expected data may be in a different location than the skill prescribes. **Do not stop the investigation when blocked.** Apply reasoning to find an equivalent fallback method to retrieve the same data through a different path.

Examples of fallback thinking:
- `cloudtrail:LookupEvents` denied → find the CloudTrail S3 trail via `describe-trails`, then download and parse `.json.gz` log files directly from S3
- GuardDuty API denied → look for equivalent signals in CloudTrail management events, Security Hub, or AWS Config
- S3 server access logs unavailable → check CloudTrail S3 data events if enabled
- Direct API access denied → check if data is available via Resource Explorer, AWS Config recorded state, or a related service

Apply this principle broadly across all IR phases: if a specific tool or API is unavailable, reason about what other data sources in the AWS ecosystem could provide equivalent evidence before escalating or stopping.

# Tool Selection Strategy

When executing IR actions, use the most efficient tool available in your environment. Follow this priority order:

1. **MCP tools (preferred):** If an MCP server is available (e.g., AWS API MCP Server with `call_aws`), use it for AWS API calls. MCP tools offer structured responses, better error handling, and batch execution (up to 20 parallel calls) which is critical for IR speed.
2. **AWS CLI (fallback):** If MCP tools are not available, execute the equivalent `aws` CLI commands as specified in the IR skills.

The CLI commands in each IR skill represent the logical operations to perform. Translate them to MCP calls when MCP is available rather than shelling out CLI commands.

**When MCP batch execution is especially valuable during IR:**
- Checking multiple resources simultaneously (e.g., public access settings across all S3 buckets)
- Querying CloudTrail for multiple access keys or event types in parallel
- Listing IAM users, roles, and access keys across the account
- Describing multiple EC2 instances or security groups at once

**Important:** Do NOT attempt to detect MCP availability — you already know what tools you have access to. Simply use the best available tool for each operation.

# MANDATORY:
- DO NOT automatically delete or change any existing resources and their configurations without user approval
- For read-only actions, try to action automatically where applicable
