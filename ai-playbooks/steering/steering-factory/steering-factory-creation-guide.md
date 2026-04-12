---
inclusion: manual
description: |
  Guidance steering file for creating new incident response (IR) steering files by translating human-centric IR playbooks into agent-centric steering files.
  Use this steering file when you want to translate an existing playbook from the playbooks/ folder into a Kiro steering file, convert a human-centric IR playbook into an agent-actionable format, or add a new incident type to the IR steering file library from an existing source document.
---

# Guidance: Translating IR Playbooks into Agent-Centric Steering Files

## Purpose
This steering file guides you (the agent) through creating a new incident response [steering file](https://kiro.dev/docs/steering/) by translating a human-centric IR playbook from the `playbooks/` folder into an agent-actionable steering file stored in `.kiro/steering/kiro-steering/` and mirrored to `ai-playbooks/steering/reference/`.

## Procedure Overview

1. User indicates which playbook(s) in `playbooks/` to translate
2. You analyze the source playbook, reference existing steering files for format/structure, and produce a new steering file
3. You register the new steering file in the routing system so it can be invoked during incidents

---

## Step 1: Analyze the Source Playbook

Read the source playbook from `playbooks/` and extract:
- The incident type (e.g., "Credential Compromise", "Unintended S3 Data Access", "DoS/DDoS")
- The NIST 800-61 phases covered (Detection/Evidence, Containment, Eradication, Recovery, Post-Incident)
- Specific investigation steps, containment actions, and recovery procedures
- Any AWS services, APIs, or CLI commands referenced
- Alert sources and detection mechanisms mentioned

## Step 2: Reference Existing Steering Files

Read the existing steering files in `.kiro/steering/kiro-steering/` to understand the target format:

- #[[file:.kiro/steering/kiro-steering/steering-irp-credential-compromise.md]]
- #[[file:.kiro/steering/kiro-steering/steering-irp-data-access.md]]

Use these as structural templates. The new steering file MUST follow the same patterns.

## Step 3: Create the New Steering File

### 3.1 File Naming Convention

The file MUST be named: `steering-irp-<short-name>.md`

Where `<short-name>` is a concise, lowercase, hyphenated descriptor of the incident type.

Examples:
- `steering-irp-credential-compromise.md`
- `steering-irp-data-access.md`
- `steering-irp-dos-ddos.md`
- `steering-irp-ransomware.md`

Store the file in: `.kiro/steering/kiro-steering/` and mirror to `ai-playbooks/steering/reference/`

### 3.2 Front-Matter (REQUIRED)

Every steering file MUST begin with YAML front-matter:

```yaml
---
inclusion: manual
description: Incident response playbook for <incident type description>. Invoke with "steering-irp-<short-name>.md" when responding to <incident scenario>.
---
```

Rules:
- `inclusion` MUST be `manual` — these are invoked on-demand by the core playbook, not always loaded
- `description` MUST include the invoke filename so the routing system can reference it

### 3.3 Required Document Structure

The new steering file MUST follow this exact 5-part structure aligned with NIST 800-61 R3:

```
# Playbook: <Incident Type Title>

## Incident Type
<One paragraph describing the incident scenario>

## Quick Reference
<Table with columns: Phase | Key Action | Verification>
<One row per phase: Evidence, Contain, Eradicate, Recover, Post-Incident>

---

## Part 1: Acquire, Preserve, Document Evidence
### 1.1 Identify the Alert Source
### 1.2 <Investigation steps specific to this incident type>
### 1.x Document and Communicate

---

## Part 2: Contain the Incident
<Goal statement>
### 2.x <Containment actions with CLI commands>
### 2.x Verify Containment

---

## Part 3: Eradicate the Incident
<Goal statement>
### 3.x <Eradication steps with CLI commands>

---

## Part 4: Recover from the Incident
<Goal statement>
### 4.x <Recovery steps>
### 4.x Verify Recovery

---

## Part 5: Post-Incident Activity
### 5.1 Document Lessons Learned
### 5.2 Retrospective Questions
### 5.3 Update Defenses
### 5.4 Regulatory Notifications

---

## References
<Relevant AWS documentation links>
```

### 3.4 Content Transformation Rules

When translating from the human-centric playbook to the agent-centric steering file:

**STRIP the following from source playbooks:**
- Legal disclaimers and shared responsibility boilerplate
- "Introduction" and "Summary" sections that describe the playbook itself
- References to "customizing this template" or "Game Days"
- Cost Explorer disclaimers about incurred costs
- Generic NIST framework explanations (the core playbook already covers this)

**TRANSFORM the following:**
- Numbered prose steps → concise subsections with descriptive headings
- Vague instructions like "check CloudTrail" → specific AWS CLI commands with placeholder parameters (e.g., `<bucket-name>`, `<instance-id>`)
- Human decision points → checklists with `- [ ]` checkboxes
- References to "consult your CMDB" → keep but make them actionable checklist items
- Long paragraphs → bullet points or short paragraphs

**ADD the following if missing from the source playbook:**
- AWS CLI commands for every investigation and remediation step where applicable
- A Quick Reference table summarizing all phases
- Verification steps after containment and recovery
- Specific API call names to look for in CloudTrail (relevant to the incident type)
- Warning callouts (⚠️) for actions that affect production workloads
- Goal statements at the start of Parts 2, 3, and 4
- Loop-back instructions at the end of Parts 3 and 4: if new evidence or a different attack vector is discovered, direct the agent to return to Part 1 and reassess scope
- In Part 5 "Update Defenses", include: "Propose updates to this playbook and related steering files based on lessons learned — present changes to the operator for review and approval before modifying any steering files"

**PRESERVE the following from source playbooks:**
- The logical flow and ordering of incident response phases
- All AWS service-specific guidance and technical details
- Alert source identification steps
- Communication and stakeholder notification steps
- Post-incident and lessons-learned processes

### 3.5 CLI Command and Tool Selection Standards

All IR steering files use AWS CLI commands as the canonical representation of each operation. These serve as both the precise specification of what to do AND the fallback execution method.

When authoring CLI commands in the steering file:
- Use `aws` CLI syntax
- Include placeholder parameters in angle brackets: `<parameter-name>`
- Wrap in ```bash code blocks
- Include a brief comment above the command explaining its purpose when not obvious
- Group related commands under a single code block where logical

**MCP-aware authoring:** Where a set of CLI commands would benefit from parallel execution, add a comment noting the batch opportunity. For example:

```bash
# MCP batch opportunity: the following checks can be run in parallel
aws s3api get-public-access-block --bucket <bucket-1>
aws s3api get-public-access-block --bucket <bucket-2>
aws s3api get-public-access-block --bucket <bucket-3>
```

The agent will use MCP batch calls when available, or fall back to sequential CLI execution. Do NOT write MCP-specific syntax in the steering file — keep CLI as the universal format. The core playbook's Tool Selection Strategy handles runtime tool choice.

### 3.6 Quality Checklist Before Saving

Before writing the file, verify:
- [ ] Front-matter has `inclusion: manual` and a descriptive `description` with invoke syntax
- [ ] All 5 NIST phases are covered (Evidence, Contain, Eradicate, Recover, Post-Incident)
- [ ] Quick Reference table is present with all 5 phases
- [ ] CLI commands use placeholder parameters, not hardcoded values
- [ ] Warning callouts exist for destructive or production-impacting actions
- [ ] Verification steps exist after containment and recovery
- [ ] Loop-back instructions present at end of Parts 3 and 4 (return to Part 1 if new evidence emerges)
- [ ] Part 5 "Update Defenses" includes human-approval language for steering file modifications
- [ ] References section includes relevant AWS documentation links
- [ ] No legal boilerplate or template meta-commentary remains from the source playbook
- [ ] File is named `steering-irp-<short-name>.md`
- [ ] File is saved in `.kiro/steering/kiro-steering/` and mirrored to `ai-playbooks/steering/reference/`

## Step 4: Register the New Steering File in the Routing System

After creating the steering file, you MUST update the following files to wire it into the incident routing system:

### 4.1 Update the Core Playbook

Edit `.kiro/steering/kiro-steering/steering-irp-core.md` (and its mirror at `ai-playbooks/steering/steering-irp-core.md`):

1. In the front-matter `description`, add a new bullet for the new steering file:
   ```
   - Invoke with "steering-irp-<short-name>.md" when responding to <incident scenario>.
   ```

2. In the "Keyword Pattern Matching" section (Step 1), add relevant primary and secondary keywords that should trigger this playbook.

3. If the new incident type warrants its own selection logic, add a new subsection under "Context Analysis" (Step 2) describing the alert sources and suspicious activities specific to this incident type.

### 4.2 Update Sibling Steering File Descriptions

Edit each existing steering file in `.kiro/steering/kiro-steering/` (and their mirrors in `ai-playbooks/steering/reference/`) and add the new playbook's invoke line to their `description` front-matter, so all sibling IR playbooks cross-reference each other.

For example, add to each sibling's front-matter description:

```
- Invoke with "steering-irp-<short-name>.md" when responding to <incident scenario>.
```

This ensures that when any IR steering file is loaded, the agent is aware of all available IR playbooks.

---

## Example Workflow

User prompt: "Create a new IR steering file based on the DoS playbook in playbooks/IRP-DoS.md"

Agent actions:
1. Read `playbooks/IRP-DoS.md`
2. Read existing steering files for format reference (as linked above)
3. Create `.kiro/steering/kiro-steering/steering-irp-dos-ddos.md` following all rules in Step 3, and mirror to `ai-playbooks/steering/reference/steering-irp-dos-ddos.md`
4. Update `.kiro/steering/kiro-steering/steering-irp-core.md` and `ai-playbooks/steering/steering-irp-core.md` front-matter and keyword routing (Step 4.1)
5. Update description front-matter in `steering-irp-credential-compromise.md` and `steering-irp-data-access.md` in both `.kiro/steering/kiro-steering/` and `ai-playbooks/steering/reference/` (Step 4.2)
6. Present the created file to the user for review
