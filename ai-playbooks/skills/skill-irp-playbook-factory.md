---
description: Guidance for creating new AWS incident response skills for Claude Code by translating human-centric IR playbooks into agent-actionable skill files. Use this skill when you want to create a new IR playbook skill, translate an existing playbook from the playbooks/ folder into a Claude Code skill, or add a new incident type to the IR skill library.
---

# Guidance: Translating IR Playbooks into Agent-Centric Claude Code Skills

## Purpose
This skill guides you (the agent) through creating a new incident response skill by translating a human-centric IR playbook from the `playbooks/` folder into an agent-actionable skill file stored in `.claude/skills/`.

## Procedure Overview

1. User indicates which playbook(s) in `playbooks/` to translate
2. You analyze the source playbook, reference existing skills for format/structure, and produce a new skill file
3. You register the new skill in the routing system so it can be invoked during incidents

---

## Step 1: Analyze the Source Playbook

Read the source playbook from `playbooks/` and extract:
- The incident type (e.g., "Credential Compromise", "Unintended S3 Data Access", "DoS/DDoS")
- The NIST 800-61 phases covered (Detection/Evidence, Containment, Eradication, Recovery, Post-Incident)
- Specific investigation steps, containment actions, and recovery procedures
- Any AWS services, APIs, or CLI commands referenced
- Alert sources and detection mechanisms mentioned

## Step 2: Reference Existing Skills

Read the existing skills in `.claude/skills/` to understand the target format:

- `.claude/skills/skill-irp-credential-compromise.md`
- `.claude/skills/skill-irp-data-access.md`

Use these as structural templates. The new skill file MUST follow the same patterns.

## Step 3: Create the New Skill File

### 3.1 File Naming Convention

The file MUST be named: `skill-irp-<short-name>.md`

Where `<short-name>` is a concise, lowercase, hyphenated descriptor of the incident type.

Examples:
- `skill-irp-credential-compromise.md`
- `skill-irp-data-access.md`
- `skill-irp-dos-ddos.md`
- `skill-irp-ransomware.md`

Store the file in: `.claude/skills/`

### 3.2 Front-Matter (REQUIRED)

Every skill file MUST begin with a YAML front-matter description block:

```yaml
---
description: Incident response playbook for <incident type description>. Use this skill when responding to <keyword-rich scenario description covering the main trigger keywords for this incident type>.
---
```

Rules:
- The `description` field is used by Claude Code for skill trigger matching — make it keyword-rich with terms that operators are likely to use when describing this incident type
- Do NOT include an `inclusion` field — skills are loaded on demand, not based on `inclusion` metadata
- Do NOT include cross-references to sibling skills in the description — `CLAUDE.md` handles all routing

### 3.3 Required Document Structure

The new skill file MUST follow this exact 5-part structure aligned with NIST 800-61 R2:

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

When translating from the human-centric playbook to the agent-centric skill file:

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

**PRESERVE the following from source playbooks:**
- The logical flow and ordering of incident response phases
- All AWS service-specific guidance and technical details
- Alert source identification steps
- Communication and stakeholder notification steps
- Post-incident and lessons-learned processes

### 3.5 CLI Command and Tool Selection Standards

All IR skills use AWS CLI commands as the canonical representation of each operation. These serve as both the precise specification of what to do AND the fallback execution method.

When authoring CLI commands in the skill file:
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

The agent will use MCP batch calls when available, or fall back to sequential CLI execution. Do NOT write MCP-specific syntax in the skill file — keep CLI as the universal format. The `CLAUDE.md` Tool Selection Strategy handles runtime tool choice.

### 3.6 Quality Checklist Before Saving

Before writing the file, verify:
- [ ] Front-matter has a keyword-rich `description` covering the main trigger scenarios for this incident type
- [ ] No `inclusion` field in front-matter
- [ ] No sibling skill cross-references in description (CLAUDE.md handles routing)
- [ ] All 5 NIST phases are covered (Evidence, Contain, Eradicate, Recover, Post-Incident)
- [ ] Quick Reference table is present with all 5 phases
- [ ] CLI commands use placeholder parameters, not hardcoded values
- [ ] Warning callouts exist for destructive or production-impacting actions
- [ ] Verification steps exist after containment and recovery
- [ ] References section includes relevant AWS documentation links
- [ ] No legal boilerplate or template meta-commentary remains from the source playbook
- [ ] File is named `skill-irp-<short-name>.md`
- [ ] File is saved in `.claude/skills/`

## Step 4: Register the New Skill in the Routing System

After creating the skill file, you MUST update `CLAUDE.md` to wire it into the incident routing system.

### 4.1 Update CLAUDE.md

Edit `CLAUDE.md` at the repo root:

1. In the "Keyword Pattern Matching" section (Step 1), add relevant primary and secondary keywords that should trigger this playbook.

2. If the new incident type warrants its own selection logic, add a new subsection under "Context Analysis" (Step 2) describing the alert sources and suspicious activities specific to this incident type.

3. Update the "Default option" section if the new incident type should be the default fallback.

Note: Unlike the Kiro steering system, you do NOT need to update sibling skill files — `CLAUDE.md` is the single routing authority and is always loaded. Sibling skills do not need to cross-reference each other.

---

## Example Workflow

User prompt: "Create a new IR skill based on the DoS playbook in playbooks/IRP-DoS.md"

Agent actions:
1. Read `playbooks/IRP-DoS.md`
2. Read existing skills for format reference (`.claude/skills/skill-irp-credential-compromise.md` and `.claude/skills/skill-irp-data-access.md`)
3. Create `.claude/skills/skill-irp-dos-ddos.md` following all rules in Step 3
4. Update `CLAUDE.md` keyword routing (Step 4.1)
5. Present the created file to the user for review
