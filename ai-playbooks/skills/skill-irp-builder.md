---
description: Interactive builder for creating new AWS incident response skill files from scratch. Use this skill when you want to build an IR playbook from scratch, design a custom incident response process, create a new IR workflow with no existing source playbook, build a new security runbook, design IR procedures for a specific AWS service, or create a custom response plan for an incident type not covered by existing playbooks.
---

# Skill: IR Playbook Builder (From Scratch)

## Purpose

This skill conducts an interactive step-by-step interview to build a complete IR skill file from scratch when no existing source playbook exists. It walks the user through each NIST 800-61 phase, synthesizes a complete skill file matching the repo's established format, and registers it in CLAUDE.md routing.

**Differentiation from the factory skill:** The factory skill (`skill-irp-playbook-factory`) translates an existing human-centric playbook from `playbooks/` into a skill file. This builder skill creates a skill file from scratch through guided interview when no source playbook exists.

## Interview Process Overview

1. **Step 0:** Pre-interview setup — greet, check for existing skills, derive filename
2. **Step 1:** Incident type and scenario definition
3. **Step 2:** Detection and alert sources
4. **Step 3:** Evidence gathering and investigation
5. **Step 4:** Containment strategy
6. **Step 5:** Eradication
7. **Step 6:** Recovery
8. **Step 7:** Post-incident activities
9. **Step 8:** References
10. **Step 9:** Derive Quick Reference table

**Quick mode option:** At the start, offer the user "quick mode" — if they provide the incident type and primary AWS service, generate reasonable defaults for Steps 2-6 based on AWS documentation research, then present the full draft for review instead of asking every sub-question individually. This is ideal for experienced IR practitioners who prefer to edit a draft rather than answer each question.

## AWS Documentation Research Strategy

- **Primary:** Use AWS docs MCP tools (`search_documentation`, `read_documentation`, `read_sections`) to look up relevant GuardDuty finding types, AWS CLI commands, service-specific security guidance, and best practices
- **Fallback:** Use AWS CLI commands (e.g., `aws guardduty list-findings`, `aws configservice describe-compliance-by-config-rule`, `aws securityhub get-findings`) when MCP is unavailable
- **Never block on MCP availability** — always have a CLI-based alternative path ready
- At each interview step, offer research: "Would you like me to search AWS documentation for relevant [detection sources / CLI commands / best practices]?"

---

## Step 0: Pre-Interview Setup

### 0.1 Greet and Orient the User

Present a brief overview:
- Explain the interview process (10 steps covering all NIST 800-61 phases)
- Explain the expected output (a complete skill file + CLAUDE.md routing update)
- Offer "quick mode" vs "detailed mode" choice
- Set expectation: each step will produce draft content for review before moving on

### 0.2 Check for Existing Skills

List all existing IR skills:
```bash
ls .claude/skills/skill-irp-*.md
```

Present the list to the user. If a skill with a similar name or incident type already exists, warn:
- "A skill for `<incident-type>` already exists at `<path>`. Do you want to create a new one, or would you prefer to update the existing skill?"

### 0.3 Priming Question

Ask: "What is the name or short description of the incident type you want to build a skill for?"

From the answer, derive:
- A candidate filename: `skill-irp-<short-name>.md` (lowercase, hyphenated)
- Present the filename for confirmation

---

## Step 1: Incident Type and Scenario Definition

### 1.1 Questions to Ask

- What incident type or scenario does this skill address?
- What AWS services are primarily involved?
- Describe a typical trigger — what does detection look like when this incident occurs?

### 1.2 Content to Build

From the answers, draft:
- The YAML `description` field (keyword-rich, covering trigger keywords an operator would use)
- The `## Incident Type` paragraph (one paragraph describing the scenario)
- Confirm the candidate filename

### 1.3 Research Offer

Offer to search AWS documentation for:
- Relevant GuardDuty finding types for this scenario
- Service-specific security documentation
- Known attack patterns

**MCP primary:**
```
search_documentation: "<incident-type> <aws-service> security"
```

**CLI fallback:**
```bash
aws guardduty list-findings --detector-id <detector-id> \
  --finding-criteria '{"Criterion":{"type":{"Eq":["<relevant-finding-type>"]}}}'
```

### 1.4 User Confirmation Gate

Present the drafted content (description + Incident Type paragraph + filename). Wait for user approval before proceeding.

---

## Step 2: Detection and Alert Sources

### 2.1 Questions to Ask

- How is this incident type typically detected? (GuardDuty, CloudWatch, Security Hub, billing alerts, user report, external notification)
- Are there specific GuardDuty finding types, Config rules, or Security Hub controls relevant to this scenario?
- Are there secondary signals that could indicate this incident?

### 2.2 Content to Build

Draft `### 1.1 Identify the Alert Source` with a bullet list of common alert sources for this incident type.

### 2.3 Research Offer

Offer to look up:
- GuardDuty finding types related to the incident
- AWS Config managed rules for the relevant services
- Security Hub controls

**MCP primary:**
```
search_documentation: "GuardDuty finding types <service>"
search_documentation: "AWS Config rules <service>"
```

**CLI fallback:**
```bash
aws configservice describe-config-rules \
  --query 'ConfigRules[?contains(ConfigRuleName, `<service-keyword>`)].ConfigRuleName'
```

### 2.4 User Confirmation Gate

Present the drafted alert source section. Wait for approval.

---

## Step 3: Evidence Gathering and Investigation

### 3.1 Questions to Ask (one at a time)

- What information should be gathered immediately? (scope, affected principal, timeline)
- What AWS APIs or CLI commands are needed for investigation?
- Are there specific CloudTrail event names that serve as indicators?
- What key timestamps or events need to be established?

### 3.2 Content to Build

From the answers, draft:
- `### 1.2` through `### 1.x` investigation subsections (numbered sequentially)
- CLI commands with `<placeholder>` params in ```bash blocks
- `# MCP batch opportunity:` comments where parallel execution applies
- `### 1.x Document and Communicate` checklist using `- [ ]` checkboxes

### 3.3 Research Offer

Offer to search for:
- Relevant AWS CLI commands and API references for the involved services
- CloudTrail event names for key operations
- Investigation best practices

**MCP primary:**
```
search_documentation: "<service> CLI reference <operation>"
search_documentation: "CloudTrail <service> API events"
```

### 3.4 User Confirmation Gate

Present all drafted Part 1 subsections. Wait for approval.

---

## Step 4: Containment Strategy

### 4.1 Questions to Ask

- What is the containment goal? (one sentence)
- What immediate actions stop the bleeding?
- Are there multiple containment options depending on circumstances?
- Which actions affect legitimate users or production workloads? (these need warning callouts)

### 4.2 Content to Build

Draft:
- `## Part 2: Contain the Incident` with `**Goal:**` statement
- Containment subsections with CLI commands in ```bash blocks
- `Warning` callouts (using the pattern: `⚠️ **Warning:** <text>`) for production-impacting actions
- `### 2.x Verify Containment` subsection with monitoring commands

### 4.3 Research Offer

Offer to search for:
- Service-specific containment strategies
- Security group, NACL, or IAM policy patterns for isolation
- AWS best practices for incident containment

### 4.4 User Confirmation Gate

Present all drafted Part 2 content. Wait for approval.

---

## Step 5: Eradication

### 5.1 Questions to Ask

- What is the eradication goal? (one sentence)
- What attacker-created resources or artifacts need to be removed?
- What persistence mechanisms should be checked?
- What CLI commands find and remove these artifacts?

### 5.2 Content to Build

Draft:
- `## Part 3: Eradicate the Incident` with `**Goal:**` statement
- Audit subsections (identify malicious artifacts)
- Removal subsections with CLI commands
- `# MCP batch opportunity:` comments where applicable

### 5.3 Research Offer

Offer to search for:
- Common persistence mechanisms for the attack type
- Service-specific cleanup procedures

### 5.4 User Confirmation Gate

Present all drafted Part 3 content. Wait for approval.

---

## Step 6: Recovery

### 6.1 Questions to Ask

- What is the recovery goal? (one sentence)
- What resources need to be restored? Are backups, snapshots, or versioning available?
- What does "back to normal" look like for this incident type?

### 6.2 Content to Build

Draft:
- `## Part 4: Recover from the Incident` with `**Goal:**` statement
- Restore steps with CLI commands
- `### 4.x Verify Recovery` checklist using `- [ ]` checkboxes

### 6.3 Research Offer

Offer to search for:
- AWS Backup integration for the relevant services
- Service-specific restore procedures
- Recovery verification best practices

### 6.4 User Confirmation Gate

Present all drafted Part 4 content. Wait for approval.

---

## Step 7: Post-Incident Activities

### 7.1 Offer Standard Template

Present the standard Part 5 structure shared by all existing skills:

```
## Part 5: Post-Incident Activity

### 5.1 Document Lessons Learned
- Timeline, root cause, impact, response effectiveness, recommendations

### 5.2 Retrospective Questions
- Detection improvement, response acceleration, blast radius reduction

### 5.3 Update Defenses
- Checklist of hardening actions

### 5.4 Regulatory Notifications
- Jurisdiction-specific notification requirements
```

Ask: "Do you want to accept this standard template, or customize it for this incident type?"

### 7.2 Incident-Specific Customizations

If the user wants customization, ask:
- Are there forensic analysis steps specific to this incident type?
- Are there regulatory notification requirements beyond the standard?
- What specific defense updates should be recommended?

---

## Step 8: References

### 8.1 Always Include

Every skill file must include:
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)

### 8.2 Ask for Additional Links

Ask: "Are there specific AWS documentation pages or external references to include?"

### 8.3 Auto-Include MCP Sources

If AWS documentation was searched during the interview, automatically include relevant documentation URLs discovered during research.

---

## Step 9: Derive Quick Reference Table

### 9.1 Build from Prior Steps

Synthesize a Quick Reference table from the content built in Steps 2-7:

```
| Phase | Key Action | Verification |
|-------|------------|--------------|
| Evidence | <from Steps 2-3> | <from Step 3> |
| Contain | <from Step 4> | <from Step 4 verify> |
| Eradicate | <from Step 5> | <from Step 5> |
| Recover | <from Step 6> | <from Step 6 verify> |
| Post-Incident | <from Step 7> | <from Step 7> |
```

### 9.2 Present for Review

Show the table. User corrects cells if needed.

---

## Quality Checklist

Before saving, verify the generated skill file passes ALL checks:

- [ ] Front-matter `description` is keyword-rich and covers main trigger scenarios
- [ ] No `inclusion` field in front-matter
- [ ] No sibling skill cross-references in description
- [ ] `## Incident Type` paragraph clearly describes the scenario
- [ ] `## Quick Reference` table covers all 5 NIST phases
- [ ] Part 1: alert sources, investigation subsections, `Document and Communicate` checklist
- [ ] Part 2: `**Goal:**` statement, containment CLI commands, warning callouts, `Verify Containment` subsection
- [ ] Part 3: `**Goal:**` statement, eradication CLI commands
- [ ] Part 4: `**Goal:**` statement, recovery CLI commands, `Verify Recovery` checklist
- [ ] Part 5: lessons learned, retrospective questions, update defenses, regulatory notifications
- [ ] All CLI commands use `<placeholder>` params (not hardcoded values)
- [ ] `⚠️ **Warning:**` callouts present for production-impacting actions
- [ ] `# MCP batch opportunity:` comments where parallel execution applies
- [ ] `## References` section includes AWS Security IR Guide
- [ ] File named `skill-irp-<short-name>.md`
- [ ] No `<!-- TODO: validate -->` markers remain in the final output

**If the agent had to assume content (user said "I don't know"):** mark those sections with `<!-- TODO: validate -->` during drafting, then resolve ALL markers before final save. If a marker cannot be resolved, flag it to the user explicitly.

---

## File Creation and Registration

### Write Skill Files

After the quality checklist passes:

1. Save to `.claude/skills/skill-irp-<short-name>.md`
2. Mirror to `ai-playbooks/skills/skill-irp-<short-name>.md`

### Update CLAUDE.md Routing

Edit `ai-playbooks/skills/CLAUDE.md` to register the new skill:

1. **Step 1 (Keyword Pattern Matching):** Add primary keywords that should trigger the new skill
2. **Step 2 (Context Analysis):** Add incident-specific indicators if warranted
3. **Default option:** Update only if the new skill should be considered as a fallback

Present the CLAUDE.md diff to the user for approval before saving.

---

## Output Format

The generated skill file MUST exactly match the existing skill format:

```
---
description: <keyword-rich description>
---

# Playbook: <Incident Type Title>

## Incident Type
<One paragraph describing the scenario>

## Quick Reference
| Phase | Key Action | Verification |
|-------|------------|--------------|
| Evidence | ... | ... |
| Contain | ... | ... |
| Eradicate | ... | ... |
| Recover | ... | ... |
| Post-Incident | ... | ... |

---

## Part 1: Acquire, Preserve, Document Evidence
### 1.1 Identify the Alert Source
### 1.2 <Investigation steps>
### 1.x Document and Communicate

---

## Part 2: Contain the Incident
**Goal:** <one sentence>
### 2.x <Containment actions with CLI commands>
### 2.x Verify Containment

---

## Part 3: Eradicate the Incident
**Goal:** <one sentence>
### 3.x <Eradication steps with CLI commands>

---

## Part 4: Recover from the Incident
**Goal:** <one sentence>
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
```

Conventions: `<placeholder>` params in CLI commands, `⚠️ **Warning:**` callouts, `- [ ]` checklists, `# MCP batch opportunity:` comments, ```bash code blocks.
