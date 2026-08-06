# AI Playbook Template

Use this template to convert any human-readable incident response playbook (IRP-*.md) into an AI-assisted version for the `scenarios/` directory.

---

## Conversion Principles

1. **Extract, don't duplicate** — Pull out the actionable steps. Skip narrative context (the AI gets that from the core router).
2. **Commands must be complete** — Every CLI command should be copy-pasteable with clearly marked placeholders (e.g., `INSTANCE_ID`, `ACCOUNT_ID`).
3. **Decision points as tables** — The AI needs structured logic to reason about what to do next.
4. **Human approval gates** — Mark every containment/destructive action with a confirmation prompt.
5. **150–250 lines** — Keep it focused. Reference the full human playbook for regulatory context, post-incident checklists, and game day guidance.
6. **Vendor-agnostic** — No IDE-specific front matter or syntax. Plain markdown only.

---

## Template Structure

Copy the structure below and fill in for your scenario:

```markdown
# AI IRP: [Scenario Name]

[One-paragraph description: what this incident type is, why it matters, and the key principle that makes this scenario unique (e.g., "terminate first" for cryptomining, "never terminate" for EC2 compromise).]

## Critical Rule

```
╔══════════════════════════════════════════════════════════════╗
║  [THE SINGLE MOST IMPORTANT RULE FOR THIS SCENARIO]         ║
║  [Keep to 2-3 lines. This is what the AI must never forget] ║
╚══════════════════════════════════════════════════════════════╝
```

## Priority Assessment

| Signal | Priority |
|--------|----------|
| [High-confidence indicator] | P1 |
| [Confirmed but scope unclear] | P2 |
| [Anomalous but unconfirmed] | P3 |
| [Policy violation, no active threat] | P4 |

## Step 1: [First Action — Usually Identification/Confirmation]

[Brief description of what this step accomplishes]

```bash
# Command(s) to execute — read-only, no confirmation needed
aws [service] [command] --[parameters]
```

**Decision: [What to decide based on output]**

| Condition | Next Action |
|-----------|-------------|
| [If X] | [Do Y — or route to another playbook] |
| [If Z] | [Do W] |

## Step 2: [Second Action — Usually Containment]

> ⚠️ **Requires user confirmation before executing.**

[Explain what this action does and its impact]

```bash
# Command to present to user — wait for approval
aws [service] [command] --[parameters]
```

**Present to user:**
> "I recommend [action]. This will [impact]. It is [reversible/irreversible]. Shall I proceed?"

## Step 3: [Third Action — Usually Scoping/Investigation]

[Investigation commands — read-only, can execute freely]

**Key Athena query — [what it finds]:**

```sql
SELECT [fields]
FROM cloudtrail_logs
WHERE [conditions]
ORDER BY eventTime ASC;
```

## Step 4: [Fourth Action — Usually Eradication]

> ⚠️ **Requires user confirmation before executing.**

[What to remove/clean up]

```bash
# Present each destructive command individually for approval
aws [service] [command] --[parameters]
```

## Step 5: [Fifth Action — Usually Recovery]

> ⚠️ **Requires user confirmation before executing.**

[Recovery steps]

```bash
aws [service] [command] --[parameters]
```

## Step 6: [Sixth Action — Hardening]

Recommend these hardening actions to the user:

- [ ] [Hardening action 1]
- [ ] [Hardening action 2]
- [ ] [Hardening action 3]

## Escalation Triggers

- [Condition] → [Escalation action]
- [Condition] → [Route to another playbook]

## Reference

Full human playbook: `IRP-[ScenarioName].md`
```

---

## Conversion Checklist

When converting a human playbook to an AI version, verify:

- [ ] **Critical Rule** captures the single most important principle for this scenario
- [ ] **Priority Assessment** table helps the AI quickly classify severity
- [ ] **Every containment/destructive command** has a "Requires user confirmation" gate
- [ ] **Read-only commands** (describe, list, get, query) are clearly marked as safe to execute
- [ ] **Decision tables** are used at every branch point (not prose paragraphs)
- [ ] **Athena queries** include the 2-3 most important queries from the human playbook (not all of them)
- [ ] **Escalation triggers** tell the AI when to route to a different playbook
- [ ] **Reference link** points to the full human playbook
- [ ] **No vendor-specific syntax** (no YAML front matter, no IDE-specific instructions)
- [ ] **American English spelling** used throughout
- [ ] **Placeholders** are clearly marked (UPPERCASE with underscores: `INSTANCE_ID`, `BUCKET_NAME`)
- [ ] **Total length** is 150–250 lines (trim if longer, expand if too thin)

---

## What to Include vs. What to Skip

### Include (from the human playbook):

- Detection signals and finding types (for the Priority Assessment table)
- CLI commands for investigation (Steps 1, 3)
- CLI commands for containment and eradication (Steps 2, 4 — with confirmation gates)
- Key decision points (as tables)
- The 2-3 most important Athena queries
- Hardening recommendations (as a checklist)
- Escalation triggers and cross-references to other playbooks

### Skip (reference the human playbook instead):

- Full preparation checklists (service configurations, IAM prerequisites)
- Communication and escalation role tables
- Game Day scenarios
- Regulatory and compliance considerations
- Post-incident review questions
- Detailed timeline reconstruction templates
- Revision history

---

## Naming Convention

AI playbook files follow this naming pattern:

```
ai-irp-[scenario-name-with-hyphens].md
```

Examples:
- `ai-irp-credential-compromise.md`
- `ai-irp-sts-token-abuse.md`
- `ai-irp-ec2-compromise.md`
- `ai-irp-container-eks-compromise.md`
- `ai-irp-root-takeover.md`

---

## After Creating a New AI Playbook

1. **Add to the routing table** in `ai-irp-core.md` — add a row with keywords and the filename
2. **Update the README** — move the scenario from "Planned" to "Created" in the status table
3. **Test with at least two AI tools** — verify the routing works and the steps are followable
4. **Verify confirmation gates** — ensure no destructive action can execute without user approval
