# AI-Consumable Incident Response Playbooks

Vendor-agnostic, AI-readable incident response playbooks for AWS security incidents. These work with **any** AI coding assistant or LLM — no proprietary format, no vendor lock-in.

> ⚠️ **Safety by design:** These playbooks instruct AI assistants to GUIDE responders, not act autonomously. The AI will always present commands and explain their impact before execution, and will wait for explicit human confirmation before taking any action that modifies the environment. Read-only investigation commands may be executed freely; containment and destructive actions always require human approval.

## What These Are

Plain markdown files that give AI assistants the context to help you respond to AWS security incidents. They provide:

- Structured decision trees an AI can follow
- Complete CLI commands ready to execute
- Scenario routing based on incident keywords
- Tool selection strategy (MCP tools > CLI > ask human)

These are **not** replacements for your human playbooks. They are optimized summaries that let AI assistants provide fast, accurate guidance during incidents. Each scenario file references the full human playbook for complete detail.

## Architecture

```
ai-irp-core.md              ← ROUTER (always loaded). NIST lifecycle, keyword matching, tool strategy, safeguards.
AI-PLAYBOOK-TEMPLATE.md     ← Template for creating new AI playbooks from human playbooks.
IDE-SETUP.md                ← Setup instructions per tool (the ONLY vendor-specific file).
scenarios/
  ai-irp-credential-compromise.md
  ai-irp-sts-token-abuse.md
  ai-irp-data-access.md
  ai-irp-api-security-breach.md
  ai-irp-ec2-compromise.md
  ai-irp-cryptomining.md
  ai-irp-root-takeover.md
  ai-irp-ransomware.md
```

**Loading strategy:** Always load `ai-irp-core.md`. It routes to the correct scenario file based on keywords in the user's request. Load scenario files on demand.

## IDE / Tool Setup

| Tool | Method | Auto-loads core? | Notes |
|------|--------|-----------------|-------|
| **Kiro** | `.kiro/steering/` with `inclusion: auto` | Yes | See IDE-SETUP.md for front matter |
| **Claude Code** | `CLAUDE.md` reference | Yes | Add include directive |
| **Cursor** | `.cursor/rules/` | Yes | One rule file per playbook |
| **Windsurf** | `.windsurfrules` | Yes | Single rules file |
| **GitHub Copilot** | `.github/copilot-instructions.md` | Yes | Workspace instructions |
| **Generic LLM** | Paste into system prompt | Manual | Copy core + relevant scenario |

See [IDE-SETUP.md](IDE-SETUP.md) for complete setup instructions per tool.

## Design Principles

1. **Vendor-agnostic** — Plain markdown. No YAML front matter in playbook content. No tool-specific syntax.
2. **Action-oriented** — Every step has a concrete CLI command or decision. No filler paragraphs.
3. **Router pattern** — Core file matches keywords → loads specific scenario. Keeps context windows small.
4. **Tool-aware** — Prefers MCP tools when available, falls back to CLI, asks human when uncertain.
5. **Speed over completeness** — Optimized for incident response speed. References human playbooks for full detail.
6. **Safe defaults** — Never terminates instances (except cryptomining). Always preserves evidence first.
7. **Inclusive language** — Uses allowlist/denylist, primary/replica terminology throughout.

## Operational Impact & Customization

> ⚠️ **Containment actions in these scenarios may impact legitimate operations.** Revoking credentials breaks applications that depend on them. Blocking public access on S3 disrupts any public-facing content served from that bucket. Emergency SCPs halt all account activity. WAF IP blocks and throttling can affect legitimate users.

**Every mutative action in these playbooks is gated behind a confirmation prompt** — the AI must present the command, explain its impact, and wait for explicit human approval before executing. You maintain full control.

**Customizing for your environment:**

- **Remove actions you don't authorize.** If your organization never wants an AI assistant to suggest credential revocation (preferring manual runbooks for that step), delete those steps from the scenario file. The AI will stop at the investigation phase.
- **Add additional confirmation gates.** Wrap any step with `> ⚠️ Requires user confirmation before executing.` to force the AI to pause and ask.
- **Restrict to read-only investigation.** To prevent the AI from suggesting *any* mutative action, add this to `ai-irp-core.md`:
  ```
  ## Override: Read-Only Mode
  You are restricted to read-only investigation actions only. 
  Do NOT suggest or execute any containment, eradication, or 
  recovery actions. Present findings and recommend the human 
  operator execute containment manually.
  ```
- **Scope containment to specific accounts or environments.** Add environment-specific guards (e.g., "never suggest SCP changes in production accounts without Change Management approval").
- **Add organization-specific approval workflows.** Reference your internal ticketing or change management system in the confirmation prompts.

The scenario files are plain markdown — edit them freely to match your risk tolerance, change management requirements, and operational constraints.

### Controlling mutative actions via IAM

The most robust way to prevent unwanted changes is to **scope the IAM role used during AI-assisted IR** to only the actions you authorize. If the role lacks `ec2:TerminateInstances`, the agent physically cannot terminate instances — no playbook text overrides IAM.

- Grant **read-only permissions broadly** — investigation actions (describe, list, get, lookup) should always succeed
- Grant **mutative permissions selectively** — only for the containment actions your organization approves
- The AI agent handles `AccessDenied` gracefully: it informs the responder, documents the gap, and offers alternatives (escalate for permission, proceed without, or hand off the command for manual execution)

This gives you a **defense-in-depth** approach: the playbook defines what *could* be done, IAM controls what *can* be done, and the confirmation gates ensure the human decides what *should* be done.

## Available Playbooks

| Scenario | File | Priority | Key Signal |
|----------|------|----------|------------|
| Credential Compromise | `ai-irp-credential-compromise.md` | P1–P2 | Leaked keys, unauthorized API calls |
| STS Token Abuse | `ai-irp-sts-token-abuse.md` | P1–P2 | AssumeRole chains, cross-account pivots |
| Data Access / S3 Exfiltration | `ai-irp-data-access.md` | P1–P2 | Bulk GetObject, public bucket, Macie alerts |
| API Security Breach | `ai-irp-api-security-breach.md` | P1–P2 | WAF triggers, OWASP API Top 10, injection |
| EC2 Compromise | `ai-irp-ec2-compromise.md` | P1–P2 | C2 traffic, lateral movement, reverse shell |
| Cryptomining | `ai-irp-cryptomining.md` | P2 | GPU/CPU spike, mining pools, cost alerts |
| Root Account Takeover | `ai-irp-root-takeover.md` | P1 | Root login, MFA changes, org modifications |
| Ransomware | `ai-irp-ransomware.md` | P1 | Encryption activity, ransom notes, KMS abuse |

## Planned (Not Yet Written)

- Denial of Service
- Identity Center Compromise (AI scenario — human playbook exists)
- Federated Access Abuse (AI scenario — human playbook exists)
- Insider Threat (AI scenario — human playbook exists)
- Container / EKS Compromise
- CI/CD Pipeline Compromise

## Contributing

When adding a new scenario file:

1. Add keyword entries to the routing table in `ai-irp-core.md`
2. Follow the structure of existing scenario files (numbered steps, decision tables, CLI commands)
3. Keep files between 150–250 lines
4. Reference the full human playbook for complete procedures
5. Test with at least two different AI tools before merging
