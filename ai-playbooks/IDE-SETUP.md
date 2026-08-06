# IDE Setup Guide — AI Incident Response Playbooks

This is the ONLY file with vendor-specific content. The playbook files themselves are pure markdown with no vendor lock-in.

## Architecture Recap

```
ai-irp-core.md              ← Always loaded (router + principles)
scenarios/ai-irp-*.md       ← Loaded on demand per incident type
```

The core file routes to scenario files based on keywords. Your IDE setup should auto-load the core file so it's always available in context.

---

## Kiro

Kiro uses steering files in `.kiro/steering/`. Files with `inclusion: auto` are loaded automatically.

### Setup

Create `.kiro/steering/ai-irp-core.md` with this front matter:

```yaml
---
inclusion: auto
description: AI Incident Response — Core router and IR principles. Routes to scenario-specific playbooks.
globs:
  - "**/*"
---
```

Then paste the contents of `ai-irp-core.md` below the front matter.

For scenario files, create them as manual-inclusion steering files:

```yaml
---
inclusion: manual
description: AI IRP — Credential Compromise response steps
globs:
  - "**/*"
---
```

### Loading Scenarios in Kiro

Reference scenario files in conversation using `#` mentions, or instruct Kiro to load them:

> "Load the credential compromise playbook and help me respond to this incident"

### Recommended File Structure

```
.kiro/
  steering/
    ai-irp-core.md          (inclusion: auto)
    ai-irp-scenarios/
      credential-compromise.md   (inclusion: manual)
      sts-token-abuse.md         (inclusion: manual)
      ec2-compromise.md          (inclusion: manual)
      cryptomining.md            (inclusion: manual)
      root-takeover.md           (inclusion: manual)
      ransomware.md              (inclusion: manual)
```

---

## Claude Code

Claude Code uses `CLAUDE.md` files for persistent context. Place at project root or in a subdirectory.

### Setup

Add to your project's `CLAUDE.md`:

```markdown
## Incident Response

When helping with AWS security incidents, follow the IR playbooks:

- Core router and principles: ./playbooks/ai-irp-core.md
- Scenario files: ./playbooks/scenarios/ai-irp-*.md

Always load the core file first. Route to the appropriate scenario based on incident keywords.
Load scenario files with: @playbooks/scenarios/ai-irp-SCENARIO.md
```

### Alternative: Direct Include

Place `ai-irp-core.md` content directly in `CLAUDE.md` under an `## Incident Response` section. This ensures it's always in context without requiring file references.

### File Structure

```
project-root/
  CLAUDE.md                  (references playbook files)
  playbooks/
    ai-irp-core.md
    scenarios/
      ai-irp-credential-compromise.md
      ai-irp-sts-token-abuse.md
      ...
```

---

## Cursor

Cursor uses `.cursor/rules/` directory for project-level rules.

### Setup

Create `.cursor/rules/ai-irp-core.mdc`:

```markdown
---
description: AWS Incident Response — Core router and principles
globs:
  - "**/*"
alwaysApply: true
---

[Paste contents of ai-irp-core.md here]
```

For scenario files, create separate rule files with `alwaysApply: false`:

```markdown
---
description: AWS IRP — Credential Compromise
globs:
  - "**/*"
alwaysApply: false
---

[Paste contents of ai-irp-credential-compromise.md here]
```

### File Structure

```
.cursor/
  rules/
    ai-irp-core.mdc              (alwaysApply: true)
    ai-irp-credential.mdc        (alwaysApply: false)
    ai-irp-sts.mdc               (alwaysApply: false)
    ai-irp-ec2.mdc               (alwaysApply: false)
    ai-irp-cryptomining.mdc      (alwaysApply: false)
    ai-irp-root.mdc              (alwaysApply: false)
    ai-irp-ransomware.mdc        (alwaysApply: false)
```

### Loading Scenarios in Cursor

Use `@` to reference scenario files, or ask Cursor to load them:

> "@ai-irp-credential.mdc help me respond to a leaked access key"

---

## Windsurf

Windsurf uses `.windsurfrules` at the project root.

### Setup

Create `.windsurfrules` and include the core router content:

```markdown
# AI Incident Response Rules

[Paste contents of ai-irp-core.md here]

## Scenario Files

When a specific incident type is identified, load the corresponding file:
- Credential compromise: ./playbooks/scenarios/ai-irp-credential-compromise.md
- STS token abuse: ./playbooks/scenarios/ai-irp-sts-token-abuse.md
- EC2 compromise: ./playbooks/scenarios/ai-irp-ec2-compromise.md
- Cryptomining: ./playbooks/scenarios/ai-irp-cryptomining.md
- Root takeover: ./playbooks/scenarios/ai-irp-root-takeover.md
- Ransomware: ./playbooks/scenarios/ai-irp-ransomware.md
```

### File Structure

```
project-root/
  .windsurfrules              (contains core router)
  playbooks/
    scenarios/
      ai-irp-credential-compromise.md
      ai-irp-sts-token-abuse.md
      ...
```

---

## GitHub Copilot

Copilot uses `.github/copilot-instructions.md` for workspace-level instructions.

### Setup

Create `.github/copilot-instructions.md`:

```markdown
# AI Incident Response Instructions

When helping with AWS security incidents, follow these principles and routing rules.

[Paste contents of ai-irp-core.md here]

## Loading Scenario Details

For specific incident types, reference the scenario files in this repository:
- `playbooks/scenarios/ai-irp-credential-compromise.md`
- `playbooks/scenarios/ai-irp-sts-token-abuse.md`
- `playbooks/scenarios/ai-irp-ec2-compromise.md`
- `playbooks/scenarios/ai-irp-cryptomining.md`
- `playbooks/scenarios/ai-irp-root-takeover.md`
- `playbooks/scenarios/ai-irp-ransomware.md`
```

### File Structure

```
project-root/
  .github/
    copilot-instructions.md   (contains core router)
  playbooks/
    scenarios/
      ai-irp-*.md
```

---

## Generic LLM (ChatGPT, API, etc.)

For tools without file-based configuration, paste content directly into the system prompt or conversation.

### Setup — System Prompt Method

1. Copy the full contents of `ai-irp-core.md`
2. Paste into the system prompt / custom instructions
3. When an incident occurs, also paste the relevant scenario file

### Setup — Conversation Method

Start each IR session with:

```
I need help with an AWS security incident. Here are my IR playbooks:

[Paste ai-irp-core.md]

The incident is: [describe incident]
```

The AI will use the routing table to identify the scenario, then ask you to provide the relevant scenario file if needed.

### Custom GPT (ChatGPT)

1. Create a Custom GPT
2. Paste `ai-irp-core.md` into the Instructions field
3. Upload all scenario files as Knowledge files
4. Set the conversation starter to: "Describe your AWS security incident and I'll guide you through response."

---

## MCP Server Configuration

If your environment uses MCP (Model Context Protocol) servers for AWS access, configure them for IR use.

### Example MCP Configuration

```json
{
  "mcpServers": {
    "aws-ir": {
      "command": "node",
      "args": ["./mcp-servers/aws-ir-server.js"],
      "env": {
        "AWS_PROFILE": "ir-breakglass",
        "AWS_REGION": "us-east-1"
      }
    },
    "polymer": {
      "command": "polymer-mcp",
      "args": ["--config", "./mcp-config.json"]
    }
  }
}
```

### MCP Tool Priority

When MCP tools are available, the playbooks prefer them over raw CLI:

| Task | MCP Tool (example) | CLI Fallback |
|------|----------|--------------|
| Account lookup | `describe_account` | `aws organizations describe-account` |
| IP enrichment | `get_ip_ownership` | Manual WHOIS + CloudTrail source IP analysis |
| Instance state | `get_instance_state` | `aws ec2 describe-instances` |
| Identity lookup | `get_user_details` | Your organization's directory service |
| Credential info | `get_access_key_info` | `aws iam get-access-key-last-used` |

> 📌 MCP tool names vary by implementation. The examples above are generic — substitute your organization's actual MCP server tool names.

---

## Testing Your Setup

After configuring your IDE, test with this prompt:

> "I found an AWS access key on a public GitHub repository. The key is AKIA... and belongs to a production account. Help me respond."

Expected behavior:
1. AI identifies this as credential compromise
2. Routes to credential compromise scenario
3. Provides immediate disable command
4. Walks through session revocation, blast radius assessment, and eradication

If the AI doesn't follow the playbook structure, verify the core file is loading correctly.
