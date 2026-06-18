# Contributing to AWS Incident Response Playbooks

Thank you for your interest in contributing to this project! We welcome contributions from the community to help improve and expand these incident response playbooks.

---

## Table of Contents

- [How to Contribute](#how-to-contribute)
- [Playbook Contributions](#playbook-contributions)
- [AI Playbook Contributions](#ai-playbook-contributions)
- [Contribution Guidelines](#contribution-guidelines)
- [Testing Your Contributions](#testing-your-contributions)
- [Inclusive Language](#inclusive-language)
- [Security Issue Notifications](#security-issue-notifications)
- [Licensing](#licensing)

---

## How to Contribute

1. **Fork** the repository
2. **Create a branch** for your contribution (`feature/new-playbook-name` or `fix/description`)
3. **Make your changes** following the guidelines below
4. **Test your changes** (see Testing section)
5. **Submit a Pull Request** with a clear description of what you've changed and why

### Types of Contributions We Welcome

- New incident response playbooks for scenarios not yet covered
- Updates to existing playbooks (new services, updated CLI commands, corrected console paths)
- AI playbook variants (steering files for Kiro, skills for Claude Code)
- Automation pattern examples
- Bug fixes (broken links, typos, formatting)
- Translations
- Improvements to documentation and guides

---

## Playbook Contributions

### Use the Template

All new playbooks **must** follow the standard template: [`PLAYBOOK_TEMPLATE.md`](PLAYBOOK_TEMPLATE.md)

The template ensures consistency across playbooks and includes all required sections:
- Metadata (scenario, NIST phase mapping, severity indicators)
- Scope & Assumptions
- Prerequisites
- Detection & Analysis
- Containment
- Eradication
- Recovery
- Post-Incident Activity
- Automation Hooks
- Regulatory Considerations
- References

### Playbook Quality Checklist

Before submitting a playbook, verify:

- [ ] Follows the `PLAYBOOK_TEMPLATE.md` structure
- [ ] All CLI commands use AWS CLI v2 syntax
- [ ] Console paths are current (verify in the AWS Console)
- [ ] All referenced services and features are Generally Available (not preview/beta)
- [ ] NIST SP 800-61r3 lifecycle phases are correctly mapped
- [ ] Severity indicators align with the [Triage Guide](TRIAGE_GUIDE.md)
- [ ] No customer-specific information, account IDs, or PII included
- [ ] References section includes links to relevant AWS documentation
- [ ] Regulatory considerations reference the [Regulatory Context](REGULATORY_CONTEXT.md) document
- [ ] Inclusive language guidelines are followed (see below)

### Updating Existing Playbooks

When updating an existing playbook:
- Update the "Last Updated" date in the metadata table
- Note what changed in your PR description
- If adding new services or features, verify they are GA
- Ensure the update doesn't break the overall flow of the playbook

---

## AI Playbook Contributions

### Overview

The `ai-playbooks/` directory contains playbooks designed to be consumed by AI-powered IDEs. These come in two formats:

| Format | Location | IDE |
|---|---|---|
| Steering files | `ai-playbooks/steering/reference/` | [Kiro](https://kiro.dev/) |
| Skills | `ai-playbooks/skills/` | [Claude Code](https://code.claude.com/) |

### Creating AI Playbook Variants

When contributing a new AI playbook:

1. **Start with the human playbook** — The AI variant should be derived from an existing human-readable playbook in `playbooks/`
2. **Use the factory guides:**
   - For Kiro: Use `ai-playbooks/steering/steering-factory/` as your guide
   - For Claude Code: Use `ai-playbooks/skills/skill-irp-builder.md` or `skill-irp-playbook-factory.md`
3. **Update the routing:**
   - For Kiro: Update keyword patterns in `ai-playbooks/steering/steering-irp-core.md`
   - For Claude Code: Update routing in `ai-playbooks/skills/CLAUDE.md`
4. **Test with the IDE** — Verify the AI agent correctly routes to your playbook based on incident description keywords

### AI Playbook Quality Checklist

- [ ] Derived from a corresponding human playbook
- [ ] Front matter includes correct `inclusion` type (`manual` for incident-specific playbooks)
- [ ] Keyword patterns are specific enough to avoid false routing
- [ ] CLI commands are formatted for AI consumption (complete, copy-pasteable)
- [ ] Decision points are clearly structured for AI reasoning
- [ ] Both Kiro steering and Claude Code skill versions are provided (preferred, not required)

### AI-Assisted Contributions

We welcome contributions that were drafted with AI assistance. When submitting AI-assisted contributions:

- **Disclose AI usage** — Note in your PR description if AI tools were used in drafting
- **Verify all technical content** — AI can hallucinate service names, API calls, and console paths. Every command and reference must be human-verified
- **Test the playbook** — AI-generated playbooks must pass the same testing requirements as human-written ones
- **Review for coherence** — Ensure the playbook reads naturally and doesn't have repetitive or contradictory sections

---

## Contribution Guidelines

### Writing Style

- Write in clear, direct language appropriate for incident responders under pressure
- Use active voice ("Revoke the credentials" not "The credentials should be revoked")
- Be specific about what to look for and what actions to take
- Include both CLI commands and console path references where applicable
- Use American English spelling (behavior, color, analyze, organization, authorize) for consistency across the repository

### Formatting

- Use Markdown formatting consistently
- Code blocks must specify the language (```bash, ```json, etc.)
- Tables should be used for structured data (findings, services, parameters)
- Use blockquotes (>) for important warnings or notes
- Internal links should use relative paths

### Scope

- Playbooks should focus on **AWS-specific** incident response
- Keep content within the shared responsibility model — we cover security **in** the cloud
- Do not include proprietary tooling or vendor-specific solutions (beyond AWS services)
- Reference external tools generically (e.g., "your SIEM" not "Splunk")

---

## Testing Your Contributions

### Minimum Testing Requirements

1. **Link validation** — All internal and external links resolve correctly
2. **CLI command verification** — Run commands against a test account to verify syntax and output
3. **Console path verification** — Navigate the referenced console paths to confirm they exist
4. **Markdown rendering** — Preview your markdown to ensure tables, code blocks, and formatting render correctly

### Recommended Testing

4. **Scenario walkthrough** — Walk through the playbook steps in a test/sandbox AWS account
5. **Peer review** — Have someone unfamiliar with the scenario follow the playbook
6. **AI playbook testing** — For AI variants, test that the IDE correctly routes to and executes the playbook

### Testing Tools

- [markdownlint](https://github.com/DavidAnson/markdownlint) — Markdown style and consistency
- [markdown-link-check](https://github.com/tcort/markdown-link-check) — Verify all links resolve
- AWS CLI with `--dry-run` flags where available
- A dedicated AWS test account (never test against production)

---

## Inclusive Language

All contributions must use inclusive language. The following terms should be avoided:

| Don't Use | Use Instead |
|---|---|
| master | primary, main, leader, controller |
| slave | replica, secondary, follower, responder |
| whitelist | allowlist, approved list, inclusion list |
| blacklist | denylist, blocklist, exclusion list |
| whiteday(s) | clear day(s), allowed day(s) |
| blackday(s) | blocked day(s) |

---

## Security Issue Notifications

If you discover a potential security issue in this project, please notify AWS/Amazon Security via our [vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/) or directly via email to [aws-security@amazon.com](mailto:aws-security@amazon.com).

**Please do not create a public GitHub issue for security vulnerabilities.**

---

## Licensing

See the [LICENSE](LICENSE) file for details. By contributing, you agree that your contributions will be licensed under the same terms.

- Documentation: Creative Commons Attribution-ShareAlike 4.0 International License
- Sample code: MIT-0 License
