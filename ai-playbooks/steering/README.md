# AI-Powered Incident Response Automation
This README relates specifically to this directory subsection of the aws-incident-response-playbook repository. The markdown files in this directory are to be used to create - and then use - a set of guidance files that can be used with your AI-powered IDE of choice and will assist you to respond to security incidents.

These markdown documents are created to be used as templates only. They should be customized by administrators working with AWS to suit their particular needs, risks, available tools and work processes. These files are not official AWS documentation and are provided as-is to customers using AWS products and who are looking to improve their incident response capability, by powering it with artificial intelligence ("AI").

These markdown documents are written to facilitate editing and consumption into a variety of integrated development environments ("IDE"s) as guidance files. [In Kiro, these are known as "steering files"](https://kiro.dev/docs/steering/) and [in Claude Code, they are known as "skills"](https://code.claude.com/docs/en/skills). In both examples, the files are written in markdown for consumption into the relevant IDE.

<<<<<<< HEAD:ai-playbooks/README.md
Note that you need to copy the files in this repo into the correct directory in your IDE. In Kiro, we recommend setting up a new project, and defining a [workspace](https://kiro.dev/docs/steering/) and keeping your steering files in the steering directory *for the workspace*.

The markdown documents included cover several common scenarios faced by AWS customers. They outline steps based on the [NIST Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) (Special Publication 800-61 Revision 2) and codify these steps as structured guidance that AI agents can use to assist a human operator investigate and resolve an incident. This includes the following steps outlined by NIST:
=======
The markdown documents included cover several common scenarios faced by AWS customers. They outline steps based on the [NIST Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final) (Special Publication 800-61 Revision 3) and codify these steps as structured guidance that AI agents can use to assist a human operator investigate and resolve an incident. This includes the following steps outlined by NIST:
>>>>>>> upstream/master:ai-playbooks/steering/README.md

* Gather evidence
* Contain and then eradicate the incident
* Recover from the incident
* Conduct post-incident activities, including post-mortem and feedback processes

## Usage
### Kiro IDE

#### File types
There are three categories of markdown files we have created for this AI-powered incident response solution:

* **Steering Factory**: Use the `.kiro-steering/steering-factory/steering-factory-creation-guide.md` to create your own incident response steering files. This file is _only_ used when you want to create new `steering-irp-<playbook>.md` steering files
* **Steering Core**: The `.kiro-steering/steering-irp-core.md` file is _always_ used when you are using the Kiro IDE to investigate and respond to a security incident. The `steering-irp-core.md` file can be saved under `.kiro/steering/` within a given workspace. We recommend you create a [separate workspace](https://kiro.dev/docs/editor/multi-root-workspaces/) specifically for incident response.
* **Steering Incident Response**: These files are invoked as needed based on the initial problem description given by the operator; the steering core file helps Kiro make a decision about which incident-specific playbook to load. These files are also. stored under `.kiro/steering/` along with the core file.

#### How the files direct Kiro IDE
The core file (steering-irp-core.md) is set to inclusion: always, so it's loaded into every conversation automatically. It acts as the orchestrator — it defines the NIST 800-61 lifecycle, contains keyword pattern matching logic to classify the incident type, and then tells the AI which specific playbook to pull in.

The incident-specific files (such as "credential compromise", "unintended data access", and "ransomware") are all inclusion: manual. They don't load unless explicitly invoked. But the core file's keyword matching logic determines which one(s) to invoke based on what the operator describes.

So the flow is:

User describes a security incident
Core file (always loaded) kicks in, analyzes the prompt against its keyword patterns
Core file directs the AI to invoke the appropriate manual steering file(s)
The specific playbook guides the actual IR steps
It's essentially a router pattern — one always-on dispatcher that selectively activates specialized playbooks on demand. And since each manual file also lists all three playbooks in its description front matter, the AI knows about the other playbooks even when it's deep in one specific response, so it can pivot if the incident turns out to be multi-vector (e.g., credential compromise leading to ransomware).

```mermaid
---
config:
  flowchart:
    padding: 15
---
flowchart TD
    A[User describes security incident] --> B[steering-irp-core.md <br/> **always loaded**]
    B --> C{Keyword Pattern <br/> Matching}
    C -->|credential, access key, <br/> IAM user, GuardDuty| D[steering-irp-credential-compromise.md]
    C -->|S3 bucket, data access, <br/> public bucket, object ACL| E[steering-irp-data-access.md]
    C -->|Ransomware, ransom, <br/> encrypted files, locked out| F[steering-irp-ransomware.md]
    C -->|no clear match| D
    D --> G[Execute NIST 800-61 Lifecycle <br/> Evidence → Contain → Eradicate → Recover → Post-Incident]
    E --> G
    F --> G
    G --> H{Multi-vector <br/>detected?}
    H -->|Yes| I[Invoke additional <br/> playbook]
    I --> G
    H -->|No| J[Root cause analysis <br/> &#40actions taken&#41 <br/> + further actions needed]

    style B fill:#2d6a4f,color:#fff
    style D fill:#1b4965,color:#fff
    style E fill:#1b4965,color:#fff
    style F fill:#1b4965,color:#fff
    style C fill:#6c757d,color:#fff
    style H fill:#6c757d,color:#fff
```

The "Tool Selection Strategy" section in the core file is also a nice touch — it tells the AI to prefer MCP tools over CLI when available, without requiring us as authors to maintain two versions of every command.

### Claude Code

Claude Code uses a parallel structure to the Kiro steering system, adapted to how Claude Code loads context.

#### File types

There are three categories of files for Claude Code:

* **Skill Factory**: Use `.claude/skills/skill-irp-playbook-factory.md` to create new IR skills from existing playbooks in `playbooks/`. This skill is only invoked when you want to create new `skill-irp-<playbook>.md` skill files.
* **CLAUDE.md (Core Router)**: The `CLAUDE.md` file at the repo root is **always loaded** by Claude Code at the start of every conversation in this directory. It serves the same role as `steering-irp-core.md` in Kiro — it defines the NIST 800-61 lifecycle, contains keyword pattern matching logic to classify the incident type, and directs Claude Code to invoke the appropriate skill.
* **IR Skills**: The incident-specific skill files (`.claude/skills/skill-irp-*.md`) are invoked on demand. Claude Code's skill system loads them when the operator invokes them directly (e.g., `/skill-irp-credential-compromise`) or when the routing logic in `CLAUDE.md` determines the incident type and requests the relevant skill.

#### Architecture mapping

| Kiro Concept | Claude Code Equivalent |
|---|---|
| `steering-irp-core.md` (`inclusion: always`) | `CLAUDE.md` at repo root (always loaded) |
| `steering-irp-*.md` (`inclusion: manual`) | `.claude/skills/skill-irp-*.md` (loaded on demand) |
| Steering factory guide | `.claude/skills/skill-irp-playbook-factory.md` |

#### How the files direct Claude Code

`CLAUDE.md` is loaded into every conversation automatically. It acts as the orchestrator — it defines the NIST 800-61 lifecycle, contains keyword pattern matching logic to classify the incident type, and tells Claude Code which specific skill to pull in.

The incident-specific skills (credential compromise, unintended data access, ransomware) are loaded on demand. Unlike the Kiro system, sibling skills do not cross-reference each other — `CLAUDE.md` is the single routing authority.

The flow is identical to Kiro:

```mermaid
---
config:
  flowchart:
    padding: 15
---
flowchart TD
    A[User describes security incident] --> B[CLAUDE.md <br/> **always loaded**]
    B --> C{Keyword Pattern <br/> Matching}
    C -->|credential, access key, <br/> IAM user, GuardDuty| D[skill-irp-credential-compromise]
    C -->|S3 bucket, data access, <br/> public bucket, object ACL| E[skill-irp-data-access]
    C -->|Ransomware, ransom, <br/> encrypted files, locked out| F[skill-irp-ransomware]
    C -->|no clear match| D
    D --> G[Execute NIST 800-61 Lifecycle <br/> Evidence → Contain → Eradicate → Recover → Post-Incident]
    E --> G
    F --> G
    G --> H{Multi-vector <br/>detected?}
    H -->|Yes| I[Invoke additional <br/> skill]
    I --> G
    H -->|No| J[Root cause analysis <br/> &#40actions taken&#41 <br/> + further actions needed]

    style B fill:#2d6a4f,color:#fff
    style D fill:#1b4965,color:#fff
    style E fill:#1b4965,color:#fff
    style F fill:#1b4965,color:#fff
    style C fill:#6c757d,color:#fff
    style H fill:#6c757d,color:#fff
```

The Tool Selection Strategy section in `CLAUDE.md` tells Claude Code to prefer MCP tools (e.g., `call_aws` via the AWS API MCP Server) over CLI when available, without requiring two versions of every command.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

Artificial intelligence can make mistakes. Ensure that operators carefully check and verify output.

## License Summary

The documentation is made available under the Creative Commons Attribution-ShareAlike 4.0 International License. See the LICENSE file.

The sample code within this documentation is made available under the MIT-0 license. See the LICENSE-SAMPLECODE file.