# AWS Incident Response Playbook Samples

These playbooks are provided as templates for organizations building incident response capability on AWS. They should be customized to suit your specific needs, risks, available tools, and work processes. These guides are not official AWS documentation and are provided as-is.

All playbooks are aligned to the [NIST SP 800-61 Revision 3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final) framework and mapped to the CSF 2.0 Community Profile.

> **What's new in this version:** This repository was significantly refreshed in 2026. Playbooks have been rewritten to align with NIST SP 800-61r3 (previously r2), reference current AWS services (including the AWS Security Incident Response service, IAM Access Analyzer, Amazon Macie, and GuardDuty Runtime Monitoring), and follow a standardized template structure. AI-assisted playbook variants and automation patterns have been added.

---

## Getting Started

| Resource | Purpose |
|---|---|
| [Triage Guide](TRIAGE_GUIDE.md) | Quickly assess incident severity (P1–P4) and determine response urgency |
| [Playbook Template](PLAYBOOK_TEMPLATE.md) | Standard structure for all playbooks — use when creating new ones |
| [Regulatory Context](REGULATORY_CONTEXT.md) | Notification obligations by incident type and regulation |
| [Contributing](CONTRIBUTING.md) | How to contribute new playbooks or improvements |

---

## Playbooks

### Identity & Access Scenarios

| Playbook | Description |
|---|---|
| [Credential Compromise](playbooks/IRP-CredCompromise.md) | IAM access key or console credential theft and abuse |
| [STS Token Abuse](playbooks/IRP-STSTokenAbuse.md) | AssumeRole chain attacks, cross-account pivoting, IMDS credential theft |
| [Identity Center Compromise](playbooks/IRP-IdentityCenterCompromise.md) | AWS SSO permission set abuse, identity store manipulation |
| [Federated Access Abuse](playbooks/IRP-FederatedAccessAbuse.md) | BEC or IdP compromise (Okta, Azure AD) leading to AWS access |
| [Insider Threat](playbooks/IRP-InsiderThreat.md) | Anomalous authorized user behavior — technical detection and containment |

### Compute & Infrastructure Scenarios

| Playbook | Description |
|---|---|
| [EC2 Compromise](playbooks/IRP-EC2Compromise.md) | Instance-level compromise — C2, lateral movement, IMDS abuse |
| [Container/EKS Compromise](playbooks/IRP-ContainerEKSCompromise.md) | Pod escape, malicious images, IRSA abuse, Kubernetes RBAC manipulation |
| [CI/CD Compromise](playbooks/IRP-CICDCompromise.md) | Pipeline compromise, dependency poisoning, build artifact tampering |
| [Cryptomining](playbooks/IRP-Cryptomining.md) | Unauthorized compute resource abuse for cryptocurrency mining |
| [Ransomware](playbooks/IRP-Ransomware.md) | Cloud-native ransomware — EBS encryption, S3 deletion, KMS abuse |
| [Denial of Service](playbooks/IRP-DoS.md) | DDoS and application-layer attacks |

### Data & Application Scenarios

| Playbook | Description |
|---|---|
| [Data Access](playbooks/IRP-DataAccess.md) | Unauthorized access to data stores (S3, DynamoDB, Secrets Manager) |
| [S3 Data Exfiltration](playbooks/IRP-S3DataExfiltration.md) | Bulk S3 extraction — replication abuse, presigned URLs, batch operations |
| [Root Account Takeover](playbooks/IRP-AccountTakeoverRoot.md) | Root credential compromise — always P1 |
| [Personal Data Breach](playbooks/IRP-PersonalDataBreach.md) | Regulatory notification workflow when personal data is involved |

### AI / Agentic Workload Scenarios

Incident response for Amazon Bedrock AgentCore — autonomous AI agents whose blast radius expands with every tool call. These scenarios cover the AgentCore-specific attack surface (Cedar authorization, Token Vault credentials, sandbox tools, Memory, observability) that traditional compute/identity playbooks do not address.

| Playbook | Description |
|---|---|
| [AgentCore Identity & Credential Compromise](playbooks/IRP-AgentCoreIdentityCompromise.md) | Stolen Cognito JWT, machine-client secret, workload-identity session, or Token Vault / OAuth2 / API-key credential-provider theft |
| [AgentCore Agent Integrity](playbooks/IRP-AgentCoreAgentIntegrity.md) | Prompt injection, memory poisoning, poisoned Runtime artifact (S3 ZIP / ECR image), Registry supply-chain compromise |
| [AgentCore Authorization Bypass](playbooks/IRP-AgentCoreAuthorizationBypass.md) | Cedar Policy Engine flipped ENFORCE → LOG_ONLY, rogue Gateway target, cross-account resource-based policy |
| [AgentCore Tool Abuse](playbooks/IRP-AgentCoreToolAbuse.md) | Code Interpreter SSRF / exfiltration, Browser SSRF / saved-profile persistence, network-mode drift to PUBLIC |
| [AgentCore Observability Tampering](playbooks/IRP-AgentCoreObservabilityTampering.md) | CloudTrail / Log Group / X-Ray / KMS tampering that blinds the investigator; Evaluations-role trace exfiltration |

### GuardDuty Finding Quick-Response Guides

These are finding-specific quick-response guides (5-minute triage) that route to the full lifecycle playbooks above.

| Category | Findings Covered |
|---|---|
| [EC2 Findings](guardduty-playbooks/ec2-findings.md) | Backdoor, Trojan, CryptoCurrency, UnauthorizedAccess, Recon, Impact |
| [S3 Findings](guardduty-playbooks/s3-findings.md) | Exfiltration, Discovery, Impact, Policy, UnauthorizedAccess |
| [IAM Findings](guardduty-playbooks/iam-findings.md) | CredentialAccess, Discovery, InitialAccess, Persistence, PrivilegeEscalation |
| [EKS & Runtime Findings](guardduty-playbooks/eks-runtime-findings.md) | Execution, PrivilegeEscalation, Persistence, Discovery, DefenseEvasion |

---

## AI-Assisted Playbooks

The `ai-playbooks/` directory contains vendor-agnostic, AI-readable versions of these playbooks. They work with any AI coding assistant or LLM — Kiro, Claude Code, Cursor, Windsurf, GitHub Copilot, or any tool that can consume markdown as context.

The AI playbooks are designed with human-in-the-loop safeguards: the AI guides and recommends, but always waits for explicit human confirmation before executing any action that modifies the environment.

See the [AI Playbooks README](ai-playbooks/README.md) for setup instructions and architecture details.

---

## Automation Patterns

The `automation-patterns/` directory contains reference examples showing how to wire AWS services for IR automation. These are starting points, not production-ready IaC.

| Pattern | Description |
|---|---|
| [EventBridge Rules](automation-patterns/eventbridge-rules.md) | 10 event patterns for common IR triggers (GuardDuty, root activity, CloudTrail tampering) |
| [Step Functions Workflow](automation-patterns/step-functions-ir-workflow.md) | Reference state machine for IR orchestration with human approval gates |
| [Security Hub Custom Actions](automation-patterns/security-hub-custom-actions.md) | Human-in-the-loop automation — click a button to isolate, revoke, or preserve |

For production-ready implementations, see [aws-samples/aws-security-incident-response-integrations](https://github.com/aws-samples/aws-security-incident-response-integrations).

---

## Getting Help from AWS

All AWS customers can request assistance from the AWS Customer Incident Response Team (CIRT) through a support case, regardless of support plan level. You do not need any specific service subscription to get help during a security incident.

Additionally, the [AWS Security Incident Response](https://aws.amazon.com/security-incident-response/) service provides automated triage, case management, and proactive engagement capabilities for customers who enable it.

---

## Related Resources

| Resource | Description |
|---|---|
| [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html) | Comprehensive guide to IR on AWS |
| [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) | Incident Response Recommendations and Considerations |
| [AWS Customer Playbook Framework](https://github.com/aws-samples/aws-customer-playbook-framework) | Additional playbook templates with multi-language support |
| [AWS Security IR Integrations](https://github.com/aws-samples/sample-aws-security-incident-response-integrations) | Sample automation integrations for IR workflows |
| [AWS CIRT Workshops](https://aws.amazon.com/blogs/security/aws-cirt-announces-the-release-of-five-publicly-available-workshops/) | Hands-on IR workshops |
| [AWS Threat Detection & Response Workshop](https://catalog.workshops.aws/threat-detection-and-response) | Workshop for detection and response |
| [AWS Security Reference Architecture](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html) | Prescriptive security architecture guidance |

---

## Usage

These playbooks are written in markdown to facilitate editing and consumption into a variety of systems. They should be tested (for example, in Game Days) prior to deployment and all responders should be familiar with the actions required.

Some incident response steps may incur costs in your AWS account(s). Customizing and testing these scenarios will help you determine potential cost impact.

---

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

---

## License Summary

The documentation is made available under the Creative Commons Attribution-ShareAlike 4.0 International License. See the LICENSE file.

The sample code within this documentation is made available under the MIT-0 license. See the LICENSE-SAMPLECODE file.
