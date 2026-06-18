# Incident Triage Guide

This guide helps responders quickly assess the severity of a security incident and determine the appropriate response urgency. Use this alongside the specific incident response playbooks.

---

## Severity Matrix

| Priority | Label | Response Time | Description |
|---|---|---|---|
| **P1** | Critical | Immediate (< 15 min) | Active data exfiltration, production outage, confirmed breach with customer impact, or regulatory notification required |
| **P2** | High | < 1 hour | Confirmed compromise with containment needed, lateral movement detected, or privileged credential abuse |
| **P3** | Medium | < 4 hours | Suspicious activity requiring investigation, potential compromise not yet confirmed, or policy violation with security implications |
| **P4** | Low | < 24 hours | Informational findings, minor policy violations, or reconnaissance activity with no confirmed impact |

---

## Severity Decision Tree

### Step 1: Is there confirmed unauthorized access?

- **YES** → Go to Step 2
- **NO, but suspicious activity detected** → Start at **P3**, investigate to confirm or rule out
- **NO, informational only** → **P4**

### Step 2: Is data confirmed accessed or exfiltrated?

- **YES, customer/personal data** → **P1** (regulatory notification likely required)
- **YES, internal/operational data** → **P2**
- **NO, but access to sensitive resources confirmed** → **P2**
- **UNKNOWN** → Start at **P2**, escalate to P1 if data exposure confirmed

### Step 3: Is the threat actor still active?

- **YES, active session/access** → Escalate one level (minimum **P2**)
- **NO, access revoked/expired** → Maintain current priority
- **UNKNOWN** → Treat as active until confirmed otherwise

---

## Escalation Triggers

The following conditions should **immediately escalate** priority regardless of initial assessment:

| Trigger | Escalate To | Rationale |
|---|---|---|
| Multiple accounts compromised | P1 | Indicates organizational-level breach |
| Root account access detected | P1 | Highest privilege, maximum blast radius |
| Data confirmed exfiltrated externally | P1 | Regulatory notification likely required |
| Production workloads impacted | P1 | Customer-facing impact |
| Threat actor has persistence mechanisms | P2 (minimum) | Eradication required before recovery |
| Lateral movement between accounts | P2 (minimum) | Scope expanding |
| Credentials posted publicly (e.g., GitHub) | P2 | Race condition with threat actors |

---

## De-escalation Criteria

Priority may be **reduced** when:

| Condition | Action |
|---|---|
| Investigation confirms false positive | Close with documented rationale |
| Scope confirmed limited to non-production, non-sensitive resources | Reduce by one level |
| Threat actor access confirmed expired with no persistence | Reduce by one level |
| Automated containment confirmed effective | Maintain priority but reduce urgency |

---

## When to Engage AWS for Support

| Situation | Action | How |
|---|---|---|
| Suspected compromise of AWS infrastructure (not your resources) | Contact AWS Security | [aws-security@amazon.com](mailto:aws-security@amazon.com) or [vulnerability reporting](https://aws.amazon.com/security/vulnerability-reporting/) |
| Need forensic assistance or IR support | AWS Support (any plan level) | Open a support case requesting CIRT assistance |
| Account access lost / root compromise | AWS Support | Support case (Critical severity) or account recovery |
| DDoS attack in progress (Shield Advanced) | AWS Shield Response Team | Support case or proactive engagement |
| Need to preserve evidence beyond your access | AWS Support | Support case with IR context |

### Options for AWS Assistance

**Option 1: AWS Support (any AWS Support plan)**
Any customer with AWS Support can open a support case and request assistance from the AWS Customer Incident Response Team (CIRT). No additional service subscription is required.

**Option 2: AWS Security Incident Response service (if enabled)**
The [AWS Security Incident Response](https://aws.amazon.com/security-incident-response/) service provides additional capabilities for customers who have enabled it:
- Automated triage of security findings from GuardDuty and Security Hub
- 24/7 access to the AWS Customer Incident Response Team (CIRT)
- Dedicated case management and coordination
- Post-incident reporting

**When to engage AWS:**
- Any P1 or P2 incident where you need expert assistance
- When you're unsure about scope or containment effectiveness
- When the incident involves AWS service-level concerns
- When you need help with evidence preservation

---

## Initial Response Checklist (All Priorities)

Regardless of priority, the first responder should:

- [ ] **Document the trigger** — What alert, finding, or report initiated this?
- [ ] **Timestamp everything** — Note when you were notified and when you began response (UTC)
- [ ] **Assess scope** — How many accounts, regions, and resources are potentially affected?
- [ ] **Preserve evidence** — Do NOT terminate instances, delete logs, or modify resources before capturing state
- [ ] **Assign priority** — Use the matrix above
- [ ] **Notify stakeholders** — Per your organization's communication plan
- [ ] **Open a case** — In your incident tracking system
- [ ] **Begin playbook** — Select the appropriate playbook based on incident type

---

## Incident Type Quick Reference

| Indicators | Likely Scenario | Playbook |
|---|---|---|
| Unusual API calls from unknown IP, new access keys created | Credential compromise | [IRP-CredCompromise](playbooks/IRP-CredCompromise.md) |
| Large data transfers, S3 GetObject spikes, unusual Macie findings | Data exfiltration | [IRP-S3DataExfiltration](playbooks/IRP-S3DataExfiltration.md) |
| GuardDuty CryptoCurrency findings, CPU spikes, unusual instance types | Cryptomining | [IRP-Cryptomining](playbooks/IRP-Cryptomining.md) |
| Encrypted volumes, ransom notes, backup deletion attempts | Ransomware | [IRP-Ransomware](playbooks/IRP-Ransomware.md) |
| AssumeRole chains, cross-account activity, unusual federation | STS token abuse | [IRP-STSTokenAbuse](playbooks/IRP-STSTokenAbuse.md) |
| SSO permission changes, new assignments, IdP configuration changes | Identity Center compromise | [IRP-IdentityCenterCompromise](playbooks/IRP-IdentityCenterCompromise.md) |
| Traffic spikes, 5xx errors, Shield/WAF alerts | DoS/DDoS | [IRP-DoS](playbooks/IRP-DoS.md) |
| Pod escape, container runtime alerts, Kubernetes audit anomalies | Container/EKS compromise | [IRP-ContainerEKSCompromise](playbooks/IRP-ContainerEKSCompromise.md) |
| Build artifact changes, dependency alerts, pipeline modifications | CI/CD compromise | [IRP-CICDCompromise](playbooks/IRP-CICDCompromise.md) |
| Root login, MFA changes, account recovery attempts | Root account takeover | [IRP-AccountTakeoverRoot](playbooks/IRP-AccountTakeoverRoot.md) |
| C2 traffic, reverse shells, IMDS access from unusual processes | EC2 compromise | [IRP-EC2Compromise](playbooks/IRP-EC2Compromise.md) |
| Off-hours bulk access, privilege escalation by authorized user | Insider threat | [IRP-InsiderThreat](playbooks/IRP-InsiderThreat.md) |
| SAML assertion anomalies, IdP config changes, federated session abuse | Federated access abuse | [IRP-FederatedAccessAbuse](playbooks/IRP-FederatedAccessAbuse.md) |
| Personal data access confirmed, Macie PII findings | Personal data breach | [IRP-PersonalDataBreach](playbooks/IRP-PersonalDataBreach.md) |

---

## References

- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
- [AWS Security Incident Response Service](https://aws.amazon.com/security-incident-response/)
